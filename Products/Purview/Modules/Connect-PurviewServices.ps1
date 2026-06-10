#requires -Version 7.0
<#
.SYNOPSIS
    Connects to all Microsoft 365 services required by the Purview Best Practice toolkit.

.DESCRIPTION
    Idempotent connection helper. Detects existing sessions and reuses them.
    Supports both standard customer-admin auth and partner GDAP delegated auth via
    -DelegatedOrganization.

    Services connected:
      * Exchange Online                (Connect-ExchangeOnline)
      * Security & Compliance (IPPS)   (Connect-IPPSSession)
      * SharePoint Online              (Connect-SPOService)
      * Microsoft Graph (Beta)         (Connect-MgGraph) — only if -ConnectGraph is passed

    Required PowerShell modules:
      * ExchangeOnlineManagement
      * Microsoft.Online.SharePoint.PowerShell
      * Microsoft.Graph.Beta.Identity.DirectoryManagement (only if -ConnectGraph)

.PARAMETER TenantAdminUpn
    UPN of the customer tenant admin (or partner GDAP admin) used for sign-in.

.PARAMETER NeedsSharePoint
    Connect to SharePoint Online (after Exchange Online). The admin URL is
    auto-derived using the following precedence chain:
      1. -SharePointAdminUrl (explicit override)
      2. -DelegatedOrganization (GDAP — tenant primary domain)
      3. Admin UPN suffix (when *.onmicrosoft.com)
      4. EXO Get-AcceptedDomain (final fallback)

.PARAMETER SharePointAdminUrl
    Optional override for the SharePoint admin centre URL
    (e.g. https://contoso-admin.sharepoint.com). When omitted, the URL is
    auto-derived using the precedence chain described under -NeedsSharePoint.
    Pass this explicitly for multi-geo, renamed tenants, or vanity-domain
    admin UPNs where the chain cannot resolve.

.PARAMETER DelegatedOrganization
    Customer tenant primary domain (e.g. contoso.onmicrosoft.com) when a partner
    is signing in via GDAP. Forwarded to Connect-ExchangeOnline and
    Connect-IPPSSession.

.PARAMETER ConnectGraph
    Connect to Microsoft Graph (Beta). Required only when configuring container
    labels (Group.Unified EnableMIPLabels).

.PARAMETER GraphScopes
    Delegated Microsoft Graph scopes to request when -ConnectGraph is used.
    Defaults to the read-only set 'Organization.Read.All' (sufficient for license
    auto-detect via /subscribedSkus and tenant-identity confirm via /organization).
    The orchestrator adds 'Directory.ReadWrite.All' on top of this only
    when container labels (Group.Unified EnableMIPLabels) will actually be
    written, keeping the consented privilege as narrow as the run requires.
    NOTE: Directory.ReadWrite.All is the historically-consented, known-working
    scope on most tenants for /directorySettingTemplates and /settings. A
    narrower scope (GroupSettings.ReadWrite.All) was tried but produced 403
    Authorization_RequestDenied on tenants where admins had only consented
    Directory.ReadWrite.All historically.

.PARAMETER AutoInstallModules
    When set, missing PowerShell modules are installed automatically (scope
    CurrentUser) without prompting. Without this switch the script prompts
    interactively before installing.

.OUTPUTS
    PSCustomObject with the resolved SharePointAdminUrl (when SPO was connected).

.EXAMPLE
    .\Connect-PurviewServices.ps1 -TenantAdminUpn admin@contoso.onmicrosoft.com `
        -NeedsSharePoint

.EXAMPLE
    # Partner GDAP scenario with explicit SPO URL override
    .\Connect-PurviewServices.ps1 -TenantAdminUpn partneradmin@fabrikam.onmicrosoft.com `
        -NeedsSharePoint -SharePointAdminUrl https://contoso-admin.sharepoint.com `
        -DelegatedOrganization contoso.onmicrosoft.com
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [string] $TenantAdminUpn,

    [Parameter()]
    [switch] $NeedsSharePoint,

    [Parameter()]
    [string] $SharePointAdminUrl,

    [Parameter()]
    [string] $DelegatedOrganization,

    [Parameter()]
    [switch] $ConnectGraph,

    [Parameter()]
    [string[]] $GraphScopes = @('Organization.Read.All'),

    [Parameter()]
    [switch] $AutoInstallModules,

    [Parameter()]
    [switch] $NonInteractive,

    # When set, run the Copilot DLP module-readiness pre-check. Used by the
    # orchestrator when the AI governance step is in scope (default-on for
    # E5 / Purview Suite tenants); skipped when the operator passed
    # -SkipAIControls / -BPOnly so we don't emit noise for runs that won't
    # touch the Copilot DLP cmdlets.
    [Parameter()]
    [switch] $AIControlsInScope
)

# Minimum ExchangeOnlineManagement version whose IPPS REST proxy exposes the
# Copilot DLP parameters (-Locations / -EnforcementPlanes) reliably. Below
# this version, Setup-AIGovernance's sanity check bails ("module does not
# expose the Copilot DLP parameters") because the dynamically-generated
# New-DlpCompliancePolicy proxy is missing those parameters. This constant
# drives a NON-blocking pre-req warning + HTML report callout — the actual
# hard backstop still lives in Setup-AIGovernance.ps1.
$script:CopilotDlpMinExoVersion = [version]'3.9.0'

$ErrorActionPreference = 'Stop'

# Connecting to services is a precondition, not a destructive change. Some
# auth flows (notably Connect-SPOService and Import-Module -UseWindowsPowerShell)
# have internal steps that respect $WhatIfPreference and silently skip work
# under -WhatIf, producing misleading "No valid OAuth 2.0 authentication
# session exists" errors. Force WhatIf off for the duration of this script.
$WhatIfPreference = $false
$ConfirmPreference = 'None'

# ---------------------------------------------------------------------------
# Run log helper — idempotent dot-source so Add-RunLogEntry is available even
# when this script is invoked standalone (i.e. without the orchestrator). The
# helper itself wraps all writes in try/catch and lazy-inits $global:PurviewRunLog,
# so calling it when no run log was initialised is a silent no-op.
# Same pattern as Invoke-WithTransientRetry.ps1.
# ---------------------------------------------------------------------------
$_purviewRunLogPath = Join-Path $PSScriptRoot 'PurviewRunLog.ps1'
if (Test-Path $_purviewRunLogPath) {
    . $_purviewRunLogPath
}

function Add-ConnectGuardLog {
    <#
        Emits a structured Add-RunLogEntry for a connect-side session guard
        decision. Detail is built as 'reason=<key>; k1=v1; k2=v2; ...' using
        stable key names so operators can grep / filter Get-PurviewRunLog
        output after the fact.

        Status semantics for this helper:
          * Info    — guard accepted the cached session OR neutral observation
          * Started — about to call Connect-* (cold start or after stale discard)
          * Retried — guard rejected the cached session and will reconnect
          * Skipped — guard intentionally bypassed (e.g. service disabled by flag)
          * Failed  — recoverable problem detected by a guard helper
                      (e.g. Beta version pin self-heal couldn't install / import).
                      Use 'Failed' (not 'Error') for parity with Add-RunLogEntry.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string] $Service,
        [Parameter(Mandatory)]
        [ValidateSet('Info','Started','Retried','Skipped','Failed')]
        [string] $Status,
        [Parameter(Mandatory)] [string] $ReasonKey,
        [hashtable] $Detail
    )

    if (-not (Get-Command Add-RunLogEntry -ErrorAction SilentlyContinue)) { return }

    $parts = @("reason=$ReasonKey")
    if ($Detail) {
        foreach ($k in ($Detail.Keys | Sort-Object)) {
            $v = $Detail[$k]
            if ($null -eq $v) { $v = '' }
            $parts += ('{0}={1}' -f $k, $v)
        }
    }

    try {
        Add-RunLogEntry -Module 'Connect-PurviewServices' `
            -Action "SessionGuard:$Service" `
            -Status $Status `
            -Detail ($parts -join '; ')
    } catch {
        Write-Verbose "Add-ConnectGuardLog failed: $($_.Exception.Message)"
    }
}

function Test-WamBrokerReadiness {
    <#
        Best-effort readiness check for Windows Authentication Manager (WAM).
        Returns a PSCustomObject with:
          * Eligible — $true when no blocking issues were found
          * Issues   — list of short human-readable problem descriptions
          * Info     — diagnostic hashtable for the run log

        WAM is enabled by default on Windows 10 / Server 2019 and later in current
        Microsoft.Graph.Authentication (>= 2.x) and ExchangeOnlineManagement
        (>= 3.3). When WAM is active, second-and-subsequent sign-in prompts show
        the single-click "Continue" account picker instead of a full browser
        sign-in. When unavailable, every service connection falls back to a
        browser popup — that is the cause of the "6 prompts per run" symptom.

        Per MS Learn: 'Signin by Web Account Manager (WAM) is enabled by default
        on Windows and cannot be disabled' in current modules — so no runtime
        DisableLoginByWAM check is performed; we only check environment + module
        readiness here.
    #>
    [CmdletBinding()]
    param()

    $issues = @()
    $info   = [ordered]@{
        wamEligible            = $false
        psEdition              = $PSVersionTable.PSEdition
        psVersion              = $PSVersionTable.PSVersion.ToString()
        isWindows              = [bool]$IsWindows
        windowsBuild           = $null
        productType            = $null
        userInteractive        = [Environment]::UserInteractive
        runningAsSystem        = $false
        graphAuthModuleVersion = 'not-installed'
        exoModuleVersion       = 'not-installed'
    }

    if (-not $IsWindows) {
        $issues += "Not running on Windows — WAM is a Windows-only broker; every connect call falls back to a browser popup."
        return [pscustomobject]@{ Eligible = $false; Issues = $issues; Info = $info }
    }

    try {
        $os = Get-CimInstance Win32_OperatingSystem -ErrorAction Stop
        $build = [int]($os.BuildNumber)
        $productType = [int]$os.ProductType  # 1=workstation, 2=DC, 3=server
        $info.windowsBuild = $build
        $info.productType  = $productType

        if ($productType -eq 1 -and $build -lt 10240) {
            $issues += "Windows build $build is older than Windows 10 1507 (10240) — WAM not available."
        } elseif ($productType -ge 2 -and $build -lt 17763) {
            $issues += "Windows Server build $build is older than Server 2019 (17763) — WAM not available."
        }
    } catch {
        # CIM failure is non-fatal; treat as 'unknown', not a blocker.
        Write-Verbose "Could not detect Windows build via CIM: $($_.Exception.Message)"
    }

    try {
        $current = [Security.Principal.WindowsIdentity]::GetCurrent()
        if ($current -and $current.IsSystem) {
            $info.runningAsSystem = $true
            $issues += "Running as SYSTEM — WAM requires a user desktop session; sign-in will fall back to browser."
        }
    } catch { }

    if (-not [Environment]::UserInteractive) {
        $issues += "PowerShell host is not interactive — WAM popup requires an interactive desktop session."
    }

    $mgMod = Get-Module Microsoft.Graph.Authentication -ListAvailable -ErrorAction SilentlyContinue |
        Sort-Object Version -Descending | Select-Object -First 1
    if ($mgMod) {
        $info.graphAuthModuleVersion = $mgMod.Version.ToString()
        if ($mgMod.Version.Major -lt 2) {
            $issues += "Microsoft.Graph.Authentication v$($mgMod.Version) predates built-in WAM (need 2.x). Update: Update-Module Microsoft.Graph.Authentication"
        }
    }

    $exoMod = Get-Module ExchangeOnlineManagement -ListAvailable -ErrorAction SilentlyContinue |
        Sort-Object Version -Descending | Select-Object -First 1
    if ($exoMod) {
        $info.exoModuleVersion = $exoMod.Version.ToString()
        if ($exoMod.Version -lt [version]'3.3.0') {
            $issues += "ExchangeOnlineManagement v$($exoMod.Version) predates WAM integration (need 3.3+). Update: Update-Module ExchangeOnlineManagement"
        }
    }

    $info.wamEligible = ($issues.Count -eq 0)
    [pscustomobject]@{
        Eligible = $info.wamEligible
        Issues   = $issues
        Info     = $info
    }
}

function Test-MsalDllCompatibility {
    <#
        Detects mismatched Microsoft.Identity.Client.dll (MSAL) versions
        bundled by ExchangeOnlineManagement and Microsoft.Graph.Authentication.

        Why this matters
        ----------------
        Each module ships its OWN copy of Microsoft.Identity.Client.dll under
        its module folder (e.g. ExchangeOnlineManagement\<ver>\netCore\ vs
        Microsoft.Graph.Authentication\<ver>\Dependencies\Core\). When both
        modules are imported into the same PowerShell process, the CLR binds
        to whichever copy was loaded FIRST and ignores the other. This script
        connects to Exchange Online BEFORE Microsoft Graph, so EXO's MSAL
        wins the AppDomain.

        If EXO and Graph were compiled against different MSAL versions and a
        method signature changed between those versions (a recurring event
        in MSAL releases, e.g. WithLogging(IIdentityLogger, Boolean) moving
        between AbstractApplicationBuilder and BaseAbstractApplicationBuilder
        in 4.83), Connect-MgGraph throws:

            InteractiveBrowserCredential authentication failed:
            Method not found: '!0 Microsoft.Identity.Client.<X>.<Method>(...)'.

        That error reads like a credential failure but is purely a DLL-binding
        mismatch. We surface it as a structured pre-flight warning so the
        operator knows exactly which two module versions disagree and how to
        re-align them BEFORE Connect-MgGraph blows up.

        Returns a PSCustomObject with:
          * Compatible — $true when MSAL DLLs are aligned (or only one of the
                         two modules is installed, so no in-process conflict
                         is possible from this script)
          * Issues     — list of short human-readable problem descriptions
          * Info       — diagnostic hashtable for the run log
    #>
    [CmdletBinding()]
    param()

    $issues = @()
    $info = [ordered]@{
        psEdition          = $PSVersionTable.PSEdition
        exoModuleVersion   = $null
        exoMsalDllPath     = $null
        exoMsalVersion     = $null
        graphModuleVersion = $null
        graphMsalDllPath   = $null
        graphMsalVersion   = $null
        loadedMsalVersion  = $null
        loadedMsalLocation = $null
    }

    function _findMsalDll([string]$ModuleBase) {
        if (-not $ModuleBase -or -not (Test-Path $ModuleBase)) { return $null }
        # Prefer the edition-specific subfolder (Core for PS 7, Desktop for
        # PS 5.1 / Windows PowerShell). Module layouts vary:
        #   ExchangeOnlineManagement\<ver>\netCore\Microsoft.Identity.Client.dll
        #   ExchangeOnlineManagement\<ver>\netFramework\Microsoft.Identity.Client.dll
        #   Microsoft.Graph.Authentication\<ver>\Dependencies\Core\Microsoft.Identity.Client.dll
        #   Microsoft.Graph.Authentication\<ver>\Dependencies\Desktop\Microsoft.Identity.Client.dll
        $isCore = ($PSVersionTable.PSEdition -eq 'Core')
        $preferred = if ($isCore) { @('netCore', 'Dependencies\Core', 'Core') }
                     else        { @('netFramework', 'Dependencies\Desktop', 'Desktop') }
        foreach ($sub in $preferred) {
            $path = Join-Path $ModuleBase $sub
            if (Test-Path $path) {
                $hit = Get-ChildItem -Path $path -Filter 'Microsoft.Identity.Client.dll' -Recurse -ErrorAction SilentlyContinue |
                       Select-Object -First 1
                if ($hit) { return $hit }
            }
        }
        # Fallback: any copy under the module base.
        Get-ChildItem -Path $ModuleBase -Filter 'Microsoft.Identity.Client.dll' -Recurse -ErrorAction SilentlyContinue |
            Select-Object -First 1
    }

    function _toVersion([string]$raw) {
        if (-not $raw) { return $null }
        $m = [regex]::Match($raw, '^\d+(\.\d+){1,3}')
        if ($m.Success) { try { return [version]$m.Value } catch { return $null } }
        return $null
    }

    $exoMod = Get-Module ExchangeOnlineManagement -ListAvailable -ErrorAction SilentlyContinue |
        Sort-Object Version -Descending | Select-Object -First 1
    if ($exoMod) {
        $info.exoModuleVersion = $exoMod.Version.ToString()
        $dll = _findMsalDll $exoMod.ModuleBase
        if ($dll) {
            $info.exoMsalDllPath = $dll.FullName
            try { $info.exoMsalVersion = (Get-Item $dll.FullName).VersionInfo.FileVersion } catch {}
        }
    }

    $mgMod = Get-Module Microsoft.Graph.Authentication -ListAvailable -ErrorAction SilentlyContinue |
        Sort-Object Version -Descending | Select-Object -First 1
    if ($mgMod) {
        $info.graphModuleVersion = $mgMod.Version.ToString()
        $dll = _findMsalDll $mgMod.ModuleBase
        if ($dll) {
            $info.graphMsalDllPath = $dll.FullName
            try { $info.graphMsalVersion = (Get-Item $dll.FullName).VersionInfo.FileVersion } catch {}
        }
    }

    # An MSAL assembly already loaded in this process wins for the rest of
    # the session, regardless of which module updates we recommend below.
    # .NET cannot swap a loaded assembly in-place — the only remedy is to
    # close the PowerShell window and start a fresh one.
    try {
        $loaded = [System.AppDomain]::CurrentDomain.GetAssemblies() |
            Where-Object { $_.GetName().Name -eq 'Microsoft.Identity.Client' } |
            Select-Object -First 1
        if ($loaded) {
            $info.loadedMsalVersion = $loaded.GetName().Version.ToString()
            try { $info.loadedMsalLocation = $loaded.Location } catch {}
        }
    } catch { }

    if (-not $info.exoMsalVersion -or -not $info.graphMsalVersion) {
        # Only one of the two modules is installed (or its MSAL DLL couldn't
        # be located). No in-process conflict is possible from this script.
        return [pscustomobject]@{
            Compatible = $true
            Issues     = $issues
            Info       = $info
        }
    }

    $exoVer   = _toVersion $info.exoMsalVersion
    $graphVer = _toVersion $info.graphMsalVersion

    if ($exoVer -and $graphVer -and $exoVer -ne $graphVer) {
        # Direction-agnostic: any mismatch is risky because MSAL has shipped
        # breaking method-signature changes in both directions across recent
        # 4.x releases. The connect helper's calling site decides what to do
        # about it — either auto-apply the pre-load workaround (when MSAL is
        # not yet loaded in this process) or recommend opening a fresh window.
        $issues += ("MSAL DLL mismatch: ExchangeOnlineManagement v{0} ships Microsoft.Identity.Client v{1}, " +
                    "but Microsoft.Graph.Authentication v{2} ships v{3}. The two modules cannot share an AppDomain " +
                    "without the older / mismatched MSAL causing Connect-MgGraph to throw 'Method not found' for " +
                    "an MSAL method whose signature changed between those versions.") -f `
                    $info.exoModuleVersion, $exoVer, $info.graphModuleVersion, $graphVer
    }

    $loadedVer = _toVersion $info.loadedMsalVersion
    if ($loadedVer -and $graphVer -and $loadedVer -ne $graphVer) {
        $issues += ("Microsoft.Identity.Client v{0} is ALREADY loaded in this PowerShell process (from '{1}'), " +
                    "but Microsoft.Graph.Authentication v{2} was built against v{3}. .NET cannot swap a loaded " +
                    "assembly — close this PowerShell window, open a fresh one, and re-run this script.") -f `
                    $loadedVer, $info.loadedMsalLocation, $info.graphModuleVersion, $graphVer
    }

    [pscustomobject]@{
        Compatible = ($issues.Count -eq 0)
        Issues     = $issues
        Info       = $info
    }
}

function Test-IsAdmin {
    try {
        $current = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
        return $current.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    } catch {
        return $false
    }
}

function Test-CopilotDlpModuleReadiness {
    <#
        Checks whether the locally installed ExchangeOnlineManagement module
        is recent enough for its IPPS REST proxy to expose the Copilot DLP
        parameters (-Locations / -EnforcementPlanes) that
        New-DlpCompliancePolicy needs for Microsoft 365 Copilot location
        policies.

        Returns a PSCustomObject with:
          * Eligible — $true when no blocking issues were found
          * Issues   — list of short human-readable problem descriptions
          * Info     — diagnostic hashtable for the run log / HTML report

        This is a NON-blocking pre-req check: it produces a Write-Warning
        and a run-log entry. The hard backstop ("does the live IPPS proxy
        actually have the parameters?") still lives in Setup-AIGovernance.ps1.

        Why a separate helper from Test-WamBrokerReadiness:
          * WAM readiness gates EVERY run (single connect prompt).
          * Copilot DLP readiness only matters when the AI governance step
            is in scope, so the orchestrator opts in via -AIControlsInScope.
    #>
    [CmdletBinding()]
    param()

    $issues = @()
    $info = [ordered]@{
        moduleName       = 'ExchangeOnlineManagement'
        installed        = 'not-installed'
        installedPath    = $null
        minimumRequired  = $script:CopilotDlpMinExoVersion.ToString()
        meetsMinimum     = $false
    }

    $exoMod = Get-Module ExchangeOnlineManagement -ListAvailable -ErrorAction SilentlyContinue |
        Sort-Object Version -Descending | Select-Object -First 1

    if (-not $exoMod) {
        $issues += "ExchangeOnlineManagement module is not installed. Install: Install-Module ExchangeOnlineManagement -Scope CurrentUser -Force"
        return [pscustomobject]@{ Eligible = $false; Issues = $issues; Info = $info }
    }

    $info.installed     = $exoMod.Version.ToString()
    $info.installedPath = $exoMod.ModuleBase
    $info.meetsMinimum  = ($exoMod.Version -ge $script:CopilotDlpMinExoVersion)

    if (-not $info.meetsMinimum) {
        $issues += "ExchangeOnlineManagement v$($exoMod.Version) is older than the recommended minimum (v$($script:CopilotDlpMinExoVersion)) for Microsoft 365 Copilot DLP. The IPPS REST proxy this version builds at connect time does NOT expose the -Locations / -EnforcementPlanes parameters that New-DlpCompliancePolicy needs for Copilot DLP policies, so step [5/5] AI governance will fail. Update: Update-Module ExchangeOnlineManagement -Force  (or, in an elevated prompt: Install-Module ExchangeOnlineManagement -Scope AllUsers -Force -AllowClobber). Close and reopen PowerShell after updating."
    }

    [pscustomobject]@{
        Eligible = ($issues.Count -eq 0)
        Issues   = $issues
        Info     = $info
    }
}

function Test-GraphBetaCompat {
    <#
        Detects mismatched Microsoft.Graph.Authentication / Microsoft.Graph.Beta.*
        module versions BEFORE the orchestrator's container-labels step
        (step [5/5]) tries to call Get-MgBetaDirectorySetting and fails with:

            The 'Get-MgBetaDirectorySetting' command was found in the module
            'Microsoft.Graph.Beta.Identity.DirectoryManagement', but the
            module could not be loaded due to the following error:
            [Could not load file or assembly 'Microsoft.Graph.Authentication,
             Version=2.36.1.0...'. Assembly with same name is already loaded]

        Why this matters
        ----------------
        Each Microsoft.Graph.Beta.* sub-module's manifest declares a
        RequiredModules entry that strict-pins Microsoft.Graph.Authentication
        to the EXACT same version (e.g. Beta.Identity.DirectoryManagement
        v2.36.1 requires Authentication = 2.36.1.0, not >= 2.36.1.0). When
        a newer Microsoft.Graph.Authentication is already loaded — typically
        after the operator runs 'Update-Module Microsoft.Graph.Authentication
        -Force' to fix an MSAL issue WITHOUT also updating the Beta family —
        Import-Module on the Beta sub-module fails because .NET can't load
        a second copy of Microsoft.Graph.Authentication into the AppDomain.

        Returns a PSCustomObject with:
          * Compatible — $true when the highest installed Beta sub-module's
                         required Authentication version matches one of the
                         installed Authentication versions AND the loaded
                         Authentication version, OR when the Beta sub-module
                         is not installed (Ensure-RequiredModule will install
                         a matching version on demand)
          * Issues     — list of human-readable problem descriptions
          * Info       — diagnostic hashtable for the run log
          * FixCommand — exact PowerShell command to recover
    #>
    [CmdletBinding()]
    param(
        [string] $BetaModuleName = 'Microsoft.Graph.Beta.Identity.DirectoryManagement'
    )

    $issues = @()
    $info = [ordered]@{
        graphAuthInstalled       = @()
        graphAuthLoadedVersion   = $null
        betaModuleName           = $BetaModuleName
        betaInstalled            = @()
        betaHighestVersion       = $null
        betaHighestRequiredAuth  = $null
    }
    $fixCommand = $null

    # Inventory: every installed Microsoft.Graph.Authentication version.
    $authMods = @(Get-Module Microsoft.Graph.Authentication -ListAvailable -ErrorAction SilentlyContinue |
        Sort-Object Version -Descending)
    $info.graphAuthInstalled = @($authMods | ForEach-Object { $_.Version.ToString() })

    # Whichever Authentication version is currently loaded wins for the rest
    # of the session (.NET cannot load a second copy of an assembly).
    $loadedAuth = Get-Module Microsoft.Graph.Authentication -ErrorAction SilentlyContinue |
        Select-Object -First 1
    if ($loadedAuth) {
        $info.graphAuthLoadedVersion = $loadedAuth.Version.ToString()
    }

    # Inventory: every installed copy of the Beta sub-module + its pinned Auth dep.
    $betaMods = @(Get-Module $BetaModuleName -ListAvailable -ErrorAction SilentlyContinue |
        Sort-Object Version -Descending)
    foreach ($b in $betaMods) {
        $authReq = $b.RequiredModules | Where-Object Name -eq 'Microsoft.Graph.Authentication' | Select-Object -First 1
        $info.betaInstalled += [ordered]@{
            version          = $b.Version.ToString()
            requiredAuthVer  = if ($authReq) { $authReq.Version.ToString() } else { '(none)' }
            modulePath       = $b.ModuleBase
        }
    }

    if (-not $betaMods) {
        # No Beta sub-module installed at all. Because the orchestrator
        # bypasses Ensure-RequiredModule for the Beta module (Ensure has
        # a silent-success bug that returns OK when the module is merely
        # listed in Get-Module -ListAvailable even if Import-Module would
        # fail), we MUST surface this as incompatible here. The caller's
        # auto-install branch will then run Install-Module against the
        # currently loaded/installed Auth version. Without this signal
        # the caller skips install and the picker downstream finds no
        # matching Beta version → throws "no-matching-version-installed"
        # on a fresh machine where Beta was never installed.
        $effectiveAuth = if ($info.graphAuthLoadedVersion) {
            $info.graphAuthLoadedVersion
        } elseif ($info.graphAuthInstalled.Count -gt 0) {
            $info.graphAuthInstalled[0]
        } else {
            $null
        }
        if ($effectiveAuth) {
            $fixCommand = "Install-Module $BetaModuleName -RequiredVersion $effectiveAuth -Scope CurrentUser -Force -AllowClobber"
        } else {
            $fixCommand = "Install-Module $BetaModuleName -Scope CurrentUser -Force -AllowClobber"
        }
        return [pscustomobject]@{
            Compatible = $false
            Issues     = @("$BetaModuleName is not installed (required for container labels at step [5/5]). Will be installed side-by-side against Microsoft.Graph.Authentication v$effectiveAuth.")
            Info       = $info
            FixCommand = $fixCommand
        }
    }

    $highestBeta = $betaMods[0]
    $info.betaHighestVersion = $highestBeta.Version.ToString()
    $highestBetaAuthReq = $highestBeta.RequiredModules |
        Where-Object Name -eq 'Microsoft.Graph.Authentication' |
        Select-Object -First 1
    if ($highestBetaAuthReq) {
        $info.betaHighestRequiredAuth = $highestBetaAuthReq.Version.ToString()
    }

    # The check that matters: can Import-Module on the highest Beta succeed
    # against the CURRENTLY LOADED Authentication version?
    # If Authentication isn't loaded yet, fall back to: does the highest Auth
    # installed match what the highest Beta requires? (Import-Module Beta
    # will trigger Import-Module Authentication on its required version.)
    $effectiveAuth = if ($info.graphAuthLoadedVersion) {
        $info.graphAuthLoadedVersion
    } elseif ($info.graphAuthInstalled.Count -gt 0) {
        $info.graphAuthInstalled[0]
    } else {
        $null
    }

    if (-not $effectiveAuth) {
        # No Auth installed at all — Ensure-RequiredModule will handle it.
        return [pscustomobject]@{
            Compatible = $true
            Issues     = @()
            Info       = $info
            FixCommand = $null
        }
    }

    # PowerShell only honours strict-pinned RequiredModules — version must match exactly.
    if ($info.betaHighestRequiredAuth -and $info.betaHighestRequiredAuth -ne $effectiveAuth) {
        # See if any OTHER installed Beta version pins to the loaded/installed Auth.
        $matchingBeta = $info.betaInstalled | Where-Object { $_.requiredAuthVer -eq $effectiveAuth } | Select-Object -First 1
        if ($matchingBeta) {
            # A matching Beta version IS installed — Import-Module would pick the
            # highest by default though, so we still need to either pin import or
            # tell the user to remove/update. Treat as incompatible with hint.
            $issues += "An installed copy of $BetaModuleName v$($matchingBeta.version) pins Microsoft.Graph.Authentication v$effectiveAuth (matches loaded), but the highest installed version v$($info.betaHighestVersion) pins v$($info.betaHighestRequiredAuth). PowerShell's Import-Module picks the highest by default, so the import will still fail."
            $fixCommand = "Install-Module $BetaModuleName -RequiredVersion $effectiveAuth -Scope CurrentUser -Force -AllowClobber"
        } else {
            $issues += "$BetaModuleName v$($info.betaHighestVersion) (the highest installed) strict-pins Microsoft.Graph.Authentication v$($info.betaHighestRequiredAuth), but the loaded/installed Authentication version is v$effectiveAuth. Microsoft.Graph.Beta sub-modules require an EXACT version match in their manifest's RequiredModules. Step [5/5] container labels will fail when it calls Get-MgBetaDirectorySetting."
            $fixCommand = "Install-Module $BetaModuleName -RequiredVersion $effectiveAuth -Scope CurrentUser -Force -AllowClobber"
        }
    }

    [pscustomobject]@{
        Compatible = ($issues.Count -eq 0)
        Issues     = $issues
        Info       = $info
        FixCommand = $fixCommand
    }
}

function Resolve-SpoAdminUrlFromInputs {
    [CmdletBinding()]
    param(
        [string] $ExplicitUrl,
        [string] $DelegatedOrganization,
        [string] $TenantAdminUpn
    )

    if ($ExplicitUrl) {
        return [pscustomobject]@{ Url = $ExplicitUrl; Source = 'explicit (-SharePointAdminUrl)' }
    }

    if ($DelegatedOrganization -and $DelegatedOrganization -match '^(?<t>[A-Za-z0-9-]+)\.onmicrosoft\.com$') {
        $prefix = $Matches.t
        return [pscustomobject]@{
            Url    = "https://$prefix-admin.sharepoint.com"
            Source = "-DelegatedOrganization ($DelegatedOrganization)"
        }
    }

    if ($TenantAdminUpn -and $TenantAdminUpn -match '@(?<t>[A-Za-z0-9-]+)\.onmicrosoft\.com$') {
        $prefix = $Matches.t
        return [pscustomobject]@{
            Url    = "https://$prefix-admin.sharepoint.com"
            Source = "admin UPN suffix ($TenantAdminUpn)"
        }
    }

    return $null
}

function Invoke-SpoConnectWithFallback {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string] $SharePointAdminUrl,
        [Parameter(Mandatory)] [string] $TenantAdminUpn
    )

    $spoConnected = $false
    $spoProbeError = $null
    try {
        $current = Get-SPOTenant -ErrorAction Stop
        if ($current) { $spoConnected = $true }
    } catch {
        $spoConnected = $false
        $spoProbeError = $_.Exception.Message
    }

    if ($spoConnected) {
        Add-ConnectGuardLog -Service 'SPO' -Status 'Info' -ReasonKey 'reused' -Detail @{
            check                = 'Get-SPOTenant'
            expectedAdminUrl     = $SharePointAdminUrl
            actualTenantIdentity = 'unverified'
        }
        Write-Host "SharePoint Online: existing session reused." -ForegroundColor DarkGray
        return
    }

    Add-ConnectGuardLog -Service 'SPO' -Status 'Started' `
        -ReasonKey ($(if ($spoProbeError) { 'probe-failed' } else { 'no-existing-session' })) `
        -Detail @{
            check            = 'Get-SPOTenant'
            expectedAdminUrl = $SharePointAdminUrl
            probeError       = ($spoProbeError -as [string])
        }

    $spoMod = Get-Module Microsoft.Online.SharePoint.PowerShell -ErrorAction SilentlyContinue |
        Select-Object -First 1
    if (-not $spoMod) {
        $spoMod = Get-Module Microsoft.Online.SharePoint.PowerShell -ListAvailable |
            Sort-Object Version -Descending | Select-Object -First 1
    }
    $spoVersion = if ($spoMod -and $spoMod.Version) { $spoMod.Version.ToString() } else { 'unknown' }
    $isCore = $PSVersionTable.PSEdition -eq 'Core'

    Write-Host "Connecting to SharePoint Online ($SharePointAdminUrl)..." -ForegroundColor Cyan
    Write-Host ("  PowerShell: {0} {1} | SPO module: {2}{3}" -f `
        $PSVersionTable.PSEdition, $PSVersionTable.PSVersion, $spoVersion,
        $(if ($isCore) { ' (loaded via Windows PowerShell 5.1 proxy)' } else { '' })) -ForegroundColor DarkGray

    # Clear any stale/cached SPO session state before attempting a fresh
    # connect — this avoids "No valid OAuth 2.0 authentication session
    # exists" caused by a prior failed/expired token.
    try { Disconnect-SPOService -ErrorAction SilentlyContinue } catch { }

    try {
        Connect-SPOService -Url $SharePointAdminUrl -ErrorAction Stop
        return
    } catch {
        $errMsg = $_.Exception.Message

        # ZT-pattern: detect MSAL DLL conflict — recommend a pwsh restart.
        $spoConflict = @($_.Exception, $_.Exception.InnerException) |
            Where-Object { $_ -is [System.MissingMethodException] -or $_ -is [System.IO.FileLoadException] } |
            Select-Object -First 1
        $isMsalConflict = $spoConflict -and ($spoConflict.Message -like '*Microsoft.Identity.Client*' -or $spoConflict.Message -like '*Microsoft.IdentityModel*')

        # Detect "the PS 5.1 proxy couldn't find the SPO module" — happens when
        # PS 7 has the module installed but PS 5.1 does not (PS 7's
        # Install-Module installs to the PS 7 module path only).
        $proxyModuleMissing = $errMsg -match 'no valid module file was found' -or `
                              $errMsg -match 'module .* was not loaded' -or `
                              $errMsg -match 'Could not find the module'

        $hints = @()
        if ($isMsalConflict) {
            $hints += "* DLL conflict on Microsoft.Identity.Client. Another module loaded a conflicting MSAL into this session before SharePoint."
            $hints += "  Fix: CLOSE this PowerShell window, open a fresh pwsh, and re-run the script. Do not import other Microsoft modules first."
        }
        if ($errMsg -match 'No valid OAuth') {
            $hints += "* The sign-in account ($TenantAdminUpn) must hold the SharePoint Administrator (or Global Administrator) role on the customer tenant."
            $hints += "* Make sure the browser sign-in pop-up is allowed and not blocked by your default browser, and complete MFA if prompted."
            $hints += "* You can pre-authenticate manually first, then re-run this script: Connect-SPOService -Url $SharePointAdminUrl"
        }
        if ($isCore -and $proxyModuleMissing) {
            $hints += "* The Windows PowerShell 5.1 proxy could not find 'Microsoft.Online.SharePoint.PowerShell'."
            $hints += "  PS 7's 'Install-Module' installs to the PS 7 module path only; the proxy runs under PS 5.1 and needs the module in its path too."
            $hints += "  Fix: open Windows PowerShell 5.1 (powershell.exe) once and run:"
            $hints += "      Install-Module Microsoft.Online.SharePoint.PowerShell -Scope CurrentUser -Force -AllowClobber"
            $hints += "  Then re-run this script from pwsh."
        }
        $hints += "* If your SPO module is old, run: Update-Module Microsoft.Online.SharePoint.PowerShell -Force"

        $msg = "Connect-SPOService failed: $errMsg"
        if ($hints) { $msg += "`nTroubleshooting:`n  " + ($hints -join "`n  ") }
        throw $msg
    }
}

function Ensure-RequiredModule {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string] $Name,
        [string] $RequiredCmdlet,
        [switch] $AutoInstall,
        [switch] $NonInteractive,
        [switch] $UseWindowsPowerShellProxy
    )

    # On PS Core, the Microsoft.Online.SharePoint.PowerShell module is a Windows
    # Desktop assembly. Loading it natively into PS 7 works for delegated auth
    # but breaks certificate-based auth and can clash with EXO's bundled
    # Microsoft.Identity.Client.dll. The Zero Trust Assessment connect helper
    # solves this by loading SPO via -UseWindowsPowerShell (implicit WinPS 5.1
    # remoting) AFTER EXO is already connected. We follow the same pattern.
    $proxy = $UseWindowsPowerShellProxy.IsPresent -and ($PSVersionTable.PSEdition -eq 'Core')

    $available = Get-Module -ListAvailable -Name $Name -ErrorAction SilentlyContinue

    if ($available) {
        try {
            if ($proxy) {
                # WinCompat sessions use a stock PSModulePath that doesn't include the
                # PS 7 user-module location. Discover the module's full path on the
                # PS 7 side and pass it explicitly so the proxy import loads from the
                # same on-disk location regardless of WinCompat's own PSModulePath.
                $availMod = Get-Module -ListAvailable -Name $Name -ErrorAction SilentlyContinue |
                    Sort-Object Version -Descending |
                    Select-Object -First 1
                if ($availMod -and $availMod.Path) {
                    Import-Module -UseWindowsPowerShell -FullyQualifiedName $availMod.Path `
                        -DisableNameChecking -WarningAction SilentlyContinue -ErrorAction Stop | Out-Null
                } else {
                    Import-Module $Name -UseWindowsPowerShell -DisableNameChecking `
                        -WarningAction SilentlyContinue -ErrorAction Stop | Out-Null
                }
            } else {
                Import-Module $Name -DisableNameChecking -ErrorAction Stop | Out-Null
            }
        } catch {
            Write-Verbose "Import-Module '$Name' failed: $($_.Exception.Message)"
        }
    }

    $cmdletOk = if ($RequiredCmdlet) {
        [bool] (Get-Command $RequiredCmdlet -ErrorAction SilentlyContinue)
    } else {
        [bool] $available
    }

    if ($cmdletOk) { return }

    Write-Warning "Required module '$Name' is missing or its cmdlets cannot load$(if ($RequiredCmdlet) { " ($RequiredCmdlet not found)" })."

    $shouldInstall = $AutoInstall.IsPresent
    if (-not $shouldInstall -and $NonInteractive.IsPresent) {
        $manual = "Install-Module $Name -Scope CurrentUser -Force -AllowClobber"
        throw "Module '$Name' is required but is not installed and -NonInteractive is set (cannot prompt). Either pre-install the module or re-run with -AutoInstallModules:`n    $manual"
    }
    if (-not $shouldInstall) {
        $resp = Read-Host "Install '$Name' from PSGallery now to the current user scope? [Y/n]"
        if ([string]::IsNullOrWhiteSpace($resp) -or $resp -match '^(y|yes)$') {
            $shouldInstall = $true
        }
    }

    if (-not $shouldInstall) {
        $manual = "Install-Module $Name -Scope CurrentUser -Force -AllowClobber"
        throw "Module '$Name' is required but was not installed. Install manually and re-run:`n    $manual"
    }

    $isAdmin = Test-IsAdmin
    if (-not $isAdmin) {
        Write-Host "  Note: this PowerShell session is NOT elevated." -ForegroundColor DarkGray
        Write-Host "        Installing to -Scope CurrentUser (no admin rights required)." -ForegroundColor DarkGray
        Write-Host "        If install fails with an access-denied error, re-run PowerShell as Administrator." -ForegroundColor DarkGray
    }

    Write-Host "Installing '$Name' (Scope: CurrentUser)..." -ForegroundColor Cyan
    $installError = $null
    try {
        Install-Module -Name $Name -Scope CurrentUser -Force -AllowClobber -ErrorAction Stop
    } catch {
        $installError = $_
    }

    if ($installError) {
        $hint = if ($isAdmin) {
            "Try installing for all users:`n    Install-Module $Name -Scope AllUsers -Force -AllowClobber"
        } else {
            "Close this window, right-click PowerShell -> 'Run as Administrator', then re-run this script (or install manually with: Install-Module $Name -Scope CurrentUser -Force -AllowClobber)."
        }
        throw "Failed to install module '$Name': $($installError.Exception.Message)`n$hint"
    }

    try {
        if ($proxy) {
            # WinCompat sessions use a stock PSModulePath that doesn't include the
            # PS 7 user-module location. Discover the module's full path on the
            # PS 7 side and pass it explicitly so the proxy import loads from the
            # same on-disk location regardless of WinCompat's own PSModulePath.
            $availMod = Get-Module -ListAvailable -Name $Name -ErrorAction SilentlyContinue |
                Sort-Object Version -Descending |
                Select-Object -First 1
            if ($availMod -and $availMod.Path) {
                Import-Module -UseWindowsPowerShell -FullyQualifiedName $availMod.Path `
                    -DisableNameChecking -WarningAction SilentlyContinue -ErrorAction Stop | Out-Null
            } else {
                Import-Module $Name -UseWindowsPowerShell -DisableNameChecking `
                    -WarningAction SilentlyContinue -ErrorAction Stop | Out-Null
            }
        } else {
            Import-Module $Name -DisableNameChecking -ErrorAction Stop | Out-Null
        }
    } catch {
        throw "Module '$Name' was installed but failed to import: $($_.Exception.Message)"
    }

    if ($RequiredCmdlet -and -not (Get-Command $RequiredCmdlet -ErrorAction SilentlyContinue)) {
        throw "Module '$Name' was installed but cmdlet '$RequiredCmdlet' is still not available. Restart PowerShell and re-run."
    }

    Write-Host "  Installed and loaded '$Name'." -ForegroundColor Green
}

# ---------------------------------------------------------------------------
# WAM (Windows Authentication Manager) broker readiness
# ---------------------------------------------------------------------------
# Run BEFORE any module load / connect so the user gets a clear up-front
# explanation when prompts will be heavier than expected. This is observation
# only — we do not change connect arguments. WAM is on by default in current
# Microsoft.Graph.Authentication (>= 2.x) and ExchangeOnlineManagement
# (>= 3.3); the helper just surfaces blockers (non-Windows, SYSTEM, etc.).
$wamReadiness = Test-WamBrokerReadiness
if ($wamReadiness.Eligible) {
    Write-Host "WAM broker available: sign-in prompts should be reduced (often 1-click 'Continue')." -ForegroundColor DarkGray
    Write-Host "  Note: first-time consent, tenant switches, missing scopes, stale sessions, or SharePoint can still trigger additional prompts." -ForegroundColor DarkGray
} else {
    Write-Warning "Windows Authentication Manager (WAM) broker is not fully usable in this environment."
    Write-Warning "Expect a browser sign-in popup per service (Exchange Online, Security & Compliance, SharePoint, Microsoft Graph)."
    foreach ($issue in $wamReadiness.Issues) {
        Write-Warning "  * $issue"
    }
    Write-Warning "  See Products/Purview/README.md -> 'Sign-in prompts (WAM broker)' for guidance."
}
Add-ConnectGuardLog -Service 'Startup' -Status 'Info' `
    -ReasonKey ($(if ($wamReadiness.Eligible) { 'wam-ready' } else { 'wam-not-ready' })) `
    -Detail $wamReadiness.Info

# ---------------------------------------------------------------------------
# MSAL DLL compatibility (Microsoft.Identity.Client.dll) between EXO and Graph
# ---------------------------------------------------------------------------
# ExchangeOnlineManagement and Microsoft.Graph.Authentication each ship their
# OWN copy of Microsoft.Identity.Client.dll. When both are imported into the
# same PowerShell process, the CLR binds to whichever copy was loaded FIRST.
# This script imports EXO before Graph, so EXO's MSAL wins the AppDomain. If
# the two modules disagree on MSAL version (a recurring source of breakage —
# MSAL has shipped method-signature changes in both 4.82 -> 4.83 and earlier)
# Connect-MgGraph throws a cryptic 'Method not found' exception that reads
# like an auth failure but is actually a DLL-binding mismatch. We detect it
# up-front so the operator gets actionable guidance BEFORE the deploy spends
# minutes connecting to everything else only to die at the Graph step.
# Observation only — we never block; the connect call still runs and remains
# the definitive backstop.
$msalCompat = Test-MsalDllCompatibility
if ($msalCompat.Compatible) {
    if ($msalCompat.Info.exoMsalVersion -and $msalCompat.Info.graphMsalVersion) {
        Write-Host ("MSAL DLL check: ExchangeOnlineManagement and Microsoft.Graph.Authentication both ship Microsoft.Identity.Client v{0}." -f `
            $msalCompat.Info.graphMsalVersion) -ForegroundColor DarkGray
    }
} else {
    Write-Warning "Microsoft.Identity.Client (MSAL) DLL mismatch between Exchange Online and Microsoft Graph modules."
    Write-Warning "This is the #1 cause of 'InteractiveBrowserCredential authentication failed: Method not found' errors during Connect-MgGraph."
    foreach ($issue in $msalCompat.Issues) {
        Write-Warning "  * $issue"
    }
    if ($msalCompat.Info.loadedMsalVersion) {
        # MSAL is already loaded in this process — we can't change which
        # version is bound. The user must restart PowerShell.
        Write-Warning "  Action required: close this PowerShell window and open a fresh one — .NET cannot swap a loaded MSAL assembly in-place."
    } elseif ($ConnectGraph) {
        # We mitigate at runtime by connecting Microsoft Graph FIRST (before
        # ExchangeOnlineManagement loads). This is the same pattern used by
        # microsoft/zerotrustassessment's Connect-ZtAssessment. When Graph
        # loads its bundled MSAL into the AppDomain first, EXO loads on top
        # and its MSAL calls still succeed — verified end-to-end.
        # If MSAL is somehow loaded by another module before us, the JIT will
        # throw 'Method not found' and there is NO runtime workaround
        # (-UseDeviceCode does NOT help — DeviceCodeCredential invokes the
        # same broken MSAL method overload). In that case the only fix is
        # to close pwsh and reopen.
        Write-Warning "  Mitigation 1: this script connects Microsoft Graph FIRST so Graph's MSAL wins the AppDomain race (Zero Trust Assessment pattern). This prevents 'Method not found' in Connect-MgGraph."
        Write-Warning "  Mitigation 2: Connect-ExchangeOnline / Connect-IPPSSession will be invoked with -DisableWAM so EXO falls back to the standard interactive browser flow. This avoids 'NullReferenceException at Microsoft.Identity.Client.Platforms.Features.RuntimeBroker.RuntimeBroker..ctor', which fires when EXO's WAM code path is loaded against Graph's older MSAL."
        Write-Warning "  If a 'Method not found' or RuntimeBroker NullReferenceException still fires below, CLOSE this PowerShell window and open a fresh one — runtime mitigation is not possible once MSAL is loaded with the wrong version."
    } else {
        Write-Warning "  Manual fix: update both modules in a FRESH PowerShell window — 'Update-Module ExchangeOnlineManagement -Force; Update-Module Microsoft.Graph.Authentication -Force' — then re-run."
    }
}
# Whether subsequent EXO/IPPS Connect calls should pass -DisableWAM to dodge
# the WAM RuntimeBroker NullReferenceException that fires when EXO 3.10's WAM
# code path runs against Graph's older MSAL. We only opt out of WAM when a
# mismatch is detected — matched MSAL versions keep the 1-click WAM UX.
$script:MsalRequiresDisableWam = -not $msalCompat.Compatible
Add-ConnectGuardLog -Service 'Startup' -Status ($(if ($msalCompat.Compatible) { 'Info' } else { 'Retried' })) `
    -ReasonKey ($(if ($msalCompat.Compatible) { 'msal-aligned' } else { 'msal-mismatch' })) `
    -Detail $msalCompat.Info

# ---------------------------------------------------------------------------
# Copilot DLP module readiness (pre-req, non-blocking)
# ---------------------------------------------------------------------------
# AI governance / Copilot DLP is default-on for E5 / Purview Suite tenants.
# Step [5/5] in the orchestrator calls New-DlpCompliancePolicy with
# -Locations / -EnforcementPlanes, which only appear on the IPPS REST proxy
# built by ExchangeOnlineManagement v3.9.0+. On older modules the proxy
# silently lacks the parameters and Setup-AIGovernance throws a clear
# instruction to update. We surface the same instruction up-front so the
# operator sees it BEFORE the run blows 5 minutes setting up everything else.
# Observation only — never throws; the AI step still runs and provides the
# definitive backstop.
if ($AIControlsInScope) {
    $copilotDlpReadiness = Test-CopilotDlpModuleReadiness
    if ($copilotDlpReadiness.Eligible) {
        Write-Host ("ExchangeOnlineManagement v{0} meets the Copilot DLP minimum (v{1}+)." -f `
            $copilotDlpReadiness.Info.installed, $copilotDlpReadiness.Info.minimumRequired) -ForegroundColor DarkGray
    } else {
        Write-Warning "Copilot DLP pre-req check: your ExchangeOnlineManagement module is older than the recommended minimum for AI governance (step [5/5])."
        foreach ($issue in $copilotDlpReadiness.Issues) {
            Write-Warning "  * $issue"
        }
        Write-Warning "  This is a WARNING only — the rest of the deploy continues. Step [5/5] will fail with the same guidance unless you update the module before that step runs."
        Write-Warning "  See the HTML report 'Module currency' section for copy-pasteable install commands."
    }
    Add-ConnectGuardLog -Service 'CopilotDlp' -Status ($(if ($copilotDlpReadiness.Eligible) { 'Info' } else { 'Retried' })) `
        -ReasonKey ($(if ($copilotDlpReadiness.Eligible) { 'exo-version-ok' } else { 'exo-version-below-copilot-dlp-minimum' })) `
        -Detail $copilotDlpReadiness.Info
}

# ---------------------------------------------------------------------------
# Module checks (auto-install on demand)
# ---------------------------------------------------------------------------
# Following the Zero Trust Assessment pattern: load EXO module up front,
# but defer the SPO module import until AFTER EXO is connected. SPO's WinPS
# proxy import has a chance of perturbing PS 7's AppDomain — doing it AFTER
# EXO has already loaded its MSAL is the safest order.
#
# MSAL mismatch handling (verified end-to-end + matches the pattern in
# microsoft/zerotrustassessment's Connect-ZtAssessment):
#   ExchangeOnlineManagement and Microsoft.Graph.Authentication each ship
#   their OWN copy of Microsoft.Identity.Client.dll, and PowerShell loads
#   them lazily on first cmdlet call. Once one is loaded with a given
#   strong name + public key, .NET binds ALL subsequent requests for that
#   simple name to the already-loaded version — even if a different
#   version is requested. So whichever module CONNECTS first wins.
#
#   * If EXO 3.10's MSAL 4.83 loads first, Graph 2.37's
#     InteractiveBrowserCredential ctor invokes
#     BaseAbstractApplicationBuilder<T>.WithLogging(IIdentityLogger, Boolean)
#     which moved between 4.82 and 4.83 → "Method not found".
#     (DeviceCodeCredential hits the SAME ctor path → -UseDeviceCode does
#     NOT help.)
#   * Pre-loading Graph's older MSAL via [Reflection.Assembly]::LoadFrom
#     does NOT work either — EXO's own module then refuses to load with
#     FileLoadException 0x80131040 ("manifest does not match").
#
#   The fix is to connect Microsoft Graph FIRST, so Graph's MSAL wins the
#   AppDomain race. EXO's MSAL calls remain forwards-compatible enough to
#   work on Graph's older MSAL (validated: Connect-ExchangeOnline reaches
#   the MSAL token request without binding errors). This is the order
#   Connect-PurviewServices uses below.
#
#   If MSAL was already loaded into the process by another module before
#   this script ran, there is no runtime fix — the operator must restart
#   pwsh. We detect that case in the pre-flight check above.

Ensure-RequiredModule -Name 'ExchangeOnlineManagement' `
    -RequiredCmdlet 'Connect-ExchangeOnline' `
    -AutoInstall:$AutoInstallModules `
    -NonInteractive:$NonInteractive

if ($ConnectGraph) {
    # Connect-MgGraph / Get-MgContext live in Microsoft.Graph.Authentication.
    Ensure-RequiredModule -Name 'Microsoft.Graph.Authentication' `
        -RequiredCmdlet 'Connect-MgGraph' `
        -AutoInstall:$AutoInstallModules `
        -NonInteractive:$NonInteractive
    # The Beta directory management module is needed for setting Group.Unified
    # values used by container labels (step [5/5] orchestrator). Microsoft.Graph.Beta.*
    # sub-modules strict-pin Microsoft.Graph.Authentication to an EXACT version in
    # their RequiredModules manifest. If the installed Beta version pins a different
    # Auth version than what's already loaded, Import-Module fails with:
    #   Could not load file or assembly 'Microsoft.Graph.Authentication, Version=X.Y.Z.0'.
    #   Assembly with same name is already loaded
    # This typically happens after the operator runs 'Update-Module
    # Microsoft.Graph.Authentication -Force' (e.g. to fix the MSAL/EXO issue) WITHOUT
    # also updating the Beta family.
    #
    # Recovery strategy: this is a deterministic, non-destructive self-heal
    # (installing one specific version of a sub-module the operator already
    # has other versions of). It runs UNCONDITIONALLY when a mismatch is
    # detected — matching the existing self-heal pattern used for PSGallery
    # trust restore (#11). If PSGallery is unreachable, we degrade
    # gracefully with the exact fix command. -NonInteractive operators in
    # locked-down environments who don't want auto-install can pre-pin the
    # matching Beta version themselves.
    $betaCompat = Test-GraphBetaCompat -BetaModuleName 'Microsoft.Graph.Beta.Identity.DirectoryManagement'
    $targetAuthVer = if ($betaCompat.Info.graphAuthLoadedVersion) { $betaCompat.Info.graphAuthLoadedVersion } else { $betaCompat.Info.graphAuthInstalled | Select-Object -First 1 }
    if (-not $betaCompat.Compatible) {
        Write-Warning "Microsoft.Graph.Beta module version mismatch detected (would break container labels at step [5/5])."
        foreach ($issue in $betaCompat.Issues) {
            Write-Warning "  * $issue"
        }
        if ($targetAuthVer) {
            Write-Host "  Self-healing: installing Microsoft.Graph.Beta.Identity.DirectoryManagement v$targetAuthVer side-by-side to match the loaded Authentication module..." -ForegroundColor Cyan
            try {
                Install-Module -Name 'Microsoft.Graph.Beta.Identity.DirectoryManagement' `
                    -RequiredVersion $targetAuthVer `
                    -Scope CurrentUser `
                    -Force `
                    -AllowClobber `
                    -ErrorAction Stop
                Write-Host "  Installed. Re-validating..." -ForegroundColor DarkGray
                $betaCompat = Test-GraphBetaCompat -BetaModuleName 'Microsoft.Graph.Beta.Identity.DirectoryManagement'
                if ($betaCompat.Compatible) {
                    Write-Host "  Microsoft.Graph.Beta v$targetAuthVer now aligned with Microsoft.Graph.Authentication v$targetAuthVer." -ForegroundColor Green
                    Add-ConnectGuardLog -Service 'GraphBeta' -Status 'Info' -ReasonKey 'auto-installed-matching-version' -Detail $betaCompat.Info
                } else {
                    Add-ConnectGuardLog -Service 'GraphBeta' -Status 'Retried' -ReasonKey 'auto-install-incomplete' -Detail $betaCompat.Info
                }
            } catch {
                Write-Warning "  Auto-install failed: $($_.Exception.Message)"
                Write-Warning "  Manual fix: $($betaCompat.FixCommand)"
                Write-Warning "  Then re-run this script."
                Add-ConnectGuardLog -Service 'GraphBeta' -Status 'Failed' -ReasonKey 'auto-install-failed' -Detail @{
                    error = $_.Exception.Message
                    fixCommand = $betaCompat.FixCommand
                }
                throw "Microsoft.Graph.Beta sub-module version mismatch and auto-install failed. Run: $($betaCompat.FixCommand)"
            }
        } else {
            $cmd = if ($betaCompat.FixCommand) { $betaCompat.FixCommand } else { "Update-Module Microsoft.Graph.Beta.Identity.DirectoryManagement -Force" }
            Add-ConnectGuardLog -Service 'GraphBeta' -Status 'Failed' -ReasonKey 'version-pin-mismatch-no-target' -Detail @{
                betaCompat = $betaCompat.Info
                fixCommand = $betaCompat.FixCommand
            }
            throw "Microsoft.Graph.Beta sub-module version mismatch but Authentication version could not be resolved. Manual fix: $cmd"
        }
    } else {
        Add-ConnectGuardLog -Service 'GraphBeta' -Status 'Info' -ReasonKey 'version-pin-aligned' -Detail $betaCompat.Info
    }

    # Force the Beta module import to the version whose Auth pin matches the
    # loaded/installed Authentication version. Without this, PowerShell's
    # default Import-Module picks the highest-installed Beta version — which
    # may still be the mismatched copy when older Beta versions are present
    # alongside the freshly-installed matching one.
    $betaMatch = $null
    if ($targetAuthVer) {
        $betaMatch = Get-Module -ListAvailable -Name 'Microsoft.Graph.Beta.Identity.DirectoryManagement' -ErrorAction SilentlyContinue |
            Where-Object {
                $req = $_.RequiredModules | Where-Object Name -eq 'Microsoft.Graph.Authentication' | Select-Object -First 1
                $req -and $req.Version.ToString() -eq $targetAuthVer
            } |
            Sort-Object Version -Descending |
            Select-Object -First 1
    }
    if ($betaMatch) {
        try {
            Import-Module -Name 'Microsoft.Graph.Beta.Identity.DirectoryManagement' `
                -RequiredVersion $betaMatch.Version `
                -DisableNameChecking -ErrorAction Stop | Out-Null
            Add-ConnectGuardLog -Service 'GraphBeta' -Status 'Info' -ReasonKey 'imported-matching-version' -Detail @{
                importedVersion = $betaMatch.Version.ToString()
                requiredAuthVer = $targetAuthVer
            }
        } catch {
            Write-Warning "Failed to import Microsoft.Graph.Beta.Identity.DirectoryManagement v$($betaMatch.Version): $($_.Exception.Message)"
            throw
        }
    } else {
        # No matching version installed (and auto-install above either threw
        # or no target was resolvable). Surface a clear actionable error
        # rather than falling through to a PowerShell auto-load failure
        # later in the deploy.
        $cmd = if ($betaCompat -and $betaCompat.FixCommand) {
            $betaCompat.FixCommand
        } else {
            "Install-Module Microsoft.Graph.Beta.Identity.DirectoryManagement -RequiredVersion $targetAuthVer -Scope CurrentUser -Force -AllowClobber"
        }
        Add-ConnectGuardLog -Service 'GraphBeta' -Status 'Failed' -ReasonKey 'no-matching-version-installed' -Detail @{
            requiredAuthVer = $targetAuthVer
            fixCommand = $cmd
        }
        throw "No installed Microsoft.Graph.Beta.Identity.DirectoryManagement version matches the loaded Microsoft.Graph.Authentication v$targetAuthVer. Manual fix: $cmd"
    }
}

# ---------------------------------------------------------------------------
# Microsoft Graph (Beta) — connect FIRST (ZTA pattern)
# ---------------------------------------------------------------------------
# Connect Microsoft Graph BEFORE Exchange Online so Graph's bundled
# Microsoft.Identity.Client.dll (MSAL) wins the AppDomain race. EXO's
# MSAL surface is forwards-compatible enough to work on Graph's MSAL, but
# Graph 2.37's InteractiveBrowserCredential / DeviceCodeCredential ctors
# invoke method overloads that don't exist on EXO 3.10's newer MSAL — so
# the order matters and Graph MUST go first. This matches the pattern
# used by microsoft/zerotrustassessment's Connect-ZtAssessment.
if ($ConnectGraph) {
    # GDAP FIX: When the deploy targets a customer via GDAP (-DelegatedOrganization),
    # the Connect-MgGraph -TenantId MUST be the CUSTOMER tenant, not the partner
    # tenant. The previous code split the admin UPN suffix
    # (e.g. 'partnerAdmin@fabrikam.onmicrosoft.com' -> 'fabrikam.onmicrosoft.com')
    # and silently authed Graph into the partner tenant — so license auto-detect
    # and container-label setup ran against the wrong tenant on every partner-led run.
    $targetTenantDomain = if ($DelegatedOrganization) {
        $DelegatedOrganization
    } else {
        ($TenantAdminUpn -split '@')[-1]
    }
    # Normalise scope set (drop empties / dupes, preserve order) before reuse-check.
    $requiredScopes = @($GraphScopes | Where-Object { $_ } | Select-Object -Unique)
    if ($requiredScopes.Count -eq 0) { $requiredScopes = @('Organization.Read.All') }
    $graphConnected = $false
    $graphGuardReason = $null
    $graphGuardDetail = @{
        expectedUpn            = $TenantAdminUpn
        expectedTenantDomain   = $targetTenantDomain
        expectedScopes         = ($requiredScopes -join ',')
    }
    try {
        $ctx = Get-MgContext -ErrorAction Stop
        # Reuse only when the cached session belongs to the SAME admin, has the
        # required scopes, AND (for GDAP) is authenticated against the customer
        # tenant. A stale session for a different tenant produces a "Selected
        # user account does not exist in tenant" popup the moment any Graph
        # cmdlet triggers an MSAL token refresh.
        $cachedScopes = @($ctx.Scopes)
        $missingScopes = @($requiredScopes | Where-Object { $cachedScopes -notcontains $_ })
        if ($ctx -and `
            $ctx.Account -and ($ctx.Account -ieq $TenantAdminUpn) -and `
            $missingScopes.Count -eq 0) {

            $tenantOk = $true
            $tenantCheckFailureKey = $null
            if ($DelegatedOrganization) {
                # Confirm the cached session is actually authed against the customer
                # tenant by listing verifiedDomains on /organization and looking for
                # the DelegatedOrganization. Mismatch ⇒ a stale partner-tenant session.
                try {
                    $org = Invoke-MgGraphRequest -Method GET `
                        -Uri 'https://graph.microsoft.com/v1.0/organization?$select=verifiedDomains' `
                        -ErrorAction Stop
                    $domains = @()
                    foreach ($o in @($org.value)) {
                        foreach ($d in @($o.verifiedDomains)) { if ($d.name) { $domains += $d.name.ToLowerInvariant() } }
                    }
                    $tenantOk = $domains -contains $DelegatedOrganization.ToLowerInvariant()
                    if (-not $tenantOk) { $tenantCheckFailureKey = 'tenant-domain-mismatch' }
                } catch {
                    $tenantOk = $false
                    $tenantCheckFailureKey = 'tenant-verification-failed'
                    $graphGuardDetail.tenantVerifyError = $_.Exception.Message
                }
            }

            if ($tenantOk) {
                $graphConnected = $true
                $graphGuardReason = 'reused'
                $graphGuardDetail.cachedAccount = $ctx.Account
                $graphGuardDetail.cachedTenantId = ($ctx.TenantId -as [string])
            } else {
                $graphGuardReason = $tenantCheckFailureKey
                $graphGuardDetail.cachedAccount   = $ctx.Account
                $graphGuardDetail.cachedTenantId  = ($ctx.TenantId -as [string])
                $graphGuardDetail.actualContainsExpected = $false
                Write-Host "Microsoft Graph: cached session is not authed against '$DelegatedOrganization'; reconnecting." -ForegroundColor DarkYellow
                Add-ConnectGuardLog -Service 'Graph' -Status 'Retried' -ReasonKey $graphGuardReason -Detail $graphGuardDetail
                try { Disconnect-MgGraph -ErrorAction SilentlyContinue | Out-Null } catch {}
            }
        } elseif ($ctx) {
            $cachedAcct = if ($ctx.Account) { $ctx.Account } else { '(no account)' }
            if ($missingScopes.Count -gt 0 -and $ctx.Account -ieq $TenantAdminUpn) {
                $graphGuardReason = 'missing-scopes'
                $graphGuardDetail.cachedAccount = $cachedAcct
                $graphGuardDetail.missingScopes = ($missingScopes -join ',')
                Write-Host "Microsoft Graph: cached session for '$cachedAcct' is missing required scopes ($($missingScopes -join ', ')); reconnecting." -ForegroundColor DarkYellow
            } else {
                $graphGuardReason = 'account-mismatch'
                $graphGuardDetail.cachedAccount = $cachedAcct
                Write-Host "Microsoft Graph: discarding cached session for '$cachedAcct' (does not match '$TenantAdminUpn' or required scopes)." -ForegroundColor DarkYellow
            }
            Add-ConnectGuardLog -Service 'Graph' -Status 'Retried' -ReasonKey $graphGuardReason -Detail $graphGuardDetail
            try { Disconnect-MgGraph -ErrorAction SilentlyContinue | Out-Null } catch {}
        } else {
            $graphGuardReason = 'no-context'
        }
    } catch {
        $graphConnected = $false
        $graphGuardReason = 'get-mgcontext-failed'
        $graphGuardDetail.error = $_.Exception.Message
    }

    if ($graphConnected) {
        Add-ConnectGuardLog -Service 'Graph' -Status 'Info' -ReasonKey 'reused' -Detail $graphGuardDetail
        Write-Host "Microsoft Graph: existing session reused (account + tenant + scopes match)." -ForegroundColor DarkGray
    } else {
        $startedReason = if ($graphGuardReason) { "reconnect-$graphGuardReason" } else { 'no-existing-session' }
        Add-ConnectGuardLog -Service 'Graph' -Status 'Started' -ReasonKey $startedReason -Detail $graphGuardDetail
        Write-Host ("Connecting to Microsoft Graph (Beta) for tenant {0} with scopes: {1}..." -f $targetTenantDomain, ($requiredScopes -join ', ')) -ForegroundColor Cyan
        # ZTA pattern: catch MissingMethodException from Microsoft.Identity
        # and emit the only fix that actually works — restart pwsh. No
        # runtime workaround exists once MSAL has been loaded with the
        # "wrong" version (including -UseDeviceCode, which hits the same
        # broken ctor path).
        try {
            Connect-MgGraph -TenantId $targetTenantDomain -Scopes $requiredScopes -NoWelcome -ErrorAction Stop
        } catch {
            $methodNotFound = $null
            if ($_.Exception -is [System.MissingMethodException]) {
                $methodNotFound = $_.Exception
            } elseif ($_.Exception.InnerException -is [System.MissingMethodException]) {
                $methodNotFound = $_.Exception.InnerException
            } elseif ($_.Exception.Message -match 'Method not found.*Microsoft\.Identity') {
                # Some .NET versions wrap the inner MissingMethodException in
                # a generic AuthenticationFailedException — message-match it.
                $methodNotFound = $_.Exception
            }
            if ($methodNotFound) {
                Write-Warning ""
                Write-Warning "Microsoft Graph sign-in failed with a Microsoft.Identity.Client (MSAL) DLL conflict."
                Write-Warning "This happens when another module loaded its own MSAL into this PowerShell process before Microsoft Graph could load its own."
                Write-Warning ""
                Write-Warning "There is NO runtime workaround once MSAL is loaded with the wrong version:"
                Write-Warning "  * -UseDeviceCode does NOT help (it hits the same broken MSAL method)."
                Write-Warning "  * Pre-loading the other MSAL via [Reflection.Assembly]::LoadFrom does NOT help (EXO refuses)."
                Write-Warning ""
                Write-Warning "Fix: CLOSE this PowerShell window, open a FRESH pwsh, and re-run this script."
                Write-Warning "     Do not import Microsoft.Graph.*, Az.*, PnP.PowerShell or ExchangeOnlineManagement in the new window before running this script."
                Add-ConnectGuardLog -Service 'Graph' -Status 'Failed' -ReasonKey 'msal-method-not-found-restart-pwsh' -Detail @{
                    error      = $methodNotFound.Message
                    exoModule  = $msalCompat.Info.exoModuleVersion
                    exoMsal    = $msalCompat.Info.exoMsalVersion
                    graphModule = $msalCompat.Info.graphModuleVersion
                    graphMsal  = $msalCompat.Info.graphMsalVersion
                    loadedMsal = $msalCompat.Info.loadedMsalVersion
                }
            }
            throw
        }
    }
}

# ---------------------------------------------------------------------------
# Exchange Online — connect AFTER Graph (Graph-first ordering preserves MSAL)
# ---------------------------------------------------------------------------
# Reuse an existing EXO session ONLY when it matches BOTH the target admin UPN
# AND the GDAP delegated organisation. Without this guard, back-to-back deploys
# against different customer tenants (or after a partner-tenant context switch)
# silently reuse the stale session and every Set-* call runs against the WRONG
# tenant.
$exoConnected = $false
$staleExo     = @()
$exoLookupOk  = $true
try {
    $exoSessions = @(Get-ConnectionInformation -ErrorAction Stop |
        Where-Object { $_.State -eq 'Connected' -and $_.TokenStatus -eq 'Active' -and $_.Name -like 'ExchangeOnline*' -and $_.ConnectionUri -notlike '*compliance.protection.outlook.com*' })
    foreach ($s in $exoSessions) {
        $upnOk = $s.UserPrincipalName -ieq $TenantAdminUpn
        $delegOk = if ($DelegatedOrganization) {
            $s.DelegatedOrganization -ieq $DelegatedOrganization
        } else {
            [string]::IsNullOrEmpty($s.DelegatedOrganization)
        }
        if ($upnOk -and $delegOk) { $exoConnected = $true }
        else {
            $reasonKey = if (-not $upnOk -and -not $delegOk) { 'upn-and-deleg-org-mismatch' }
                         elseif (-not $upnOk) { 'upn-mismatch' }
                         else { 'deleg-org-mismatch' }
            Add-ConnectGuardLog -Service 'EXO' -Status 'Retried' -ReasonKey $reasonKey -Detail @{
                expectedUpn          = $TenantAdminUpn
                actualUpn            = ($s.UserPrincipalName -as [string])
                expectedDelegatedOrg = ($DelegatedOrganization -as [string])
                actualDelegatedOrg   = ($s.DelegatedOrganization -as [string])
            }
            $staleExo += $s
        }
    }
} catch {
    $exoConnected = $false
    $exoLookupOk  = $false
    Add-ConnectGuardLog -Service 'EXO' -Status 'Info' -ReasonKey 'get-connectioninformation-failed' -Detail @{
        error = $_.Exception.Message
    }
}

if ($staleExo.Count -gt 0) {
    $targetDesc = if ($DelegatedOrganization) { "$TenantAdminUpn -> $DelegatedOrganization" } else { $TenantAdminUpn }
    Write-Host "Discarding $($staleExo.Count) stale Exchange Online session(s) (target: $targetDesc)." -ForegroundColor DarkYellow
    foreach ($s in $staleExo) {
        try {
            Disconnect-ExchangeOnline -ConnectionId $s.ConnectionId -Confirm:$false -ErrorAction SilentlyContinue | Out-Null
        } catch {
            Write-Verbose "  Could not disconnect stale EXO session $($s.ConnectionId): $($_.Exception.Message)"
        }
    }
}

if ($exoConnected) {
    Add-ConnectGuardLog -Service 'EXO' -Status 'Info' -ReasonKey 'reused' -Detail @{
        expectedUpn          = $TenantAdminUpn
        expectedDelegatedOrg = ($DelegatedOrganization -as [string])
    }
    Write-Host "Exchange Online: existing session reused (UPN + delegated-org match)." -ForegroundColor DarkGray
} else {
    $exoColdReason = if (-not $exoLookupOk) { 'reconnect-after-lookup-failure' }
                     elseif ($staleExo.Count -gt 0) { 'reconnect-after-stale-discard' }
                     else { 'no-existing-session' }
    Add-ConnectGuardLog -Service 'EXO' -Status 'Started' -ReasonKey $exoColdReason -Detail @{
        expectedUpn          = $TenantAdminUpn
        expectedDelegatedOrg = ($DelegatedOrganization -as [string])
    }
    $signInBanner = if ($DelegatedOrganization) { "$TenantAdminUpn (GDAP delegated: $DelegatedOrganization)" } else { $TenantAdminUpn }
    Write-Host "Connecting to Exchange Online as $signInBanner..." -ForegroundColor Cyan
    $exoArgs = @{ UserPrincipalName = $TenantAdminUpn; ShowBanner = $false }
    if ($DelegatedOrganization) { $exoArgs['DelegatedOrganization'] = $DelegatedOrganization }
    if ($script:MsalRequiresDisableWam) {
        # MSAL mismatch detected up-front. EXO 3.10's WAM RuntimeBroker
        # constructor null-refs when called against Graph 2.37's MSAL 4.82.
        # -DisableWAM falls back to interactive browser (still 1 click via
        # default browser) and avoids the broken WAM code path.
        $exoArgs['DisableWAM'] = $true
        Write-Host "  Using -DisableWAM for Exchange Online (MSAL mismatch — falls back to interactive browser)." -ForegroundColor DarkGray
        Add-ConnectGuardLog -Service 'EXO' -Status 'Info' -ReasonKey 'disable-wam-msal-mismatch' -Detail @{
            exoMsalVersion   = $msalCompat.Info.exoMsalVersion
            graphMsalVersion = $msalCompat.Info.graphMsalVersion
        }
    }
    try {
        Connect-ExchangeOnline @exoArgs
    } catch {
        # ZT-pattern: detect MSAL DLL conflict and tell the user to restart pwsh.
        # No script can recover from this — once a conflicting Microsoft.Identity.Client
        # is loaded into PS 7's AppDomain it cannot be unloaded.
        $exoConflict = @($_.Exception, $_.Exception.InnerException) |
            Where-Object { $_ -is [System.MissingMethodException] -or $_ -is [System.IO.FileLoadException] } |
            Select-Object -First 1
        if ($exoConflict -and ($exoConflict.Message -like '*Microsoft.Identity.Client*' -or $exoConflict.Message -like '*Microsoft.IdentityModel*')) {
            Write-Host ""
            Write-Warning "DLL conflict detected ($($exoConflict.GetType().Name)) loading Exchange Online's Microsoft.Identity.Client.dll."
            Write-Warning "This means a conflicting Microsoft.Identity.Client was loaded into this PowerShell session before Exchange Online."
            Write-Warning "Common causes: Microsoft.Graph, PnP.PowerShell, Az.* or Microsoft.Online.SharePoint.PowerShell was imported earlier in this session."
            Write-Warning "Fix: CLOSE this PowerShell window, open a fresh pwsh, and re-run the script. Do not import any other Microsoft modules first."
            Write-Host ""
        }
        # WAM RuntimeBroker NullReferenceException — fires when EXO's WAM
        # code path is loaded against Graph's older MSAL. Should not happen
        # now that we auto-pass -DisableWAM on detected mismatch, but keep
        # the structured guidance for the edge case where mismatch detection
        # under-reports (e.g. MSAL already loaded before script start).
        $errText = ($_.Exception.Message + "`n" + $_.ScriptStackTrace + "`n" + $_.Exception.StackTrace)
        if ($errText -match 'Microsoft\.Identity\.Client\.Platforms\.Features\.RuntimeBroker' -or
            ($_.Exception -is [System.NullReferenceException] -and $errText -match 'RuntimeBroker')) {
            Write-Host ""
            Write-Warning "WAM broker crash detected (NullReferenceException in Microsoft.Identity.Client.Platforms.Features.RuntimeBroker)."
            Write-Warning "This means EXO's WAM code path was loaded against a mismatched Microsoft.Identity.Client version (typically Graph 2.37's MSAL 4.82 + EXO 3.10's WAM expectations)."
            Write-Warning "Fix: re-run with the script's -DisableWAM mitigation (auto-applied when MSAL mismatch is detected). If this fires anyway, CLOSE this PowerShell window, open a fresh pwsh, and re-run the script."
            Write-Host ""
            Add-ConnectGuardLog -Service 'EXO' -Status 'Failed' -ReasonKey 'wam-runtimebroker-nullref' -Detail @{
                exoMsalVersion    = $msalCompat.Info.exoMsalVersion
                graphMsalVersion  = $msalCompat.Info.graphMsalVersion
                loadedMsalVersion = $msalCompat.Info.loadedMsalVersion
            }
        }
        throw
    }
}

# ---------------------------------------------------------------------------
# Security & Compliance (IPPS) — separate connection from EXO
# ---------------------------------------------------------------------------
# Same tenant-match guard as EXO: a stale IPPS session for a different tenant
# silently routes every Set-Label / Set-Dlp* call to the wrong customer.
$ippsConnected = $false
$staleIpps     = @()
$ippsLookupOk  = $true
try {
    $ippsSessions = @(Get-ConnectionInformation -ErrorAction Stop |
        Where-Object { $_.State -eq 'Connected' -and $_.TokenStatus -eq 'Active' -and $_.ConnectionUri -like '*compliance.protection.outlook.com*' })
    foreach ($s in $ippsSessions) {
        $upnOk = $s.UserPrincipalName -ieq $TenantAdminUpn
        $delegOk = if ($DelegatedOrganization) {
            $s.DelegatedOrganization -ieq $DelegatedOrganization
        } else {
            [string]::IsNullOrEmpty($s.DelegatedOrganization)
        }
        if ($upnOk -and $delegOk) { $ippsConnected = $true }
        else {
            $reasonKey = if (-not $upnOk -and -not $delegOk) { 'upn-and-deleg-org-mismatch' }
                         elseif (-not $upnOk) { 'upn-mismatch' }
                         else { 'deleg-org-mismatch' }
            Add-ConnectGuardLog -Service 'IPPS' -Status 'Retried' -ReasonKey $reasonKey -Detail @{
                expectedUpn          = $TenantAdminUpn
                actualUpn            = ($s.UserPrincipalName -as [string])
                expectedDelegatedOrg = ($DelegatedOrganization -as [string])
                actualDelegatedOrg   = ($s.DelegatedOrganization -as [string])
            }
            $staleIpps += $s
        }
    }
} catch {
    $ippsConnected = $false
    $ippsLookupOk  = $false
    Add-ConnectGuardLog -Service 'IPPS' -Status 'Info' -ReasonKey 'get-connectioninformation-failed' -Detail @{
        error = $_.Exception.Message
    }
}

if ($staleIpps.Count -gt 0) {
    $targetDesc = if ($DelegatedOrganization) { "$TenantAdminUpn -> $DelegatedOrganization" } else { $TenantAdminUpn }
    Write-Host "Discarding $($staleIpps.Count) stale Security & Compliance (IPPS) session(s) (target: $targetDesc)." -ForegroundColor DarkYellow
    foreach ($s in $staleIpps) {
        try {
            Disconnect-ExchangeOnline -ConnectionId $s.ConnectionId -Confirm:$false -ErrorAction SilentlyContinue | Out-Null
        } catch {
            Write-Verbose "  Could not disconnect stale IPPS session $($s.ConnectionId): $($_.Exception.Message)"
        }
    }
}

if ($ippsConnected) {
    Add-ConnectGuardLog -Service 'IPPS' -Status 'Info' -ReasonKey 'reused' -Detail @{
        expectedUpn          = $TenantAdminUpn
        expectedDelegatedOrg = ($DelegatedOrganization -as [string])
    }
    Write-Host "Security & Compliance (IPPS): existing session reused (UPN + delegated-org match)." -ForegroundColor DarkGray
} else {
    $ippsColdReason = if (-not $ippsLookupOk) { 'reconnect-after-lookup-failure' }
                      elseif ($staleIpps.Count -gt 0) { 'reconnect-after-stale-discard' }
                      else { 'no-existing-session' }
    Add-ConnectGuardLog -Service 'IPPS' -Status 'Started' -ReasonKey $ippsColdReason -Detail @{
        expectedUpn          = $TenantAdminUpn
        expectedDelegatedOrg = ($DelegatedOrganization -as [string])
    }
    $ippsBanner = if ($DelegatedOrganization) { " (GDAP delegated: $DelegatedOrganization)" } else { '' }
    Write-Host "Connecting to Security & Compliance Center$ippsBanner..." -ForegroundColor Cyan
    $ippsArgs = @{ UserPrincipalName = $TenantAdminUpn; ShowBanner = $false }
    if ($DelegatedOrganization) { $ippsArgs['DelegatedOrganization'] = $DelegatedOrganization }
    if ($script:MsalRequiresDisableWam) {
        # Same WAM-RuntimeBroker NullRef applies to IPPS (same module / same
        # MSAL surface). -DisableWAM keeps the interactive browser flow.
        $ippsArgs['DisableWAM'] = $true
        Write-Host "  Using -DisableWAM for Security & Compliance (IPPS) (MSAL mismatch — falls back to interactive browser)." -ForegroundColor DarkGray
        Add-ConnectGuardLog -Service 'IPPS' -Status 'Info' -ReasonKey 'disable-wam-msal-mismatch' -Detail @{
            exoMsalVersion   = $msalCompat.Info.exoMsalVersion
            graphMsalVersion = $msalCompat.Info.graphMsalVersion
        }
    }
    Connect-IPPSSession @ippsArgs
}

# ---------------------------------------------------------------------------
# SharePoint Online — module loaded LAST (via WinPS proxy) and connected LAST
# ---------------------------------------------------------------------------
# ZT-aligned pattern: Microsoft.Online.SharePoint.PowerShell is a Windows-only
# module. On PS Core we load it via -UseWindowsPowerShell so its bundled
# Microsoft.Identity.Client.dll never enters PS 7's AppDomain (it stays in the
# hidden PS 5.1 sub-process). The module import happens HERE — after EXO/IPPS
# are already connected — to guarantee EXO's own MSAL has loaded cleanly first.
#
# Resolver precedence for the admin URL:
#   1. -SharePointAdminUrl
#   2. -DelegatedOrganization (<tenant>.onmicrosoft.com)
#   3. Admin UPN suffix (when @<tenant>.onmicrosoft.com)
#   4. EXO Get-AcceptedDomain (final fallback — uses the EXO session above)
if ($NeedsSharePoint) {
    Ensure-RequiredModule -Name 'Microsoft.Online.SharePoint.PowerShell' `
        -RequiredCmdlet 'Connect-SPOService' `
        -AutoInstall:$AutoInstallModules `
        -NonInteractive:$NonInteractive `
        -UseWindowsPowerShellProxy

    $resolved = Resolve-SpoAdminUrlFromInputs `
        -ExplicitUrl $SharePointAdminUrl `
        -DelegatedOrganization $DelegatedOrganization `
        -TenantAdminUpn $TenantAdminUpn

    if ($resolved) {
        $SharePointAdminUrl = $resolved.Url
        Write-Host "SharePoint admin URL resolved via $($resolved.Source): $SharePointAdminUrl" -ForegroundColor DarkGray
    } else {
        Write-Host "Resolving SharePoint admin URL from tenant initial domain (EXO Get-AcceptedDomain)..." -ForegroundColor Cyan
        try {
            # Get-AcceptedDomain runs in the EXO session we just connected.
            # The InitialDomain (always <tenant>.onmicrosoft.com) is the
            # reliable basis for the SPO admin URL.
            $initial = Get-AcceptedDomain |
                Where-Object { $_.InitialDomain } |
                Select-Object -First 1
            if (-not $initial) {
                throw "No initial (.onmicrosoft.com) domain found via Get-AcceptedDomain."
            }
            $tenantPrefix = ($initial.DomainName -split '\.')[0]
            $SharePointAdminUrl = "https://$tenantPrefix-admin.sharepoint.com"
            Write-Host "  Resolved: $SharePointAdminUrl" -ForegroundColor Green
        } catch {
            throw "Could not auto-derive SharePoint admin URL: $($_.Exception.Message)`nPass -SharePointAdminUrl explicitly (e.g. https://<tenant>-admin.sharepoint.com)."
        }
    }

    Invoke-SpoConnectWithFallback -SharePointAdminUrl $SharePointAdminUrl -TenantAdminUpn $TenantAdminUpn
}

Write-Host "All required services connected." -ForegroundColor Green

[pscustomobject]@{
    SharePointAdminUrl = if ($NeedsSharePoint) { $SharePointAdminUrl } else { $null }
}
