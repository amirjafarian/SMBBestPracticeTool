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
    [switch] $NonInteractive
)

$ErrorActionPreference = 'Stop'

# Connecting to services is a precondition, not a destructive change. Some
# auth flows (notably Connect-SPOService and Import-Module -UseWindowsPowerShell)
# have internal steps that respect $WhatIfPreference and silently skip work
# under -WhatIf, producing misleading "No valid OAuth 2.0 authentication
# session exists" errors. Force WhatIf off for the duration of this script.
$WhatIfPreference = $false
$ConfirmPreference = 'None'
$script:spoViaWinPsProxy = $false
$script:spoWinPsSessionIds = @()

function Test-IsAdmin {
    try {
        $current = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
        return $current.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    } catch {
        return $false
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
    try {
        $current = Get-SPOTenant -ErrorAction Stop
        if ($current) { $spoConnected = $true }
    } catch { $spoConnected = $false }

    if ($spoConnected) {
        Write-Host "SharePoint Online: existing session reused." -ForegroundColor DarkGray
        return
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
    $trackSpoProxy = $proxy -and $Name -eq 'Microsoft.Online.SharePoint.PowerShell'

    $available = Get-Module -ListAvailable -Name $Name -ErrorAction SilentlyContinue

    if ($available) {
        try {
            if ($proxy) {
                $preProxySessionIds = if ($trackSpoProxy) { @(Get-PSSession -ErrorAction SilentlyContinue | ForEach-Object { $_.Id }) } else { @() }
                Import-Module $Name -UseWindowsPowerShell -DisableNameChecking `
                    -WarningAction SilentlyContinue -ErrorAction Stop | Out-Null
                if ($trackSpoProxy) {
                    $script:spoViaWinPsProxy = $true
                    $script:spoWinPsSessionIds = @(Get-PSSession -ErrorAction SilentlyContinue |
                        Where-Object { $preProxySessionIds -notcontains $_.Id } |
                        ForEach-Object { $_.Id })
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

    $psg = Get-PSRepository -Name PSGallery -ErrorAction SilentlyContinue
    $restoreUntrusted = $false
    if ($psg -and $psg.InstallationPolicy -ne 'Trusted') {
        try {
            Set-PSRepository -Name PSGallery -InstallationPolicy Trusted -ErrorAction SilentlyContinue
            $restoreUntrusted = $true
        } catch { }
    }

    Write-Host "Installing '$Name' (Scope: CurrentUser)..." -ForegroundColor Cyan
    $installError = $null
    try {
        try {
            Install-Module -Name $Name -Scope CurrentUser -Force -AllowClobber -ErrorAction Stop
        } catch {
            $installError = $_
        }
    } finally {
        # Restore PSGallery trust policy even if Install-Module threw or was Ctrl+C'd.
        if ($restoreUntrusted) {
            try { Set-PSRepository -Name PSGallery -InstallationPolicy Untrusted -ErrorAction SilentlyContinue } catch { }
        }
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
            $preProxySessionIds = if ($trackSpoProxy) { @(Get-PSSession -ErrorAction SilentlyContinue | ForEach-Object { $_.Id }) } else { @() }
            Import-Module $Name -UseWindowsPowerShell -DisableNameChecking `
                -WarningAction SilentlyContinue -ErrorAction Stop | Out-Null
            if ($trackSpoProxy) {
                $script:spoViaWinPsProxy = $true
                $script:spoWinPsSessionIds = @(Get-PSSession -ErrorAction SilentlyContinue |
                    Where-Object { $preProxySessionIds -notcontains $_.Id } |
                    ForEach-Object { $_.Id })
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
# Module checks (auto-install on demand)
# ---------------------------------------------------------------------------
# Following the Zero Trust Assessment pattern: load EXO module up front,
# but defer the SPO module import until AFTER EXO is connected. SPO's WinPS
# proxy import has a chance of perturbing PS 7's AppDomain — doing it AFTER
# EXO has already loaded its MSAL is the safest order.
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
    # values used by container labels.
    Ensure-RequiredModule -Name 'Microsoft.Graph.Beta.Identity.DirectoryManagement' `
        -AutoInstall:$AutoInstallModules `
        -NonInteractive:$NonInteractive
}

# ---------------------------------------------------------------------------
# Exchange Online — connect FIRST
# ---------------------------------------------------------------------------
# Reuse an existing EXO session ONLY when it matches BOTH the target admin UPN
# AND the GDAP delegated organisation. Without this guard, back-to-back deploys
# against different customer tenants (or after a partner-tenant context switch)
# silently reuse the stale session and every Set-* call runs against the WRONG
# tenant.
$exoConnected = $false
$staleExo     = @()
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
        else { $staleExo += $s }
    }
} catch { $exoConnected = $false }

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
    Write-Host "Exchange Online: existing session reused (UPN + delegated-org match)." -ForegroundColor DarkGray
} else {
    $signInBanner = if ($DelegatedOrganization) { "$TenantAdminUpn (GDAP delegated: $DelegatedOrganization)" } else { $TenantAdminUpn }
    Write-Host "Connecting to Exchange Online as $signInBanner..." -ForegroundColor Cyan
    $exoArgs = @{ UserPrincipalName = $TenantAdminUpn; ShowBanner = $false }
    if ($DelegatedOrganization) { $exoArgs['DelegatedOrganization'] = $DelegatedOrganization }
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
        else { $staleIpps += $s }
    }
} catch { $ippsConnected = $false }

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
    Write-Host "Security & Compliance (IPPS): existing session reused (UPN + delegated-org match)." -ForegroundColor DarkGray
} else {
    $ippsBanner = if ($DelegatedOrganization) { " (GDAP delegated: $DelegatedOrganization)" } else { '' }
    Write-Host "Connecting to Security & Compliance Center$ippsBanner..." -ForegroundColor Cyan
    $ippsArgs = @{ UserPrincipalName = $TenantAdminUpn; ShowBanner = $false }
    if ($DelegatedOrganization) { $ippsArgs['DelegatedOrganization'] = $DelegatedOrganization }
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

# ---------------------------------------------------------------------------
# Microsoft Graph (Beta) — optional
# ---------------------------------------------------------------------------
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
                } catch { $tenantOk = $false }
            }

            if ($tenantOk) {
                $graphConnected = $true
            } else {
                Write-Host "Microsoft Graph: cached session is not authed against '$DelegatedOrganization'; reconnecting." -ForegroundColor DarkYellow
                try { Disconnect-MgGraph -ErrorAction SilentlyContinue | Out-Null } catch {}
            }
        } elseif ($ctx) {
            $cachedAcct = if ($ctx.Account) { $ctx.Account } else { '(no account)' }
            if ($missingScopes.Count -gt 0 -and $ctx.Account -ieq $TenantAdminUpn) {
                Write-Host "Microsoft Graph: cached session for '$cachedAcct' is missing required scopes ($($missingScopes -join ', ')); reconnecting." -ForegroundColor DarkYellow
            } else {
                Write-Host "Microsoft Graph: discarding cached session for '$cachedAcct' (does not match '$TenantAdminUpn' or required scopes)." -ForegroundColor DarkYellow
            }
            try { Disconnect-MgGraph -ErrorAction SilentlyContinue | Out-Null } catch {}
        }
    } catch { $graphConnected = $false }

    if ($graphConnected) {
        Write-Host "Microsoft Graph: existing session reused (account + tenant + scopes match)." -ForegroundColor DarkGray
    } else {
        Write-Host ("Connecting to Microsoft Graph (Beta) for tenant {0} with scopes: {1}..." -f $targetTenantDomain, ($requiredScopes -join ', ')) -ForegroundColor Cyan
        Connect-MgGraph -TenantId $targetTenantDomain -Scopes $requiredScopes -NoWelcome
    }
}

Write-Host "All required services connected." -ForegroundColor Green

[pscustomobject]@{
    SharePointAdminUrl = if ($NeedsSharePoint) { $SharePointAdminUrl } else { $null }
    SpoUsedWinPsProxy  = $script:spoViaWinPsProxy
    SpoWinPsSessionIds = @($script:spoWinPsSessionIds)
}
