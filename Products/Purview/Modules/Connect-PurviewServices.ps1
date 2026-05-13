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
    Connect to SharePoint Online. The admin URL is auto-derived from the
    tenant's initial domain after Exchange Online is connected, unless
    -SharePointAdminUrl is passed as an override.

.PARAMETER SharePointAdminUrl
    Optional override for the SharePoint admin centre URL
    (e.g. https://contoso-admin.sharepoint.com). When omitted, the URL is
    auto-derived from the tenant's initial onmicrosoft.com domain — works for
    standard tenants. Use this parameter only when auto-derivation fails
    (e.g. multi-geo, renamed tenants, unusual domain configurations).

.PARAMETER DelegatedOrganization
    Customer tenant primary domain (e.g. contoso.onmicrosoft.com) when a partner
    is signing in via GDAP. Forwarded to Connect-ExchangeOnline and
    Connect-IPPSSession.

.PARAMETER ConnectGraph
    Connect to Microsoft Graph (Beta). Required only when configuring container
    labels (Group.Unified EnableMIPLabels).

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
    [switch] $AutoInstallModules
)

$ErrorActionPreference = 'Stop'

# Connecting to services is a precondition, not a destructive change. Some
# auth flows (notably Connect-SPOService and Import-Module -UseWindowsPowerShell)
# have internal steps that respect $WhatIfPreference and silently skip work
# under -WhatIf, producing misleading "No valid OAuth 2.0 authentication
# session exists" errors. Force WhatIf off for the duration of this script.
$WhatIfPreference = $false
$ConfirmPreference = 'None'

function Test-IsAdmin {
    try {
        $current = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
        return $current.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    } catch {
        return $false
    }
}

function Ensure-RequiredModule {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string] $Name,
        [string] $RequiredCmdlet,
        [switch] $AutoInstall
    )

    $available = Get-Module -ListAvailable -Name $Name -ErrorAction SilentlyContinue

    if ($available) {
        try {
            Import-Module $Name -DisableNameChecking -ErrorAction Stop | Out-Null
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
        Install-Module -Name $Name -Scope CurrentUser -Force -AllowClobber -ErrorAction Stop
    } catch {
        $installError = $_
    }

    if ($restoreUntrusted) {
        try { Set-PSRepository -Name PSGallery -InstallationPolicy Untrusted -ErrorAction SilentlyContinue } catch { }
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
        Import-Module $Name -DisableNameChecking -ErrorAction Stop | Out-Null
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
Ensure-RequiredModule -Name 'ExchangeOnlineManagement' `
    -RequiredCmdlet 'Connect-ExchangeOnline' `
    -AutoInstall:$AutoInstallModules

if ($NeedsSharePoint) {
    Ensure-RequiredModule -Name 'Microsoft.Online.SharePoint.PowerShell' `
        -RequiredCmdlet 'Connect-SPOService' `
        -AutoInstall:$AutoInstallModules
}

if ($ConnectGraph) {
    # Connect-MgGraph / Get-MgContext live in Microsoft.Graph.Authentication.
    Ensure-RequiredModule -Name 'Microsoft.Graph.Authentication' `
        -RequiredCmdlet 'Connect-MgGraph' `
        -AutoInstall:$AutoInstallModules
    # The Beta directory management module is needed for setting Group.Unified
    # values used by container labels.
    Ensure-RequiredModule -Name 'Microsoft.Graph.Beta.Identity.DirectoryManagement' `
        -AutoInstall:$AutoInstallModules
}

# ---------------------------------------------------------------------------
# Exchange Online
# ---------------------------------------------------------------------------
$exoConnected = $false
try {
    $info = Get-ConnectionInformation -ErrorAction Stop |
        Where-Object { $_.State -eq 'Connected' -and $_.TokenStatus -eq 'Active' -and $_.Name -like 'ExchangeOnline*' }
    if ($info) { $exoConnected = $true }
} catch { $exoConnected = $false }

if ($exoConnected) {
    Write-Host "Exchange Online: existing session reused." -ForegroundColor DarkGray
} else {
    Write-Host "Connecting to Exchange Online as $TenantAdminUpn..." -ForegroundColor Cyan
    $exoArgs = @{ UserPrincipalName = $TenantAdminUpn; ShowBanner = $false }
    if ($DelegatedOrganization) { $exoArgs['DelegatedOrganization'] = $DelegatedOrganization }
    Connect-ExchangeOnline @exoArgs
}

# ---------------------------------------------------------------------------
# Security & Compliance (IPPS) — separate connection from EXO
# ---------------------------------------------------------------------------
$ippsConnected = $false
try {
    $info = Get-ConnectionInformation -ErrorAction Stop |
        Where-Object { $_.State -eq 'Connected' -and $_.TokenStatus -eq 'Active' -and $_.ConnectionUri -like '*compliance.protection.outlook.com*' }
    if ($info) { $ippsConnected = $true }
} catch { $ippsConnected = $false }

if ($ippsConnected) {
    Write-Host "Security & Compliance (IPPS): existing session reused." -ForegroundColor DarkGray
} else {
    Write-Host "Connecting to Security & Compliance Center..." -ForegroundColor Cyan
    $ippsArgs = @{ UserPrincipalName = $TenantAdminUpn; ShowBanner = $false }
    if ($DelegatedOrganization) { $ippsArgs['DelegatedOrganization'] = $DelegatedOrganization }
    Connect-IPPSSession @ippsArgs
}

# ---------------------------------------------------------------------------
# SharePoint Online (with auto-derivation of admin URL)
# ---------------------------------------------------------------------------
$resolvedSpoUrl = $null

if ($NeedsSharePoint) {
    if (-not $SharePointAdminUrl) {
        Write-Host "Resolving SharePoint admin URL from tenant initial domain..." -ForegroundColor Cyan
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
    } else {
        Write-Host "Using supplied SharePoint admin URL: $SharePointAdminUrl" -ForegroundColor DarkGray
    }

    $resolvedSpoUrl = $SharePointAdminUrl

    $spoConnected = $false
    try {
        $current = Get-SPOTenant -ErrorAction Stop
        # Verify the existing session is for the same tenant we want
        if ($current) { $spoConnected = $true }
    } catch { $spoConnected = $false }

    if ($spoConnected) {
        Write-Host "SharePoint Online: existing session reused." -ForegroundColor DarkGray
    } else {
        $spoMod = Get-Module Microsoft.Online.SharePoint.PowerShell -ErrorAction SilentlyContinue
        if (-not $spoMod) {
            $spoMod = Get-Module Microsoft.Online.SharePoint.PowerShell -ListAvailable |
                Sort-Object Version -Descending | Select-Object -First 1
        }
        $spoVersion = if ($spoMod) { $spoMod.Version.ToString() } else { 'unknown' }
        $isCore = $PSVersionTable.PSEdition -eq 'Core'

        Write-Host "Connecting to SharePoint Online ($SharePointAdminUrl)..." -ForegroundColor Cyan
        Write-Host ("  PowerShell: {0} {1} | SPO module: {2}" -f `
            $PSVersionTable.PSEdition, $PSVersionTable.PSVersion, $spoVersion) -ForegroundColor DarkGray

        # Clear any stale/cached SPO session state before attempting a fresh
        # connect — this avoids "No valid OAuth 2.0 authentication session
        # exists" caused by a prior failed/expired token.
        try { Disconnect-SPOService -ErrorAction SilentlyContinue } catch { }

        try {
            Connect-SPOService -Url $SharePointAdminUrl -ErrorAction Stop
        } catch {
            $errMsg = $_.Exception.Message
            $isOAuthErr = $errMsg -match 'No valid OAuth'

            $retried = $false
            if ($isOAuthErr -and $isCore) {
                Write-Warning "Connect-SPOService failed under PowerShell 7. The SPO module's OAuth flow is unreliable on PS Core; retrying via Windows PowerShell 5.1 proxy..."
                try {
                    Remove-Module Microsoft.Online.SharePoint.PowerShell -Force -ErrorAction SilentlyContinue
                    Import-Module Microsoft.Online.SharePoint.PowerShell -UseWindowsPowerShell `
                        -DisableNameChecking -WarningAction SilentlyContinue -ErrorAction Stop | Out-Null
                    Connect-SPOService -Url $SharePointAdminUrl -ErrorAction Stop
                    Write-Host "  Connected via Windows PowerShell proxy." -ForegroundColor Green
                    $retried = $true
                } catch {
                    $errMsg = "$errMsg`nFallback (UseWindowsPowerShell) also failed: $($_.Exception.Message)"
                }
            }

            if (-not $retried) {
                $hints = @()
                if ($isOAuthErr) {
                    $hints += "* The sign-in account ($TenantAdminUpn) must hold the SharePoint Administrator (or Global Administrator) role on the customer tenant."
                    $hints += "* Make sure the browser sign-in pop-up is allowed and not blocked by your default browser, and complete MFA if prompted."
                    $hints += "* You can pre-authenticate manually first, then re-run this script: Connect-SPOService -Url $SharePointAdminUrl"
                }

                $fallbackModuleMissing = $errMsg -match 'no valid module file was found' -or `
                                         $errMsg -match "module .* was not loaded"
                if ($isCore -and $fallbackModuleMissing) {
                    $hints += "* The Windows PowerShell 5.1 fallback could not find 'Microsoft.Online.SharePoint.PowerShell'."
                    $hints += "  PS 7's 'Install-Module' installs to the PS 7 module path only; the fallback runs under PS 5.1 and needs the module in its path too."
                    $hints += "  Fix: open Windows PowerShell 5.1 (powershell.exe) once and run:"
                    $hints += "      Install-Module Microsoft.Online.SharePoint.PowerShell -Scope CurrentUser -Force -AllowClobber"
                    $hints += "  Then re-run this script from pwsh."
                } elseif ($isCore) {
                    $hints += "* If the SPO module is outdated, update it: Update-Module Microsoft.Online.SharePoint.PowerShell -Force"
                    $hints += "  (Do NOT downgrade to Windows PowerShell 5.1 to run this script — PS 5.1 is not supported by this toolkit.)"
                } else {
                    $hints += "* If your SPO module is old, run: Update-Module Microsoft.Online.SharePoint.PowerShell -Force"
                }

                $msg = "Connect-SPOService failed: $errMsg"
                if ($hints) { $msg += "`nTroubleshooting:`n  " + ($hints -join "`n  ") }
                throw $msg
            }
        }
    }
}

# ---------------------------------------------------------------------------
# Microsoft Graph (Beta) — optional
# ---------------------------------------------------------------------------
if ($ConnectGraph) {
    # Derive the target tenant from the admin UPN suffix. Connect-MgGraph
    # accepts a verified domain (e.g. contoso.onmicrosoft.com) in -TenantId,
    # which forces MSAL to authenticate against THIS tenant rather than
    # whichever tenant happens to be cached from a prior session.
    $targetTenantDomain = ($TenantAdminUpn -split '@')[-1]
    $graphConnected = $false
    try {
        $ctx = Get-MgContext -ErrorAction Stop
        # Reuse only when the cached session belongs to the SAME admin AND
        # has the required scope. A stale session for a different tenant
        # produces a "Selected user account does not exist in tenant"
        # popup the moment any Graph cmdlet triggers an MSAL token refresh.
        if ($ctx -and `
            $ctx.Account -and ($ctx.Account -ieq $TenantAdminUpn) -and `
            $ctx.Scopes -contains 'Directory.ReadWrite.All') {
            $graphConnected = $true
        } elseif ($ctx) {
            $cachedAcct = if ($ctx.Account) { $ctx.Account } else { '(no account)' }
            Write-Host "Microsoft Graph: discarding cached session for '$cachedAcct' (does not match '$TenantAdminUpn')." -ForegroundColor DarkYellow
            try { Disconnect-MgGraph -ErrorAction SilentlyContinue | Out-Null } catch {}
        }
    } catch { $graphConnected = $false }

    if ($graphConnected) {
        Write-Host "Microsoft Graph: existing session reused." -ForegroundColor DarkGray
    } else {
        Write-Host "Connecting to Microsoft Graph (Beta) for tenant $targetTenantDomain..." -ForegroundColor Cyan
        Connect-MgGraph -TenantId $targetTenantDomain -Scopes 'Directory.ReadWrite.All' -NoWelcome
    }
}

Write-Host "All required services connected." -ForegroundColor Green

[pscustomobject]@{
    SharePointAdminUrl = $resolvedSpoUrl
}
