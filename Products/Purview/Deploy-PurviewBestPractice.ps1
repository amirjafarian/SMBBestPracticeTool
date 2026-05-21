# =============================================================================
# DISCLAIMER
# =============================================================================
# This sample script is not supported under any Microsoft standard support
# program or service. The sample script is provided AS IS without warranty of
# any kind. Microsoft further disclaims all implied warranties including,
# without limitation, any implied warranties of merchantability or of fitness
# for a particular purpose. The entire risk arising out of the use or
# performance of the sample scripts and documentation remains with you. In no
# event shall Microsoft, its authors, or anyone else involved in the creation,
# production, or delivery of the scripts be liable for any damages whatsoever
# (including, without limitation, damages for loss of business profits,
# business interruption, loss of business information, or other pecuniary
# loss) arising out of the use of or inability to use the sample scripts or
# documentation, even if Microsoft has been advised of the possibility of
# such damages.
#
# Please do not contact Microsoft support with any issues or concerns
# regarding this script.
# =============================================================================

<#
.SYNOPSIS
    Deploys the Microsoft Purview Best Practice baseline for Microsoft 365
    Business Premium tenants.

.DESCRIPTION
    Single entry point that orchestrates the full deployment based on the
    Microsoft "Data Security Best Practice Deployment" guide for Business
    Premium. The toolkit is modular — every task is an independent script
    under .\Modules and can be run standalone.

    Tasks (in order):
      1. Tenant settings        — audit log, AIP/SPO integration, PDF labels,
                                  co-authoring (and optional container labels
                                  + premium audit)
      2. Sensitivity labels     — Personal, Public, General, Confidential
                                  (with AllEmployees sub-label),
                                  Highly Confidential — encryption applied,
                                  ordered, and published with General as the
                                  default
      3. DLP                    — separate Exchange and SPO+OneDrive policies
                                  blocking external sharing of the
                                  Confidential\AllEmployees label
      4. Retention              — Exchange mailbox 2-year retain-then-delete
      5. AI governance          — OPT-IN. Microsoft 365 Copilot DLP policies
                                  (e.g. AI_054 - Block Copilot for Highly
                                  Confidential). Provisioned only when
                                  -ApplyAIControls is supplied.

    Default mode = APPLY changes. Pass -WhatIf for preview, or -Confirm for
    per-action confirmation prompts.

.PARAMETER TenantAdminUpn
    UPN of the tenant administrator (or partner GDAP admin) used for sign-in.

.PARAMETER SharePointAdminUrl
    Optional override for the SharePoint admin centre URL
    (e.g. https://contoso-admin.sharepoint.com). When omitted, the URL is
    auto-derived from the tenant's initial onmicrosoft.com domain after
    Exchange Online is connected. Use this parameter only when auto-derivation
    fails (e.g. multi-geo or unusual domain configurations).

.PARAMETER DelegatedOrganization
    Customer tenant primary domain when running as a partner via GDAP.

.PARAMETER ConfigPath
    Path to a custom PurviewConfig.psd1. Defaults to .\Config\PurviewConfig.psd1.

.PARAMETER SkipTenantSettings
    Skip foundational tenant settings (audit, SPO integration, co-authoring).

.PARAMETER SkipLabels
    Skip sensitivity-label creation and publishing.

.PARAMETER SkipDLP
    Skip DLP policy creation.

.PARAMETER ApplyRetention
    Provision the Exchange mailbox retention policy from
    PurviewConfig.psd1. **Opt-in** — retention does NOT run by default
    because the shipped 2-year retain-then-delete default is destructive
    (deletes mail older than 2 years tenant-wide) and is wrong for most
    regulated verticals (law / accounting / healthcare / financial
    advisors / construction / real estate). The partner must consciously
    choose a duration for the customer's vertical before enabling.
    See docs/Retention-Default-Risk.md.

.PARAMETER ApplyAIControls
    Provision AI governance / Microsoft 365 Copilot DLP policies from the
    AIGovernance section of PurviewConfig.psd1 (e.g. AI_054 — Block Copilot
    for Highly Confidential). Off by default; AI policies are only created
    when this switch is supplied. Requires Microsoft 365 Copilot per-user
    licensing on the target tenant for enforcement to apply.

.PARAMETER EnableContainerLabels
    Also enable Group.Unified EnableMIPLabels so labels can be applied to
    Microsoft 365 groups, Teams, and SharePoint sites. Requires Microsoft
    Graph (Beta) connection. Off by default.

.PARAMETER EnablePremiumAudit
    Also enable per-mailbox SearchQueryInitiated audit. Requires Audit
    (Premium) licensing.

.PARAMETER PremiumAuditMailbox
    Mailbox UPN(s) on which to enable SearchQueryInitiated audit.

.PARAMETER AdoptExisting
    Update labels, policies, and rules that already exist but were not created
    by this toolkit. Use only after auditing existing configuration.

.PARAMETER EnableCoAuth
    Forwarded to Setup-SensitivityLabels. Use Microsoft's full "Co-Author"
    rights bundle (View, View Rights, Edit Content, Save, Copy, Print, Reply,
    Reply All, Forward, Allow Macros) instead of the default "Reviewer"
    bundle on encrypted sub-labels. Required for Office co-authoring (auto-
    save + simultaneous editing) and for third-party tooling that uses the
    Office object model. Off by default to avoid breaking integrations that
    read doc metadata.

.PARAMETER NonInteractive
    Skip the preflight confirmation prompt (e.g. for CI/automation runs).
    Also skips the post-connect tenant-identity confirmation prompt. If the
    connected tenant's verified domains do NOT include the expected domain
    (from -DelegatedOrganization or the -TenantAdminUpn suffix), the script
    aborts with a hard error BEFORE any destructive change.

.PARAMETER AutoInstallModules
    Auto-install any missing PowerShell modules (ExchangeOnlineManagement,
    Microsoft.Online.SharePoint.PowerShell, Microsoft.Graph.*) to the current
    user scope without prompting. Without this switch you are prompted before
    each install.

.PARAMETER NoLicenseAutoDetect
    Disable automatic license-tier detection. By default the script connects to
    Microsoft Graph, reads /subscribedSkus, and auto-enables -EnableContainerLabels
    when a Microsoft 365 E5 or Purview Suite SKU is detected on the tenant. Pass
    this switch to skip detection (e.g. when running unattended in a tenant
    where the operator does not have Directory.ReadWrite.All consent).

.PARAMETER BPOnly
    Hard-restrict the toolkit to Microsoft 365 Business Premium-eligible
    features only. Refuses to enable add-ons that require Microsoft 365 E5 /
    Microsoft Purview Suite licensing:
      * Container labels for Teams / Sites / M365 Groups (-EnableContainerLabels)
      * Premium Audit / 1-year retention (-EnablePremiumAudit)
      * Endpoint DLP (Devices), DLP for Defender for Cloud Apps,
        on-premises DLP scanner, Power BI DLP
    Also propagates to the DLP module so any custom workload added to
    PurviewConfig.psd1 that requires E5 is rejected up-front.

.EXAMPLE
    # Standard partner-managed customer onboarding — SharePoint admin URL is
    # auto-derived from the tenant's initial domain.
    .\Deploy-PurviewBestPractice.ps1 -TenantAdminUpn admin@contoso.onmicrosoft.com

.EXAMPLE
    # Preview every change without applying
    .\Deploy-PurviewBestPractice.ps1 `
        -TenantAdminUpn admin@contoso.onmicrosoft.com -WhatIf

.EXAMPLE
    # GDAP partner-delegated scenario, with retention opt-in
    .\Deploy-PurviewBestPractice.ps1 `
        -TenantAdminUpn partneradmin@fabrikam.onmicrosoft.com `
        -DelegatedOrganization contoso.onmicrosoft.com `
        -ApplyRetention

.EXAMPLE
    # Override the auto-derived SharePoint admin URL (rare — multi-geo/vanity)
    .\Deploy-PurviewBestPractice.ps1 `
        -TenantAdminUpn admin@contoso.onmicrosoft.com `
        -SharePointAdminUrl https://contoso-admin.sharepoint.com

.NOTES
    * Required modules: ExchangeOnlineManagement,
      Microsoft.Online.SharePoint.PowerShell, and
      Microsoft.Graph.Beta.Identity.DirectoryManagement (only when
      -EnableContainerLabels is used).
    * Label and policy changes can take up to 24 hours to propagate.
    * Always pilot in a test tenant before production rollout.
#>
[CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'None')]
param(
    [Parameter(Mandatory)]
    [string] $TenantAdminUpn,

    [Parameter()]
    [string] $SharePointAdminUrl,

    [Parameter()]
    [string] $DelegatedOrganization,

    [Parameter()]
    [string] $ConfigPath,

    [Parameter()]
    [switch] $SkipTenantSettings,

    [Parameter()]
    [switch] $SkipLabels,

    [Parameter()]
    [switch] $SkipDLP,

    [Parameter()]
    [switch] $ApplyRetention,

    [Parameter()]
    [switch] $ApplyAIControls,

    [Parameter()]
    [switch] $EnableContainerLabels,

    [Parameter()]
    [switch] $EnablePremiumAudit,

    [Parameter()]
    [string[]] $PremiumAuditMailbox,

    [Parameter()]
    [switch] $AdoptExisting,

    [Parameter()]
    [switch] $EnableCoAuth,

    [Parameter()]
    [switch] $NonInteractive,

    [Parameter()]
    [switch] $AutoInstallModules,

    [Parameter()]
    [switch] $BPOnly,

    [Parameter()]
    [switch] $NoLicenseAutoDetect,

    # PR-Report: end-of-run HTML report (Tier 1 - task status + run metadata).
    # Default location: same folder as the script, named with a timestamp.
    # Pass -NoReport to suppress, or -ReportPath <path> to control location.
    [Parameter()]
    [string] $ReportPath,

    [Parameter()]
    [switch] $NoReport
)

$ErrorActionPreference = 'Stop'
# Auto-confirm: this toolkit is designed for unattended/scripted runs. Use -WhatIf for dry-run.
$ConfirmPreference   = 'None'

# ---------------------------------------------------------------------------
# Toolkit version
# ---------------------------------------------------------------------------
# Surfaced in the end-of-run HTML report and (eventually) in support logs.
# Bump on each release. The runtime build suffix is the short Git SHA when
# the script lives in a working tree -- fall back to '' in tarball deploys.
$script:DeployVersion = '0.5.0'
try {
    $gitSha = & git -C $PSScriptRoot rev-parse --short HEAD 2>$null
    if ($LASTEXITCODE -eq 0 -and $gitSha) {
        $script:DeployVersion = "$script:DeployVersion+$($gitSha.Trim())"
    }
} catch { }

# Capture start time and run identifier as early as possible so the
# end-of-run report has accurate timing even if connect/license auto-detect
# throws before any task runs.
$script:StartTime = Get-Date
$script:RunId     = [guid]::NewGuid()

# Tier-2 run log: initialise the singleton collection that Setup-* modules
# and the retry helper will append decision-point entries to. Dot-source
# here so the functions are defined before any module is invoked.
. (Join-Path $PSScriptRoot 'Modules\PurviewRunLog.ps1')
Initialize-PurviewRunLog

# ---------------------------------------------------------------------------
# PowerShell version gate
# ---------------------------------------------------------------------------
# This toolkit requires PowerShell 7+ (PowerShell Core / pwsh.exe).
# Windows PowerShell 5.1 (powershell.exe) is NOT supported because:
#   * ExchangeOnlineManagement v3+ Connect-IPPSSession's REST/EXOv3 path
#     and the Microsoft.Graph SDK both rely on .NET Core APIs that PS 5.1
#     does not expose, leading to silent auth and cmdlet-discovery failures.
#   * Newer label / DLP cmdlets are surfaced only over the v3 REST channel.
# We hard-fail upfront so partners aren't left debugging cryptic mid-run errors.
if ($PSVersionTable.PSVersion.Major -lt 7) {
    $edition = if ($PSVersionTable.PSEdition) { $PSVersionTable.PSEdition } else { 'Desktop' }
    $msg = @"
This toolkit requires PowerShell 7 or later (PowerShell Core / pwsh.exe).
You are running: PowerShell $($PSVersionTable.PSVersion) (Edition: $edition).

Windows PowerShell 5.1 is not supported — the Exchange Online v3 REST channel
and Microsoft.Graph SDK depend on .NET Core APIs unavailable in PS 5.1, which
causes silent connection failures and missing cmdlets later in the deploy.

Install PowerShell 7:  winget install --id Microsoft.PowerShell --source winget
                  or:  https://aka.ms/PowerShell-Release
Then re-run this script from a `pwsh` prompt (not `powershell`).
"@
    throw $msg
}

# ---------------------------------------------------------------------------
# Locate config & modules relative to this script
# ---------------------------------------------------------------------------
$scriptRoot = Split-Path -Parent $PSCommandPath
if (-not $ConfigPath) {
    $ConfigPath = Join-Path $scriptRoot 'Config\PurviewConfig.psd1'
}
if (-not (Test-Path $ConfigPath)) {
    throw "Config file not found: $ConfigPath"
}
$config = Import-PowerShellDataFile -Path $ConfigPath

$moduleRoot = Join-Path $scriptRoot 'Modules'
$connectScript      = Join-Path $moduleRoot 'Connect-PurviewServices.ps1'
$tenantScript       = Join-Path $moduleRoot 'Setup-TenantSettings.ps1'
$labelsScript       = Join-Path $moduleRoot 'Setup-SensitivityLabels.ps1'
$dlpScript          = Join-Path $moduleRoot 'Setup-DLP.ps1'
$retentionScript    = Join-Path $moduleRoot 'Setup-Retention.ps1'
$aiScript           = Join-Path $moduleRoot 'Setup-AIGovernance.ps1'

foreach ($s in @($connectScript, $tenantScript, $labelsScript, $dlpScript, $retentionScript, $aiScript)) {
    if (-not (Test-Path $s)) { throw "Required module script not found: $s" }
}

# ---------------------------------------------------------------------------
# Validate parameter combinations
# ---------------------------------------------------------------------------
$needsSpo = -not $SkipTenantSettings -or -not $SkipLabels
if ($EnablePremiumAudit -and (-not $PremiumAuditMailbox -or $PremiumAuditMailbox.Count -eq 0)) {
    throw "-EnablePremiumAudit requires -PremiumAuditMailbox <upn[]>."
}

if ($BPOnly) {
    $bpViolations = @()
    if ($EnableContainerLabels) {
        $bpViolations += "  * -EnableContainerLabels requires Microsoft 365 E5 / Purview Suite (AAD P1+)."
    }
    if ($EnablePremiumAudit) {
        $bpViolations += "  * -EnablePremiumAudit (Audit Premium / SearchQueryInitiated) requires Microsoft 365 E5."
    }
    if ($bpViolations) {
        throw "-BPOnly conflicts with E5-only options:`n$($bpViolations -join "`n")`nRemove the conflicting switches, or omit -BPOnly if the customer holds E5/Purview Suite."
    }
}

# ---------------------------------------------------------------------------
# Preflight summary
# ---------------------------------------------------------------------------
$bannerSpoUrl   = if ($SharePointAdminUrl)   { $SharePointAdminUrl } elseif ($needsSpo) { '(auto-derive from tenant)' } else { '(not needed)' }
$bannerDelegate = if ($DelegatedOrganization) { $DelegatedOrganization } else { '(none)' }
$tickTenant     = if (-not $SkipTenantSettings) { 'X' } else { ' ' }
$tickLabels     = if (-not $SkipLabels)         { 'X' } else { ' ' }
$tickDlp        = if (-not $SkipDLP)            { 'X' } else { ' ' }
$tickRetention  = if ($ApplyRetention)          { 'X' } else { ' ' }
$tickAi         = if ($ApplyAIControls)         { 'X' } else { ' ' }
$tickContainer  = if ($BPOnly -or $NoLicenseAutoDetect -or $SkipTenantSettings) {
                      if ($EnableContainerLabels) { 'X' } else { ' ' }
                  } elseif ($EnableContainerLabels) { 'X' }
                  else                              { '?' }
$tickPremium    = if ($EnablePremiumAudit)      { 'X' } else { ' ' }
$tickAdopt      = if ($AdoptExisting)           { 'X' } else { ' ' }
$tickCoAuth     = if ($EnableCoAuth)            { 'X' } else { ' ' }
$bannerMode     = if ($WhatIfPreference) { 'WHAT-IF (preview only — no changes)' } else { 'APPLY (changes will be made)' }
$bannerTier     = if ($BPOnly) { 'Business Premium ONLY (E5 features blocked)' } else { 'No license tier restriction' }

$banner = @"

==============================================================================
  Microsoft Purview Best Practice Deployment
  Reference: M365 Business Premium "Data Security Best Practice Deployment"
==============================================================================
  Tenant admin UPN     : $TenantAdminUpn
  SharePoint admin URL : $bannerSpoUrl
  Delegated org (GDAP) : $bannerDelegate
  Config file          : $ConfigPath

  Tasks to run:
    [$tickTenant] Tenant settings    (audit, SPO/AIP, co-auth, PDF)
    [$tickLabels] Sensitivity labels (3 parents + 5 sub-labels, publish)
    [$tickDlp] DLP policies       (Exchange + SPO/OneDrive)
    [$tickRetention] Retention          (Exchange 2 years — opt-in via -ApplyRetention)
    [$tickAi] AI governance      (Microsoft 365 Copilot DLP — opt-in)

  Optional features:
    [$tickContainer] Container labels (Group.Unified EnableMIPLabels)   ['?' = auto-enable on M365 E5 / Purview Suite]
    [$tickPremium] Premium audit    (SearchQueryInitiated)
    [$tickAdopt] Adopt existing   (overwrite non-toolkit objects)
    [$tickCoAuth] Co-Author rights (Copy/Print/Allow Macros) on encrypted labels — default is Reviewer

  Mode: $bannerMode
  License tier: $bannerTier
==============================================================================

"@

Write-Host $banner -ForegroundColor Cyan

if (-not $WhatIfPreference -and -not $NonInteractive) {
    $confirmation = Read-Host "Proceed with deployment? [y/N]"
    if ($confirmation -notmatch '^[yY]') {
        Write-Host "Deployment cancelled." -ForegroundColor Yellow
        return
    }
}

# ---------------------------------------------------------------------------
# Connect
# ---------------------------------------------------------------------------
Write-Host "`n--- Connecting to services ---" -ForegroundColor White
$connectArgs = @{ TenantAdminUpn = $TenantAdminUpn }
if ($needsSpo)             { $connectArgs['NeedsSharePoint']     = $true }
if ($SharePointAdminUrl)   { $connectArgs['SharePointAdminUrl']   = $SharePointAdminUrl }
if ($DelegatedOrganization){ $connectArgs['DelegatedOrganization'] = $DelegatedOrganization }
$wantGraphForAutoDetect = (-not $BPOnly -and -not $NoLicenseAutoDetect -and -not $SkipTenantSettings -and -not $EnableContainerLabels)
if ($EnableContainerLabels -or $wantGraphForAutoDetect) { $connectArgs['ConnectGraph'] = $true }
# Least-privilege Graph scopes (Jim's PR1 feedback):
#   * Organization.Read.All       — covers /subscribedSkus + /organization (license auto-detect, tenant-identity confirm)
#   * Directory.ReadWrite.All     — only added when container labels are explicitly requested.
#                                   Required for Get-MgBetaDirectorySettingTemplate + New-/Update-MgBetaDirectorySetting
#                                   against the Group.Unified directory setting. Note: we did experiment with the
#                                   narrower GroupSettings.ReadWrite.All scope (the documented permission for
#                                   /directorySettingTemplates), but it triggered a 403 Authorization_RequestDenied
#                                   on tenants whose admins had only ever consented to Directory.ReadWrite.All — the
#                                   token cache wasn't refreshed and admin-consent for the narrower scope wasn't
#                                   reliably available. Directory.ReadWrite.All is the historically-consented,
#                                   known-working scope and the canonical fallback per the Graph docs.
#   Auto-detect promotion (E5/Purview Suite tenant -> EnableContainerLabels gets flipped) extends the
#   consent later via a second Connect-MgGraph call.
$graphScopes = @()
if ($connectArgs.ContainsKey('ConnectGraph')) {
    $graphScopes = @('Organization.Read.All')
    if ($EnableContainerLabels) { $graphScopes += 'Directory.ReadWrite.All' }
    $connectArgs['GraphScopes'] = $graphScopes
}
if ($AutoInstallModules)   { $connectArgs['AutoInstallModules']   = $true }
if ($NonInteractive)       { $connectArgs['NonInteractive']       = $true }
$connectionInfo = & $connectScript @connectArgs
if ($connectionInfo -and $connectionInfo.SharePointAdminUrl) {
    $SharePointAdminUrl = $connectionInfo.SharePointAdminUrl
}

# ---------------------------------------------------------------------------
# License auto-detection (E5 / Purview Suite -> auto-enable Container labels)
# ---------------------------------------------------------------------------
function Get-TenantPurviewLicenseTier {
    [CmdletBinding()]
    param()

    $result = [pscustomobject]@{
        Tier        = 'Unknown'
        PartNumbers = @()
        Reason      = $null
    }

    if (-not (Get-Command Invoke-MgGraphRequest -ErrorAction SilentlyContinue)) {
        $result.Reason = 'Microsoft.Graph.Authentication module not loaded'
        return $result
    }

    try {
        $resp = Invoke-MgGraphRequest -Method GET -Uri 'https://graph.microsoft.com/v1.0/subscribedSkus' -ErrorAction Stop
    } catch {
        $result.Reason = "Subscribed-SKUs query failed: $($_.Exception.Message)"
        return $result
    }

    if (-not $resp -or -not $resp.value) {
        $result.Reason = 'Subscribed-SKUs response empty'
        return $result
    }

    $skus = @($resp.value | Where-Object { $_.capabilityStatus -ne 'Suspended' -and $_.capabilityStatus -ne 'Deleted' })
    $partNumbers = @($skus | ForEach-Object { $_.skuPartNumber } | Where-Object { $_ })
    $result.PartNumbers = $partNumbers

    # Headline SKUs that grant container-label rights (Group.Unified EnableMIPLabels)
    # IMPORTANT: SKU part-numbers are exact-match strings, NOT wildcards. When
    # Microsoft introduces a new SKU variant (e.g. the EU no-Teams unbundling)
    # it gets a new part-number and we must add it here explicitly or the
    # tenant gets misclassified as 'Other' and auto-detect skips container
    # labels / -BPOnly gets force-enabled. To inventory a tenant's real SKUs:
    #   Invoke-MgGraphRequest -Method GET -Uri 'https://graph.microsoft.com/v1.0/subscribedSkus' |
    #     Select-Object -ExpandProperty value |
    #     Where-Object capabilityStatus -ne 'Suspended' |
    #     Select-Object skuPartNumber, skuId
    $e5Sku = @(
        # M365 E5 (full bundle, includes Teams)
        'SPE_E5','SPE_E5_NOPSTNCONF',
        # M365 E5 no-Teams variants (EU unbundling, May 2024+).
        # Teams must be licensed separately via 'Microsoft_Teams_Enterprise_New'.
        'Microsoft_365_E5_(no_Teams)','Microsoft_365_E5_no_Teams','SPE_E5_NOPSTNCONF_no_Teams',
        # Office 365 E5
        'ENTERPRISEPREMIUM','ENTERPRISEPREMIUM_NOPSTNCONF',
        # Compliance / Security add-ons (each includes the IPPS container-label rights)
        'INFORMATION_PROTECTION_COMPLIANCE',
        'IDENTITY_THREAT_PROTECTION',
        'M365_E5_SUITE_COMPONENTS',
        'Microsoft_Purview_Suite',
        'INFORMATION_PROTECTION_AND_GOVERNANCE',
        # Education A5 (compliance feature parity with E5)
        'M365EDU_A5_FACULTY','M365EDU_A5_STUDENT','M365EDU_A5_STUUSEBNFT'
    )
    $matched = @($partNumbers | Where-Object { $_ -in $e5Sku })
    if ($matched.Count -gt 0) {
        $result.Tier = 'E5OrPurviewSuite'
        $result.PartNumbers = $matched
        return $result
    }

    if ($partNumbers -contains 'SPB' -or $partNumbers -contains 'BUSINESS_PREMIUM') {
        $result.Tier = 'BusinessPremium'
        $result.PartNumbers = @($partNumbers | Where-Object { $_ -in 'SPB','BUSINESS_PREMIUM' })
        return $result
    }

    $result.Tier = 'Other'
    return $result
}

if ($wantGraphForAutoDetect) {
    Write-Host "`n--- License auto-detect ---" -ForegroundColor White
    $tier = Get-TenantPurviewLicenseTier
    switch ($tier.Tier) {
        'E5OrPurviewSuite' {
            $EnableContainerLabels = $true
            Write-Host ("  Detected: Microsoft 365 E5 / Purview Suite (SKU: {0})." -f ($tier.PartNumbers -join ', ')) -ForegroundColor Green
            Write-Host "  Auto-enabling: Container labels (Group.Unified EnableMIPLabels)." -ForegroundColor Green
            Write-Host "  (To opt out, re-run with -NoLicenseAutoDetect or -BPOnly.)" -ForegroundColor DarkGray
        }
        'BusinessPremium' {
            Write-Host "  Detected: Microsoft 365 Business Premium." -ForegroundColor DarkGray
            Write-Host "  Container labels (E5 / Purview Suite feature) not auto-enabled." -ForegroundColor DarkGray
            if (-not $BPOnly) {
                $BPOnly = $true
                Write-Host "  Auto-enabling -BPOnly: E5/Purview-Suite-only DLP workloads (Endpoint, MCAS, OnPrem, PowerBI) will be SKIPPED with a warning, not attempted." -ForegroundColor Yellow
                Write-Host "  (To override, re-run with -NoLicenseAutoDetect.)" -ForegroundColor DarkGray
            }
        }
        'Other' {
            $skuList = if ($tier.PartNumbers) { $tier.PartNumbers -join ', ' } else { '(none)' }
            Write-Host ("  Tenant SKUs: {0}" -f $skuList) -ForegroundColor DarkGray
            Write-Host "  No E5 / Purview Suite SKU detected; container labels not auto-enabled." -ForegroundColor DarkGray
            if (-not $BPOnly) {
                $BPOnly = $true
                Write-Host "  Auto-enabling -BPOnly (no E5/Purview-Suite SKU detected): E5-only DLP workloads will be SKIPPED with a warning, not attempted." -ForegroundColor Yellow
                Write-Host "  (To override, re-run with -NoLicenseAutoDetect.)" -ForegroundColor DarkGray
            }
        }
        default {
            Write-Host "  Could not classify tenant license tier." -ForegroundColor DarkYellow
            if ($tier.Reason) { Write-Host "  Reason: $($tier.Reason)" -ForegroundColor DarkYellow }
            Write-Host "  Pass -EnableContainerLabels manually if eligible." -ForegroundColor DarkYellow
        }
    }
}

# ---------------------------------------------------------------------------
# Graph scope extension after auto-detect promotion (least-privilege)
# ---------------------------------------------------------------------------
# If license auto-detect just flipped $EnableContainerLabels on, the initial
# Graph connect did NOT request 'Directory.ReadWrite.All' (we only asked
# for 'Organization.Read.All'). Extend consent NOW, before Setup-TenantSettings
# tries to read /directorySettingTemplates and write via New-/Update-MgBetaDirectorySetting.
# The Graph SDK is happy to add scopes incrementally — already-consented users see no prompt.
#
# NOTE: Directory.ReadWrite.All is the historically-consented, known-working
# scope for /directorySettingTemplates and /settings on most tenants. We
# experimented with the narrower GroupSettings.ReadWrite.All but it caused
# 403 Authorization_RequestDenied where admins had only ever consented to
# Directory.ReadWrite.All.
if ($EnableContainerLabels -and `
    $connectArgs.ContainsKey('ConnectGraph') -and `
    ('Directory.ReadWrite.All' -notin $graphScopes)) {

    $graphScopes = @($graphScopes + 'Directory.ReadWrite.All')
    Write-Host "`n--- Extending Graph consent ---" -ForegroundColor White
    Write-Host "  Auto-detect promoted -EnableContainerLabels; extending Graph scope to include 'Directory.ReadWrite.All' (needed to read /directorySettingTemplates and write Group.Unified)." -ForegroundColor DarkGray
    try {
        $targetTid = if ($DelegatedOrganization) { $DelegatedOrganization } else { ($TenantAdminUpn -split '@')[-1] }
        Connect-MgGraph -TenantId $targetTid -Scopes $graphScopes -NoWelcome -ErrorAction Stop
        Write-Host ("  Graph scopes now: {0}" -f ($graphScopes -join ', ')) -ForegroundColor DarkGray
    } catch {
        Write-Warning ("Could not extend Graph scope to include 'Directory.ReadWrite.All': {0}" -f $_.Exception.Message)
        Write-Warning "Container-label setup ([5/5] in Tenant settings) may fail with an authorization error. To skip the prompt, re-run with -EnableContainerLabels passed explicitly so the scope is requested upfront."
    }
}

# ---------------------------------------------------------------------------
# Tenant identity confirmation (PR1 — Jim's feedback)
# ---------------------------------------------------------------------------
# After connect succeeds, resolve the ACTUAL tenant we landed in and confirm
# it matches what the user implied via -TenantAdminUpn / -DelegatedOrganization.
# Catches the classic "I thought I was on tenant A but my last interactive
# sign-in was on tenant B" disaster before any destructive change runs.
function Get-ActualTenantIdentity {
    [CmdletBinding()]
    param()

    $identity = [pscustomobject]@{
        DisplayName   = $null
        TenantId      = $null
        DefaultDomain = $null
        InitialDomain = $null
        AllDomains    = @()
        Source        = $null
    }

    # Prefer Graph (cleaner structured response) when /organization is reachable.
    if (Get-Command Invoke-MgGraphRequest -ErrorAction SilentlyContinue) {
        try {
            $org = Invoke-MgGraphRequest -Method GET `
                -Uri 'https://graph.microsoft.com/v1.0/organization?$select=id,displayName,verifiedDomains' `
                -ErrorAction Stop
            if ($org -and $org.value -and $org.value.Count -gt 0) {
                $o = $org.value[0]
                $identity.DisplayName = $o.displayName
                $identity.TenantId    = $o.id
                $identity.AllDomains  = @($o.verifiedDomains | ForEach-Object { $_.name })
                $defaultDom = @($o.verifiedDomains | Where-Object { $_.isDefault })
                $initialDom = @($o.verifiedDomains | Where-Object { $_.isInitial })
                if ($defaultDom.Count -gt 0) { $identity.DefaultDomain = $defaultDom[0].name }
                if ($initialDom.Count -gt 0) { $identity.InitialDomain = $initialDom[0].name }
                $identity.Source = 'Microsoft Graph (/organization)'
                return $identity
            }
        } catch {
            Write-Verbose "Graph identity lookup failed, falling back to EXO: $($_.Exception.Message)"
        }
    }

    # Fall back to Exchange Online — always available because EXO is the first
    # service we connect to.
    try {
        $orgCfg = Get-OrganizationConfig -ErrorAction Stop
        if ($orgCfg) {
            $identity.DisplayName = if ($orgCfg.DisplayName) { $orgCfg.DisplayName } else { $orgCfg.Name }
            if ($orgCfg.PSObject.Properties['Guid'] -and $orgCfg.Guid) {
                $identity.TenantId = [string]$orgCfg.Guid
            }
        }
        $domains = @(Get-AcceptedDomain -ErrorAction Stop)
        $identity.AllDomains = @($domains | ForEach-Object { $_.DomainName })
        $defaultDom = @($domains | Where-Object { $_.Default })
        $initialDom = @($domains | Where-Object { $_.InitialDomain })
        if ($defaultDom.Count -gt 0) { $identity.DefaultDomain = $defaultDom[0].DomainName }
        if ($initialDom.Count -gt 0) { $identity.InitialDomain = $initialDom[0].DomainName }
        $identity.Source = 'Exchange Online (Get-OrganizationConfig + Get-AcceptedDomain)'
        return $identity
    } catch {
        throw "Could not resolve tenant identity from Graph or Exchange Online. Connection may have failed silently. Error: $($_.Exception.Message)"
    }
}

function Test-ExpectedTenantMatch {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] $Identity,
        [string] $TenantAdminUpn,
        [string] $DelegatedOrganization
    )

    # GDAP: expected = -DelegatedOrganization (a domain on the customer tenant).
    # Non-GDAP: expected = the admin UPN's domain suffix.
    $expected = if ($DelegatedOrganization) {
        $DelegatedOrganization.ToLowerInvariant()
    } elseif ($TenantAdminUpn -match '@(.+)$') {
        $Matches[1].ToLowerInvariant()
    } else {
        $null
    }

    if (-not $expected) {
        return [pscustomobject]@{
            Match    = $false
            Source   = '(could not derive expected tenant from inputs)'
            Expected = $null
            Reason   = 'Cannot validate tenant identity: no -DelegatedOrganization and -TenantAdminUpn has no domain suffix.'
        }
    }

    $source = if ($DelegatedOrganization) { '-DelegatedOrganization' } else { 'admin UPN suffix' }
    $allDomains = @($Identity.AllDomains | ForEach-Object { $_.ToLowerInvariant() })
    $match = $allDomains -contains $expected

    return [pscustomobject]@{
        Match    = $match
        Source   = $source
        Expected = $expected
        Reason   = if ($match) {
                        "Expected domain '$expected' (from $source) is a verified domain on the connected tenant."
                    } else {
                        "Expected domain '$expected' (from $source) is NOT a verified domain on the connected tenant. The signed-in session appears to be authed against a DIFFERENT tenant than intended."
                    }
    }
}

Write-Host "`n--- Tenant identity confirmation ---" -ForegroundColor White
$tenantIdentity = Get-ActualTenantIdentity
$expectedMatch  = Test-ExpectedTenantMatch -Identity $tenantIdentity `
                    -TenantAdminUpn $TenantAdminUpn `
                    -DelegatedOrganization $DelegatedOrganization

$idTenantId      = if ($tenantIdentity.TenantId)      { $tenantIdentity.TenantId }      else { '(not resolved)' }
$idDisplayName   = if ($tenantIdentity.DisplayName)   { $tenantIdentity.DisplayName }   else { '(not resolved)' }
$idDefaultDomain = if ($tenantIdentity.DefaultDomain) { $tenantIdentity.DefaultDomain } else { '(not resolved)' }
$idInitialDomain = if ($tenantIdentity.InitialDomain) { $tenantIdentity.InitialDomain } else { '(not resolved)' }
$idUpnSuffix     = if ($TenantAdminUpn -match '@(.+)$') { $Matches[1] } else { '(unknown)' }
$idGdap          = if ($DelegatedOrganization) { $DelegatedOrganization } else { '(none)' }

$idBanner = @"
  Connected tenant (live from $($tenantIdentity.Source)):
    Display name   : $idDisplayName
    Default domain : $idDefaultDomain
    Initial domain : $idInitialDomain
    Tenant ID      : $idTenantId

  Expected (from arguments):
    UPN suffix     : $idUpnSuffix
    GDAP target    : $idGdap
"@
Write-Host $idBanner -ForegroundColor Cyan

if ($expectedMatch.Match) {
    Write-Host "  [OK] Identity matches expected: $($expectedMatch.Reason)" -ForegroundColor Green
} else {
    Write-Host "  [!!] IDENTITY MISMATCH: $($expectedMatch.Reason)" -ForegroundColor Red
    if ($NonInteractive) {
        throw "Tenant identity mismatch (running with -NonInteractive). Aborting before any destructive change.`n  Expected (from $($expectedMatch.Source)): $($expectedMatch.Expected)`n  Connected tenant verified domains: $($tenantIdentity.AllDomains -join ', ')"
    }
}

if (-not $WhatIfPreference -and -not $NonInteractive) {
    $tenantLabel = if ($tenantIdentity.DisplayName -and $tenantIdentity.DefaultDomain) {
        "$($tenantIdentity.DisplayName) ($($tenantIdentity.DefaultDomain))"
    } elseif ($tenantIdentity.DefaultDomain) {
        $tenantIdentity.DefaultDomain
    } else {
        '(unidentified tenant)'
    }
    $confirm = Read-Host "`nConfirm: deploy to '$tenantLabel'? [y/N]"
    if ($confirm -notmatch '^[yY]') {
        Write-Host "Deployment cancelled at tenant identity check." -ForegroundColor Yellow
        return
    }
}

# ---------------------------------------------------------------------------
# Run tasks in order
# ---------------------------------------------------------------------------
# Jim's PR5 feedback: wrap the entire run-tasks block in try/finally so the
# deployment summary ALWAYS prints, even when one of the modules throws a
# terminating error mid-run. Operators need to know what got done before the
# crash; losing the summary is worse than the crash itself.
$summary = [ordered]@{}
try {

if (-not $SkipTenantSettings) {
    Write-Host "`n--- [1/5] Tenant settings ---" -ForegroundColor White
    $_taskSw = [System.Diagnostics.Stopwatch]::StartNew()
    Add-RunLogEntry -Module 'Setup-TenantSettings' -Action 'Module start' -Status 'Started'
    try {
        $taskArgs = @{ Config = $config }
        if ($EnableContainerLabels) { $taskArgs['EnableContainerLabels'] = $true }
        if ($EnablePremiumAudit)    { $taskArgs['EnablePremiumAudit']    = $true; $taskArgs['PremiumAuditMailbox'] = $PremiumAuditMailbox }
        if ($NonInteractive)        { $taskArgs['NonInteractive']        = $true }
        & $tenantScript @taskArgs
        $summary['Tenant settings'] = 'OK'
        $_taskSw.Stop()
        Add-RunLogEntry -Module 'Setup-TenantSettings' -Action 'Module complete' -Status 'Succeeded' -ElapsedMs ([int]$_taskSw.ElapsedMilliseconds)
    } catch {
        $summary['Tenant settings'] = "FAILED: $($_.Exception.Message)"
        $_taskSw.Stop()
        Add-RunLogEntry -Module 'Setup-TenantSettings' -Action 'Module complete' -Status 'Failed' -ElapsedMs ([int]$_taskSw.ElapsedMilliseconds) -Detail $_.Exception.Message
        Write-Error $_
    }
} else {
    $summary['Tenant settings'] = 'Skipped'
    Add-RunLogEntry -Module 'Setup-TenantSettings' -Action 'Module' -Status 'Skipped' -Detail '-SkipTenantSettings was set'
}

if (-not $SkipLabels) {
    Write-Host "`n--- [2/5] Sensitivity labels ---" -ForegroundColor White
    $_taskSw = [System.Diagnostics.Stopwatch]::StartNew()
    Add-RunLogEntry -Module 'Setup-SensitivityLabels' -Action 'Module start' -Status 'Started'
    try {
        $taskArgs = @{ Config = $config }
        if ($AdoptExisting) { $taskArgs['AdoptExisting'] = $true }
        if ($EnableCoAuth)  { $taskArgs['EnableCoAuth']  = $true }
        & $labelsScript @taskArgs
        $summary['Sensitivity labels'] = 'OK'
        $_taskSw.Stop()
        Add-RunLogEntry -Module 'Setup-SensitivityLabels' -Action 'Module complete' -Status 'Succeeded' -ElapsedMs ([int]$_taskSw.ElapsedMilliseconds)
    } catch {
        $summary['Sensitivity labels'] = "FAILED: $($_.Exception.Message)"
        $_taskSw.Stop()
        Add-RunLogEntry -Module 'Setup-SensitivityLabels' -Action 'Module complete' -Status 'Failed' -ElapsedMs ([int]$_taskSw.ElapsedMilliseconds) -Detail $_.Exception.Message
        Write-Error $_
    }
} else {
    $summary['Sensitivity labels'] = 'Skipped'
    Add-RunLogEntry -Module 'Setup-SensitivityLabels' -Action 'Module' -Status 'Skipped' -Detail '-SkipLabels was set'
}

if (-not $SkipDLP) {
    Write-Host "`n--- [3/5] DLP policies ---" -ForegroundColor White
    $_taskSw = [System.Diagnostics.Stopwatch]::StartNew()
    Add-RunLogEntry -Module 'Setup-DLP' -Action 'Module start' -Status 'Started'
    try {
        $taskArgs = @{ Config = $config }
        if ($AdoptExisting) { $taskArgs['AdoptExisting'] = $true }
        if ($BPOnly)        { $taskArgs['BPOnly']        = $true }
        & $dlpScript @taskArgs
        $summary['DLP policies'] = 'OK'
        $_taskSw.Stop()
        Add-RunLogEntry -Module 'Setup-DLP' -Action 'Module complete' -Status 'Succeeded' -ElapsedMs ([int]$_taskSw.ElapsedMilliseconds)
    } catch {
        $summary['DLP policies'] = "FAILED: $($_.Exception.Message)"
        $_taskSw.Stop()
        Add-RunLogEntry -Module 'Setup-DLP' -Action 'Module complete' -Status 'Failed' -ElapsedMs ([int]$_taskSw.ElapsedMilliseconds) -Detail $_.Exception.Message
        Write-Error $_
    }
} else {
    $summary['DLP policies'] = 'Skipped'
    Add-RunLogEntry -Module 'Setup-DLP' -Action 'Module' -Status 'Skipped' -Detail '-SkipDLP was set'
}

if ($ApplyRetention) {
    Write-Host "`n--- [4/5] Retention ---" -ForegroundColor White
    $_taskSw = [System.Diagnostics.Stopwatch]::StartNew()
    Add-RunLogEntry -Module 'Setup-Retention' -Action 'Module start' -Status 'Started'
    try {
        $taskArgs = @{ Config = $config }
        if ($AdoptExisting) { $taskArgs['AdoptExisting'] = $true }
        & $retentionScript @taskArgs
        $summary['Retention'] = 'OK'
        $_taskSw.Stop()
        Add-RunLogEntry -Module 'Setup-Retention' -Action 'Module complete' -Status 'Succeeded' -ElapsedMs ([int]$_taskSw.ElapsedMilliseconds)
    } catch {
        $summary['Retention'] = "FAILED: $($_.Exception.Message)"
        $_taskSw.Stop()
        Add-RunLogEntry -Module 'Setup-Retention' -Action 'Module complete' -Status 'Failed' -ElapsedMs ([int]$_taskSw.ElapsedMilliseconds) -Detail $_.Exception.Message
        Write-Error $_
    }
} else {
    $summary['Retention'] = 'Skipped (opt-in — pass -ApplyRetention to enable; see docs/Retention-Default-Risk.md)'
    Add-RunLogEntry -Module 'Setup-Retention' -Action 'Module' -Status 'Skipped' -Detail '-ApplyRetention not set (opt-in)'
}

# AI governance is opt-in. Without -ApplyAIControls we still print the step
# header so the [N/5] counter is consistent and it's obvious AI controls
# exist as a knob; otherwise it's invisible to operators.
Write-Host "`n--- [5/5] AI governance (Copilot DLP) ---" -ForegroundColor White
if ($ApplyAIControls) {
    $_taskSw = [System.Diagnostics.Stopwatch]::StartNew()
    Add-RunLogEntry -Module 'Setup-AIGovernance' -Action 'Module start' -Status 'Started'
    try {
        $taskArgs = @{ Config = $config }
        if ($AdoptExisting) { $taskArgs['AdoptExisting'] = $true }
        & $aiScript @taskArgs
        $summary['AI governance'] = 'OK'
        $_taskSw.Stop()
        Add-RunLogEntry -Module 'Setup-AIGovernance' -Action 'Module complete' -Status 'Succeeded' -ElapsedMs ([int]$_taskSw.ElapsedMilliseconds)
    } catch {
        $summary['AI governance'] = "FAILED: $($_.Exception.Message)"
        $_taskSw.Stop()
        Add-RunLogEntry -Module 'Setup-AIGovernance' -Action 'Module complete' -Status 'Failed' -ElapsedMs ([int]$_taskSw.ElapsedMilliseconds) -Detail $_.Exception.Message
        Write-Error $_
    }
} else {
    Write-Host "      Skipped (-ApplyAIControls not set)." -ForegroundColor DarkGray
    Write-Host "      Re-run with -ApplyAIControls to provision Microsoft 365 Copilot DLP policies" -ForegroundColor DarkGray
    Write-Host "      defined in PurviewConfig.psd1 -> AIGovernance section."                       -ForegroundColor DarkGray
    $summary['AI governance'] = 'Skipped (-ApplyAIControls not set)'
    Add-RunLogEntry -Module 'Setup-AIGovernance' -Action 'Module' -Status 'Skipped' -Detail '-ApplyAIControls not set (opt-in)'
}

} finally {
    # ---------------------------------------------------------------------------
    # Summary (always runs — even if a task threw a terminating error above).
    # ---------------------------------------------------------------------------
    Write-Host "`n==============================================================================" -ForegroundColor Cyan
    Write-Host "  Deployment summary" -ForegroundColor Cyan
    Write-Host "==============================================================================" -ForegroundColor Cyan
    if ($summary.Count -eq 0) {
        Write-Host "  (No tasks recorded — run aborted before any step started.)" -ForegroundColor DarkYellow
    } else {
        $summary.GetEnumerator() | ForEach-Object {
            $color = switch -Wildcard ($_.Value) {
                'OK'        { 'Green' }
                'Skipped*'  { 'DarkGray' }
                'FAILED:*'  { 'Red' }
                default     { 'White' }
            }
            Write-Host ("  {0,-22} {1}" -f $_.Key, $_.Value) -ForegroundColor $color
        }
    }
    Write-Host "==============================================================================" -ForegroundColor Cyan

    Write-Host "`nReminder: sensitivity-label and DLP changes can take up to 24 hours to fully propagate." -ForegroundColor DarkYellow

    # ---------------------------------------------------------------------------
    # HTML report (Tier 1 + Tier 2) — emitted AFTER the CLI summary so a
    # renderer failure can never hide the console output. Suppress with
    # -NoReport.
    # ---------------------------------------------------------------------------
    if (-not $NoReport) {
        try {
            . (Join-Path $PSScriptRoot 'Modules\Write-PurviewHtmlReport.ps1')

            $resolvedReportPath = if ($ReportPath) {
                $ReportPath
            } else {
                # Default: drop the report in the caller's working directory
                # (where they ran the script from), NOT $PSScriptRoot. Operators
                # expect output next to where they invoked the tool, and the
                # install folder may be read-only on managed devices.
                Join-Path (Get-Location).Path ("Deploy-PurviewBestPractice-Report-{0}.html" -f $script:StartTime.ToString('yyyyMMdd-HHmmss'))
            }

            $endTime = Get-Date
            $reportRunLog = Get-PurviewRunLog

            $reportParams = @{
                Summary       = $summary
                OutputPath    = $resolvedReportPath
                StartTime     = $script:StartTime
                EndTime       = $endTime
                RunId         = $script:RunId
                Parameters    = $PSBoundParameters
                ScriptVersion = $script:DeployVersion
            }
            if ($tenantIdentity) { $reportParams['TenantIdentity'] = $tenantIdentity }
            if ($TenantAdminUpn) { $reportParams['TenantAdminUpn'] = $TenantAdminUpn }
            if ($reportRunLog -and $reportRunLog.Count -gt 0) {
                $reportParams['RunLog'] = $reportRunLog
            }

            $written = Write-PurviewHtmlReport @reportParams
            Write-Host ("`nHTML report written: {0}" -f $written) -ForegroundColor Cyan

            # JSON sidecar -- same path, .json extension. Machine-readable
            # mirror of the run log + summary, handy for auditing or for
            # piping into ticketing systems.
            try {
                $jsonPath = [System.IO.Path]::ChangeExtension($written, '.json')
                $tid = if ($tenantIdentity) { [string]$tenantIdentity.TenantId } else { '' }
                Save-PurviewRunLogJson `
                    -Path           $jsonPath `
                    -RunId          $script:RunId `
                    -StartTime      $script:StartTime `
                    -EndTime        $endTime `
                    -ScriptVersion  $script:DeployVersion `
                    -TenantId       $tid `
                    -TenantAdminUpn $TenantAdminUpn `
                    -Summary        $summary | Out-Null
                Write-Host ("JSON sidecar:       {0}" -f $jsonPath) -ForegroundColor Cyan
            } catch {
                Write-Warning ("JSON sidecar could not be written: {0}" -f $_.Exception.Message)
            }
        } catch {
            # Never throw out of the finally block — the CLI summary already
            # printed; a report failure is a usability bug, not a deploy bug.
            Write-Warning ("HTML report could not be written: {0}" -f $_.Exception.Message)
        } finally {
            # Clear $global:PurviewRunLog so it doesn't leak between runs
            # in interactive PowerShell sessions.
            try { Clear-PurviewRunLog } catch { }
        }
    }
}
