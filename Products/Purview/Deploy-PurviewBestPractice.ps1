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

.PARAMETER SkipRetention
    Skip retention policy creation.

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
    # GDAP partner-delegated scenario, skip retention
    .\Deploy-PurviewBestPractice.ps1 `
        -TenantAdminUpn partneradmin@fabrikam.onmicrosoft.com `
        -DelegatedOrganization contoso.onmicrosoft.com `
        -SkipRetention

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
    [switch] $SkipRetention,

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
    [switch] $NoLicenseAutoDetect
)

$ErrorActionPreference = 'Stop'
# Auto-confirm: this toolkit is designed for unattended/scripted runs. Use -WhatIf for dry-run.
$ConfirmPreference   = 'None'

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
$tickRetention  = if (-not $SkipRetention)      { 'X' } else { ' ' }
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
    [$tickRetention] Retention          (Exchange 2 years)
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
if ($AutoInstallModules)   { $connectArgs['AutoInstallModules']   = $true }
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
    $e5Sku = @(
        'SPE_E5','SPE_E5_NOPSTNCONF',
        'ENTERPRISEPREMIUM','ENTERPRISEPREMIUM_NOPSTNCONF',
        'INFORMATION_PROTECTION_COMPLIANCE',
        'IDENTITY_THREAT_PROTECTION',
        'M365_E5_SUITE_COMPONENTS',
        'Microsoft_Purview_Suite',
        'INFORMATION_PROTECTION_AND_GOVERNANCE'
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
        }
        'Other' {
            $skuList = if ($tier.PartNumbers) { $tier.PartNumbers -join ', ' } else { '(none)' }
            Write-Host ("  Tenant SKUs: {0}" -f $skuList) -ForegroundColor DarkGray
            Write-Host "  No E5 / Purview Suite SKU detected; container labels not auto-enabled." -ForegroundColor DarkGray
        }
        default {
            Write-Host "  Could not classify tenant license tier." -ForegroundColor DarkYellow
            if ($tier.Reason) { Write-Host "  Reason: $($tier.Reason)" -ForegroundColor DarkYellow }
            Write-Host "  Pass -EnableContainerLabels manually if eligible." -ForegroundColor DarkYellow
        }
    }
}

# ---------------------------------------------------------------------------
# Run tasks in order
# ---------------------------------------------------------------------------
$summary = [ordered]@{}

if (-not $SkipTenantSettings) {
    Write-Host "`n--- [1/5] Tenant settings ---" -ForegroundColor White
    try {
        $taskArgs = @{ Config = $config }
        if ($EnableContainerLabels) { $taskArgs['EnableContainerLabels'] = $true }
        if ($EnablePremiumAudit)    { $taskArgs['EnablePremiumAudit']    = $true; $taskArgs['PremiumAuditMailbox'] = $PremiumAuditMailbox }
        & $tenantScript @taskArgs
        $summary['Tenant settings'] = 'OK'
    } catch {
        $summary['Tenant settings'] = "FAILED: $($_.Exception.Message)"
        Write-Error $_
    }
} else {
    $summary['Tenant settings'] = 'Skipped'
}

if (-not $SkipLabels) {
    Write-Host "`n--- [2/5] Sensitivity labels ---" -ForegroundColor White
    try {
        $taskArgs = @{ Config = $config }
        if ($AdoptExisting) { $taskArgs['AdoptExisting'] = $true }
        if ($EnableCoAuth)  { $taskArgs['EnableCoAuth']  = $true }
        & $labelsScript @taskArgs
        $summary['Sensitivity labels'] = 'OK'
    } catch {
        $summary['Sensitivity labels'] = "FAILED: $($_.Exception.Message)"
        Write-Error $_
    }
} else {
    $summary['Sensitivity labels'] = 'Skipped'
}

if (-not $SkipDLP) {
    Write-Host "`n--- [3/5] DLP policies ---" -ForegroundColor White
    try {
        $taskArgs = @{ Config = $config }
        if ($AdoptExisting) { $taskArgs['AdoptExisting'] = $true }
        if ($BPOnly)        { $taskArgs['BPOnly']        = $true }
        & $dlpScript @taskArgs
        $summary['DLP policies'] = 'OK'
    } catch {
        $summary['DLP policies'] = "FAILED: $($_.Exception.Message)"
        Write-Error $_
    }
} else {
    $summary['DLP policies'] = 'Skipped'
}

if (-not $SkipRetention) {
    Write-Host "`n--- [4/5] Retention ---" -ForegroundColor White
    try {
        $taskArgs = @{ Config = $config }
        if ($AdoptExisting) { $taskArgs['AdoptExisting'] = $true }
        & $retentionScript @taskArgs
        $summary['Retention'] = 'OK'
    } catch {
        $summary['Retention'] = "FAILED: $($_.Exception.Message)"
        Write-Error $_
    }
} else {
    $summary['Retention'] = 'Skipped'
}

# AI governance is opt-in. Without -ApplyAIControls we still print the step
# header so the [N/5] counter is consistent and it's obvious AI controls
# exist as a knob; otherwise it's invisible to operators.
Write-Host "`n--- [5/5] AI governance (Copilot DLP) ---" -ForegroundColor White
if ($ApplyAIControls) {
    try {
        $taskArgs = @{ Config = $config }
        if ($AdoptExisting) { $taskArgs['AdoptExisting'] = $true }
        & $aiScript @taskArgs
        $summary['AI governance'] = 'OK'
    } catch {
        $summary['AI governance'] = "FAILED: $($_.Exception.Message)"
        Write-Error $_
    }
} else {
    Write-Host "      Skipped (-ApplyAIControls not set)." -ForegroundColor DarkGray
    Write-Host "      Re-run with -ApplyAIControls to provision Microsoft 365 Copilot DLP policies" -ForegroundColor DarkGray
    Write-Host "      defined in PurviewConfig.psd1 -> AIGovernance section."                       -ForegroundColor DarkGray
    $summary['AI governance'] = 'Skipped (-ApplyAIControls not set)'
}

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
Write-Host "`n==============================================================================" -ForegroundColor Cyan
Write-Host "  Deployment summary" -ForegroundColor Cyan
Write-Host "==============================================================================" -ForegroundColor Cyan
$summary.GetEnumerator() | ForEach-Object {
    $color = switch -Wildcard ($_.Value) {
        'OK'        { 'Green' }
        'Skipped'   { 'DarkGray' }
        'FAILED:*'  { 'Red' }
        default     { 'White' }
    }
    Write-Host ("  {0,-22} {1}" -f $_.Key, $_.Value) -ForegroundColor $color
}
Write-Host "==============================================================================" -ForegroundColor Cyan

Write-Host "`nReminder: sensitivity-label and DLP changes can take up to 24 hours to fully propagate." -ForegroundColor DarkYellow
