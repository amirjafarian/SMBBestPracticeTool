#requires -Version 7.0
<#
.SYNOPSIS
    Creates a Microsoft Purview retention policy for Exchange mailboxes
    (default: 2 years, retain-then-delete).

.DESCRIPTION
    Implements Priority 2 from the Microsoft 365 Business Premium Data Security
    Best Practice Deployment guide. Default scope is Exchange mailboxes; can
    be widened to SharePoint and OneDrive via the config file's
    Retention.Locations array.

    Idempotent: existing toolkit-managed objects are updated in place; foreign
    objects abort the run unless -AdoptExisting is supplied.

.PARAMETER Config
    Hashtable from PurviewConfig.psd1.

.PARAMETER AdoptExisting
    Update retention objects that already exist but are not managed by this
    toolkit.
#>
[CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'None')]
param(
    [Parameter(Mandatory)]
    [hashtable] $Config,

    [Parameter()]
    [switch] $AdoptExisting
)

$ErrorActionPreference = 'Stop'
# Auto-confirm: this toolkit is designed for unattended/scripted runs. Use -WhatIf for dry-run.
$ConfirmPreference   = 'None'

# Shared retry helper for transient IPPS errors (502, 503, 504, 429, timeouts).
. (Join-Path $PSScriptRoot 'Invoke-WithTransientRetry.ps1')

# Extract a meaningful error message from an IPPS ErrorRecord. IPPS REST cmdlets
# sometimes leave Exception.Message empty and only populate ErrorDetails or
# FullyQualifiedErrorId, so we walk through several properties in priority order.
function Format-IPPSError {
    param([Parameter(Mandatory)] $ErrorRecord)
    if (-not $ErrorRecord) { return '(no error record)' }
    $candidates = @(
        $ErrorRecord.Exception.Message,
        $ErrorRecord.ErrorDetails.Message,
        $ErrorRecord.CategoryInfo.Reason,
        $ErrorRecord.FullyQualifiedErrorId,
        $ErrorRecord.ToString()
    )
    foreach ($c in $candidates) {
        if ($c -and $c.ToString().Trim().Length -gt 0) { return $c.ToString().Trim() }
    }
    return '(IPPS returned an empty error - check Audit logs in Purview portal)'
}
$tag = $Config.ManagedByTag
$r = $Config.Retention

function Test-Owned {
    param($Object, [string] $Tag)
    if (-not $Object) { return $false }
    $desc = if ($Object.PSObject.Properties.Name -contains 'Comment') { $Object.Comment }
            elseif ($Object.PSObject.Properties.Name -contains 'Description') { $Object.Description }
            else { '' }
    return ($desc -and $desc -like "*$Tag*")
}

Write-Host "Retention policy: $($r.Name)" -ForegroundColor Cyan

# Purview enforces a 64-character maximum on policy/rule names. The IPPS
# backend rejects longer names with an empty/cryptic error, so we validate
# upfront to give partners a clear, actionable diagnostic.
if ($r.Name.Length -gt 64) {
    throw "Retention policy name '$($r.Name)' is $($r.Name.Length) characters; Microsoft Purview enforces a 64-character maximum. Edit PurviewConfig.psd1 and shorten the Retention.Name field."
}
if ($r.RuleName.Length -gt 64) {
    throw "Retention rule name '$($r.RuleName)' is $($r.RuleName.Length) characters; Microsoft Purview enforces a 64-character maximum. Edit PurviewConfig.psd1 and shorten the Retention.RuleName field."
}

# ---------------------------------------------------------------------------
# Policy
# ---------------------------------------------------------------------------
$existing = Get-RetentionCompliancePolicy -Identity $r.Name -ErrorAction SilentlyContinue
$owned = Test-Owned -Object $existing -Tag $tag

if ($existing -and -not $owned -and -not $AdoptExisting) {
    throw "Retention policy '$($r.Name)' exists but is not managed by this toolkit. Re-run with -AdoptExisting to update it."
}

$policyArgs = @{
    Name    = $r.Name
    Comment = "$tag $($r.Comment)"
}
foreach ($loc in $r.Locations) {
    switch ($loc) {
        'Exchange'   { $policyArgs['ExchangeLocation']   = 'All' }
        'SharePoint' { $policyArgs['SharePointLocation'] = 'All' }
        'OneDrive'   { $policyArgs['OneDriveLocation']   = 'All' }
        default      { Write-Warning "Unknown retention location '$loc' — skipping." }
    }
}

if (-not $existing) {
    if ($PSCmdlet.ShouldProcess($r.Name, 'New-RetentionCompliancePolicy')) {
        try {
            Invoke-WithTransientRetry -Description ("New-RetentionCompliancePolicy '$($r.Name)'") -AlreadyExistsIsSuccess -Action {
                New-RetentionCompliancePolicy @policyArgs `
                    -ErrorAction Stop -WarningAction SilentlyContinue -Confirm:$false | Out-Null
            }
            Write-Host "  + Created policy." -ForegroundColor Green
            $existing = Get-RetentionCompliancePolicy -Identity $r.Name -ErrorAction SilentlyContinue
        } catch {
            Write-Warning "  Failed to create policy '$($r.Name)': $(Format-IPPSError $_)"
            return
        }
    }
} else {
    if ($PSCmdlet.ShouldProcess($r.Name, 'Set-RetentionCompliancePolicy (comment refresh)')) {
        try {
            Invoke-WithTransientRetry -Description ("Set-RetentionCompliancePolicy '$($r.Name)'") -Action {
                Set-RetentionCompliancePolicy -Identity $r.Name -Comment $policyArgs.Comment `
                    -ErrorAction Stop -WarningAction SilentlyContinue -Confirm:$false | Out-Null
            }
            Write-Host "  ~ Updated policy comment." -ForegroundColor Yellow
        } catch {
            Write-Warning "  Failed to update policy '$($r.Name)': $(Format-IPPSError $_)"
        }
    }
}

# ---------------------------------------------------------------------------
# Rule
# ---------------------------------------------------------------------------
$existingRule = Get-RetentionComplianceRule -Identity $r.RuleName -ErrorAction SilentlyContinue
$ruleOwned = Test-Owned -Object $existingRule -Tag $tag

if ($existingRule -and -not $ruleOwned -and -not $AdoptExisting) {
    throw "Retention rule '$($r.RuleName)' exists but is not managed by this toolkit. Re-run with -AdoptExisting to update it."
}

$ruleArgs = @{
    Name                         = $r.RuleName
    Policy                       = $r.Name
    Comment                      = "$tag Retention rule"
    RetentionDuration            = $r.DurationDays
    RetentionDurationDisplayHint = $r.DurationDisplayHint
    RetentionComplianceAction    = $r.Action
    ExpirationDateOption         = $r.ExpirationDateOption
}

if (-not $existingRule) {
    if ($PSCmdlet.ShouldProcess($r.RuleName, 'New-RetentionComplianceRule')) {
        try {
            Invoke-WithTransientRetry -Description ("New-RetentionComplianceRule '$($r.RuleName)'") -AlreadyExistsIsSuccess -Action {
                New-RetentionComplianceRule @ruleArgs `
                    -ErrorAction Stop -WarningAction SilentlyContinue -Confirm:$false | Out-Null
            }
            Write-Host "  + Created rule." -ForegroundColor Green
        } catch {
            Write-Warning "  Failed to create rule '$($r.RuleName)': $(Format-IPPSError $_)"
        }
    }
} else {
    if ($existingRule.Policy -ne $r.Name) {
        Write-Warning "Rule '$($r.RuleName)' belongs to policy '$($existingRule.Policy)', not '$($r.Name)'. Skipping — retention rules cannot be moved between policies."
        Add-RunLogEntry -Module 'Setup-Retention' -Action 'Set-RetentionComplianceRule' -Target $r.RuleName -Status 'Skipped' -Detail "Rule belongs to a different policy ('$($existingRule.Policy)'); cannot move."
    } elseif ($PSCmdlet.ShouldProcess($r.RuleName, 'Set-RetentionComplianceRule (refresh)')) {
        $setArgs = @{
            Identity                     = $r.RuleName
            Comment                      = $ruleArgs.Comment
            RetentionDuration            = $r.DurationDays
            RetentionDurationDisplayHint = $r.DurationDisplayHint
            RetentionComplianceAction    = $r.Action
            ExpirationDateOption         = $r.ExpirationDateOption
        }
        try {
            Invoke-WithTransientRetry -Description ("Set-RetentionComplianceRule '$($r.RuleName)'") -Action {
                Set-RetentionComplianceRule @setArgs `
                    -ErrorAction Stop -WarningAction SilentlyContinue -Confirm:$false | Out-Null
            }
            Write-Host "  ~ Updated rule." -ForegroundColor Yellow
        } catch {
            Write-Warning "  Failed to update rule '$($r.RuleName)': $(Format-IPPSError $_)"
        }
    }
}

Write-Host "Retention policy complete." -ForegroundColor Green
