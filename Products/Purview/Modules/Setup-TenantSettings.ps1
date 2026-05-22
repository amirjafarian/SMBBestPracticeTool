#requires -Version 7.0
<#
.SYNOPSIS
    Applies foundational Microsoft Purview tenant settings.

.DESCRIPTION
    Configures the tenant-wide settings that must be in place before sensitivity
    labels and DLP policies can work effectively across SharePoint, OneDrive,
    Office, and Exchange.

    Settings applied (controlled by PurviewConfig.psd1 / parameters):
      * Unified Audit Log ingestion           (Set-AdminAuditLogConfig)
      * SharePoint sensitivity label support  (Set-SPOTenant -EnableAIPIntegration)
      * SharePoint PDF labelling              (Set-SPOTenant -EnableSensitivityLabelforPDF)
      * Office co-authoring with labels       (Set-PolicyConfig -EnableLabelCoauth)
      * (optional) Group/Site MIP labels      (Group.Unified directory setting)
      * (optional) Premium Audit              (SearchQueryInitiated mailbox audit)

    Idempotent: every change is preceded by a Get-* read and skipped if already
    in the desired state.

.PARAMETER Config
    Hashtable from PurviewConfig.psd1.

.PARAMETER EnableContainerLabels
    Apply Group.Unified EnableMIPLabels=True for container (group/site) labels.
    Requires Microsoft Graph (Beta) connection.

.PARAMETER EnablePremiumAudit
    Enable per-mailbox SearchQueryInitiated audit on the supplied mailbox(es).
    Requires Microsoft 365 Audit (Premium) licensing.

.PARAMETER PremiumAuditMailbox
    Mailbox UPN(s) on which to enable SearchQueryInitiated audit. Required when
    -EnablePremiumAudit is passed.
#>
[CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'None')]
param(
    [Parameter(Mandatory)]
    [hashtable] $Config,

    [Parameter()]
    [switch] $EnableContainerLabels,

    [Parameter()]
    [switch] $EnablePremiumAudit,

    [Parameter()]
    [string[]] $PremiumAuditMailbox,

    [Parameter()]
    [switch] $NonInteractive
)

$ErrorActionPreference = 'Stop'
# Auto-confirm: this toolkit is designed for unattended/scripted runs. Use -WhatIf for dry-run.
$ConfirmPreference   = 'None'
$settings = $Config.TenantSettings

# ---------------------------------------------------------------------------
# !!! DO NOT ADD -Confirm TO Set-SPOTenant CALLS — IT WILL BREAK THE RUN !!!
#
#   Set-SPOTenant (Microsoft.Online.SharePoint.PowerShell) does NOT implement
#   SupportsShouldProcess and therefore does NOT accept -Confirm. Passing
#   -Confirm:$false fails at parameter-binding time with:
#       "A parameter cannot be found that matches parameter name 'Confirm'."
#   This was previously diagnosed and fixed in May 2026 after a multi-hour
#   debug session; do not re-introduce it. Verified against MS Learn:
#   https://learn.microsoft.com/powershell/module/sharepoint-online/set-spotenant
#
#   We rely on $ConfirmPreference = 'None' above for any cmdlet that DOES
#   honour it (EXO / IPPS Set-* cmdlets). Set-SPOTenant doesn't prompt
#   interactively in module-mode either, so no -Confirm is needed.
#
# !!! DO NOT ADD `Set-PolicyConfig -EnableSpoAipMigration` AS A STEP !!!
#
#   `EnableSpoAipMigration` is an EXO/IPPS internal flag for tenants
#   MIGRATING from legacy on-premises AIP/RMS. It is NOT a prerequisite for
#   SPO sensitivity-label support and NOT a prerequisite for label
#   co-authoring (`EnableLabelCoauth`) on a normal greenfield tenant.
#   The MS Learn opt-in for SPO/ODFB labels is one cmdlet only:
#       Set-SPOTenant -EnableAIPIntegration $true
#   Ref: https://learn.microsoft.com/purview/sensitivity-labels-sharepoint-onedrive-files#use-powershell-to-enable-support-for-sensitivity-labels
#
#   A transient `SetPolicyConfigEnableLabelCoauthSpoAIpMigrationIsDisabledException`
#   on Set-PolicyConfig -EnableLabelCoauth was previously misdiagnosed (May
#   2026) as a hard prereq on EnableSpoAipMigration. It is NOT. Verified on
#   tenant m365b485722: EnableLabelCoauth=True with EnableSpoAipMigration=False.
#   Re-attempting Set-PolicyConfig -EnableSpoAipMigration alone throws
#   `SetPolicyConfigEnableSpoAipMigrationRequiresEnableLabelCoauthException`,
#   confirming the flag has its own pairing rules and is not safe to touch
#   blindly. Do not re-introduce a step that sets it.
# ---------------------------------------------------------------------------

# ---------------------------------------------------------------------------
# Transient-error retry helper - shared across all Setup-* modules (PR4).
# Defined in Modules/Invoke-WithTransientRetry.ps1; dot-sourced here so this
# module can use Invoke-WithTransientRetry + Test-TransientServerError.
# ---------------------------------------------------------------------------
. (Join-Path $PSScriptRoot 'Invoke-WithTransientRetry.ps1')

# ---------------------------------------------------------------------------
# 1. Unified Audit Log (checked & set in Exchange Online, not IPPS)
# ---------------------------------------------------------------------------
if ($settings.EnableUnifiedAuditLog) {
    Write-Host "[1/5] Unified Audit Log..." -ForegroundColor Cyan

    # Preflight: many EXO/IPPS write cmdlets (incl. Set-AdminAuditLogConfig) fail
    # with a generic 'server side error' on dehydrated tenants. Hydrate proactively.
    $orgCustomizationAttempted = $false
    try {
        $orgCfg = Get-OrganizationConfig -ErrorAction Stop
        if ($orgCfg.IsDehydrated) {
            Write-Host "      Tenant is dehydrated. Running Enable-OrganizationCustomization (one-time, ~30-60s)..." -ForegroundColor Yellow
            try {
                Enable-OrganizationCustomization -ErrorAction Stop
                $orgCustomizationAttempted = $true
                Write-Host "      Organization customization enabled. Waiting 15s for propagation..." -ForegroundColor DarkGray
                Start-Sleep -Seconds 15
            } catch {
                $inner = $_.Exception.Message
                if ($inner -match 'already' -or $inner -match 'DSAlreadyExist') {
                    $orgCustomizationAttempted = $true
                    Write-Host "      Organization customization already enabled (continuing)." -ForegroundColor DarkGray
                } else {
                    Write-Warning "      Enable-OrganizationCustomization failed during preflight: $inner"
                    Write-Warning "      Continuing — Set-* will retry the hydration if it surfaces in the error path."
                }
            }
        } else {
            Write-Host "      Tenant already hydrated (IsDehydrated=False)." -ForegroundColor DarkGray
        }
    } catch {
        Write-Warning "      Get-OrganizationConfig failed during preflight: $($_.Exception.Message). Continuing."
    }

    $audit = $null
    try {
        Invoke-WithTransientRetry -Description 'Get-AdminAuditLogConfig' -Action {
            $script:auditCfg = Get-AdminAuditLogConfig -ErrorAction Stop
        } | Out-Null
        $audit = $script:auditCfg
    } catch {
        Write-Warning "      Get-AdminAuditLogConfig failed: $($_.Exception.Message). Skipping audit-log step."
    }


    if ($null -eq $audit) {
        # already warned above
    } elseif ($audit.UnifiedAuditLogIngestionEnabled) {
        Write-Host "      Already enabled." -ForegroundColor DarkGray
        Add-RunLogEntry -Module 'Setup-TenantSettings' -Action 'UnifiedAuditLogIngestion' -Target 'Tenant' -Status 'Skipped' -Detail 'Already enabled; no action taken.'
    } elseif ($PSCmdlet.ShouldProcess('Tenant', 'Enable Unified Audit Log ingestion')) {

        # Call the cmdlet plainly. Empirically, on some tenants any of the
        # following will cause Set-AdminAuditLogConfig to fail with a generic
        # "server side error" in-script while working when typed manually:
        #   * Piping to Out-Null
        #   * -ErrorAction SilentlyContinue
        #   * -ErrorVariable capture
        # Bare invocation works. $ErrorActionPreference='Stop' is set at the
        # top of the file, so any real failure becomes a terminating exception
        # we catch below.
        $auditSucceeded = $false
        try {
            Invoke-WithTransientRetry -Description 'Set-AdminAuditLogConfig -UnifiedAuditLogIngestionEnabled' -Action {
                Set-AdminAuditLogConfig -UnifiedAuditLogIngestionEnabled $true
            }

            # Verify the write took effect. Both EXO and IPPS expose
            # Get-AdminAuditLogConfig, but only EXO exposes Set. Because the
            # toolkit connects IPPS after EXO, a bare Get can bind to the IPPS
            # session and shadow the EXO view we just wrote. Resolve Get from
            # the same module that exposes Set so verification reads the same
            # source of truth, then poll briefly for eventual consistency.
            $setCmd = Get-Command Set-AdminAuditLogConfig -ErrorAction SilentlyContinue
            $auditGetCmd = $null
            if ($setCmd) {
                $auditGetCmd = Get-Command Get-AdminAuditLogConfig -All -ErrorAction SilentlyContinue |
                    Where-Object { $_.Source -eq $setCmd.Source } |
                    Select-Object -First 1
            }
            if (-not $auditGetCmd) {
                $auditGetCmd = Get-Command Get-AdminAuditLogConfig -ErrorAction SilentlyContinue
            }

            $verifyAttempts = 5
            $auditVerified  = $false
            for ($va = 1; $va -le $verifyAttempts; $va++) {
                try {
                    $vCfg = & $auditGetCmd -ErrorAction Stop
                    if ($vCfg.UnifiedAuditLogIngestionEnabled) {
                        $auditVerified = $true
                        break
                    }
                } catch {
                    # Read failure is non-fatal here; keep polling.
                }
                if ($va -lt $verifyAttempts) {
                    Write-Host ("      Audit config not confirmed yet (attempt $va/$verifyAttempts). Waiting 5s...") -ForegroundColor DarkYellow
                    Start-Sleep -Seconds 5
                }
            }

            if ($auditVerified) {
                Write-Host "      Enabled and verified." -ForegroundColor Green
            } else {
                Write-Host "      Pending — audit configuration may still be applying (UnifiedAuditLogIngestionEnabled returned False after 20s)." -ForegroundColor Yellow
                Write-Host "      To verify: Connect-ExchangeOnline; (Get-AdminAuditLogConfig).UnifiedAuditLogIngestionEnabled" -ForegroundColor DarkGray
                Write-Host "      Expected on some tenants where EXO propagation exceeds 20s — the Set call succeeded (no exception)." -ForegroundColor DarkGray
            }
            $auditSucceeded = $true
        } catch {
            $err = $_
            $msg = if ($err.ErrorDetails -and $err.ErrorDetails.Message) {
                $err.ErrorDetails.Message
            } else {
                $err.Exception.Message
            }

            # Hydration retry: tenant not customized yet.
            if (-not $orgCustomizationAttempted -and $msg -match 'Enable-OrganizationCustomization') {
                Write-Host "      Tenant not customized yet. Running Enable-OrganizationCustomization..." -ForegroundColor Yellow
                try {
                    Enable-OrganizationCustomization -ErrorAction Stop
                    $orgCustomizationAttempted = $true
                    Write-Host "      Organization customization enabled. Retrying audit toggle..." -ForegroundColor DarkGray
                    Start-Sleep -Seconds 15
                    Invoke-WithTransientRetry -Description 'Set-AdminAuditLogConfig (post-hydration)' -Action {
                        Set-AdminAuditLogConfig -UnifiedAuditLogIngestionEnabled $true
                    }
                    Write-Host "      Enabled (propagation can take up to 60 minutes)." -ForegroundColor Green
                    $auditSucceeded = $true
                } catch {
                    $inner = $_.Exception.Message
                    if ($inner -match 'already' -or $inner -match 'DSAlreadyExist') {
                        $orgCustomizationAttempted = $true
                        Start-Sleep -Seconds 15
                        try {
                            Invoke-WithTransientRetry -Description 'Set-AdminAuditLogConfig (post-hydration, DS already exists)' -Action {
                                Set-AdminAuditLogConfig -UnifiedAuditLogIngestionEnabled $true
                            }
                            Write-Host "      Enabled (propagation can take up to 60 minutes)." -ForegroundColor Green
                            $auditSucceeded = $true
                        } catch {
                            Write-Warning "      Set-AdminAuditLogConfig failed after hydration: $($_.Exception.Message)"
                        }
                    } else {
                        Write-Warning "      Enable-OrganizationCustomization failed: $inner"
                    }
                }
            } else {
                Write-Warning "      Set-AdminAuditLogConfig failed: $msg"
            }
        }

        if (-not $auditSucceeded) {
            Write-Warning "      Manual fix:"
            Write-Warning "        1. In a fresh PowerShell window: Connect-ExchangeOnline ; Set-AdminAuditLogConfig -UnifiedAuditLogIngestionEnabled `$true"
            Write-Warning "        2. Or via the portal: https://purview.microsoft.com/audit (click 'Start recording user and admin activity')"
            Write-Warning "      Other deploy steps will continue."
        }
    }
} else {
    Write-Host "[1/5] Unified Audit Log: skipped (config disabled)." -ForegroundColor DarkGray
}

# ---------------------------------------------------------------------------
# 2. SharePoint AIP integration (sensitivity labels for SPO/ODFB)
# ---------------------------------------------------------------------------
$spoAvailable = $null -ne (Get-Command Get-SPOTenant -ErrorAction SilentlyContinue)

if ($spoAvailable -and $settings.EnableAIPIntegrationInSPO) {
    Write-Host "[2/5] SharePoint AIP integration (EnableAIPIntegration)..." -ForegroundColor Cyan
    try {
        Invoke-WithTransientRetry -Description 'Get-SPOTenant' -Action {
            $script:spoTenantState = Get-SPOTenant
        } | Out-Null
        $spoTenant = $script:spoTenantState
        if ($spoTenant.EnableAIPIntegration) {
            Write-Host "      Already enabled." -ForegroundColor DarkGray
            Add-RunLogEntry -Module 'Setup-TenantSettings' -Action 'Set-SPOTenant EnableAIPIntegration' -Target 'SharePoint Online' -Status 'Skipped' -Detail 'Already enabled; no action taken.'
        } elseif ($PSCmdlet.ShouldProcess('SharePoint Online', 'Enable AIP integration')) {
            # PR5/5f banner: tell the operator what is about to change BEFORE the
            # tenant-wide setting flip. We rely on $ConfirmPreference='None' (set
            # at the top of this file) for any cmdlet that honours -Confirm; this
            # banner ensures unattended/scripted runs are never silent about a
            # tenant-wide change.
            #
            # NOTE: Do NOT pass -Confirm:$false to Set-SPOTenant — see the big
            # warning block at the top of this file. Set-SPOTenant does not
            # implement SupportsShouldProcess.
            Write-Host "      About to change a TENANT-WIDE SharePoint setting:" -ForegroundColor Yellow
            Write-Host "        Set-SPOTenant -EnableAIPIntegration = `$true" -ForegroundColor Yellow
            Write-Host "        Effect: SharePoint Online and OneDrive for Business start honouring sensitivity" -ForegroundColor DarkGray
            Write-Host "                labels on files (auto-labelling, label-based access, downstream DLP)." -ForegroundColor DarkGray
            Write-Host "                Required for label policies to enforce on SPO/ODFB content." -ForegroundColor DarkGray
            Invoke-WithTransientRetry -Description 'Set-SPOTenant -EnableAIPIntegration' -Action {
                Set-SPOTenant -EnableAIPIntegration $true -WarningAction SilentlyContinue -ErrorAction Stop
            } | Out-Null
            Write-Host "      Enabled." -ForegroundColor Green
        }
    } catch {
        Write-Warning "      SharePoint AIP integration step failed after retries: $($_.Exception.Message)"
    }
} else {
    Write-Host "[2/5] SharePoint AIP integration: skipped." -ForegroundColor DarkGray
}

# ---------------------------------------------------------------------------
# 3. SharePoint PDF sensitivity labels
#
# NOTE: As of late 2023, EnableSensitivityLabelforPDF was removed from
# Set-SPOTenant -- PDF sensitivity-label support is now built into SPO and
# always on. Recent SPO module versions don't ship the parameter at all.
# We dynamically check whether the parameter still exists; if not, we treat
# the feature as built-in and skip cleanly.
# ---------------------------------------------------------------------------
if ($spoAvailable -and $settings.EnableSensitivityLabelForPDF) {
    Write-Host "[3/5] SharePoint PDF sensitivity labels..." -ForegroundColor Cyan

    $setSpoCmd = Get-Command Set-SPOTenant -ErrorAction SilentlyContinue
    $hasPdfParam = $false
    if ($setSpoCmd) {
        $hasPdfParam = $setSpoCmd.Parameters.ContainsKey('EnableSensitivityLabelforPDF')
    }

    if (-not $hasPdfParam) {
        Write-Host "      Built-in (parameter removed from Set-SPOTenant; PDF labels always on)." -ForegroundColor DarkGray
    } else {
        $spoTenant = Get-SPOTenant
        $current = $null
        try { $current = $spoTenant.EnableSensitivityLabelforPDF } catch { $current = $null }

        if ($current -eq $true) {
            Write-Host "      Already enabled." -ForegroundColor DarkGray
        } elseif ($PSCmdlet.ShouldProcess('SharePoint Online', 'Enable EnableSensitivityLabelforPDF')) {
            # PR5/5f banner: see comment in section [2/5] above. PDF labelling
            # is also tenant-wide and worth surfacing before the flip.
            Write-Host "      About to change a TENANT-WIDE SharePoint setting:" -ForegroundColor Yellow
            Write-Host "        Set-SPOTenant -EnableSensitivityLabelforPDF = `$true" -ForegroundColor Yellow
            Write-Host "        Effect: SharePoint Online applies sensitivity labels to PDF files (display label" -ForegroundColor DarkGray
            Write-Host "                in the SPO viewer, persist label on the PDF, honour label-based access)." -ForegroundColor DarkGray
            try {
                # NOTE: Do NOT pass -Confirm to Set-SPOTenant — see warning block
                # at the top of this file. The cmdlet does not implement
                # SupportsShouldProcess and -Confirm fails parameter binding.
                Invoke-WithTransientRetry -Description 'Set-SPOTenant -EnableSensitivityLabelforPDF' -Action {
                    Set-SPOTenant -EnableSensitivityLabelforPDF $true -ErrorAction Stop -WarningAction SilentlyContinue
                }
                Write-Host "      Enabled." -ForegroundColor Green
            } catch {
                Write-Warning "      Set-SPOTenant -EnableSensitivityLabelforPDF failed: $($_.Exception.Message). PDF labels may already be built-in for this tenant."
            }
        }
    }
} else {
    Write-Host "[3/5] SharePoint PDF labels: skipped." -ForegroundColor DarkGray
}

# ---------------------------------------------------------------------------
# 4. Office co-authoring with sensitivity labels
#
# LICENSING: NOT an E5-only feature. Co-authoring on labeled/encrypted Office
# files is part of the standard sensitivity-labels capability available in
# Microsoft 365 Business Premium, E3, E5, A3, A5, F3, AIP P1, AIP P2 (per the
# Microsoft Purview service description). That's why this step runs
# unconditionally for every tier the toolkit supports — do not add an E5/
# Purview-Suite gate here. The E5-only label feature is container labels
# (step [5/5], gated by -EnableContainerLabels), not co-authoring.
# Ref: https://learn.microsoft.com/purview/sensitivity-labels-coauthoring
# ---------------------------------------------------------------------------
if ($settings.EnableLabelCoAuth) {
    Write-Host "[4/5] Label co-authoring (Set-PolicyConfig)..." -ForegroundColor Cyan

    if ($PSCmdlet.ShouldProcess('Tenant', 'Enable label co-authoring')) {
        # Set-PolicyConfig -EnableLabelCoauth:$true is idempotent and has NO
        # prereq on EnableSpoAipMigration in a normal Business-Premium / E3 /
        # E5 tenant. See the big warning block at the top of this file —
        # EnableSpoAipMigration is a legacy on-prem AIP migration flag, not a
        # prereq for label co-authoring. Do not gate this step on it.
        #
        # -WarningAction SilentlyContinue suppresses the cosmetic
        # "command completed successfully but no settings ... have been modified"
        # warning that fires when the setting is already in the desired state.
        try {
            Invoke-WithTransientRetry -Description 'Set-PolicyConfig -EnableLabelCoauth' -Action {
                Set-PolicyConfig -EnableLabelCoauth:$true -WarningAction SilentlyContinue -ErrorAction Stop
            } | Out-Null
            Write-Host "      Enabled (idempotent re-apply)." -ForegroundColor Green
        } catch {
            Write-Warning "      Set-PolicyConfig failed after retries: $($_.Exception.Message)"
        }
    }
} else {
    Write-Host "[4/5] Label co-authoring: skipped." -ForegroundColor DarkGray
}

# ---------------------------------------------------------------------------
# 5a. (optional) Container labels — Group.Unified EnableMIPLabels
# ---------------------------------------------------------------------------
if ($EnableContainerLabels) {
    Write-Host "[5/5] Container labels (Group.Unified EnableMIPLabels)..." -ForegroundColor Cyan

    $existing = Get-MgBetaDirectorySetting -ErrorAction SilentlyContinue |
        Where-Object { $_.TemplateId -and ($_.Values.Name -contains 'EnableMIPLabels') }

    if ($null -eq $existing) {
        # Create from template, preserving template defaults for every other value.
        $template = Get-MgBetaDirectorySettingTemplate |
            Where-Object { $_.DisplayName -eq 'Group.Unified' }
        if (-not $template) { throw "Group.Unified directory setting template not found." }

        $values = foreach ($def in $template.Values) {
            if ($def.Name -eq 'EnableMIPLabels') {
                @{ name = $def.Name; value = 'True' }
            } else {
                @{ name = $def.Name; value = $def.DefaultValue }
            }
        }

        if ($PSCmdlet.ShouldProcess('Group.Unified directory setting', 'Create with EnableMIPLabels=True')) {
            Invoke-WithTransientRetry -Description 'New-MgBetaDirectorySetting Group.Unified' -AlreadyExistsIsSuccess -Action {
                New-MgBetaDirectorySetting -BodyParameter @{ templateId = $template.Id; values = $values } -ErrorAction Stop | Out-Null
            }
            Write-Host "      Created with EnableMIPLabels=True." -ForegroundColor Green
        }
    } else {
        $current = ($existing.Values | Where-Object Name -EQ 'EnableMIPLabels').Value
        if ($current -eq 'True') {
            Write-Host "      Already enabled." -ForegroundColor DarkGray
            Add-RunLogEntry -Module 'Setup-TenantSettings' -Action 'Group.Unified EnableMIPLabels' -Target 'AAD directory setting' -Status 'Skipped' -Detail 'Already True; no action taken.'
        } elseif ($PSCmdlet.ShouldProcess('Group.Unified directory setting', 'Set EnableMIPLabels=True (preserving other values)')) {
            # Read-modify-write: preserve every other value the customer has set.
            $newValues = foreach ($v in $existing.Values) {
                if ($v.Name -eq 'EnableMIPLabels') {
                    @{ name = $v.Name; value = 'True' }
                } else {
                    @{ name = $v.Name; value = $v.Value }
                }
            }
            Invoke-WithTransientRetry -Description 'Update-MgBetaDirectorySetting Group.Unified' -Action {
                Update-MgBetaDirectorySetting -DirectorySettingId $existing.Id `
                    -BodyParameter @{ values = $newValues } -ErrorAction Stop | Out-Null
            }
            Write-Host "      Set EnableMIPLabels=True (other values preserved)." -ForegroundColor Green
        }
    }
} else {
    Write-Host "[5/5] Container labels: skipped (-EnableContainerLabels not set)." -ForegroundColor DarkGray
}

# ---------------------------------------------------------------------------
# 5b. (optional) Premium Audit — SearchQueryInitiated per-mailbox
# ---------------------------------------------------------------------------
if ($EnablePremiumAudit) {
    if (-not $PremiumAuditMailbox -or $PremiumAuditMailbox.Count -eq 0) {
        Write-Warning "Premium Audit enabled but no -PremiumAuditMailbox specified. Skipping."
    } else {
        Write-Host "Premium Audit (SearchQueryInitiated) on $($PremiumAuditMailbox.Count) mailbox(es)..." -ForegroundColor Cyan
        foreach ($mbx in $PremiumAuditMailbox) {
            try {
                $existing = (Get-Mailbox -Identity $mbx).AuditOwner
                if ($existing -contains 'SearchQueryInitiated') {
                    Write-Host "      $mbx : already enabled." -ForegroundColor DarkGray
                    continue
                }
                if ($PSCmdlet.ShouldProcess($mbx, 'Add SearchQueryInitiated to AuditOwner')) {
                    Invoke-WithTransientRetry -Description ("Set-Mailbox -Identity $mbx -AuditOwner +SearchQueryInitiated") -Action {
                        Set-Mailbox -Identity $mbx -AuditOwner @{ Add = 'SearchQueryInitiated' } -ErrorAction Stop
                    }
                    Write-Host "      $mbx : enabled." -ForegroundColor Green
                }
            } catch {
                Write-Warning "Failed to enable premium audit on $mbx : $($_.Exception.Message)"
            }
        }
    }
}

Write-Host "Tenant settings complete." -ForegroundColor Green
