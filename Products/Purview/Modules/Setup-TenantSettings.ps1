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
    [string[]] $PremiumAuditMailbox
)

$ErrorActionPreference = 'Stop'
# Auto-confirm: this toolkit is designed for unattended/scripted runs. Use -WhatIf for dry-run.
$ConfirmPreference   = 'None'
$settings = $Config.TenantSettings

# ---------------------------------------------------------------------------
# Transient-error retry helper (EXO/IPPS/SPO occasionally return 5xx that
# resolve on retry — same pattern used by the cleanup script).
# ---------------------------------------------------------------------------
function Test-TransientServerError {
    param([Parameter(Mandatory)] $ErrorRecord)

    $blob = @(
        $ErrorRecord.Exception.Message,
        $ErrorRecord.ErrorDetails.Message,
        $ErrorRecord.CategoryInfo.Reason,
        $ErrorRecord.FullyQualifiedErrorId,
        $ErrorRecord.Exception.GetType().FullName
    ) -join ' '

    if ([string]::IsNullOrWhiteSpace($blob)) { return $false }

    $patterns = @(
        '\b(429|500|502|503|504)\b',
        'Service Unavailable',
        'Gateway Timeout',
        'Internal Server Error',
        'server[- ]side error',
        'could not be completed',
        'try again',
        'temporarily unavailable',
        'throttl',
        'timeout',
        'A task was canceled'
    )
    foreach ($p in $patterns) {
        if ($blob -match $p) { return $true }
    }
    return $false
}

function Invoke-WithTransientRetry {
    param(
        [Parameter(Mandatory)][scriptblock] $Action,
        [Parameter(Mandatory)][string]      $Description,
        [int] $MaxAttempts = 6,
        [int[]] $BackoffSeconds = @(5, 15, 30, 45, 60)   # ~155s total before giving up
    )

    for ($attempt = 1; $attempt -le $MaxAttempts; $attempt++) {
        try {
            & $Action
            return $true
        } catch {
            $err = $_
            $isTransient = Test-TransientServerError -ErrorRecord $err
            $isLast      = $attempt -ge $MaxAttempts
            if ($isTransient -and -not $isLast) {
                $sleep = $BackoffSeconds[[Math]::Min($attempt - 1, $BackoffSeconds.Count - 1)]
                $sleep += Get-Random -Minimum 0 -Maximum 3
                Write-Host ("      ~ Transient error on '{0}' (attempt {1}/{2}). Sleeping {3}s and retrying..." -f $Description, $attempt, $MaxAttempts, $sleep) -ForegroundColor DarkYellow
                Write-Host ("        {0}" -f $err.Exception.Message) -ForegroundColor DarkGray
                Start-Sleep -Seconds $sleep
                continue
            }
            throw
        }
    }
}

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
    } elseif ($PSCmdlet.ShouldProcess('Tenant', 'Enable Unified Audit Log ingestion')) {

        # Call the cmdlet plainly. Empirically, on some tenants any of the
        # following will cause Set-AdminAuditLogConfig to fail with a generic
        # "server side error" in-script while working when typed manually:
        #   * Piping to Out-Null
        #   * -ErrorAction SilentlyContinue
        #   * -ErrorVariable capture
        # Bare invocation works. $ErrorActionPreference='Stop' is set at the
        # top of the file, so any real failure becomes a terminating exception
        # we catch below. Post-state verification via Get-AdminAuditLogConfig
        # is unreliable (eventual consistency — can return False for several
        # minutes after a successful Set), so we trust no-exception = success.
        $auditSucceeded = $false
        try {
            Set-AdminAuditLogConfig -UnifiedAuditLogIngestionEnabled $true
            Write-Host "      Enabled (propagation can take up to 60 minutes)." -ForegroundColor Green
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
                    Set-AdminAuditLogConfig -UnifiedAuditLogIngestionEnabled $true
                    Write-Host "      Enabled (propagation can take up to 60 minutes)." -ForegroundColor Green
                    $auditSucceeded = $true
                } catch {
                    $inner = $_.Exception.Message
                    if ($inner -match 'already' -or $inner -match 'DSAlreadyExist') {
                        $orgCustomizationAttempted = $true
                        Start-Sleep -Seconds 15
                        try {
                            Set-AdminAuditLogConfig -UnifiedAuditLogIngestionEnabled $true
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
        } elseif ($PSCmdlet.ShouldProcess('SharePoint Online', 'Enable AIP integration')) {
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
            try {
                Set-SPOTenant -EnableSensitivityLabelforPDF $true -ErrorAction Stop -WarningAction SilentlyContinue
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
# ---------------------------------------------------------------------------
if ($settings.EnableLabelCoAuth) {
    Write-Host "[4/5] Label co-authoring (Set-PolicyConfig)..." -ForegroundColor Cyan
    if ($PSCmdlet.ShouldProcess('Tenant', 'Enable label co-authoring')) {
        # Set-PolicyConfig is idempotent — always safe to re-apply.
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
            New-MgBetaDirectorySetting -BodyParameter @{ templateId = $template.Id; values = $values } | Out-Null
            Write-Host "      Created with EnableMIPLabels=True." -ForegroundColor Green
        }
    } else {
        $current = ($existing.Values | Where-Object Name -EQ 'EnableMIPLabels').Value
        if ($current -eq 'True') {
            Write-Host "      Already enabled." -ForegroundColor DarkGray
        } elseif ($PSCmdlet.ShouldProcess('Group.Unified directory setting', 'Set EnableMIPLabels=True (preserving other values)')) {
            # Read-modify-write: preserve every other value the customer has set.
            $newValues = foreach ($v in $existing.Values) {
                if ($v.Name -eq 'EnableMIPLabels') {
                    @{ name = $v.Name; value = 'True' }
                } else {
                    @{ name = $v.Name; value = $v.Value }
                }
            }
            Update-MgBetaDirectorySetting -DirectorySettingId $existing.Id `
                -BodyParameter @{ values = $newValues } | Out-Null
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
                    Set-Mailbox -Identity $mbx -AuditOwner @{ Add = 'SearchQueryInitiated' }
                    Write-Host "      $mbx : enabled." -ForegroundColor Green
                }
            } catch {
                Write-Warning "Failed to enable premium audit on $mbx : $($_.Exception.Message)"
            }
        }
    }
}

Write-Host "Tenant settings complete." -ForegroundColor Green
