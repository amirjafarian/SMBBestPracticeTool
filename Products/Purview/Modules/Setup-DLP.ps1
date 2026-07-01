#requires -Version 7.0
<#
.SYNOPSIS
    Creates Microsoft Purview DLP policies that block external sharing of
    content labelled "Confidential\AllEmployees".

.DESCRIPTION
    Implements Priority 1 DLP from the Microsoft 365 Business Premium Data
    Security Best Practice Deployment guide. Per Microsoft guidance, separate
    DLP policies are created per workload:

      * Exchange policy           — blocks send to external recipients
      * SharePoint + OneDrive     — blocks external sharing/access

    Both policies match content via the SENSITIVITY LABEL GUID (resolved at
    runtime) — never by display name — so they cannot accidentally collide
    with other labels of the same name.

    Idempotent: existing toolkit-managed policies and rules are updated in
    place; foreign objects abort the run unless -AdoptExisting is supplied.

.PARAMETER Config
    Hashtable from PurviewConfig.psd1.

.PARAMETER AdoptExisting
    Update DLP policies / rules that already exist but are not managed by
    this toolkit.

.PARAMETER BPOnly
    Reject DLP workloads that require Microsoft 365 E5 / Purview Suite
    licensing (Endpoint DLP / Devices, Defender for Cloud Apps,
    OnPremisesScanner, Power BI). Used by partners deploying against
    Microsoft 365 Business Premium tenants.
#>
[CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'None')]
param(
    [Parameter(Mandatory)]
    [hashtable] $Config,

    [Parameter()]
    [switch] $AdoptExisting,

    [Parameter()]
    [switch] $BPOnly
)

$ErrorActionPreference = 'Stop'
# Auto-confirm: this toolkit is designed for unattended/scripted runs. Use -WhatIf for dry-run.
$ConfirmPreference   = 'None'

# Shared retry helper for transient IPPS / Graph errors (502, 503, 504, 429, timeouts).
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

# Workloads that require Microsoft 365 E5 / Purview Suite licensing.
# When -BPOnly is passed, any DLP policy referencing one of these is rejected.
$script:E5OnlyWorkloads = @(
    'Endpoint','Devices','EndpointDevices','EndpointDlp',
    'OnPremisesScanner','OnPremises','OnPremScanner',
    'ThirdPartyApps','DefenderForCloudApps','MCAS',
    'PowerBI'
)

function Test-Owned {
    param($Object, [string] $Tag)
    if (-not $Object) { return $false }
    $desc = if ($Object.PSObject.Properties.Name -contains 'Comment') { $Object.Comment }
            elseif ($Object.PSObject.Properties.Name -contains 'Description') { $Object.Description }
            else { '' }
    return ($desc -and $desc -like "*$Tag*")
}

function Resolve-LabelByPath {
    <#
        LabelPath is "Parent/Child" by Name. Sub-label names are unique so the
        child Name is sufficient for Get-Label, but we validate the parent to
        catch typos.

        In -WhatIf mode against a clean tenant the label may not yet exist
        because Setup-SensitivityLabels.ps1 hasn't actually created it.
        Return a synthetic preview object so the rest of the module can
        produce a complete WhatIf preview.

        Soft-delete handling: Get-Label returns soft-deleted labels
        (Mode='PendingDeletion') for ~30 days after Remove-Label. Their
        GUIDs are tombstoned and the IPPS server will reject any DLP rule
        that references them with InvalidLabelParameterNameValueException.

        When Setup-SensitivityLabels.ps1 ran first in this same deploy, it
        auto-renamed any tombstoned configured labels to '<name>-vN' and
        published a remap on $Config.LabelNameRemap. We apply that remap to
        each segment of LabelPath so 'Confidential/AllEmployees' becomes
        e.g. 'Confidential-v2/AllEmployees-v2' transparently. If a segment
        is still tombstoned after the remap (no entry was added — e.g. the
        labels module didn't run), we throw a clear error.
    #>
    param([string] $Path)
    $remap = $null
    if ($Config -and $Config.PSObject.Properties.Name -contains 'LabelNameRemap') {
        $remap = $Config.LabelNameRemap
    } elseif ($Config -is [hashtable] -and $Config.ContainsKey('LabelNameRemap')) {
        $remap = $Config['LabelNameRemap']
    }

    $parts = $Path -split '/'
    if ($remap -and $remap.Count -gt 0) {
        $remappedParts = @()
        $changed = $false
        foreach ($seg in $parts) {
            if ($remap.ContainsKey($seg)) {
                $remappedParts += $remap[$seg]
                $changed = $true
            } else {
                $remappedParts += $seg
            }
        }
        if ($changed) {
            $newPath = $remappedParts -join '/'
            Write-Host "    Label path '$Path' remapped to '$newPath' (soft-deleted tombstone bypass)." -ForegroundColor DarkYellow
            $parts = $remappedParts
            $Path  = $newPath
        }
    }

    $childName = $parts[-1]

    # Resolve WITHOUT sleeping first. Get-Label -Identity only matches
    # Name/ImmutableId/Guid, so a Path that uses our configured internal Name
    # MISSES adopted labels (Microsoft-default / wizard-created / modern-scheme)
    # whose internal Name is a 'defa4170-...' GUID. The DisplayName fallback
    # below catches those. Running both BEFORE any wait means adopted labels
    # resolve on the first pass instead of after a 45s false 'IPPS propagation'
    # loop. (See Design-Notes/2026-06-30-label-taxonomy-ms-default-adoption.md.)
    $tryResolve = {
        $hit = Get-Label -Identity $childName -ErrorAction SilentlyContinue
        if ($hit) { return $hit }
        $cfgEntry = $null
        if ($Config -and $Config.Labels) {
            foreach ($_l in $Config.Labels) {
                if ($_l.Name -eq $childName) {
                    $cfgEntry = @{ DisplayName = $_l.DisplayName; IsSub = $false; ParentName = $null; ParentDisplayName = $null; BuiltInName = $_l.BuiltInName }
                    break
                }
                if ($_l.SubLabels) {
                    foreach ($_s in $_l.SubLabels) {
                        if ($_s.Name -eq $childName) {
                            $cfgEntry = @{ DisplayName = $_s.DisplayName; IsSub = $true; ParentName = $_l.Name; ParentDisplayName = $_l.DisplayName; BuiltInName = $_s.BuiltInName }
                            break
                        }
                    }
                    if ($cfgEntry) { break }
                }
            }
        }
        if (-not $cfgEntry) { return $null }

        # Signature match (region/scheme-proof): adopt the Microsoft built-in label
        # by its 'defa4170-...' Name regardless of DisplayName localization. Try the
        # modern-scheme group form ('<id>Group') first so a parent path resolves the
        # label GROUP; fall back to the base id (leaves + classic parents).
        if ($cfgEntry.BuiltInName) {
            $sig = Get-Label -Identity ([string]$cfgEntry.BuiltInName + 'Group') -ErrorAction SilentlyContinue
            if (-not $sig) { $sig = Get-Label -Identity ([string]$cfgEntry.BuiltInName) -ErrorAction SilentlyContinue }
            if ($sig -and -not (($sig.PSObject.Properties.Name -contains 'Mode' -and $sig.Mode -eq 'PendingDeletion') -or
                                ($sig.PSObject.Properties.Name -contains 'Disabled' -and $sig.Disabled -eq $true))) {
                Write-Host "    Label '$Path' resolved by Name signature (defa4170) (Id: $($sig.Guid), Name: $($sig.Name)) — adopted built-in label." -ForegroundColor DarkYellow
                return $sig
            }
        }
        $tenantLabels = @(Get-Label -ErrorAction SilentlyContinue) | Where-Object {
            -not (($_.PSObject.Properties.Name -contains 'Mode' -and $_.Mode -eq 'PendingDeletion') -or
                  ($_.PSObject.Properties.Name -contains 'Disabled' -and $_.Disabled -eq $true))
        }
        $byDisplay = $null
        if ($cfgEntry.IsSub) {
            $parentObj = $tenantLabels | Where-Object { $_.Name -eq $cfgEntry.ParentName -and -not $_.ParentId } | Select-Object -First 1
            if (-not $parentObj) {
                $parentObj = $tenantLabels | Where-Object { $_.DisplayName -eq $cfgEntry.ParentDisplayName -and -not $_.ParentId } | Select-Object -First 1
            }
            if ($parentObj) {
                $byDisplay = $tenantLabels | Where-Object { $_.DisplayName -eq $cfgEntry.DisplayName -and $_.ParentId -eq $parentObj.Guid } | Select-Object -First 1
            }
        } else {
            $byDisplay = $tenantLabels | Where-Object { $_.DisplayName -eq $cfgEntry.DisplayName -and -not $_.ParentId } | Select-Object -First 1
        }
        if ($byDisplay) {
            Write-Host "    Label '$Path' resolved by DisplayName '$($cfgEntry.DisplayName)' (Id: $($byDisplay.Guid), Name: $($byDisplay.Name)) — adopted-existing label." -ForegroundColor DarkYellow
        }
        return $byDisplay
    }

    $child = & $tryResolve

    # Only WAIT for IPPS propagation when the label genuinely isn't visible yet
    # (e.g. a label this same apply-mode run just created). Never wait under
    # -WhatIf: nothing was created, so a wait is pure dead time.
    if (-not $child -and -not $WhatIfPreference) {
        $maxLookupAttempts = 3
        for ($la = 1; $la -le $maxLookupAttempts; $la++) {
            Write-Host ("    Label '$childName' not visible yet (IPPS propagation). Waiting 15s (attempt $la/$maxLookupAttempts)...") -ForegroundColor DarkYellow
            Start-Sleep -Seconds 15
            $child = & $tryResolve
            if ($child) { break }
        }
    }

    if ($child) {
        $isSoftDeleted = $false
        if ($child.PSObject.Properties.Name -contains 'Mode' -and $child.Mode -eq 'PendingDeletion') { $isSoftDeleted = $true }
        if ($child.PSObject.Properties.Name -contains 'Disabled' -and $child.Disabled -eq $true)    { $isSoftDeleted = $true }
        if ($isSoftDeleted) {
            throw "Sensitivity label '$Path' is soft-deleted (Mode='$($child.Mode)') and cannot be referenced by a DLP rule. Run Setup-SensitivityLabels.ps1 first (it auto-renames tombstoned labels), or wait for the ~30-day purge."
        }
        return $child
    }

    if ($WhatIfPreference) {
        Write-Host "    What if: label '$Path' does not yet exist; using a placeholder GUID for the preview (Setup-SensitivityLabels.ps1 would create it before this module runs in apply mode)." -ForegroundColor DarkYellow
        return [pscustomobject]@{
            Name        = $childName
            DisplayName = $childName
            Guid        = [guid]::Empty
            IsPreview   = $true
        }
    }

    throw "Sensitivity label '$Path' not found. Run Setup-SensitivityLabels.ps1 first."
}

foreach ($cfg in $Config.DlpPolicies) {
    Write-Host "DLP policy: $($cfg.Name)" -ForegroundColor Cyan

    # Purview enforces a 64-character maximum on policy/rule names. The IPPS
    # backend rejects longer names with an empty/cryptic error, so we
    # validate upfront to give partners a clear, actionable diagnostic.
    if ($cfg.Name.Length -gt 64) {
        throw "DLP policy name '$($cfg.Name)' is $($cfg.Name.Length) characters; Microsoft Purview enforces a 64-character maximum. Edit PurviewConfig.psd1 and shorten the Name field."
    }
    if ($cfg.RuleName.Length -gt 64) {
        throw "DLP rule name '$($cfg.RuleName)' is $($cfg.RuleName.Length) characters; Microsoft Purview enforces a 64-character maximum. Edit PurviewConfig.psd1 and shorten the RuleName field."
    }

    if ($BPOnly -and ($script:E5OnlyWorkloads -contains $cfg.Workload)) {
        # Soft-skip (warn + continue) instead of throwing. On a Business Premium
        # tenant the default PurviewConfig.psd1 still ships the Endpoint DLP
        # policy; throwing would mark the entire DLP step as FAILED and skip the
        # Exchange + SPO/ODB policies too. Soft-skip lets the BP-eligible
        # policies deploy normally and surfaces a single clear warning for the
        # workload(s) we can't create.
        Write-Warning "  Skipping DLP policy '$($cfg.Name)': workload '$($cfg.Workload)' requires Microsoft 365 E5 / Purview Suite, and -BPOnly is in effect (passed explicitly or auto-set by license detection). Remove this policy from PurviewConfig.psd1 to silence, or omit -BPOnly / -NoLicenseAutoDetect when the customer holds an E5 / Purview Suite SKU."
        continue
    }

    # -------------------------------------------------------------------
    # Resolve the label GUID(s) we will match in the DLP rule.
    # Supports either LabelPaths (array, preferred) or LabelPath (single,
    # backward-compat). Multiple labels are OR-matched at the rule level.
    # -------------------------------------------------------------------
    $labelPathList = @()
    if ($cfg.PSObject.Properties.Name -contains 'LabelPaths' -and $cfg.LabelPaths) {
        $labelPathList = @($cfg.LabelPaths)
    } elseif ($cfg.ContainsKey('LabelPaths') -and $cfg.LabelPaths) {
        $labelPathList = @($cfg.LabelPaths)
    } elseif ($cfg.LabelPath) {
        $labelPathList = @($cfg.LabelPath)
    } else {
        throw "DLP policy '$($cfg.Name)' has no LabelPath or LabelPaths configured."
    }

    $resolvedLabelGuids = @()
    $resolvedLabels     = @()  # array of @{ Name = ...; Guid = ... } for AdvancedRule JSON
    foreach ($lp in $labelPathList) {
        $resolved = Resolve-LabelByPath -Path $lp
        $g = $resolved.Guid.ToString()
        $resolvedLabelGuids += $g
        $resolvedLabels     += @{ Name = $resolved.Name; Guid = $g }
        Write-Verbose "  Resolved '$lp' to GUID $g"
    }
    if ($resolvedLabelGuids.Count -eq 0) {
        throw "DLP policy '$($cfg.Name)' resolved no labels — check LabelPaths."
    }

    # -------------------------------------------------------------------
    # Simulation mode
    # -------------------------------------------------------------------
    # When DlpStartInSimulation is $true (default) the policy is
    # provisioned with -Mode TestWithoutNotifications ("simulation
    # mode"). The UI checkbox "Turn the policy on if it's not edited
    # within fifteen days of simulation" is not exposed via PowerShell;
    # toggle it in the Purview portal if you want Purview to flip the
    # policy to Enable automatically after 15 days. Set
    # DlpStartInSimulation = $false to create the policy directly in
    # Enable mode.
    # -------------------------------------------------------------------
    $startInSim = $true
    if ($Config.PSObject.Properties.Name -contains 'DlpStartInSimulation' -and $null -ne $Config.DlpStartInSimulation) {
        $startInSim = [bool] $Config.DlpStartInSimulation
    } elseif ($Config -is [hashtable] -and $Config.ContainsKey('DlpStartInSimulation')) {
        $startInSim = [bool] $Config['DlpStartInSimulation']
    }
    $desiredMode = if ($startInSim) { 'TestWithoutNotifications' } else { 'Enable' }

    # -------------------------------------------------------------------
    # Policy
    # -------------------------------------------------------------------
    $existing = Get-DlpCompliancePolicy -Identity $cfg.Name -ErrorAction SilentlyContinue
    $owned = Test-Owned -Object $existing -Tag $tag

    if ($existing -and -not $owned) {
        Write-Host "  DLP policy '$($cfg.Name)' exists but is not tagged as toolkit-managed. Updating in place (will be re-tagged)." -ForegroundColor DarkYellow
    }

    $policyArgs = @{
        Name    = $cfg.Name
        Comment = "$tag $($cfg.Comment)"
    }
    $skipPolicy = $false
    switch ($cfg.Workload) {
        'Exchange' {
            $policyArgs['ExchangeLocation'] = 'All'
        }
        'SharePointOneDrive' {
            $policyArgs['SharePointLocation'] = 'All'
            $policyArgs['OneDriveLocation']   = 'All'
        }
        'Endpoint' {
            $endpointCmd = Get-Command New-DlpCompliancePolicy -ErrorAction SilentlyContinue
            if (-not $endpointCmd -or -not $endpointCmd.Parameters.ContainsKey('EndpointDlpLocation')) {
                Write-Warning "Skipping '$($cfg.Name)' — Endpoint DLP not available in this IPPS session (required capability/parameter missing)."
                $skipPolicy = $true
                break
            }

            # Endpoint DLP scope is the device. 'All' covers every onboarded
            # device in the tenant; narrow with EndpointDlpLocationException
            # if needed (not currently exposed in PurviewConfig).
            $policyArgs['EndpointDlpLocation'] = 'All'
        }
        default { throw "Unknown DLP workload: $($cfg.Workload)" }
    }

    if ($skipPolicy) { continue }

    if (-not $existing) {
        if ($PSCmdlet.ShouldProcess($cfg.Name, "New-DlpCompliancePolicy (-Mode $desiredMode)")) {
            try {
                Invoke-WithTransientRetry -Description ("New-DlpCompliancePolicy '$($cfg.Name)'") -AlreadyExistsIsSuccess -Action {
                    New-DlpCompliancePolicy @policyArgs -Mode $desiredMode `
                        -ErrorAction Stop -WarningAction SilentlyContinue -Confirm:$false | Out-Null
                }
                if ($desiredMode -eq 'TestWithoutNotifications') {
                    Write-Host "  + Created policy in simulation mode (Mode=TestWithoutNotifications). Toggle 'Turn the policy on if it's not edited within fifteen days of simulation' in the Purview portal to auto-enable." -ForegroundColor Green
                } else {
                    Write-Host "  + Created policy (Mode=Enable; simulation disabled by config)." -ForegroundColor Green
                }
                $existing = Get-DlpCompliancePolicy -Identity $cfg.Name -ErrorAction SilentlyContinue
            } catch {
                Write-Warning "  Failed to create policy '$($cfg.Name)': $(Format-IPPSError $_)"
                continue
            }
        }
    } else {
        $currentMode = $existing.Mode
        $setPolicyArgs = @{
            Identity = $cfg.Name
            Comment  = "$tag $($cfg.Comment)"
        }
        # Reconcile Mode against config:
        #   - DlpStartInSimulation $true  : force Mode = TestWithoutNotifications
        #     if the existing policy is in any other state (Enable / Disable /
        #     TestWithNotifications). The script is the source of truth.
        #   - DlpStartInSimulation $false : promote to Enable if the existing
        #     policy is still in simulation.
        if ($startInSim -and $currentMode -ne 'TestWithoutNotifications') {
            $setPolicyArgs['Mode'] = 'TestWithoutNotifications'
        } elseif (-not $startInSim -and $currentMode -eq 'TestWithoutNotifications') {
            $setPolicyArgs['Mode'] = 'Enable'
        }

        if ($PSCmdlet.ShouldProcess($cfg.Name, 'Set-DlpCompliancePolicy (refresh)')) {
            try {
                Invoke-WithTransientRetry -Description ("Set-DlpCompliancePolicy '$($cfg.Name)'") -Action {
                    Set-DlpCompliancePolicy @setPolicyArgs `
                        -ErrorAction Stop -WarningAction SilentlyContinue -Confirm:$false | Out-Null
                }
                if ($setPolicyArgs.ContainsKey('Mode')) {
                    $newMode = $setPolicyArgs['Mode']
                    Write-Host "  ~ Updated policy and flipped Mode '$currentMode' -> '$newMode' (config-driven)." -ForegroundColor Green
                    Add-RunLogEntry -Module 'Setup-DLP' -Action 'Set-DlpCompliancePolicy (Mode flip)' -Target $cfg.Name -Status 'Updated' -Detail "Mode: $currentMode -> $newMode"
                    if ($newMode -eq 'TestWithoutNotifications') {
                        Write-Host "    Toggle 'Turn the policy on if it's not edited within fifteen days of simulation' in the Purview portal to auto-enable." -ForegroundColor DarkGray
                    }
                } else {
                    Write-Host "  ~ Updated policy (Mode=$currentMode unchanged — already in sync with config)." -ForegroundColor Yellow
                    Add-RunLogEntry -Module 'Setup-DLP' -Action 'Set-DlpCompliancePolicy' -Target $cfg.Name -Status 'Updated' -Detail "Mode=$currentMode unchanged (already in sync)."
                }
            } catch {
                Write-Warning "  Failed to update policy '$($cfg.Name)': $(Format-IPPSError $_)"
            }
        }
    }

    # -------------------------------------------------------------------
    # Rule
    # -------------------------------------------------------------------
    # Build OR-matched label list for the rule. Within a single group,
    # operator='Or' means "any of these labels triggers the rule".
    $labelMatches = @()
    foreach ($g in $resolvedLabelGuids) {
        $labelMatches += @{ name = $g; type = 'Sensitivity' }
    }
    $contentMatch = @{
        operator = 'And'
        groups   = @(
            @{
                operator = 'Or'
                name     = 'Default'
                labels   = $labelMatches
            }
        )
    }

    $existingRule = Get-DlpComplianceRule -Identity $cfg.RuleName -ErrorAction SilentlyContinue
    $ruleOwned = Test-Owned -Object $existingRule -Tag $tag

    if ($existingRule -and -not $ruleOwned) {
        Write-Host "  DLP rule '$($cfg.RuleName)' exists but is not tagged as toolkit-managed. Updating in place (will be re-tagged)." -ForegroundColor DarkYellow
    }

    if ($cfg.Workload -eq 'Endpoint') {
        # ---------------------------------------------------------------
        # Endpoint DLP rule.
        # The Purview portal stores Endpoint sensitivity-label conditions
        # as -AdvancedRule JSON (NOT -ContentContainsSensitiveInformation).
        # The schema below mirrors what the portal emits and what the
        # IPPS backend persists in `AdvancedRule` on the rule object.
        # ---------------------------------------------------------------
        $advLabels = @()
        foreach ($lbl in $resolvedLabels) {
            $advLabels += [ordered]@{
                Name = $lbl.Name
                Id   = $lbl.Guid
                Type = 'Sensitivity'
            }
        }
        $advancedRule = [ordered]@{
            Version   = '1.0'
            Condition = [ordered]@{
                Operator     = 'And'
                SubConditions = @(
                    [ordered]@{
                        ConditionName = 'ContentContainsSensitiveInformation'
                        Value = @(
                            [ordered]@{
                                Groups = @(
                                    [ordered]@{
                                        Name     = 'Default'
                                        Operator = 'Or'
                                        Labels   = $advLabels
                                    }
                                )
                                Operator = 'And'
                            }
                        )
                    }
                )
            }
        }
        $advancedRuleJson = $advancedRule | ConvertTo-Json -Depth 20

        # Endpoint device-action restrictions: pass-through from config.
        # Microsoft's schema requires keys 'Setting' and 'Value' (case-
        # sensitive). We accept either 'Value' (correct) or 'Action' (a
        # common mistake) and normalise to 'Value' before sending.
        $endpointRestrictions = @()
        if ($cfg.EndpointDlpRestrictions) {
            foreach ($r in $cfg.EndpointDlpRestrictions) {
                $setting = $null
                $value   = $null
                if ($r -is [hashtable]) {
                    if ($r.ContainsKey('Setting'))                                { $setting = $r['Setting'] }
                    if ($r.ContainsKey('Value'))                                  { $value   = $r['Value'] }
                    elseif ($r.ContainsKey('Action'))                             { $value   = $r['Action'] }
                } else {
                    if ($r.PSObject.Properties.Name -contains 'Setting')          { $setting = $r.Setting }
                    if ($r.PSObject.Properties.Name -contains 'Value')            { $value   = $r.Value }
                    elseif ($r.PSObject.Properties.Name -contains 'Action')       { $value   = $r.Action }
                }
                if (-not $setting -or -not $value) {
                    Write-Warning "  EndpointDlpRestrictions entry missing Setting/Value — skipping: $($r | ConvertTo-Json -Compress -Depth 4)"
                    continue
                }
                $endpointRestrictions += @{ Setting = [string]$setting; Value = [string]$value }
            }
        }

        $ruleArgs = @{
            Name                    = $cfg.RuleName
            Policy                  = $cfg.Name
            Comment                 = "$tag DLP rule for Endpoint."
            AdvancedRule            = $advancedRuleJson
            EndpointDlpRestrictions = $endpointRestrictions
        }
        if ($cfg.PSObject.Properties.Name -contains 'EnforcePortalAccess' -and $null -ne $cfg.EnforcePortalAccess) {
            $ruleArgs['EnforcePortalAccess'] = [bool] $cfg.EnforcePortalAccess
        } elseif ($cfg -is [hashtable] -and $cfg.ContainsKey('EnforcePortalAccess')) {
            $ruleArgs['EnforcePortalAccess'] = [bool] $cfg['EnforcePortalAccess']
        }
        if ($cfg.ReportSeverityLevel) { $ruleArgs['ReportSeverityLevel'] = $cfg.ReportSeverityLevel }
        if ($null -ne $cfg.GenerateAlert) { $ruleArgs['GenerateAlert'] = [bool] $cfg.GenerateAlert }
        if ($cfg.NotifyUser)             { $ruleArgs['NotifyUser']             = $cfg.NotifyUser }
        if ($cfg.GenerateIncidentReport) { $ruleArgs['GenerateIncidentReport'] = $cfg.GenerateIncidentReport }
    } else {
        $ruleArgs = @{
            Name                          = $cfg.RuleName
            Policy                        = $cfg.Name
            Comment                       = "$tag DLP rule for $($cfg.Workload)."
            ContentContainsSensitiveInformation = $contentMatch
            BlockAccess                   = $cfg.BlockAccess
            BlockAccessScope              = $cfg.BlockAccessScope
            NotifyUser                    = $cfg.NotifyUser
            GenerateIncidentReport        = $cfg.GenerateIncidentReport
        }

        # Workload-specific "external recipient / external sharing" condition
        if ($cfg.Workload -eq 'Exchange') {
            # Block only when sent OUTSIDE the organisation
            $ruleArgs['AccessScope'] = 'NotInOrganization'
        } elseif ($cfg.Workload -eq 'SharePointOneDrive') {
            # Block external (anonymous + guest) access to the labelled file.
            # BlockAccessScope is taken from config ('All' | 'PerUser' | 'PerAnonymousUser').
            $ruleArgs['AccessScope']   = 'NotInOrganization'
        }
    }

    if (-not $existingRule) {
        if ($PSCmdlet.ShouldProcess($cfg.RuleName, 'New-DlpComplianceRule')) {
            try {
                Invoke-WithTransientRetry -Description ("New-DlpComplianceRule '$($cfg.RuleName)'") -AlreadyExistsIsSuccess -Action {
                    New-DlpComplianceRule @ruleArgs `
                        -ErrorAction Stop -WarningAction SilentlyContinue -Confirm:$false | Out-Null
                }
                Write-Host "  + Created rule." -ForegroundColor Green
            } catch {
                Write-Warning "  Failed to create rule '$($cfg.RuleName)': $(Format-IPPSError $_)"
            }
        }
    } else {
        if ($existingRule.ParentPolicyName -ne $cfg.Name) {
            Write-Warning "Rule '$($cfg.RuleName)' belongs to policy '$($existingRule.ParentPolicyName)', not '$($cfg.Name)'. Skipping update — DLP rules cannot be moved between policies."
            continue
        }
        if ($PSCmdlet.ShouldProcess($cfg.RuleName, 'Set-DlpComplianceRule (refresh conditions/actions)')) {
            if ($cfg.Workload -eq 'Endpoint') {
                $setArgs = @{
                    Identity                = $cfg.RuleName
                    Comment                 = $ruleArgs.Comment
                    AdvancedRule            = $ruleArgs.AdvancedRule
                    EndpointDlpRestrictions = $ruleArgs.EndpointDlpRestrictions
                }
                foreach ($k in 'EnforcePortalAccess','ReportSeverityLevel','GenerateAlert','NotifyUser','GenerateIncidentReport') {
                    if ($ruleArgs.ContainsKey($k)) { $setArgs[$k] = $ruleArgs[$k] }
                }
            } else {
                $setArgs = @{
                    Identity = $cfg.RuleName
                    Comment  = $ruleArgs.Comment
                    ContentContainsSensitiveInformation = $contentMatch
                    BlockAccess      = $cfg.BlockAccess
                    BlockAccessScope = $ruleArgs.BlockAccessScope
                    NotifyUser       = $cfg.NotifyUser
                    GenerateIncidentReport = $cfg.GenerateIncidentReport
                    AccessScope      = $ruleArgs.AccessScope
                }
            }
            try {
                Invoke-WithTransientRetry -Description ("Set-DlpComplianceRule '$($cfg.RuleName)'") -Action {
                    Set-DlpComplianceRule @setArgs `
                        -ErrorAction Stop -WarningAction SilentlyContinue -Confirm:$false | Out-Null
                }
                Write-Host "  ~ Updated rule." -ForegroundColor Yellow
            } catch {
                Write-Warning "  Failed to update rule '$($cfg.RuleName)': $(Format-IPPSError $_)"
            }
        }
    }
}

Write-Host "DLP policies complete." -ForegroundColor Green
Write-Host "NOTE: DLP policy changes can take up to an hour to begin enforcement." -ForegroundColor DarkYellow
