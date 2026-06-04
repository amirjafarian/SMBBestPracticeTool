#requires -Version 7.0
<#
.SYNOPSIS
    Creates Microsoft Purview DLP policies that govern AI interactions
    (Microsoft 365 Copilot and Agent 365).

.DESCRIPTION
    AI governance policies live in their own toolkit category because:

      * They use a different cmdlet shape than channel-based DLP. Per the
        official documentation for New-DlpCompliancePolicy / New-DlpComplianceRule,
        Copilot DLP requires the new -Locations JSON parameter, the
        -EnforcementPlanes parameter, an -AdvancedRule body, and
        -RestrictAccess action — none of which apply to legacy
        Exchange / SPO / OneDrive DLP.
      * They are license-tier gated. The policy plane is part of E5 /
        Purview Suite, so Setup-AIGovernance auto-skips when called with
        -BPOnly. Note: the policy enforces against both paid Microsoft
        365 Copilot AND the free Microsoft 365 Copilot Chat experience
        (see https://learn.microsoft.com/purview/dlp-microsoft365-copilot-location-learn-about),
        so creation succeeds on E5 / Purview Suite tenants regardless
        of whether paid Copilot per-user SKUs are present.
      * They are default-on. The deploy script provisions them by default;
        pass -SkipAIControls to opt out.
      * Future "AI" controls (DSPM-for-AI assessments, agent governance,
        prompt policies) plug into the same AIGovernance.DlpPolicies array.

    Currently implemented controls:

      AI_054  Block Microsoft 365 Copilot from processing content bearing
              specific sensitivity labels (default: 'Highly Confidential').
              https://microsoft.github.io/zerotrustassessment/docs/workshop-guidance/AI/AI_054

    Idempotent: existing toolkit-managed policies and rules are updated in
    place; foreign objects abort the run unless -AdoptExisting is supplied.

.PARAMETER Config
    Hashtable from PurviewConfig.psd1.

.PARAMETER AdoptExisting
    Update AI DLP policies / rules that already exist but are not managed
    by this toolkit.

.PARAMETER BPOnly
    Skip immediately with an "E5 / Purview Suite required" summary entry.
    The orchestrator already gates the AI step on -BPOnly, but the module
    honours the switch independently so direct callers (test harnesses,
    ad-hoc reruns, downstream automation) get the same protection without
    needing to know the license rules.

.NOTES
    Run AFTER Setup-SensitivityLabels.ps1 in the same deploy invocation so
    that label name resolution (and the soft-delete tombstone remap) is
    consistent. Ordering is enforced by Deploy-PurviewBestPractice.ps1.
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

# Shared retry helper for transient IPPS errors (502, 503, 504, 429, timeouts).
. (Join-Path $PSScriptRoot 'Invoke-WithTransientRetry.ps1')

if ($BPOnly) {
    # Module-side defense-in-depth: the orchestrator already gates this step
    # on -BPOnly, but direct callers (ad-hoc reruns, test harnesses) get
    # the same guarantee here without needing to know the license rules.
    Write-Host "AI governance skipped: -BPOnly was set. Microsoft 365 Copilot DLP policies require Microsoft 365 E5 / Purview Suite (the policy plane is not available on Business Premium)." -ForegroundColor Yellow
    return
}

if (-not $Config.AIGovernance) {
    Write-Host "AIGovernance section not present in PurviewConfig.psd1; nothing to do." -ForegroundColor DarkGray
    return
}
if (-not $Config.AIGovernance.DlpPolicies -or $Config.AIGovernance.DlpPolicies.Count -eq 0) {
    Write-Host "AIGovernance.DlpPolicies is empty; nothing to do." -ForegroundColor DarkGray
    return
}

$tag = $Config.ManagedByTag

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
        Same logic as Setup-DLP.ps1 Resolve-LabelByPath (kept inline here so
        the AI module can run standalone). Honours $Config.LabelNameRemap
        published by Setup-SensitivityLabels.ps1 when soft-deleted labels
        were auto-renamed (e.g. 'HighlyConfidential' -> 'HighlyConfidential-v2').
    #>
    param([string] $Path)

    $remap = $null
    if ($Config -is [hashtable] -and $Config.ContainsKey('LabelNameRemap')) {
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
    $child = $null
    $maxLookupAttempts = 4
    for ($la = 1; $la -le $maxLookupAttempts; $la++) {
        $child = Get-Label -Identity $childName -ErrorAction SilentlyContinue
        if ($child) { break }
        if ($la -lt $maxLookupAttempts) {
            Write-Host ("    Label '$childName' not visible yet (IPPS propagation). Waiting 15s (attempt $la/$maxLookupAttempts)...") -ForegroundColor DarkYellow
            Start-Sleep -Seconds 15
        }
    }
    if ($child) {
        $isSoftDeleted = $false
        if ($child.PSObject.Properties.Name -contains 'Mode' -and $child.Mode -eq 'PendingDeletion') { $isSoftDeleted = $true }
        if ($child.PSObject.Properties.Name -contains 'Disabled' -and $child.Disabled -eq $true)    { $isSoftDeleted = $true }
        if ($isSoftDeleted) {
            throw "Sensitivity label '$Path' is soft-deleted (Mode='$($child.Mode)') and cannot be referenced by an AI DLP rule. Run Setup-SensitivityLabels.ps1 first (it auto-renames tombstoned labels) or wait for the ~30-day purge."
        }
        return $child
    }

    # DisplayName fallback. Setup-SensitivityLabels.ps1 matches pre-existing
    # labels by DisplayName (so a tenant where MOD Admin pre-created
    # 'Highly Confidential' is left in place with a different internal Name).
    # Get-Label -Identity only resolves Name/ImmutableId/Guid, so a Path that
    # uses our configured internal Name will miss those adopted labels. Look
    # up the configured DisplayName and search by that.
    $cfgEntry = $null
    if ($Config -and $Config.Labels) {
        foreach ($_l in $Config.Labels) {
            if ($_l.Name -eq $childName) {
                $cfgEntry = @{ DisplayName = $_l.DisplayName; IsSub = $false; ParentName = $null; ParentDisplayName = $null }
                break
            }
            if ($_l.SubLabels) {
                foreach ($_s in $_l.SubLabels) {
                    if ($_s.Name -eq $childName) {
                        $cfgEntry = @{ DisplayName = $_s.DisplayName; IsSub = $true; ParentName = $_l.Name; ParentDisplayName = $_l.DisplayName }
                        break
                    }
                }
                if ($cfgEntry) { break }
            }
        }
    }
    if ($cfgEntry) {
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
            Add-RunLogEntry -Module 'Setup-AIGovernance' -Action 'Resolve label path' -Target $Path -Status 'Adopted' -Detail "Matched by DisplayName '$($cfgEntry.DisplayName)' -> existing GUID $($byDisplay.Guid)."
            return $byDisplay
        }
    }

    if ($WhatIfPreference) {
        Write-Host "    What if: label '$Path' does not yet exist; using a placeholder GUID for the preview." -ForegroundColor DarkYellow
        return [pscustomobject]@{
            Name        = $childName
            DisplayName = $childName
            Guid        = [guid]::Empty
            IsPreview   = $true
        }
    }

    throw "Sensitivity label '$Path' not found. Run Setup-SensitivityLabels.ps1 first."
}

function ConvertTo-LocationsJson {
    <#
        Convert the Locations hashtable array from PurviewConfig.psd1 into
        the JSON string shape that New-DlpCompliancePolicy -Locations expects.
        Per Microsoft Learn the value is a JSON array of:
          { Workload, Location, Inclusions=[{Type,Identity}], Exclusions=[...] }

        Note: PowerShell's ConvertTo-Json collapses a single-element array to
        a JSON object (not [{...}] but {...}). The IPPS deserialiser then
        rejects it with "type requires a JSON array". We force-wrap when the
        input has exactly one element.
    #>
    param([Parameter(Mandatory)] [array] $Locations)

    $list = @()
    foreach ($loc in $Locations) {
        $entry = [ordered]@{
            Workload   = $loc.Workload
            Location   = $loc.Location
            Inclusions = @()
        }
        foreach ($inc in @($loc.Inclusions)) {
            if ($inc) { $entry.Inclusions += [ordered]@{ Type = $inc.Type; Identity = $inc.Identity } }
        }
        if ($loc.Exclusions) {
            $entry['Exclusions'] = @()
            foreach ($exc in @($loc.Exclusions)) {
                if ($exc) { $entry.Exclusions += [ordered]@{ Type = $exc.Type; Identity = $exc.Identity } }
            }
        }
        $list += $entry
    }
    $json = $list | ConvertTo-Json -Depth 10 -Compress
    if ($list.Count -le 1 -and -not $json.StartsWith('[')) {
        $json = "[$json]"
    }
    return $json
}

function ConvertTo-PurviewJsonString {
    <#
        Escapes a string so it is safe to drop INSIDE a JSON string literal
        (i.e. between the surrounding double-quotes) per RFC 8259 section 7.

        We assemble the AdvancedRule JSON by hand (see Build-CopilotAdvancedRuleJson
        for the long explanation of why) rather than via ConvertTo-Json. Hand
        assembly means we are responsible for escaping any character that would
        otherwise break the JSON parse — a sensitivity label called
            Acme "Confidential" Tier
        or a tenant that uses a backslash in a custom display name would
        produce malformed JSON without this helper, causing
        New-DlpComplianceRule to fail with a cryptic IPPS deserialiser error.

        Returns the inner content only (no surrounding double-quotes).
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyString()]
        [string] $Value
    )

    $sb = [System.Text.StringBuilder]::new($Value.Length + 8)
    foreach ($ch in $Value.ToCharArray()) {
        $code = [int]$ch
        # Compare by Unicode code-point so PowerShell escape-sequence ambiguity
        # (`b is backspace, `a is BEL, etc.) cannot accidentally collapse two
        # control chars onto the same switch case.
        switch ($code) {
            8  { [void]$sb.Append('\b'); break }   # backspace
            9  { [void]$sb.Append('\t'); break }   # tab
            10 { [void]$sb.Append('\n'); break }   # line feed
            12 { [void]$sb.Append('\f'); break }   # form feed
            13 { [void]$sb.Append('\r'); break }   # carriage return
            34 { [void]$sb.Append('\"'); break }   # double-quote
            92 { [void]$sb.Append('\\'); break }   # backslash
            default {
                if ($code -lt 0x20) {
                    # Any other C0 control char — escape as \u00XX.
                    [void]$sb.AppendFormat('\u{0:x4}', $code)
                } else {
                    [void]$sb.Append($ch)
                }
            }
        }
    }
    return $sb.ToString()
}

function Build-CopilotAdvancedRuleJson {
    <#
        Build the AdvancedRule JSON body for a Copilot/Application-location DLP
        rule that matches on sensitivity labels and triggers RestrictAccess.

        Why this shape:
          The Microsoft Learn snippet on the New-DlpCompliancePolicy doc page
          shows lowercase keys ('groups', 'labels', 'name', 'type') and a
          label entry of just { name = GUID; type = 'Sensitivity' }. The
          IPPS engine accepts that shape and stores it verbatim, BUT the
          Purview UI rule-edit wizard cannot parse it -- the "Customize
          advanced DLP rules" page renders an empty rule list ("0 items /
          No rules created"), even though the rule exists and is
          enforceable.

          When you create the same rule via the UI, the engine stores it in
          PascalCase with a richer label entry that includes BOTH the
          display name and the GUID:

            "Labels": [
              { "Name": "<displayName>", "Id": "<guid>", "Type": "Sensitivity" }
            ]

          That is the shape the UI parser knows how to render. We mirror it
          exactly so script-created rules show up in the same wizard UI
          that admins use to inspect / hand-edit the policy.

        Resulting JSON:
          {
            "Version": "1.0",
            "Condition": {
              "Operator": "And",
              "SubConditions": [
                {
                  "ConditionName": "ContentContainsSensitiveInformation",
                  "Value": [
                    {
                      "Groups": [
                        {
                          "Name": "Default",
                          "Operator": "Or",
                          "Labels": [
                            { "Name": "<displayName>", "Id": "<guid>", "Type": "Sensitivity" }
                          ]
                        }
                      ],
                      "Operator": "And"
                    }
                  ]
                }
              ]
            }
          }

        We assemble the JSON as a string rather than via ConvertTo-Json to
        guarantee exact casing, property order, and array shape --
        ConvertTo-Json has repeatedly proven unreliable for single-element
        arrays here.
    #>
    param(
        [Parameter(Mandatory)]
        # Each entry must be a [pscustomobject] / hashtable with at minimum:
        #   .Name  - sensitivity label display name (post-tombstone-bump value)
        #   .Guid  - sensitivity label GUID (string or [guid])
        [array] $Labels
    )

    if (-not $Labels -or $Labels.Count -eq 0) {
        throw "Build-CopilotAdvancedRuleJson: at least one label must be supplied."
    }

    $labelLines = @()
    foreach ($l in $Labels) {
        if (-not $l.Name -or -not $l.Guid) {
            throw "Build-CopilotAdvancedRuleJson: label entry missing Name or Guid."
        }
        # PR5/5a: escape Name + Guid before string-concatenating into JSON. Labels
        # named with quotes, backslashes, or control chars used to produce invalid
        # JSON that the IPPS engine rejected with a cryptic deserialiser error.
        $nameEsc = ConvertTo-PurviewJsonString -Value ([string]$l.Name)
        $guidEsc = ConvertTo-PurviewJsonString -Value ([string]$l.Guid)
        $labelLines += "                          { ""Name"": ""$nameEsc"", ""Id"": ""$guidEsc"", ""Type"": ""Sensitivity"" }"
    }
    $labelsBlock = $labelLines -join ",`n"

    return @"
{
  "Version": "1.0",
  "Condition": {
    "Operator": "And",
    "SubConditions": [
      {
        "ConditionName": "ContentContainsSensitiveInformation",
        "Value": [
          {
            "Groups": [
              {
                "Name": "Default",
                "Operator": "Or",
                "Labels": [
$labelsBlock
                ]
              }
            ],
            "Operator": "And"
          }
        ]
      }
    ]
  }
}
"@
}

# ---------------------------------------------------------------------------
# Sanity-check: are the Copilot DLP parameters available on this tenant's
# IPPS endpoint? -EnforcementPlanes and -Locations were added in 2024;
# older module versions silently ignore them, which would create a broken
# policy. Bail clearly if the parameter is missing.
# ---------------------------------------------------------------------------
$policyCmd = Get-Command New-DlpCompliancePolicy -ErrorAction SilentlyContinue
if (-not $policyCmd) {
    throw "New-DlpCompliancePolicy is not available. Connect to Security & Compliance (IPPS) first."
}
if (-not $policyCmd.Parameters.ContainsKey('Locations') -or -not $policyCmd.Parameters.ContainsKey('EnforcementPlanes')) {
    throw "Your ExchangeOnlineManagement / IPPS module does not expose the Copilot DLP parameters (-Locations / -EnforcementPlanes). Update the module: Update-Module ExchangeOnlineManagement"
}

foreach ($cfg in $Config.AIGovernance.DlpPolicies) {
    Write-Host "AI policy: $($cfg.Name)" -ForegroundColor Cyan

    if ($cfg.Name.Length -gt 64) {
        throw "AI DLP policy name '$($cfg.Name)' is $($cfg.Name.Length) characters; Microsoft Purview enforces a 64-character maximum. Edit PurviewConfig.psd1 and shorten the Name field."
    }
    if ($cfg.RuleName.Length -gt 64) {
        throw "AI DLP rule name '$($cfg.RuleName)' is $($cfg.RuleName.Length) characters; Microsoft Purview enforces a 64-character maximum. Edit PurviewConfig.psd1 and shorten the RuleName field."
    }

    # -------------------------------------------------------------------
    # Resolve labels we will block in the rule (need both Name and GUID:
    # the AdvancedRule JSON shape that the Purview UI rule-edit wizard
    # parses correctly carries both -- see Build-CopilotAdvancedRuleJson).
    # -------------------------------------------------------------------
    $labelPaths = @($cfg.LabelPaths)
    if (-not $labelPaths -or $labelPaths.Count -eq 0) {
        throw "AI DLP policy '$($cfg.Name)' has no LabelPaths configured. Add at least one parent or parent/child path."
    }
    $labelInfos = @()
    foreach ($lp in $labelPaths) {
        $lbl = Resolve-LabelByPath -Path $lp
        $labelInfos += [pscustomobject]@{
            Name = $lbl.Name
            Guid = $lbl.Guid.ToString()
        }
        Write-Verbose "  Resolved '$lp' to '$($lbl.Name)' ($($lbl.Guid))"
    }

    # -------------------------------------------------------------------
    # Policy
    # -------------------------------------------------------------------
    $existing = Get-DlpCompliancePolicy -Identity $cfg.Name -ErrorAction SilentlyContinue
    $owned    = Test-Owned -Object $existing -Tag $tag

    if ($existing -and -not $owned) {
        Write-Host "  AI DLP policy '$($cfg.Name)' exists but is not tagged as toolkit-managed. Updating in place (will be re-tagged)." -ForegroundColor DarkYellow
    }

    $locationsJson = ConvertTo-LocationsJson -Locations $cfg.Locations
    Write-Verbose "  Locations JSON: $locationsJson"

    # Mode resolution:
    #   - The toolkit-wide `DlpStartInSimulation` flag (PurviewConfig.psd1)
    #     forces ALL DLP policies — including AI/Copilot — into simulation
    #     mode (TestWithoutNotifications) when $true. This is the SMB
    #     deploy default so partners can verify scope before enforcement.
    #   - Set `DlpStartInSimulation = $false` to honour the per-policy
    #     `Mode` setting from this config block (defaults to 'Enable').
    $startInSim = $true
    if ($Config.PSObject.Properties.Name -contains 'DlpStartInSimulation' -and $null -ne $Config.DlpStartInSimulation) {
        $startInSim = [bool] $Config.DlpStartInSimulation
    } elseif ($Config -is [hashtable] -and $Config.ContainsKey('DlpStartInSimulation')) {
        $startInSim = [bool] $Config['DlpStartInSimulation']
    }
    if ($startInSim) {
        $mode = 'TestWithoutNotifications'
    } else {
        $mode = if ($cfg.Mode) { $cfg.Mode } else { 'Enable' }
    }

    if (-not $existing) {
        if ($PSCmdlet.ShouldProcess($cfg.Name, "New-DlpCompliancePolicy (Copilot, -Mode $mode)")) {
            try {
                Invoke-WithTransientRetry -Description ("New-DlpCompliancePolicy (Copilot) '$($cfg.Name)'") -AlreadyExistsIsSuccess -Action {
                    New-DlpCompliancePolicy `
                        -Name              $cfg.Name `
                        -Comment           "$tag $($cfg.Comment)" `
                        -Locations         $locationsJson `
                        -EnforcementPlanes $cfg.EnforcementPlanes `
                        -Mode              $mode `
                        -ErrorAction Stop -WarningAction SilentlyContinue -Confirm:$false | Out-Null
                }
                if ($mode -eq 'TestWithoutNotifications') {
                    Write-Host "  + Created Copilot DLP policy in simulation mode (Mode=TestWithoutNotifications). Toggle 'Turn the policy on if it's not edited within fifteen days of simulation' in the Purview portal to auto-enable." -ForegroundColor Green
                } else {
                    Write-Host "  + Created Copilot DLP policy (Mode=$mode)." -ForegroundColor Green
                }
                $existing = Get-DlpCompliancePolicy -Identity $cfg.Name -ErrorAction SilentlyContinue
            } catch {
                Write-Warning "  Failed to create AI policy '$($cfg.Name)': $(Format-IPPSError $_)"
                continue
            }
        }
    } else {
        $currentMode = $existing.Mode
        $setArgs = @{
            Identity         = $cfg.Name
            Comment          = "$tag $($cfg.Comment)"
            Locations        = $locationsJson
            EnforcementPlanes = $cfg.EnforcementPlanes
        }
        # Reconcile Mode against config (mirrors Setup-DLP.ps1):
        #   - simulation requested but currently in another state -> flip to TestWithoutNotifications
        #   - simulation not requested but currently in TestWithoutNotifications -> flip to per-policy Mode
        if ($startInSim -and $currentMode -ne 'TestWithoutNotifications') {
            $setArgs['Mode'] = 'TestWithoutNotifications'
        } elseif (-not $startInSim -and $currentMode -eq 'TestWithoutNotifications') {
            $setArgs['Mode'] = $mode
        }

        if ($PSCmdlet.ShouldProcess($cfg.Name, 'Set-DlpCompliancePolicy (refresh)')) {
            try {
                Invoke-WithTransientRetry -Description ("Set-DlpCompliancePolicy (Copilot) '$($cfg.Name)'") -Action {
                    Set-DlpCompliancePolicy @setArgs `
                        -ErrorAction Stop -WarningAction SilentlyContinue -Confirm:$false | Out-Null
                }
                if ($setArgs.ContainsKey('Mode')) {
                    Write-Host "  ~ Updated Copilot DLP policy and flipped Mode '$currentMode' -> '$($setArgs['Mode'])' (config-driven)." -ForegroundColor Green
                } else {
                    Write-Host "  ~ Updated Copilot DLP policy (Mode=$currentMode unchanged)." -ForegroundColor Yellow
                }
            } catch {
                Write-Warning "  Failed to update AI policy '$($cfg.Name)': $(Format-IPPSError $_)"
            }
        }
    }

    # -------------------------------------------------------------------
    # Rule (sensitivity-label condition + RestrictAccess block)
    # -------------------------------------------------------------------
    # We write -AdvancedRule directly instead of -ContentContainsSensitiveInformation.
    # The IPPS engine accepts -ContentContainsSensitiveInformation for the
    # Copilot/Application location and persists it -- but the resulting JSON
    # is in lowercase keys with label entries of just { name = GUID; type = ... }.
    # The Purview UI rule-edit wizard cannot parse that shape and renders
    # "No rules created", even though Get-DlpComplianceRule confirms the
    # rule exists and is enforceable. Writing AdvancedRule ourselves with
    # the PascalCase + Name+Id label shape that the UI itself produces
    # makes our rules round-trip correctly through the wizard.
    $advRuleJson = Build-CopilotAdvancedRuleJson -Labels $labelInfos
    Write-Verbose "  AdvancedRule JSON: $advRuleJson"

    # ----- Manual repro snippet (only emitted when -Debug is passed) -----
    if ($DebugPreference -ne 'SilentlyContinue') {
        $reproRestrict = ($cfg.RestrictAccess | ForEach-Object {
            "@{ setting = '$($_.setting)'; value = '$($_.value)' }"
        }) -join ', '
        Write-Host "  --- Manual repro (copy/paste in same IPPS session) ---" -ForegroundColor DarkCyan
        Write-Host "  `$advRule = @'"                                          -ForegroundColor DarkCyan
        foreach ($line in ($advRuleJson -split "`r?`n")) {
            Write-Host "  $line" -ForegroundColor DarkCyan
        }
        Write-Host "  '@"                                                      -ForegroundColor DarkCyan
        Write-Host "  New-DlpComplianceRule ``"                                 -ForegroundColor DarkCyan
        Write-Host "      -Name '$($cfg.RuleName)' ``"                          -ForegroundColor DarkCyan
        Write-Host "      -Policy '$($cfg.Name)' ``"                            -ForegroundColor DarkCyan
        Write-Host "      -AdvancedRule `$advRule ``"                           -ForegroundColor DarkCyan
        Write-Host "      -RestrictAccess @($reproRestrict)"                    -ForegroundColor DarkCyan
        Write-Host "  --- end repro ---"                                       -ForegroundColor DarkCyan
    }

    $existingRule = Get-DlpComplianceRule -Identity $cfg.RuleName -ErrorAction SilentlyContinue
    $ruleOwned    = Test-Owned -Object $existingRule -Tag $tag

    if ($existingRule -and -not $ruleOwned -and -not $AdoptExisting) {
        throw "AI DLP rule '$($cfg.RuleName)' exists but is not managed by this toolkit. Re-run with -AdoptExisting to update it."
    }

    if (-not $existingRule) {
        if ($PSCmdlet.ShouldProcess($cfg.RuleName, 'New-DlpComplianceRule (Copilot)')) {
            # DLP compliance rules behave like sensitivity labels: Remove-DlpComplianceRule
            # leaves the name in a soft-delete tombstone for ~30 days. Re-using the
            # name fails with "ComplianceRuleAlreadyExistsInScenarioException ... already
            # exists in scenario(s) 'Dlp'". When that happens we bump the rule name to
            # the next free '-vN' suffix, identical to the label-tombstone bypass in
            # Setup-SensitivityLabels.ps1. The bump is in-memory only; PurviewConfig.psd1
            # on disk is unchanged, and the original name will become reusable once the
            # tombstone purges.
            $candName    = $cfg.RuleName
            $maxBumps    = 20
            $bumpCount   = 0
            $created     = $false
            while (-not $created -and $bumpCount -le $maxBumps) {
                if ($candName.Length -gt 64) {
                    Write-Warning "  Cannot bump rule name to bypass tombstone: '$candName' would exceed 64 chars. Edit RuleName in PurviewConfig.psd1."
                    break
                }
                try {
                    Invoke-WithTransientRetry -Description ("New-DlpComplianceRule (Copilot) '$candName'") -Action {
                        New-DlpComplianceRule `
                            -Name           $candName `
                            -Policy         $cfg.Name `
                            -Comment        "$tag AI DLP rule (Copilot)." `
                            -AdvancedRule   $advRuleJson `
                            -RestrictAccess $cfg.RestrictAccess `
                            -ErrorAction Stop -WarningAction SilentlyContinue -Confirm:$false | Out-Null
                    }
                    if ($candName -ne $cfg.RuleName) {
                        Write-Host "  + Created Copilot DLP rule as '$candName' (original name '$($cfg.RuleName)' tombstoned)." -ForegroundColor Green
                    } else {
                        Write-Host "  + Created Copilot DLP rule." -ForegroundColor Green
                    }
                    $created = $true
                    break
                } catch {
                    $msg = (Format-IPPSError $_)
                    if ($msg -match 'already exists in scenario|ComplianceRuleAlreadyExistsInScenarioException') {
                        $bumpCount++
                        $nextName = "$($cfg.RuleName)-v$($bumpCount + 1)"
                        Write-Host "      '$candName' is held by a soft-delete tombstone; retrying with '$nextName'..." -ForegroundColor DarkYellow
                        $candName = $nextName
                        continue
                    }
                    Write-Warning "  Failed to create AI rule '$candName': $msg"
                    break
                }
            }
            if (-not $created -and $bumpCount -gt $maxBumps) {
                Write-Warning "  Could not find a free rule name after $maxBumps bumps. Edit RuleName in PurviewConfig.psd1 and re-run."
            }
        }
    } else {
        if ($existingRule.ParentPolicyName -ne $cfg.Name) {
            Write-Warning "Rule '$($cfg.RuleName)' belongs to policy '$($existingRule.ParentPolicyName)', not '$($cfg.Name)'. Skipping update — DLP rules cannot be moved between policies."
            continue
        }
        if ($PSCmdlet.ShouldProcess($cfg.RuleName, 'Set-DlpComplianceRule (refresh)')) {
            $setSucceeded = $false
            $setMsg = $null
            try {
                Invoke-WithTransientRetry -Description ("Set-DlpComplianceRule (Copilot) '$($cfg.RuleName)'") -Action {
                    Set-DlpComplianceRule `
                        -Identity       $cfg.RuleName `
                        -Comment        "$tag AI DLP rule (Copilot)." `
                        -AdvancedRule   $advRuleJson `
                        -RestrictAccess $cfg.RestrictAccess `
                        -ErrorAction Stop -WarningAction SilentlyContinue -Confirm:$false | Out-Null
                }
                Write-Host "  ~ Updated Copilot DLP rule." -ForegroundColor Yellow
                $setSucceeded = $true
            } catch {
                $setMsg = (Format-IPPSError $_)
            }
            if (-not $setSucceeded) {
                # Get-DlpComplianceRule sometimes returns a tombstone (soft-deleted)
                # row even though the rule is gone from the live store. Set then fails
                # with ErrorCommonComplianceRuleIsDeletedException. Detect that and
                # fall through to a fresh Create with bump-on-tombstone.
                if ($setMsg -match 'has been deleted and cannot be modified|ErrorCommonComplianceRuleIsDeletedException') {
                    Write-Host "      Existing rule is a soft-delete tombstone; recreating under bumped name." -ForegroundColor DarkYellow
                    $candName    = "$($cfg.RuleName)-v2"
                    $maxBumps    = 20
                    $bumpCount   = 1
                    $created     = $false
                    while (-not $created -and $bumpCount -le $maxBumps) {
                        if ($candName.Length -gt 64) {
                            Write-Warning "  Cannot bump rule name to bypass tombstone: '$candName' would exceed 64 chars. Edit RuleName in PurviewConfig.psd1."
                            break
                        }
                        try {
                            Invoke-WithTransientRetry -Description ("New-DlpComplianceRule (Copilot, tombstone-recreate) '$candName'") -Action {
                                New-DlpComplianceRule `
                                    -Name           $candName `
                                    -Policy         $cfg.Name `
                                    -Comment        "$tag AI DLP rule (Copilot)." `
                                    -AdvancedRule   $advRuleJson `
                                    -RestrictAccess $cfg.RestrictAccess `
                                    -ErrorAction Stop -WarningAction SilentlyContinue -Confirm:$false | Out-Null
                            }
                            Write-Host "  + Created Copilot DLP rule as '$candName' (original name '$($cfg.RuleName)' tombstoned)." -ForegroundColor Green
                            $created = $true
                            break
                        } catch {
                            $msg2 = (Format-IPPSError $_)
                            if ($msg2 -match 'already exists in scenario|ComplianceRuleAlreadyExistsInScenarioException') {
                                $bumpCount++
                                $nextName = "$($cfg.RuleName)-v$($bumpCount + 1)"
                                Write-Host "      '$candName' is held by a soft-delete tombstone; retrying with '$nextName'..." -ForegroundColor DarkYellow
                                $candName = $nextName
                                continue
                            }
                            Write-Warning "  Failed to create AI rule '$candName': $msg2"
                            break
                        }
                    }
                } else {
                    Write-Warning "  Failed to update AI rule '$($cfg.RuleName)': $setMsg"
                }
            }
        }
    }
}

Write-Host "AI governance policies complete." -ForegroundColor Green
Write-Host "NOTE: Microsoft 365 Copilot DLP enforcement requires Copilot per-user licensing." -ForegroundColor DarkYellow
Write-Host "      Policy changes can take up to an hour to begin enforcement."                -ForegroundColor DarkYellow
