# DLP Policy Creation Example (SMBTool Purview Toolkit)

This is the **Microsoft Purview DLP** portion of the SMBTool Purview Best
Practice Toolkit. It creates DLP policies that block external sharing of
content labelled `Confidential\AllEmployees`, per Microsoft's Business
Premium Data Security Best Practice guide.

Two policies are created (per Microsoft's recommendation — separate per
workload):

* **Exchange** — blocks send to external recipients
* **SharePoint + OneDrive** — blocks external sharing/access

Both policies match content via the **sensitivity label GUID** (resolved
at runtime from `LabelPath`), never by display name, so they cannot
collide with similarly-named labels.

The script is **idempotent**: existing toolkit-managed policies/rules
are updated in place; foreign objects abort the run unless
`-AdoptExisting` is supplied.

---

## 1. Configuration (excerpt from `PurviewConfig.psd1`)

```powershell
@{
    # Marker stamped in object descriptions for safe re-runs and rollback.
    ManagedByTag = '[Managed by SMBTool Purview Toolkit]'

    # ----- DLP policies -----
    # Two policies (Microsoft's recommendation): one for Exchange, one for SPO + OneDrive.
    #
    # Workloads supported under Microsoft 365 Business Premium:
    #   * 'Exchange'              - mailboxes
    #   * 'SharePointOneDrive'    - SPO sites + OneDrive for Business
    #
    # E5 / Purview Suite ONLY (rejected when Deploy-PurviewBestPractice.ps1 is
    # run with -BPOnly):
    #   * 'Endpoint' / 'Devices'  - Endpoint DLP
    #   * 'OnPremisesScanner'     - on-prem file shares & SP servers
    #   * 'DefenderForCloudApps'  - 3rd party apps via MCAS
    #   * 'PowerBI'               - Power BI tenants
    DlpPolicies = @(
        @{
            Name        = 'SMBTool - DLP - Confidential AllEmps external (EXO)'
            Comment     = 'Blocks Exchange messages labelled Confidential/AllEmployees from being sent outside the organisation.'
            Workload    = 'Exchange'
            RuleName    = 'SMBTool - DLP Rule - Confidential AllEmployees - Exchange'
            LabelPath   = 'Confidential/AllEmployees'   # parent/child by Name; resolved to GUID at runtime
            BlockAccess = $true
            # Exchange: BlockAccessScope is not used; All is the only safe value.
            BlockAccessScope = 'All'
            NotifyUser  = @('SiteAdmin','LastModifier','Owner')
            GenerateIncidentReport = @('SiteAdmin')
        }
        @{
            Name        = 'SMBTool - DLP - Confidential AllEmps external (SPO+ODB)'
            Comment     = 'Blocks SharePoint and OneDrive files labelled Confidential/AllEmployees from being shared externally.'
            Workload    = 'SharePointOneDrive'
            RuleName    = 'SMBTool - DLP Rule - Confidential AllEmployees - SPO ODFB'
            LabelPath   = 'Confidential/AllEmployees'
            BlockAccess = $true
            # SPO/ODFB: valid enums are All, PerUser, PerAnonymousUser.
            # 'All' blocks every non-org user (incl. anonymous + B2B guests).
            BlockAccessScope = 'All'
            NotifyUser  = @('SiteAdmin','LastModifier','Owner')
            GenerateIncidentReport = @('SiteAdmin')
        }
    )
}
```

---

## 2. DLP creation script (`Setup-DLP.ps1`)

```powershell
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
    #>
    param([string] $Path)
    $parts = $Path -split '/'
    $childName = $parts[-1]
    $child = Get-Label -Identity $childName -ErrorAction SilentlyContinue
    if ($child) { return $child }

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
        throw "DLP policy '$($cfg.Name)' targets workload '$($cfg.Workload)', which requires Microsoft 365 E5 / Purview Suite. Remove this policy from PurviewConfig.psd1 or omit -BPOnly."
    }

    # -------------------------------------------------------------------
    # Resolve the label GUID we will match in the DLP rule
    # -------------------------------------------------------------------
    $label = Resolve-LabelByPath -Path $cfg.LabelPath
    $labelGuid = $label.Guid.ToString()
    Write-Verbose "  Resolved '$($cfg.LabelPath)' to GUID $labelGuid"

    # -------------------------------------------------------------------
    # Policy
    # -------------------------------------------------------------------
    $existing = Get-DlpCompliancePolicy -Identity $cfg.Name -ErrorAction SilentlyContinue
    $owned = Test-Owned -Object $existing -Tag $tag

    if ($existing -and -not $owned -and -not $AdoptExisting) {
        throw "DLP policy '$($cfg.Name)' exists but is not managed by this toolkit. Re-run with -AdoptExisting to update it."
    }

    $policyArgs = @{
        Name    = $cfg.Name
        Comment = "$tag $($cfg.Comment)"
    }
    switch ($cfg.Workload) {
        'Exchange' {
            $policyArgs['ExchangeLocation'] = 'All'
        }
        'SharePointOneDrive' {
            $policyArgs['SharePointLocation'] = 'All'
            $policyArgs['OneDriveLocation']   = 'All'
        }
        default { throw "Unknown DLP workload: $($cfg.Workload)" }
    }

    if (-not $existing) {
        if ($PSCmdlet.ShouldProcess($cfg.Name, 'New-DlpCompliancePolicy')) {
            $perr = @()
            New-DlpCompliancePolicy @policyArgs -Mode Enable `
                -ErrorAction SilentlyContinue -ErrorVariable perr -WarningAction SilentlyContinue -Confirm:$false | Out-Null
            if ($perr.Count -eq 0) {
                Write-Host "  + Created policy." -ForegroundColor Green
                $existing = Get-DlpCompliancePolicy -Identity $cfg.Name -ErrorAction SilentlyContinue
            } else {
                Write-Warning "  Failed to create policy '$($cfg.Name)': $($(Format-IPPSError $perr[0]))"
                continue
            }
        }
    } else {
        if ($PSCmdlet.ShouldProcess($cfg.Name, 'Set-DlpCompliancePolicy (comment refresh)')) {
            $perr = @()
            Set-DlpCompliancePolicy -Identity $cfg.Name -Comment $policyArgs.Comment `
                -ErrorAction SilentlyContinue -ErrorVariable perr -WarningAction SilentlyContinue -Confirm:$false | Out-Null
            if ($perr.Count -eq 0) {
                Write-Host "  ~ Updated policy comment." -ForegroundColor Yellow
            } else {
                Write-Warning "  Failed to update policy '$($cfg.Name)': $($(Format-IPPSError $perr[0]))"
            }
        }
    }

    # -------------------------------------------------------------------
    # Rule
    # -------------------------------------------------------------------
    $contentMatch = @{
        operator = 'And'
        groups   = @(
            @{
                operator = 'Or'
                name     = 'Default'
                labels   = @(
                    @{ name = $labelGuid; type = 'Sensitivity' }
                )
            }
        )
    }

    $existingRule = Get-DlpComplianceRule -Identity $cfg.RuleName -ErrorAction SilentlyContinue
    $ruleOwned = Test-Owned -Object $existingRule -Tag $tag

    if ($existingRule -and -not $ruleOwned -and -not $AdoptExisting) {
        throw "DLP rule '$($cfg.RuleName)' exists but is not managed by this toolkit. Re-run with -AdoptExisting to update it."
    }

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

    if (-not $existingRule) {
        if ($PSCmdlet.ShouldProcess($cfg.RuleName, 'New-DlpComplianceRule')) {
            $rerr = @()
            New-DlpComplianceRule @ruleArgs `
                -ErrorAction SilentlyContinue -ErrorVariable rerr -WarningAction SilentlyContinue -Confirm:$false | Out-Null
            if ($rerr.Count -eq 0) {
                Write-Host "  + Created rule." -ForegroundColor Green
            } else {
                Write-Warning "  Failed to create rule '$($cfg.RuleName)': $($(Format-IPPSError $rerr[0]))"
            }
        }
    } else {
        if ($existingRule.ParentPolicyName -ne $cfg.Name) {
            Write-Warning "Rule '$($cfg.RuleName)' belongs to policy '$($existingRule.ParentPolicyName)', not '$($cfg.Name)'. Skipping update — DLP rules cannot be moved between policies."
            continue
        }
        if ($PSCmdlet.ShouldProcess($cfg.RuleName, 'Set-DlpComplianceRule (refresh conditions/actions)')) {
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
            $rerr = @()
            Set-DlpComplianceRule @setArgs `
                -ErrorAction SilentlyContinue -ErrorVariable rerr -WarningAction SilentlyContinue -Confirm:$false | Out-Null
            if ($rerr.Count -eq 0) {
                Write-Host "  ~ Updated rule." -ForegroundColor Yellow
            } else {
                Write-Warning "  Failed to update rule '$($cfg.RuleName)': $($(Format-IPPSError $rerr[0]))"
            }
        }
    }
}

Write-Host "DLP policies complete." -ForegroundColor Green
Write-Host "NOTE: DLP policy changes can take up to an hour to begin enforcement." -ForegroundColor DarkYellow
```

---

## 3. How it's invoked

The orchestrator calls this module with the loaded config hashtable:

```powershell
# From Deploy-PurviewBestPractice.ps1
$Config = Import-PowerShellDataFile -Path .\Config\PurviewConfig.psd1

# Connect to Security & Compliance Center (IPPS) first
Connect-IPPSSession -UserPrincipalName admin@contoso.onmicrosoft.com

# Run the DLP module — use -WhatIf for dry-run, -BPOnly for Business Premium tenants
.\Modules\Setup-DLP.ps1 -Config $Config -BPOnly -WhatIf
.\Modules\Setup-DLP.ps1 -Config $Config -BPOnly
```

---

## 4. Key design notes

| Aspect | Decision | Rationale |
|---|---|---|
| **Per-workload policies** | One for Exchange, one for SPO+ODFB | Microsoft's own recommendation; mixing workloads complicates rule scoping |
| **Match by label GUID** | `Resolve-LabelByPath` → `$label.Guid` | Display names can collide; GUIDs are unambiguous |
| **Idempotency** | `Test-Owned` checks `[Managed by SMBTool Purview Toolkit]` tag in `Comment` | Safe to re-run; foreign objects need explicit `-AdoptExisting` |
| **64-char name limit** | Validated upfront | IPPS rejects longer names with an empty error; we surface a clear message |
| **`-BPOnly` guard** | Rejects E5-only workloads (Endpoint, MCAS, OnPrem, PowerBI) | Prevents partners from creating policies their tenant can't enforce |
| **`AccessScope = 'NotInOrganization'`** | Both workloads | The "external" condition — only fires for outside-org recipients/sharers |
| **`BlockAccessScope`** | Exchange: `'All'` only valid; SPO/ODFB: `All`/`PerUser`/`PerAnonymousUser` | Workload-specific enums enforced by the IPPS backend |

---

## 5. Cmdlets used (Security & Compliance PowerShell / IPPS)

* `Get-DlpCompliancePolicy` / `New-DlpCompliancePolicy` / `Set-DlpCompliancePolicy`
* `Get-DlpComplianceRule`   / `New-DlpComplianceRule`   / `Set-DlpComplianceRule`
* `Get-Label` (to resolve label name → GUID)

Connection: `Connect-IPPSSession` (ExchangeOnlineManagement module).
