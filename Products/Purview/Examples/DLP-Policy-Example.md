# DLP Policy Creation Example (SMBTool Purview Toolkit)

This is the **Microsoft Purview DLP** portion of the SMBTool Purview Best
Practice Toolkit. It creates DLP policies that block external sharing of
content labelled `Confidential` or `Highly Confidential`, per Microsoft's
Business Premium Data Security Best Practice guide, with an additional
**Endpoint DLP** policy that audits device-side activity (E5 / Purview
Suite only).

Three policies are created by default:

* **Exchange** — blocks send to external recipients
* **SharePoint + OneDrive** — blocks external sharing/access
* **Endpoint** — audits copy / print / USB / network-share / cloud-sync on
  managed devices (E5 only — silently skipped under `-BPOnly`)

All three policies match content via the **sensitivity label GUID** array
(resolved at runtime from `LabelPaths`), never by display name, so they
cannot collide with similarly-named labels.

> 🛡️ **DLP starts in simulation mode by default**
> (`DlpStartInSimulation = $true` → `TestWithoutNotifications`). Telemetry
> accrues; nobody is blocked. You **must** explicitly promote out of
> simulation — see
> [`docs/DLP-Simulation-Exit-Runbook.md`](../docs/DLP-Simulation-Exit-Runbook.md)
> for the day-30 procedure.

The script is **idempotent**: existing toolkit-managed policies/rules
are updated in place; foreign objects abort the run unless
`-AdoptExisting` is supplied. On re-runs the policy **mode is reconciled
against config** — if you flip a policy to Enable in the portal but leave
`DlpStartInSimulation = $true`, the next run pulls it back to simulation.

---

## 1. Configuration (excerpt from `PurviewConfig.psd1`)

```powershell
@{
    # Marker stamped in object descriptions for safe re-runs and rollback.
    ManagedByTag = '[Managed by SMBTool Purview Toolkit]'

    # Master switch: every DLP policy is created in simulation mode
    # (TestWithoutNotifications) when this is $true. Telemetry only; no
    # user-visible block. Flip to $false to deploy directly into Enable mode.
    DlpStartInSimulation = $true

    # ----- DLP policies -----
    # Per-workload, per Microsoft's recommendation.
    #
    # Workloads supported under Microsoft 365 Business Premium:
    #   * 'Exchange'              - mailboxes
    #   * 'SharePointOneDrive'    - SPO sites + OneDrive for Business
    #
    # E5 / Purview Suite ONLY (rejected when -BPOnly is set, soft-skipped
    # at runtime when the toolkit auto-detects a Business Premium tenant):
    #   * 'Endpoint' / 'Devices'  - Endpoint DLP
    #   * 'OnPremisesScanner'     - on-prem file shares & SP servers
    #   * 'DefenderForCloudApps'  - 3rd party apps via MCAS
    #   * 'PowerBI'               - Power BI tenants
    DlpPolicies = @(
        @{
            Name        = 'SMBTool - DLP - Confidential and HC external (EXO)'
            Comment     = 'Blocks Exchange messages labelled with any Confidential or Highly Confidential sub-label from being sent outside the organisation.'
            Workload    = 'Exchange'
            RuleName    = 'SMBTool - DLP Rule - Confidential and HC - Exchange'
            # OR-match across every Confidential + Highly Confidential
            # sub-label. Resolved to GUIDs at runtime via Resolve-LabelByPath.
            # Single-LabelPath (string) is still accepted for backward compat.
            LabelPaths  = @(
                'Confidential/AllEmployees'
                'Confidential/ConfidentialSpecificPeople'
                'Confidential/ConfidentialInternalException'
                'HighlyConfidential/HCAllEmps'
                'HighlyConfidential/HCSpecificPeople'
                'HighlyConfidential/HCInternalException'
            )
            BlockAccess = $true
            # Exchange honours AccessScope=NotInOrganization (set in the script);
            # BlockAccessScope is included for UI parity ("Block only people
            # outside your organization" radio button).
            BlockAccessScope = 'PerUser'
            NotifyUser  = @('SiteAdmin','LastModifier','Owner')
            GenerateIncidentReport = @('SiteAdmin')
        }
        @{
            Name        = 'SMBTool - DLP - Confidential and HC external (SPO+ODB)'
            Comment     = 'Blocks SharePoint and OneDrive files labelled with any Confidential or Highly Confidential sub-label from being shared externally.'
            Workload    = 'SharePointOneDrive'
            RuleName    = 'SMBTool - DLP Rule - Confidential and HC - SPO ODFB'
            LabelPaths  = @(
                'Confidential/AllEmployees'
                'Confidential/ConfidentialSpecificPeople'
                'Confidential/ConfidentialInternalException'
                'HighlyConfidential/HCAllEmps'
                'HighlyConfidential/HCSpecificPeople'
                'HighlyConfidential/HCInternalException'
            )
            BlockAccess = $true
            # SPO/ODFB: 'PerUser' = "Block only people outside your organization".
            # 'All' would mean "Block everyone" (incl. internal users) — almost
            # never what you want. 'PerAnonymousUser' only blocks anonymous link
            # recipients (lets B2B guests through).
            BlockAccessScope = 'PerUser'
            NotifyUser  = @('SiteAdmin','LastModifier','Owner')
            GenerateIncidentReport = @('SiteAdmin')
        }
        # -----------------------------------------------------------------
        # Endpoint DLP — E5 / Purview Suite only.
        # On Business Premium tenants the toolkit soft-skips this policy
        # (warn + continue) so the rest of the DLP step still completes.
        #
        # WARNING: a deployed Endpoint policy enforces nothing if no devices
        # have been onboarded into Microsoft Defender / Purview compliance.
        # Confirm onboarding in the Purview portal (Settings → Device
        # onboarding) before relying on this policy for protection.
        # -----------------------------------------------------------------
        @{
            Name        = 'SMBTool - DLP - Endpoint Confidential and HC'
            Comment     = 'Endpoint DLP - audits copy / print / USB / network-share / cloud-sync actions on managed devices when content is labelled Confidential or Highly Confidential.'
            Workload    = 'Endpoint'
            RuleName    = 'SMBTool - DLP Rule - Endpoint Confidential and HC'
            LabelPaths  = @(
                'Confidential/AllEmployees'
                'Confidential/ConfidentialSpecificPeople'
                'Confidential/ConfidentialInternalException'
                'HighlyConfidential/HCAllEmps'
                'HighlyConfidential/HCSpecificPeople'
                'HighlyConfidential/HCInternalException'
            )
            # Endpoint device-action restrictions. Default 'Audit' for every
            # action so simulation produces telemetry without interrupting
            # users. Flip individual entries to 'Block' / 'BlockOverride' /
            # 'Warn' after reviewing telemetry in DLP Activity Explorer.
            #
            # Valid Setting values (case-sensitive — these are the short
            # forms the cmdlet accepts):
            #   Print, CopyPaste, ScreenCapture, RemovableMedia, NetworkShare,
            #   UnallowedApps, CloudEgress, UnallowedBluetoothTransferApps,
            #   RemoteDesktopServices, WebPagePrint, WebPageCopyPaste,
            #   WebPageSaveToLocal, PasteToBrowser, AccessByAnyAppDefault,
            #   UnallowedFtpTransferApps.
            # Valid Value values: Audit, Block, Warn, BlockOverride.
            EndpointDlpRestrictions = @(
                @{ Setting = 'CopyPaste';      Value = 'Audit' }
                @{ Setting = 'Print';          Value = 'Audit' }
                @{ Setting = 'RemovableMedia'; Value = 'Audit' }
                @{ Setting = 'NetworkShare';   Value = 'Audit' }
            )
            EnforcePortalAccess = $true
            ReportSeverityLevel = 'Medium'
            GenerateAlert       = $true
            NotifyUser  = @()
            GenerateIncidentReport = @()
        }
    )
}
```

---

## 2. How it's invoked

The orchestrator calls the DLP module with the loaded config hashtable:

```powershell
# From Deploy-PurviewBestPractice.ps1
$Config = Import-PowerShellDataFile -Path .\Config\PurviewConfig.psd1

# Connect to Security & Compliance Center (IPPS) first
Connect-IPPSSession -UserPrincipalName admin@contoso.onmicrosoft.com

# Dry-run first (always)
.\Modules\Setup-DLP.ps1 -Config $Config -BPOnly -WhatIf

# Apply — on a Business Premium tenant
.\Modules\Setup-DLP.ps1 -Config $Config -BPOnly

# Apply — on an E5 / Purview Suite tenant (Endpoint DLP policy is created)
.\Modules\Setup-DLP.ps1 -Config $Config
```

In practice you'd run the orchestrator (`Deploy-PurviewBestPractice.ps1`)
which handles license auto-detect (auto-setting `-BPOnly` when the tenant
is Business Premium) and forwards the right flags to this module.

---

## 3. Behaviour summary

| Aspect | Decision | Rationale |
|---|---|---|
| **Per-workload policies** | One for Exchange, one for SPO+ODFB, one for Endpoint (E5) | Microsoft's own recommendation; mixing workloads complicates rule scoping |
| **Match by label GUID** | `Resolve-LabelByPath` → `$label.Guid`, OR-matched across `LabelPaths` | Display names can collide; GUIDs are unambiguous |
| **`LabelPaths` (array) preferred** | `LabelPath` (single string) still accepted | Forward-compatible config; lets a single rule cover all Confidential + HC sub-labels |
| **Simulation by default** | `DlpStartInSimulation = $true` → `TestWithoutNotifications` mode | Zero user impact on day one; explicit promotion required at day 30 |
| **Mode reconciliation** | Re-runs pull policy mode back to whatever `DlpStartInSimulation` says | Prevents config drift; flip the config flag to promote, don't rely on portal-only edits |
| **Idempotency** | `Test-Owned` checks `[Managed by SMBTool Purview Toolkit]` tag in `Comment` | Safe to re-run; foreign objects need explicit `-AdoptExisting` |
| **64-char name limit** | Validated upfront | IPPS rejects longer names with an empty error; we surface a clear message |
| **`-BPOnly` guard** | Hard-rejects E5-only workloads (Endpoint, MCAS, OnPrem, PowerBI) | Prevents partners from creating policies their tenant can't enforce |
| **License auto-detect soft-skip** | When the toolkit detects a BP tenant and auto-sets `-BPOnly`, E5-only policies are warned and skipped (not thrown) | Other DLP policies still deploy; the run doesn't crash mid-step |
| **`AccessScope = 'NotInOrganization'`** | Exchange + SPO+ODFB | The "external" condition — only fires for outside-org recipients/sharers |
| **`BlockAccessScope = 'PerUser'`** | Exchange + SPO+ODFB | "Block only people outside your organization" — internal sharing is untouched |
| **Endpoint actions default to `Audit`** | Per-action — `CopyPaste`, `Print`, `RemovableMedia`, `NetworkShare` | Telemetry without user friction; promote per action once Activity Explorer shows expected behaviour |

---

## 4. Cmdlets used (Security & Compliance PowerShell / IPPS)

* `Get-DlpCompliancePolicy` / `New-DlpCompliancePolicy` / `Set-DlpCompliancePolicy`
* `Get-DlpComplianceRule`   / `New-DlpComplianceRule`   / `Set-DlpComplianceRule`
* `Get-Label` (to resolve label name → GUID)

Connection: `Connect-IPPSSession` (ExchangeOnlineManagement module).

---

## 5. Related reading

* [`docs/Scenarios.md`](../docs/Scenarios.md) — Scenario 3 explains DLP at a higher level for non-PowerShell audiences.
* [`docs/Change-Management-Playbook.md`](../docs/Change-Management-Playbook.md) — pre-deploy / day-of / day 1–5 / day-30 wrapper around this technical artefact.
* [`docs/DLP-Simulation-Exit-Runbook.md`](../docs/DLP-Simulation-Exit-Runbook.md) — how to pull the "what would have leaked" report from Activity Explorer before promoting out of simulation.
* [`Modules/Setup-DLP.ps1`](../Modules/Setup-DLP.ps1) — the actual implementation (do not paste from this example; the example is for orientation only).
