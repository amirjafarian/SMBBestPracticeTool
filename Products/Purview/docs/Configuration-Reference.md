---
title: Configuration Reference
layout: default
parent: Purview
nav_order: 3
permalink: /purview/configuration-reference/
---

# Configuration Reference — customizing `PurviewConfig.psd1`
{: .no_toc }

Every tunable the toolkit applies lives in **one file**:
[`Products/Purview/Config/PurviewConfig.psd1`](https://github.com/amirjafarian/SMBBestPracticeTool/blob/main/Products/Purview/Config/PurviewConfig.psd1).
There is no hidden state — what's in this file is exactly what lands in the
tenant. To customize a deployment you **fork the repo, edit this file, and
re-run**. Because every step is idempotent (read-modify-write), re-running only
changes what you changed.

> 🧪 **Always preview first.** Run with `-WhatIf` after any edit to see exactly
> what would change before you apply it. DLP also ships in **simulation** by
> default, so policy edits don't enforce until you promote them (see the
> [DLP Simulation Exit Runbook](dlp-simulation-exit-runbook/)).

1. TOC
{:toc}

---

## How to customize (the 3-step loop)

```powershell
# 1. Fork/clone the repo, then edit the config in your editor of choice:
code Products\Purview\Config\PurviewConfig.psd1

# 2. Preview the effect against the customer tenant (no writes):
.\Deploy-PurviewBestPractice.ps1 -TenantAdminUpn admin@contoso.onmicrosoft.com -WhatIf

# 3. Apply when the preview looks right:
.\Deploy-PurviewBestPractice.ps1 -TenantAdminUpn admin@contoso.onmicrosoft.com
```

> ⚠️ **Don't change `ManagedByTag`** after a deployment. It's the stamp the
> toolkit writes into every object's comment/description so it recognises what
> it owns on the next run. Change it and the toolkit will no longer see prior
> objects as its own (they'll look like third-party objects and need
> `-AdoptExisting`).

---

## Most-changed settings

All keys below are top-level in `PurviewConfig.psd1` unless a dotted path is
shown (e.g. `LabelPolicy.DefaultLabel` means the `DefaultLabel` key inside the
`LabelPolicy` block).

### Global behaviour

| Key | Default | What it controls |
|---|---|---|
| `DlpStartInSimulation` | `$true` | New DLP policies are created in **simulation** (`TestWithoutNotifications`). Set `$false` to create them directly in **Enable** (enforce) mode. Leave `$true` for the safe simulate-then-promote method. |
| `EnableContentMarking` | `$false` | Master switch for header / footer / watermark marking on labels. While `$false`, per-label `ContentMark = $true` entries are skipped. Flip to `$true` once you're ready to roll visual markings out to users. |
| `ManagedByTag` | `[Managed by SMBTool Purview Toolkit]` | Ownership stamp for idempotent re-runs. **Do not change after deploying.** |

### Sensitivity labels & publishing (`LabelPolicy`)

| Key | Default | What it controls |
|---|---|---|
| `LabelPolicy.DefaultLabel` | `AllEmployees` (Confidential\All Employees) | Default label applied to **documents** (Word/Excel/PowerPoint). |
| `LabelPolicy.DefaultLabelForEmail` | `GeneralAnyone` (General \ Anyone (unrestricted)) | Default label for **Outlook email**. `General` itself is a non-applicable label group, so the default points at its assignable child. Set `$null` to fall back to `DefaultLabel`. |
| `LabelPolicy.PublishedLabels` | `Public, GeneralAnyone, AllEmployees, HCAllEmps` | Subset of labels **published** to end users. All labels in `Labels` are still *created*; only these are *visible*. Set `$null`/empty to publish everything. |
| `LabelPolicy.AttachmentAction` | `'Automatic'` | "Inherit label from attachments": when a user sends an email with labelled attachments, silently applies the highest-priority attachment label to the email. `'Recommended'` prompts the user instead; `$null` turns the feature off. |
| `LabelPolicy.MandatoryLabelling` | `$true` | Forces users to pick a label before saving/sending. Set `$false` only if the customer can't tolerate the prompt during rollout (training is the better answer). |
| `LabelPolicy.DowngradeJustification` | `$true` | Require a justification when a user lowers a label's sensitivity. |

To change a label's display name, tooltip, colour, priority, encryption, or
scope, edit the relevant hashtable in the `Labels = @( ... )` array.

> ℹ️ **`BuiltInName` — don't remove it.** Each built-in label carries a
> `BuiltInName` field holding Microsoft's stable internal signature
> (`defa4170-0d19-0005-NNNN-…`). The toolkit uses it to **adopt** the label
> if the tenant already has it (any locale, any label scheme) and to
> **create** it byte-identical to Microsoft's default on a blank tenant.
> You can freely change `DisplayName`/`Tooltip`/colour/encryption — just
> don't remove or repoint `BuiltInName` on a built-in label, or adoption
> will stop matching it and the toolkit may create a duplicate.

### Encryption rights

| Key | Default | What it controls |
|---|---|---|
| `EncryptionRightsDefinitions` (global) | `{TenantDomain}:VIEW,VIEWRIGHTSDATA,EDIT,DOCEDIT,REPLY,REPLYALL,FORWARD` | The **global default** usage-rights bundle for Template-encrypted labels. The `{TenantDomain}` token scopes rights to **your tenant only** (resolved at runtime). |
| `EncryptionRightsDefinitions` (per-label) | — | Add this field to a single label's hashtable to override the global default for just that label (same token semantics). |
| `EncryptionContentExpiredOnDateInDaysOrNever` | `Never` | When encrypted content access expires. |
| `EncryptionOfflineAccessDays` | `30` | How many days encrypted content is usable offline. |

### DLP policies (`DlpPolicies` array)

Each entry is one policy. The shipped config has **Exchange** and
**SharePoint + OneDrive** (Business Premium and up) and an **Endpoint** policy
(E5 / Purview Suite — auto-created in simulation when licensed, soft-skipped on
BP).

| Field | Example | What it controls |
|---|---|---|
| `Workload` | `Exchange`, `SharePointOneDrive`, `Endpoint` | Which surface the policy targets. E5-only workloads: `Endpoint`/`Devices`, `OnPremisesScanner`, `DefenderForCloudApps`, `PowerBI` (rejected under `-BPOnly`). |
| `LabelPaths` | `Confidential/AllEmployees`, … | The sensitivity labels the rule matches (OR-matched, resolved to **GUIDs** at runtime). |
| `BlockAccess` | `$true` | Whether matched content is blocked. |
| `EndpointDlpRestrictions[].Value` | `Audit` → `Block`/`Warn`/`BlockOverride` | (Endpoint only) Per-device-action enforcement. Start at `Audit`, tighten after reviewing telemetry in DLP Activity Explorer. |

> To **add a department exception** or fix a false positive, edit the rule's
> conditions/exceptions in the relevant `DlpPolicies` entry, re-run, then start
> a fresh 30-day simulation window. See the
> [DLP Simulation Exit Runbook](dlp-simulation-exit-runbook/).

### Retention (`Retention`)  — ⚠️ destructive

Retention is **opt-in** — it only runs when you pass `-ApplyRetention`. The
shipped default **retains Exchange mail for 7 years, then deletes it**.

| Key | Default | What it controls |
|---|---|---|
| `Retention.DurationDays` | `2555` (= **7 years**) | Retention period **in days**. Change to your required duration (e.g. `3650` for 10 years). The `DurationDisplayHint` is cosmetic only. |
| `Retention.Action` | `KeepAndDelete` | `KeepAndDelete` retains then deletes; other Purview actions retain-only / delete-only. |
| `Retention.ExpirationDateOption` | `CreationAgeInDays` | Whether the clock starts at item creation vs last modification. |
| `Retention.Locations` | `@('Exchange')` | Add `'SharePoint'`, `'OneDrive'` to widen scope beyond mailboxes. |

> 🚨 **Read the [Retention Default — Risk Note](retention-default-risk/) before
> enabling retention.** The 7-year auto-delete is right for many SMB regulatory
> frameworks but wrong for some verticals — confirm with the customer.

### AI governance / Copilot DLP (`AIGovernance`)

Default-on for **E5 / Purview Suite** (auto-skipped on BP; opt out with
`-SkipAIControls`). Blocks Microsoft 365 Copilot from processing
`HighlyConfidential` content.

| Key | Default | What it controls |
|---|---|---|
| `AIGovernance.DlpPolicies[].Mode` | `Enable` | `Enable` / `TestWithNotifications` / `TestWithoutNotifications` / `Disable`. |
| `AIGovernance.DlpPolicies[].LabelPaths` | `HighlyConfidential` | Which labels Copilot is blocked from grounding on. |
| `AIGovernance.DlpPolicies[].EnforcementPlanes` | `CopilotExperiences` | Add `Agent` to extend coverage to Agent 365 (preview). |
| `Locations[].Inclusions` | tenant-wide (`Tenant=All`) | Swap to a `Group` inclusion (see the commented example in the file) to pilot on a security group first. |

### Tenant settings (`TenantSettings`)

| Key | Default | What it controls |
|---|---|---|
| `EnableUnifiedAuditLog` | `$true` | Standard unified audit log (always recommended on). |
| `EnableSensitivityLabelForPDF` | `$true` | Allow labels on PDFs. |
| `EnableAIPIntegrationInSPO` | `$true` | SharePoint AIP / label integration. |
| `EnableLabelCoAuth` | `$false` | **One-way switch** — co-authoring on encrypted Office files. Operator opt-in via `-EnableLabelCoAuthoring`. **Disabling later loses labels on unencrypted Office files and breaks older AIP scanners / OneDrive sync / MIP SDK / custom scanners.** Leave `$false` unless you understand the [one-way semantics](https://learn.microsoft.com/purview/sensitivity-labels-coauthoring). |

---

## Safety rails when editing

- **`-WhatIf` first, every time.** It previews the full run with zero writes.
- **DLP stays in simulation** (`DlpStartInSimulation = $true`) until you
  consciously promote — policy edits don't enforce on day 0.
- **Irreversible switches default to safe.** Retention (`-ApplyRetention`) and
  co-authoring (`EnableLabelCoAuth` / `-EnableLabelCoAuthoring`) are opt-in.
- **`-BPOnly`** hard-blocks every E5-only feature so a fork that adds, say, an
  Endpoint policy can't accidentally be pushed to a Business Premium customer.
- **`-AdoptExisting`** is required to update objects that exist but aren't
  stamped with `ManagedByTag` — prevents silent overwrites.

## Related

- [Scenarios & Capabilities](scenarios/) — what each setting does and the per-licence behaviour.
- [Change-Management Playbook](change-management-playbook/) — when to flip which config key across the deployment timeline.
- [Deployment Framework (Visual)](deployment-framework/) — where configuration sits in the overall method.
