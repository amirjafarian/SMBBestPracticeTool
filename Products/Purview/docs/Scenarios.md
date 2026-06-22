---
title: Scenarios & Capabilities
layout: default
parent: Purview
nav_order: 2
permalink: /purview/scenarios/
---

# What this toolkit does — Scenarios & Capabilities

> 🧰 **On the support team / service desk?** For the fast, visual
> "what's changing & what's the impact" view, start with
> [**What's Changing — Support Team Guide**](whats-changing/). This page is
> the deeper technical reference.

> **Audience.** Anyone evaluating, running, or reviewing the SMBTool Purview
> deployment script — IT admins, security leads, deployment consultants, and reviewers.
> No PowerShell expertise required to read this page; the technical
> details live behind expandable sections.

This page answers three questions:

1. **What scenarios does the script cover when I run it?**
2. **What changes if my customer's licensing changes?**
3. **What are the limits — what does it deliberately *not* do?**

For step-by-step run instructions, see [`README.md`](../README.md). For the
list of every value the script applies, see
[`Config/PurviewConfig.psd1`](../Config/PurviewConfig.psd1). For the
non-technical companion docs, see:

* [`Change-Management-Playbook.md`](Change-Management-Playbook.md) — pre-deploy / day-of / day 1–5 / day-30 promote-from-simulation gate
* [`End-User-Adoption-Guide.md`](End-User-Adoption-Guide.md) — plain-language guide to send to employees before rollout, with email templates (T-7 / T-0 / T+30)
* [`Retention-Default-Risk.md`](Retention-Default-Risk.md) — when the 7-year default is right, when it isn't, and how to override
* [`DLP-Simulation-Exit-Runbook.md`](DLP-Simulation-Exit-Runbook.md) — how to pull the "what would have leaked" report from Activity Explorer before promoting DLP out of simulation

---

## TL;DR

The script applies Microsoft's recommended **Data Security baseline** to a
Microsoft 365 tenant — designed for **Business Premium** and gracefully
expanding when **E5 / Purview Suite** licensing is present. It covers
**five scenarios**, all idempotent (safe to re-run) and DLP starts in
**simulation mode** by default so nothing breaks on day one.

| # | Scenario | Default behaviour | Customer impact |
|---|----------|-------------------|-----------------|
| 1 | **Foundational tenant settings** | Enables audit log, SharePoint label integration, PDF labels | Invisible to end users |
| 2 | **Sensitivity labels** | Creates 3 parents + 6 sub-labels with defaults; publishes 4; sets `General` as default for email and `Confidential\All Employees` as default for documents | Users see new labels in Outlook/Office; new documents auto-get a footer |
| 3 | **Data Loss Prevention (DLP)** | Blocks external sharing of Confidential and Highly Confidential content from Exchange and SharePoint/OneDrive (in **simulation** mode by default) | Telemetry only until the policy is promoted out of simulation |
| 4 | **Retention** | **Opt-in via `-ApplyRetention`.** Keeps Exchange mailbox content for 7 years, then deletes | Long-tail effect — mail older than 7 years starts to be removed |
| 5 | **AI governance (Copilot DLP)** | Opt-in — blocks Microsoft 365 Copilot from processing Highly Confidential content | Copilot ignores HC files when surfacing answers |

---

## Scenario 1 — Foundational tenant settings

**Module:** [`Setup-TenantSettings.ps1`](../Modules/Setup-TenantSettings.ps1)
**Always runs unless `-SkipTenantSettings` is passed.**

These are the prerequisites every Purview feature depends on. Without them
labels can be applied but won't be enforced or visible everywhere.

| Setting | What it enables | Default |
|---|---|---|
| **Unified Audit Log** | Every Purview / DLP / label action shows up in audit search and SIEM exports | ✅ on |
| **SharePoint AIP integration** | Sensitivity labels apply at the file level inside SharePoint and OneDrive (search, eDiscovery, DLP all see the label) | ✅ on |
| **Sensitivity labels for PDF** | New PDFs created or saved in SharePoint / OneDrive carry the parent doc's label | ✅ on |
| **Label co-authoring** | Tenant-wide switch that moves label metadata to the new embedded location so multiple users can edit a labelled / encrypted document at the same time in Office / Office Web. **One-way change** — disabling it later loses labels on unencrypted Office files; breaks third-party apps that read the old metadata location | Opt-in via `-EnableLabelCoAuthoring` |
| **Container labels** | Lets labels apply to Microsoft 365 Groups, Teams, and SharePoint sites (`Group.Unified` `EnableMIPLabels=True`) | Auto-on with Business Premium / E5 / Purview Suite (BP includes Entra ID P1+, which is the AAD-side requirement). Opt out with `-NoLicenseAutoDetect`. |
| **Premium audit** *(opt-in)* | Adds the rich `SearchQueryInitiated` event for the named mailbox(es); enables 1-year audit retention | Off — pass `-EnablePremiumAudit -PremiumAuditMailbox` |

> **Licensing note.** All four are **Business Premium**. Container labels
> are also auto-enabled on Business Premium (BP includes Entra ID P1+,
> the AAD-side requirement) — premium audit still requires **E5 / Purview
> Suite**. Skip auto-enable with `-NoLicenseAutoDetect`.

---

## Scenario 2 — Sensitivity labels

**Module:** [`Setup-SensitivityLabels.ps1`](../Modules/Setup-SensitivityLabels.ps1)
**Always runs unless `-SkipLabels` is passed.**

The toolkit creates an SMB-tuned subset of Microsoft's documented
[default sensitivity labels](https://learn.microsoft.com/en-us/purview/default-sensitivity-labels-policies):

```
Public
General                           ← default for EMAIL
Confidential
├─ All Employees                  ← default for DOCUMENTS (footer only)
├─ Specific People                (footer + ENCRYPTED, UserDefined — user picks who)
└─ Internal Exception             (footer only)
Highly Confidential               (watermark "HIGHLY CONFIDENTIAL")
├─ All Employees                  (footer + ENCRYPTED, Co-Author rights, all users in your tenant only)
├─ Specific People                (footer + ENCRYPTED, UserDefined — user picks who)
└─ Internal Exception             (footer + ENCRYPTED, Reviewer rights, all users in your tenant only)
```

### What gets published vs created

| Created in tenant | Published to users by default |
|---|---|
| All 9 labels above | `Public`, `General`, `Confidential\All Employees`, `Highly Confidential\All Employees` |

The other sub-labels are created so DLP can match on them, but kept off the
client UI to reduce decision fatigue. Edit `LabelPolicy.PublishedLabels`
in [`PurviewConfig.psd1`](../Config/PurviewConfig.psd1) to surface more.
**Note:** the two "Specific People" sub-labels apply UserDefined
encryption — Outlook auto-applies Do Not Forward; Word / Excel /
PowerPoint prompt the recipient list at apply time. Most end users do
not know how to respond to that dialog, so the default ships them
unpublished. Promote them only after user training.

### Encryption — who can open the file?

The **two Template-encrypted Highly Confidential sub-labels** (`All
Employees`, `Internal Exception`) grant rights to **all users in your
tenant only**. The rights bundle uses the `{TenantDomain}` token, which
the toolkit resolves at run time against your auto-discovered tenant
identity. Per Entra rights-management semantics, ANY verified domain in
your tenant expands to ALL verified domains in your tenant, so this
explicitly EXCLUDES external `AuthenticatedUsers` (B2B guests attached
to OTHER tenants, social/MSA accounts, OTP users from other M365
tenants).

The **two UserDefined Specific People sub-labels** (`Confidential\Specific
People`, `Highly Confidential\Specific People`) let the message / file
author pick the exact recipients at apply time. Outlook auto-applies Do
Not Forward; Word / Excel / PowerPoint show a recipient-picker dialog.

| Label | Rights bundle | Office co-authoring (rights side) | Programmatic access |
|---|---|---|---|
| `Highly Confidential \ All Employees` (default) | Microsoft "Co-Author" — View, Edit, Save, Copy, Print, Allow Macros, Reply, Reply All, Forward | ✅ | ✅ |
| `Highly Confidential \ Internal Exception` (default) | Microsoft "Reviewer" — View, Edit, Save, Reply, Reply All, Forward | ❌ | ❌ |
| Any other Template-encrypted label (no per-label override) | Inherits global default (Reviewer) | ❌ | ❌ |

The toolkit's global default is the conservative "Reviewer" bundle
because OBJMODEL access (granted by "Co-Author") is the right that most
often breaks third-party apps reading Office doc metadata. To override
the default for a specific label, add an
`EncryptionRightsDefinitions = '...'` field on that label's hashtable in
`PurviewConfig.psd1`. To change the global default for all
Template-encrypted labels at once, edit the top-level
`EncryptionRightsDefinitions` value.

To intentionally OPT IN to broader cross-tenant scope (e.g. you
collaborate with partner organizations that don't have a B2B trust into
your tenant), replace the `{TenantDomain}` token in
`EncryptionRightsDefinitions` with `{AuthenticatedUsers}` (or the
literal `AuthenticatedUsers`). The toolkit refuses to silently fall
back to this scope — if `{TenantDomain}` cannot be resolved, the
labels module aborts with an actionable error rather than re-introduce
the broad scope.

> **Retroactive scope changes only apply to NEW labelling.** Files
> already protected carry the use-license they had at the moment of
> labelling. To tighten retroactively, re-label / re-protect them.

Note: granting the "Co-Author" *rights bundle* on a label is independent
of the tenant-wide *label co-authoring switch* (`-EnableLabelCoAuthoring`)
which controls where Office stores label metadata. Office auto-save +
simultaneous editing on encrypted documents requires both: the per-label
rights bundle AND the tenant-wide switch.

### Visual marking (footers / watermarks)

Footers on all sub-labels and the watermark on `Highly Confidential` are
**defined in config but disabled tenant-wide by default**
(`EnableContentMarking = $false`). Flip the master switch to `$true` once
you've validated rendering with the customer. No re-edit per label needed.

### Default labels

* **Email:** `General` (Outlook auto-applies on new messages).
* **Documents:** `Confidential\All Employees` (Word / Excel / PowerPoint /
  service-side defaults). Every new document gets a footer.

This pairing matches Microsoft's "secure by default" recommendation for SMB:
casual mail isn't over-classified, but every document leaves a trail.

---

## Scenario 3 — Data Loss Prevention (DLP)

**Module:** [`Setup-DLP.ps1`](../Modules/Setup-DLP.ps1)
**Always runs unless `-SkipDLP` is passed.**

The toolkit creates **separate DLP policies per workload** (Microsoft's
recommended pattern). Each policy matches by **label GUID** — never by
display name — so renames don't break the rule.

### Default policies created

| Policy | Workload | Triggers when… | Action |
|---|---|---|---|
| **SMBTool - DLP - Confidential and HC external (EXO)** | Exchange Online | An email labelled with any Confidential or Highly Confidential sub-label is sent **outside the organisation** | Block + notify sender / site admin / last modifier |
| **SMBTool - DLP - Confidential and HC external (SPO+ODB)** | SharePoint + OneDrive | A labelled file is **shared externally** (anonymous or guest) | Block external recipients only — internal sharing untouched |
| **SMBTool - DLP - Endpoint Confidential and HC** *(E5 only)* | Endpoint (Windows / macOS devices) | A labelled file is **copy-pasted, printed, written to USB, or copied to a network share** on a managed device | Audit each event — telemetry visible in DLP Activity Explorer |

### Simulation mode (key safety feature)

By default (`DlpStartInSimulation = $true`) every DLP policy is created in
**`TestWithoutNotifications`** mode:

* The rule **runs and logs hits** in DLP Activity Explorer.
* **Users are not blocked or notified**.
* The Purview portal exposes a "Turn the policy on if it's not edited
  within fifteen days" toggle — flick it once you've reviewed the
  telemetry.

Set `DlpStartInSimulation = $false` to deploy directly into Enable mode
(only do this if you've already validated against a pilot tenant).

> **Important behaviour.** On every re-run the toolkit reconciles policy
> mode against config. If you flip a policy to Enable in the portal but
> leave `DlpStartInSimulation = $true`, the next run pulls it back to
> simulation. Either flip the config flag or use `-SkipDLP`.

### Endpoint DLP actions (E5 only)

By default the Endpoint policy **audits** these device actions on
labelled content:

* Copy & Paste
* Print
* Copy to Removable Media (USB drives, SD cards)
* Copy to Network Share

Change `Audit` → `Block` / `Warn` / `BlockOverride` in
`DlpPolicies[Workload='Endpoint'].EndpointDlpRestrictions` once you've seen
the telemetry. Other supported actions (ScreenCapture, UnallowedApps,
CloudEgress, RemoteDesktopServices, browser print/copy/save, etc.) can be
added the same way.

---

## Scenario 4 — Retention

**Module:** [`Setup-Retention.ps1`](../Modules/Setup-Retention.ps1)
**Opt-in.** Only runs when `-ApplyRetention` is passed.

> 🚨 **Retention is opt-in for a reason.** The shipped default deletes
> Exchange mail older than 7 years tenant-wide. That duration aligns with
> most common SMB regulatory frameworks (ATO / IRS / SEC / ASIC) but is
> still wrong for some verticals (paediatric healthcare, long-life
> construction warranties) and for customers who want no automatic
> deletion at all. See
> construction, real estate). Before passing `-ApplyRetention`, read
> [`docs/Retention-Default-Risk.md`](Retention-Default-Risk.md) and
> pick the right duration for the vertical.

| Setting | Default | Tunable in config |
|---|---|---|
| Locations | Exchange mailboxes | Add `SharePoint`, `OneDrive` |
| Duration | 7 years | `Retention.DurationDays` |
| Action at end of period | Delete | `Retention.Action` (`KeepAndDelete` / `Keep` / `Delete`) |
| Trigger | Days since item creation | `Retention.ExpirationDateOption` |

The policy is gentle by design — it only deletes mail older than 7 years
from when it was created, never anything newer. To pilot, narrow the scope
in config to a single mailbox before the wider rollout.

---

## Scenario 5 — AI governance (Microsoft 365 Copilot DLP)

**Module:** [`Setup-AIGovernance.ps1`](../Modules/Setup-AIGovernance.ps1)
**Default ON for E5 / Purview Suite tenants. Auto-skipped on Business Premium (`-BPOnly`). Opt out with `-SkipAIControls`.**

| Policy | What it does |
|---|---|
| **SMBTool - AI - Block Copilot for Highly Confidential** | Stops Microsoft 365 Copilot from grounding, summarising, or surfacing in search any content labelled `Highly Confidential` (or its sub-labels). Aligned to Microsoft's [AI_054 Zero Trust Assessment control](https://microsoft.github.io/zerotrustassessment/docs/workshop-guidance/AI/AI_054). |

This honours `DlpStartInSimulation` the same way as the other DLP policies
— safe to deploy in audit mode first.

> **Licensing note.** Requires **Microsoft 365 E5 / Purview Suite** for the
> DLP-for-Copilot policy plane. Per
> [Microsoft Learn](https://learn.microsoft.com/purview/dlp-microsoft365-copilot-location-learn-about),
> the policy enforces against both paid **Microsoft 365 Copilot** and the
> free **Microsoft 365 Copilot Chat** experience that's included in
> eligible M365 licenses — so creation succeeds on any E5 / Purview Suite
> tenant regardless of whether paid Copilot per-user licenses are present.
> On Business Premium the policy plane is not available, so the toolkit
> auto-skips this step when `-BPOnly` is set (manually or via license
> auto-detect).

---

## How licensing changes the picture

The toolkit detects the customer's licensing and adjusts behaviour
automatically. Use `-BPOnly` to hard-block any E5-only feature, or
`-NoLicenseAutoDetect` to keep things explicit.

| Capability | Business Premium | E5 / Purview Suite | Microsoft 365 Copilot |
|---|---|---|---|
| Sensitivity labels (Public → Highly Confidential) | ✅ created + published | ✅ | ✅ |
| Encryption + visual marking on labels | ✅ | ✅ | ✅ |
| DLP — Exchange | ✅ | ✅ | ✅ |
| DLP — SharePoint + OneDrive | ✅ | ✅ | ✅ |
| Retention (Exchange) | ✅ | ✅ | ✅ |
| Standard audit log (90-day) | ✅ | ✅ | ✅ |
| **Container labels** (Teams / M365 Groups / SPO sites) | ✅ auto-on (BP has AAD P1+); opt out via `-NoLicenseAutoDetect` | ✅ auto-on | ✅ |
| **Premium audit** (1-yr retention, `SearchQueryInitiated`) | ❌ | ✅ via `-EnablePremiumAudit` | ✅ |
| **Endpoint DLP** (devices) | ❌ blocked by `-BPOnly` | ✅ created in simulation | ✅ |
| **Copilot DLP** (block Copilot for HC) | ❌ blocked by `-BPOnly` | ✅ default ON (opt-out via `-SkipAIControls`) | ✅ |
| DLP for Defender for Cloud Apps / on-prem / Power BI | ❌ | ✅ if added to config | ✅ |

### What changes when a customer upgrades from Business Premium to E5

Re-run the script with no `-BPOnly` flag. On the same config:

1. **Container labels** auto-enable (no extra switch needed — license
   detection handles it).
2. **Endpoint DLP** policy starts being created (the third entry in
   `DlpPolicies` is no longer rejected).
3. **Copilot DLP / AI governance** starts being created (default-on for
   E5 / Purview Suite). Lands in simulation mode while
   `DlpStartInSimulation = $true`. Pass `-SkipAIControls` if the
   customer has a specific reason to defer this.
4. **Premium audit** stays off until you opt in with
   `-EnablePremiumAudit -PremiumAuditMailbox …` — you shouldn't
   automatically expand audit scope without a conversation.

Re-runs are **idempotent** — labels, DLP, retention objects already in
place are detected, left alone, or updated only where config has drifted.

### What changes when a customer adds Microsoft 365 Copilot

Nothing extra needs to be passed. AI governance is already default-on for
E5 / Purview Suite tenants and protects both paid Copilot and the free
Copilot Chat experience. The policy is created in simulation mode by
default (consistent with the rest of the toolkit) — once you're happy
with what it would block, flip `DlpStartInSimulation` to `$false` in
config and re-run.

---

## What the script does NOT do

This is deliberately **not** a full Purview implementation tool. The
following are out of scope:

* **Insider Risk Management** — workflow + privacy controls require their
  own consultation.
* **Communication Compliance** — same reason.
* **eDiscovery** (Premium) — case management is operator-driven.
* **Auto-labelling** (client-side and service-side) — high false-positive
  risk; configure deliberately in the Purview portal once your team has
  reviewed match patterns.
* **Customer-specific protection scopes** (per-domain, per-group rights) —
  needs per-customer trust decisions.
* **Multi-geo configurations** — SharePoint URL handling is single-region.

For the long-form Microsoft Purview guide, see
[aka.ms/Purview_LightweightGuide_PDF](https://aka.ms/Purview_LightweightGuide_PDF).

---

## Safety mechanisms (good to know before you run it)

| Mechanism | What it gives you |
|---|---|
| **`-WhatIf`** | Preview every state-changing call without executing it. |
| **Simulation mode** | DLP policies start in audit-only mode; user impact is zero until you promote them. |
| **`ManagedByTag`** | Every object the toolkit creates is stamped `[Managed by SMBTool Purview Toolkit]` — re-runs detect it and update in place. |
| **`-AdoptExisting`** | Required to update objects with the same name that the toolkit didn't create. Prevents accidental overwrite. |
| **Preflight summary + `y/N` prompt** | Master script prints what it's about to do and waits for confirmation. Skip with `-NonInteractive`. |
| **`-BPOnly`** | Hard-block E5-only features so you can't accidentally enable Endpoint DLP / container labels / premium audit on a Business Premium tenant. |
| **PowerShell 7 gate** | Refuses to run on PS 5.1 (silent EXOv3 / Graph SDK failures otherwise). |
| **Cleanup script** | [`Tests/Invoke-PurviewCleanup.ps1`](../../../Tests/Invoke-PurviewCleanup.ps1) removes every object stamped with `ManagedByTag`. |

---

## Quick scenarios cheat-sheet

| You want to… | Run |
|---|---|
| Preview everything, no changes | `-WhatIf` |
| Standard Business Premium customer | *(no extra flags — defaults are SMB-tuned)* |
| Block all E5 features explicitly | `-BPOnly` |
| Skip Copilot DLP guardrail (E5 / Purview Suite default-on) | `-SkipAIControls` |
| Customer has E5 + wants container labels | *(auto-enabled — no flag needed)* |
| Update labels / DLP that already exist (not toolkit-created) | `-AdoptExisting` |
| Re-deploy only DLP after fixing config | `-SkipTenantSettings -SkipLabels` (retention is opt-in already) |
| Office co-authoring on encrypted labels (tenant-wide, one-way) | `-EnableLabelCoAuthoring` |
| Roll back everything | Run [`Tests/Invoke-PurviewCleanup.ps1`](../../../Tests/Invoke-PurviewCleanup.ps1) |

---

*Last updated to reflect Endpoint DLP, AI Copilot DLP, and license
auto-detect. All defaults are defined in
[`Config/PurviewConfig.psd1`](../Config/PurviewConfig.psd1) — fork and edit
to customise.*
