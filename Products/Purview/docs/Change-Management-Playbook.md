---
title: Change-Management Playbook
layout: default
parent: Purview
nav_order: 2
permalink: /purview/change-management-playbook/
---

# Change-Management Playbook (Partner Edition)

> **Audience.** The partner consultant or MSP delivery lead responsible for
> rolling the SMBTool Purview baseline into a customer tenant. This is the
> *non-technical* counterpart to the script — it covers the customer
> conversation, comms, and the day-30 promote-from-simulation gate.
>
> **For the end-user-facing companion** (what employees see, plain-language
> FAQ, ready-to-send Day -7 / Day 0 / Day +30 comms templates), see
> [`End-User-Adoption-Guide.md`](End-User-Adoption-Guide.md).

The script handles the engineering correctly. **This playbook is what makes
it safe in production.** Several defaults have customer-visible consequences
the moment they take effect (silent labelling on every new document,
7-year mail deletion, DLP blocking external sends). Without a conversation
and comms plan around them, the technical deploy is a help-desk ticket
generator.

Use this as a checklist. Skip nothing on the first deployment for a
customer; you can shorten subsequent ones with experience.

---

## Phase 0 — Pre-deploy (T-7 days)

| # | Action | Owner | Output |
|---|--------|-------|--------|
| 1 | **Confirm tenant SKU** (Business Premium vs E5 / Purview Suite) | Partner | Decides whether `-BPOnly` is required. AI governance is default-on for E5 / Purview Suite tenants (covers both paid Microsoft 365 Copilot and free Copilot Chat) and auto-skipped on Business Premium |
| 2 | **Confirm vertical and any regulatory framework** (law, accounting, healthcare, financial advisor, construction, real estate) | Partner + customer | Decides whether to enable retention at all (`-ApplyRetention` is opt-in) and, if enabled, what duration. The **default 7-year mail deletion** aligns with most SMB regulatory frameworks (ATO / IRS / SEC / ASIC) but may still be wrong for some verticals — see [Retention-Default-Risk.md](Retention-Default-Risk.md) |
| 3 | **Inventory current Purview state** in the tenant — existing labels, DLP policies, retention policies | Partner | If any exist, decide between `-AdoptExisting` (toolkit takes over) or rename / archive first |
| 4 | **Identify B2B guest exposure** — does the customer routinely invite accountants, lawyers, MSPs as guests? | Partner + customer | If yes, the `AuthenticatedUsers` encryption scope is **not** "internal-only" — see [Known sharp edges](#known-sharp-edges) |
| 5 | **Pick a pilot mailbox / pilot site** for retention and DLP simulation review | Partner + customer | Names and UPNs go in the pre-deploy doc |
| 6 | **Schedule the deploy window** and the day-30 review meeting in the same calendar invite | Partner | Both dates booked before the deploy |
| 7 | **Draft user comms** (see [Comms templates](#comms-templates)) | Partner | Sent the day before the deploy |

### Decisions to lock before you run the script

* `-BPOnly` — yes/no
* `-SkipAIControls` — yes/no (AI governance is default-on for E5 / Purview Suite; only set this if the customer has a specific reason to opt out)
* `-ApplyRetention` — yes/no (**opt-in** — only enable if the customer has consciously chosen a retention duration appropriate for their vertical)
* `-SkipContainerLabels` — yes/no (default behaviour is to enable; only set this if container labels are managed by another process or the tenant lacks Entra ID P1). Strips both the tenant-side `Group.Unified EnableMIPLabels = True` toggle AND the container-scope bits (`Site`, `UnifiedGroup`) on the 3 published labels' `ContentType`. The labels still ship with `File, Email` scope.
* `-EnablePremiumAudit` + which mailbox(es) — yes/no
* `-EnableLabelCoAuthoring` — yes/no (**opt-in, one-way change** — only enable after confirming the customer has no third-party apps, scanners, scripts or services that read sensitivity-label metadata from the old custom-properties location. AIP scanner < v3.0, OneDrive sync < 19.002, MIP SDK < 1.7, custom DLP scanners and custom Exchange mail-flow rules all break if they read from the old location. Disabling later is PowerShell-only and loses labels on unencrypted Office files. Ref: [`sensitivity-labels-coauthoring`](https://learn.microsoft.com/purview/sensitivity-labels-coauthoring))
* Retention duration (only relevant if `-ApplyRetention` is enabled) — **stick with default 7 years only if the customer has explicitly agreed** (otherwise edit `Retention.DurationDays` in `PurviewConfig.psd1`)
* `EnableContentMarking` in `PurviewConfig.psd1` — leave `$false` for the initial deploy; flip to `$true` after the day-30 review

---

## Phase 1 — Day-of deploy (T-0)

| # | Action | Output |
|---|--------|--------|
| 1 | Run with **`-WhatIf` first**, capture full transcript | A complete preview of every label / DLP / retention object that *would* be created |
| 2 | Diff the `-WhatIf` output against the customer's existing Purview state from Phase 0 | Sanity-check that nothing unexpected is created or adopted |
| 3 | Run in **apply mode** during the agreed window | Live deploy |
| 4 | Save the deploy log + preflight banner to the customer record | Audit trail of what was changed, when, by whom |
| 5 | Open the **Purview portal** → Information protection → Labels and DLP → confirm objects exist and are stamped `[Managed by SMBTool Purview Toolkit]` | Visual confirmation |
| 6 | Verify **DLP simulation mode** by opening one DLP policy in the portal — Mode should read "Test with notifications off" | Confirms zero user impact on day one |
| 7 | Send the "deploy complete" comms (see [Comms templates](#comms-templates)) | Customer admins know what to expect tomorrow |

### Common day-of surprises

* `Connect-SPOService` fails on a developer machine because EXO/Graph/Az/PnP are already loaded — the toolkit now connects SPO first when the admin URL can be resolved upfront; if you hit this on a vanity-UPN tenant, pass `-SharePointAdminUrl` explicitly.
* `Set-Label -Priority` throws `InvalidSubLabelPriorityException` if the tenant has pre-existing top-level labels with sub-labels (Microsoft's `Personal` default + any demo labels). Audit existing labels in Phase 0.
* IPPS cmdlets sometimes return success before settings are live — the script retries the known propagation races automatically; if a policy looks wrong in the portal, wait 5–10 minutes and refresh.

---

## Phase 2 — Day 1 to Day 5

| # | Action | Output |
|---|--------|--------|
| 1 | **Day 1 morning:** check helpdesk queue for any Purview-related tickets | Early-warning signal |
| 2 | **Day 1:** confirm `General` is showing as default in Outlook (new mail draft) and `Confidential\AllEmployees` is showing as default in Word/Excel/PowerPoint | Visual user-side confirmation |
| 3 | **Day 1–3:** ask the pilot mailbox owner to **try sending a labelled document externally** — confirm the DLP policy hit shows up in Activity Explorer (no user block — simulation mode) | Confirms DLP is wired correctly |
| 4 | **Day 3:** review **DLP Activity Explorer** for any unexpected match patterns (e.g. internal departments routinely sending labelled content out — likely a misconfigured customer process, not a script bug) | Telemetry-driven view of what *would* be blocked |
| 5 | **Day 5:** spot-check audit log entries via the Purview portal to confirm `UnifiedAuditLog` is capturing label apply/change events | Confirms Tenant Settings step worked |

### Comms expectation for the customer

Users **will** see new labels in Outlook/Word/Excel/PowerPoint on day 1.
They **will not** be blocked from anything yet (DLP is in simulation).
The footer / watermark are **not yet visible** unless `EnableContentMarking
= $true` was set in config — by default they aren't shown until the day-30
review.

---

## Phase 3 — Day 30 promote-from-simulation gate

This is the conversation most deploys skip — and it's the one that decides
whether DLP becomes real protection or shelfware.

### Inputs to the conversation

1. **DLP Activity Explorer report** — see [DLP-Simulation-Exit-Runbook.md](DLP-Simulation-Exit-Runbook.md) for how to pull "what would have been blocked" and how to read it.
2. **Helpdesk ticket count** related to labels / DLP since day-of.
3. **Pilot mailbox feedback** — did anyone complain about labels appearing, footers appearing, or anything else?

### Decisions to make and document

| Decision | Options | How to action |
|---|---|---|
| Promote DLP out of simulation? | Promote / extend simulation / refine policy first | If promote: flip `DlpStartInSimulation = $false` in `PurviewConfig.psd1` and re-run; or toggle in Purview portal per policy |
| Turn on content marking (footers + HC watermark)? | Yes / no | Flip `EnableContentMarking = $true` in `PurviewConfig.psd1` and re-run |
| Tighten Endpoint DLP from `Audit` to `Block` / `Warn`? | (E5 only) | Edit `EndpointDlpRestrictions[].Value` in `PurviewConfig.psd1` and re-run |
| Reconfirm retention strategy | Enable (`-ApplyRetention`) / keep disabled / change duration | If enabling for the first time: pass `-ApplyRetention` on the re-run. If already enabled: edit `Retention.DurationDays` in `PurviewConfig.psd1` and re-run. **Critical for regulated verticals — see [Retention-Default-Risk.md](Retention-Default-Risk.md)** |
| Add SharePoint / OneDrive to retention scope? | Yes / no | Add `'SharePoint'` / `'OneDrive'` to `Retention.Locations` |

### Output

A signed-off (email is fine) "Phase 3 outcome" note on the customer record
listing the four decisions above and the timestamp of the re-run that
applied them. Without this, three months later nobody can answer *"is this
tenant in production-grade Purview, or still in simulation?"*

---

## Known sharp edges

These are NOT bugs. They are defaults the toolkit ships with that are
correct technically but require a conversation with the customer. Cover
them in Phase 0.

### 1. Encrypted-label rights are tenant-scoped, but not retroactive

The two Template-encrypted Highly Confidential sub-labels (`All
Employees`, `Internal Exception`) grant rights via the `{TenantDomain}`
token in `EncryptionRightsDefinitions`. At run time the toolkit resolves
this against your auto-discovered tenant identity (default verified
domain, falling back to your initial `*.onmicrosoft.com`). Per Entra
rights-management semantics, ANY verified domain expands to ALL verified
domains in your tenant — so the rights bundle is scoped to **all users
in your tenant only**, explicitly excluding B2B guests attached to OTHER
tenants, social/MSA accounts, OTP users, and `AuthenticatedUsers` from
other M365 tenants.

The two HC sub-labels use **different rights bundles** by design:

| Label | Bundle | Office co-authoring (rights side) | Copy / Print / Macros |
|---|---|---|---|
| `Highly Confidential\All Employees` | Co-Author (per-label override) | ✅ | ✅ |
| `Highly Confidential\Internal Exception` | Reviewer (global default) | ❌ | ❌ |

Co-Author adds `EXTRACT`, `PRINT`, `OBJMODEL` on top of Reviewer.
OBJMODEL grants Office object-model access — necessary for macros and
for Office simultaneous editing on encrypted files (but **not
sufficient** for the latter; the tenant-wide `-EnableLabelCoAuthoring`
switch must also be enabled — see §6 below).

**This is a default change.** Older deployments used
`AuthenticatedUsers`, which DID include external authenticated users.
If your tenant has been running an older version of the toolkit, files
labelled BEFORE this change carry the older, broader rights — Microsoft
Rights Management embeds the use-license at the moment of protection.
Tightening the label template does NOT retroactively revoke external
access to previously-labelled files.

**Mitigation when promoting this change:**
- Communicate to file owners that the new scope only applies to NEW
  label applications and to files that get re-labelled.
- To tighten retroactively for sensitive existing files, ask owners to
  re-apply the label (or remove and re-apply) — this re-issues the
  use-license under the new scope.
- If you intentionally need cross-tenant collaboration via the label
  (e.g. you do business with external partners who don't have a B2B
  trust into your tenant), edit `EncryptionRightsDefinitions` in
  `PurviewConfig.psd1` to use `{AuthenticatedUsers}` (or the literal
  `AuthenticatedUsers`) and document the decision. The toolkit refuses
  to silently fall back to that scope — if `{TenantDomain}` cannot be
  resolved, the labels module aborts with an actionable error.
- The two UserDefined Specific People sub-labels are unaffected by this
  scope — the message / file author picks the recipients each time.

### 2. `Highly Confidential\Specific People` (and `Confidential\Specific People`) prompt the user

Both Specific People sub-labels apply UserDefined encryption: Outlook
auto-applies Do Not Forward, and Word/Excel/PowerPoint ask the user to
pick who can open the file. Most users have no idea what to do with
that dialog and either cancel or grant overly broad rights.

**Mitigation.** Either don't publish these sub-labels to end users
(neither is in `LabelPolicy.PublishedLabels` by default — good), or
include a 30-second explainer in the user comms before publishing them.

### 3. Container labels are one-way

Once `Group.Unified` `EnableMIPLabels=True` is set (which the toolkit
does by default on every run, because Business Premium is the licensing
floor and BP includes Entra ID P1 — the AAD-side requirement),
Microsoft does not officially support flipping it back to `False`. You
can apply labels to Groups / Teams / SPO sites freely from then on, but
the *capability* is permanent.

In addition, the 3 **published** labels (`General`,
`Confidential\All Employees`, `Highly Confidential\All Employees`)
ship with container scope (`Site`, `UnifiedGroup`) in their
`ContentType` so they are selectable when a user creates a new Team
or M365 Group. The toolkit's adoption path uses UNION-not-replace:
any container-scope bits a customer has previously added in the portal
are preserved, and re-running the deploy is a no-op when the live set
already covers the desired set.

**Mitigation.** Treat the default-on behaviour as *decision-grade* —
confirm with the customer before the first run. Pass
`-SkipContainerLabels` to opt out (this strips both the tenant toggle
AND the per-label container bits). License auto-detect skips it
automatically on tenants where no recognised M365 BP/E5/Purview Suite
SKU is found (e.g. an E3-only tenant without Entra ID P1).

### 4. Endpoint DLP without device onboarding is theatre

The Endpoint DLP policy is created in simulation mode (or enforce mode if
`DlpStartInSimulation = $false`), but it can only fire on devices that
have been **onboarded into Microsoft Defender / Purview compliance**. On
a tenant with no onboarded devices, the policy looks deployed and
enforces nothing — silently.

**Mitigation.** Confirm Defender device onboarding is in place (or
planned) before relying on Endpoint DLP for compliance reporting. The
Purview portal → Settings → Device onboarding page lists onboarded
devices.

### 5. 7-year retention default deletes mail at the 7-year mark

See [Retention-Default-Risk.md](Retention-Default-Risk.md) — this is the
biggest single bear-trap in the default config.

---

## Comms templates

Drop these into the customer's user comms tool (or an email blast). Edit
the bracketed bits.

### Day-before template

> Subject: Heads-up — small change to Office files and email tomorrow
>
> Tomorrow [DATE], our team will turn on Microsoft Purview's standard
> data-protection settings in our Microsoft 365 tenant.
>
> **What you'll see.** A new "Sensitivity" button at the top of Word,
> Excel, PowerPoint, and Outlook. New emails will default to a label
> called *General* — leave it as-is unless you know the content needs a
> stronger label.
>
> **What's changing.** Nothing about the way you work. You will not be
> blocked from any task during this rollout. We're collecting telemetry
> for 30 days, then deciding which restrictions to switch on.
>
> Questions: [helpdesk channel].

### Day-of "deploy complete" template

> Subject: Microsoft Purview baseline is live
>
> The Purview baseline rollout completed at [TIMESTAMP] today. New labels
> are now available in Word / Excel / PowerPoint / Outlook. DLP policies
> are running in **monitoring mode for the next 30 days** — nobody is
> being blocked from sending or sharing yet.
>
> On [DATE + 30 DAYS] we'll review what those policies *would* have
> blocked and decide together which ones to enforce.
>
> Questions: [helpdesk channel].

### Day-30 "we're turning enforcement on" template (send only after Phase 3 decision)

> Subject: Sharing / sending blocks start [DATE]
>
> Following the 30-day Purview monitoring period, on [DATE] the following
> DLP policies will start **blocking** [Exchange / SharePoint / OneDrive
> / Endpoint] activity for content labelled *Confidential* or *Highly
> Confidential*:
>
> * [List the specific policies in plain English — e.g. "Emails labelled
>   Confidential cannot be sent to an external address."]
>
> If you have a legitimate business need to do one of the blocked
> actions, contact [helpdesk channel] and we'll review.

---

## When NOT to run this playbook

Skip the playbook if you are running into a **dedicated lab / sandbox
tenant** for engineering testing. Run it for **every customer-facing
deploy**, including renewals where you change a config flag.
