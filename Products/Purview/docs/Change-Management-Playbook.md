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
* `-EnableContainerLabels` — accept the auto-detect default, or override
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

### 1. `AuthenticatedUsers` is not the same as "internal only" when B2B guests exist

The three encrypting labels (`Confidential`, `Confidential\AllEmployees`,
`Highly Confidential` and its sub-labels) grant rights to
`AuthenticatedUsers`. **A B2B guest in the customer tenant counts as
authenticated.** If the customer has invited their accountant, lawyer, or
MSP staff as guests, those guests can open the protected files.

**Mitigation.** Either restrict the encryption rights to a specific group
(edit `EncryptionRightsDefinitions` in `PurviewConfig.psd1`), or audit the
customer's guest list before deploy and confirm the guest set is
intentional.

### 2. `Highly Confidential\Specific People` prompts the user

This label asks the user, in Word/Excel/PowerPoint, to pick who can open
the file. Most users have no idea what to do with that dialog and either
cancel or grant overly broad rights.

**Mitigation.** Either don't publish this sub-label to end users (it's
**not** in `LabelPolicy.PublishedLabels` by default — good), or include a
30-second explainer in the user comms.

### 3. Container labels are one-way

Once `Group.Unified` `EnableMIPLabels=True` is set (via
`-EnableContainerLabels`), Microsoft does not officially support flipping
it back to `False`. You can apply labels to Groups / Teams / SPO sites
freely from then on, but the *capability* is permanent.

**Mitigation.** Treat the `-EnableContainerLabels` switch as
*decision-grade* — get a yes from the customer before passing it. The
script's license auto-detect only auto-enables it when the tenant has
E5 / Purview Suite, but you can still opt in manually on Business
Premium tenants with the right license stack.

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
