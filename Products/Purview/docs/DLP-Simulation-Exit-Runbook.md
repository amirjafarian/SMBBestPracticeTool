---
title: DLP Simulation Exit Runbook
layout: default
parent: Purview
nav_order: 4
permalink: /purview/dlp-simulation-exit-runbook/
---

# DLP Simulation Exit Runbook

> **Audience.** The partner consultant running the Phase 3 (day-30)
> promote-from-simulation conversation with the customer. Pairs with
> [Change-Management-Playbook.md](Change-Management-Playbook.md).

By default the toolkit deploys every DLP policy in **simulation mode**
(`DlpStartInSimulation = $true` → `TestWithoutNotifications`). This is
the right default — nothing breaks on day one, telemetry accumulates,
and the customer sees what *would* have been blocked before it actually
blocks anything.

The risk is what happens at day 30: most partners either

1. **Sit there forever** because nobody knows how to read the telemetry
   (security theatre — the policies never actually enforce), or
2. **Flip enforce on without looking** (and tank legitimate outbound
   sharing on day 31, generating a helpdesk fire-drill).

This runbook gives you the exit criteria and the pull-the-report
walkthrough so you can make the decision on evidence.

---

## When to run this

Day 30 after deploy, or whenever you're about to flip a DLP policy out
of simulation. Do it **per policy**, not as a global "turn everything
on" event.

---

## Step 1 — Pull the "what would have leaked" report from Activity Explorer

This is the single most useful artifact simulation produces, and the
single most under-used feature of Purview. Most partners never open it.

### Where it lives

1. Open the **Microsoft Purview portal** (`https://purview.microsoft.com`).
2. **Solutions** → **Data loss prevention** → **Activity explorer**.
3. Filter by:
   * **Activity** = `DLP rule match`
   * **Policy** = (the policy you're reviewing)
   * **Date range** = since deploy

You'll get a row per policy hit, with the user, the file/email, the
matched label, the workload (Exchange / SPO / OneDrive / Endpoint), and
what *would* have happened (block / warn / audit).

### What to look for

| Pattern | Interpretation | Action |
|---|---|---|
| **Zero hits in 30 days** | Either the label isn't being applied (check label policy publish), or the customer genuinely doesn't share Confidential content externally | Investigate before promoting — a policy with no telemetry is a policy you can't validate |
| **A handful of hits, all from the same 1–2 users** | Likely legitimate business communication (e.g. the partner liaison emailing a quote to a known client) | Talk to those users *before* promoting; you may need an exception (allow-list domain) or business-process change |
| **Steady stream of hits across many users** | The label is being over-applied — likely `Confidential\AllEmployees` is the default for documents and people are emailing routine docs out | Tighten label defaults OR refine the DLP rule conditions OR accept that promoting will generate user friction |
| **Hits concentrated on one workload (e.g. all SPO, no EXO)** | The other workload's label adoption is lower than expected | Investigate user-side label availability (`Get-Label`, check published policy) before promoting either workload |

### Export the evidence

Click **Export** → CSV. Save to the customer record alongside the
deploy log. This is your "we made the promote-to-enforce decision based
on this telemetry" audit trail.

---

## Step 2 — Cross-check with the audit log

Activity Explorer is the DLP-specific view. For the wider picture, query
the unified audit log via PowerShell:

```powershell
# Last 30 days of DLP-related audit entries
Search-UnifiedAuditLog `
    -StartDate (Get-Date).AddDays(-30) `
    -EndDate (Get-Date) `
    -RecordType ComplianceDLPExchange,ComplianceDLPSharePoint,DLPEndpoint `
    -ResultSize 5000 |
    Group-Object -Property UserIds |
    Sort-Object Count -Descending |
    Select-Object Count, Name -First 20
```

Top-N users by DLP hit count gives you the list of people to talk to
before flipping enforce on. Two or three conversations beforehand
saves twenty helpdesk tickets after.

---

## Step 3 — Decide per policy (not globally)

For each policy in your config:

| Decision | Trigger | Action |
|---|---|---|
| **Promote to enforce** | Telemetry looks reasonable, exceptions are identified and either accepted or worked around | Flip `DlpStartInSimulation = $false` in `PurviewConfig.psd1` and re-run, OR change Mode in the Purview portal per policy |
| **Extend simulation by 30 more days** | Not enough data, or recent process change means the last 30 days isn't representative | Leave config as-is; rebook the review |
| **Refine the policy first** | Telemetry shows false positives or wrong scope (e.g. internal department gets blocked) | Edit the DLP rule conditions in `PurviewConfig.psd1` (exceptions, recipient overrides), re-run, then start a fresh 30-day window |
| **Drop the policy** | Telemetry shows the policy serves no purpose for this customer's workflow | Remove the entry from `DlpPolicies` and re-run; or `-SkipDLP` and delete manually |

---

## Step 4 — Document the decision

Add a "Phase 3 outcome" note to the customer record listing, per policy:

* Policy name
* Decision (promote / extend / refine / drop)
* Evidence cited (Activity Explorer hit count over the 30-day window)
* Timestamp and operator
* Date of next review (90 days after promote is a reasonable cadence)

Without this, three months later nobody can answer *"is this tenant in
production-grade DLP, or are the policies still in simulation?"*

---

## Endpoint DLP — extra step

For the Endpoint policy (E5 only):

1. **Confirm device onboarding.** Purview portal → Settings → Device
   onboarding. If no devices are listed, the Endpoint policy has been
   firing on zero devices — your telemetry is empty for the wrong
   reason. Onboard devices first, then start the 30-day window fresh.
2. **Promote action-by-action.** Endpoint DLP supports per-action
   modes — `CopyPaste` can be `Block` while `Print` stays `Audit`.
   The default config sets every action to `Audit`. Move to `Warn` or
   `BlockOverride` (user can override with justification) before going
   to `Block`.
3. **Test on a single device first.** Edit the policy scope in the
   portal to a pilot device group before flipping the whole tenant.

---

## How to promote out of simulation

Two ways — both work, pick whichever fits your operating model.

### Via the toolkit (preferred — consistent with re-runs)

```powershell
# Edit PurviewConfig.psd1
DlpStartInSimulation = $false

# Re-run the DLP module only
.\Deploy-PurviewBestPractice.ps1 `
    -TenantAdminUpn admin@contoso.onmicrosoft.com `
    -SkipTenantSettings -SkipLabels -ApplyRetention
```

This flips **every** DLP policy in the config to enforce mode. If you
want per-policy control, use the portal route below.

### Via the Purview portal (per-policy control)

1. Purview portal → DLP → Policies → click the policy.
2. **Edit policy** → step through to **Policy mode** → choose **Turn it on right away** or **Test it out first → Turn the policy on if it's not edited within fifteen days of simulation**.
3. Save.

> **Important.** On the next toolkit re-run, the toolkit reconciles
> policy mode against config. If you flip a policy to Enable in the
> portal but leave `DlpStartInSimulation = $true` in the config, the
> next run pulls the policy back to simulation. Either flip the config
> flag, use `-SkipDLP`, or commit to portal-only operation for that
> policy.

---

## Related reading

* [Change-Management-Playbook.md](Change-Management-Playbook.md) — Phase 3 step references this runbook.
* [Scenarios.md](Scenarios.md) — Scenario 3 documents the DLP module behaviour and simulation reconciliation on re-runs.
* Microsoft Learn — [Get started with Activity Explorer](https://learn.microsoft.com/en-us/purview/data-classification-activity-explorer).
* Microsoft Learn — [Test or simulate DLP policies](https://learn.microsoft.com/en-us/purview/dlp-test-dlp-policies).
