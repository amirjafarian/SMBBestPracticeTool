---
title: Retention Default — Risk Note
layout: default
parent: Purview
nav_order: 5
permalink: /purview/retention-default-risk/
---

# Retention Default — Risk Note

> **Read this before passing `-ApplyRetention`.** Retention is opt-in
> as of the current toolkit version. The shipped default retains
> Exchange mail for 7 years then deletes it. That duration aligns with
> most common SMB regulatory frameworks but is still a **tenant-wide
> destructive policy** — you should consciously confirm it's the right
> number for the customer before enabling.

---

This page answers a simple question: **the default retention duration
shipped in `PurviewConfig.psd1` is 7 years — when is that right, when
is it wrong, and what should you do if it's wrong?**

Retention is **opt-in** as of the current toolkit version (you must
pass `-ApplyRetention` to enable it). This page exists so that when you
decide to opt in, you also confirm the duration is right for the
customer's vertical.

---

## What the toolkit does when you opt in

`PurviewConfig.psd1` ships with:

```powershell
Retention = @{
    Name         = 'SMBTool - Exchange 7-year retention'
    DurationDays = 2555          # 7 years
    Action       = 'KeepAndDelete'
    Locations    = @('Exchange')
}
```

This creates a tenant-wide retention policy that:

* Applies to **every mailbox** in the tenant.
* **Deletes** any item once it is 7 years old (measured from item creation).
* Is **irreversible for non-litigation-hold mailboxes** — deleted mail
  cannot be recovered after the retention deletion sweep runs.
* Does not affect SharePoint / OneDrive (those locations are not in the
  default scope, but you can add them).

---

## Why 7 years is a reasonable default

Seven years aligns with the record-keeping floor for most common SMB
verticals the toolkit serves:

| Vertical | Typical regulatory retention requirement | Citation / source of obligation |
|---|---|---|
| **Law firms** | 7 years (and the file's life span where longer) | State bar rules of professional conduct (e.g. ABA Model Rule 1.15 in the US — varies by jurisdiction) |
| **Accounting / tax** | 5–7 years (often + indefinite for audit working papers) | Local tax authority rules (e.g. ATO 5 years AU; IRS 3–7 years US) |
| **Financial advisors / brokers** | 5–7 years | SEC Rule 17a-4 (US); ASIC RG 78 (AU); Sarbanes-Oxley 7 years |
| **General SMB / professional services** | No formal requirement; 7 years matches the broader regulatory floor and is a safe ceiling | — |

The default was raised from 2 years to 7 years (see issue #8) to align
with this regulatory floor. For customers in these verticals you can
keep the default unchanged.

---

## When 7 years is still wrong

The default is **not universally right**. Confirm it against the
customer before deploying:

| Scenario | Why 7 years is wrong | What to do |
|---|---|---|
| **Paediatric healthcare records** | Many jurisdictions require records to be kept until the patient reaches age of majority + N years — often 18-25+ years total | Edit `DurationDays` to a much longer value, or use `Action = 'Keep'` (no automatic deletion) |
| **Construction / engineering with statute-of-repose exposure** | Statute-of-repose periods on workmanship can run 10–15 years post-completion | Edit `DurationDays` to match the longest applicable statute-of-repose |
| **Customer wants no automatic deletion at all** | Some customers want a retention guarantee without a deletion event — e.g. ongoing litigation hold expected, family-business archives, professional advisors who keep client records indefinitely | Set `Action = 'Keep'` (retains for the duration, never deletes) or skip retention entirely (omit `-ApplyRetention`) |
| **Tenant has mail older than 7 years that the customer wants to keep** | Deploying the policy starts deleting that mail immediately | Place affected mailboxes on Litigation Hold first, or skip retention until the customer has reviewed the old mail |
| **Jurisdiction-specific shorter requirement (e.g. some EU GDPR scenarios)** | GDPR data minimisation principles may require *shorter* retention for certain personal-data categories | Edit `DurationDays` lower; consider per-data-category retention labels instead of a tenant-wide policy |

---

## What "lost mail" looks like in practice

Six weeks after a default deploy onto a tenant that already had mail
older than 7 years, a partner's helpdesk gets a ticket like:

> "I'm trying to find the email from [client] from 2017 about [matter].
> It's not in Outlook search, not in Deleted Items, not in Recoverable
> Items. Where is it?"

The answer, if the customer hadn't been told, is "the retention policy
deleted it three weeks ago." There is no recovery short of a Microsoft
support ticket for a backup restore from before the deletion sweep — and
those windows are short (~14 days).

For a regulated customer this can be a **professional liability incident**
even if the deletion was technically compliant — the customer's expectation
matters, not just the regulator's floor.

---

## What to do instead

Pick one of the following before deploy:

### Option A — Match the vertical's longer requirement

If 7 years is too short for the customer (paediatric healthcare,
long-life construction warranties, etc.), edit `PurviewConfig.psd1`:

```powershell
Retention = @{
    Name         = 'SMBTool - Exchange 15-year retention (construction)'
    Comment      = 'Retains Exchange mailbox content for 15 years from creation, then deletes. Aligned to statute-of-repose period.'
    DurationDays = 5475          # 15 years
    Action       = 'KeepAndDelete'
    Locations    = @('Exchange')
}
```

For SharePoint / OneDrive, add them to `Locations`:

```powershell
    Locations    = @('Exchange', 'SharePoint', 'OneDrive')
```

### Option B — `Keep` instead of `KeepAndDelete`

Hold mail for the duration without deleting at the end. Useful when the
customer wants a litigation-hold-style policy without a fixed deletion
date:

```powershell
    Action       = 'Keep'
```

This stops nothing being deleted by *this* policy. (Users can still
delete their own mail; the policy retains a copy in Recoverable Items
for the duration.)

### Option C — Don't enable retention yet (default behaviour)

Retention is **opt-in** — pass `-ApplyRetention` to enable. Run the
script without it, work the duration decision with the customer
separately, then re-run **only** the retention module once the duration
is agreed:

```powershell
.\Deploy-PurviewBestPractice.ps1 `
    -TenantAdminUpn admin@contoso.onmicrosoft.com
# (retention is skipped — banner shows "[ ] Retention" and the summary reports
#  "Skipped (opt-in — pass -ApplyRetention to enable; see docs/Retention-Default-Risk.md)")

# ...have the retention conversation, edit PurviewConfig.psd1 if needed...

# Then run the retention step on its own:
.\Modules\Setup-Retention.ps1 -Config (Import-PowerShellDataFile .\Config\PurviewConfig.psd1)

# Or re-run the orchestrator with everything else skipped:
.\Deploy-PurviewBestPractice.ps1 `
    -TenantAdminUpn admin@contoso.onmicrosoft.com `
    -SkipTenantSettings -SkipLabels -SkipDLP `
    -ApplyRetention
```

---

## Why the toolkit doesn't ship per-vertical presets (yet)

Per-vertical presets (law / accounting / healthcare / construction /
generic) are a planned future enhancement — see the repo issues list.
Until they ship, **the partner owns the duration decision** even though
the default now aligns with the most common SMB floor. Document the
chosen duration on the customer record before deploy, and revisit on
every renewal.

---

## What about existing customer mail older than the retention duration?

Deploying the 7-year retention policy onto a tenant whose oldest mail
is 10 years old will, over the following days, **start deleting all
mail between 7 and 10 years old**.

The deletion is **not instantaneous** — the service-side retention
sweep runs continuously and works through old mail over hours / days.
The window between deploy and "mail starts disappearing" is short
enough that customers will not notice in time to stop it.

Mitigations:

1. **Don't enable retention yet** (the default — just omit `-ApplyRetention`)
   when the tenant has mail older than the planned retention duration
   that the customer wants to keep.
2. **Place affected mailboxes on Litigation Hold** before the policy
   takes effect — Litigation Hold supersedes retention deletion.
3. **Roll out to a single pilot mailbox first** by editing the policy
   scope (this requires a manual portal change post-deploy; the
   toolkit's default scope is tenant-wide).

---

## Related reading

* [Change-Management-Playbook.md](Change-Management-Playbook.md) — Phase 0
  decisions include retention duration and Phase 3 includes a
  "reconfirm retention" gate.
* [Scenarios.md](Scenarios.md) — Scenario 4 documents the retention
  module's defaults and tunables.
* Microsoft Learn — [Retention policies and retention labels](https://learn.microsoft.com/en-us/purview/retention).
* Microsoft Learn — [Litigation Hold](https://learn.microsoft.com/en-us/purview/ediscovery-create-a-litigation-hold).
