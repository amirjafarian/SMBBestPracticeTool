# Retention Default — Risk Note

> **Read this before passing `-ApplyRetention`.** Retention is opt-in
> as of the current toolkit version, but when you do enable it the
> shipped default deletes Exchange mail older than 2 years and is
> **wrong for most regulated SMBs**.

---

This page answers a simple question: **the default retention duration
shipped in `PurviewConfig.psd1` is 2 years — when is that wrong, and
what should you do instead?**

Retention is **opt-in** as of the current toolkit version (you must
pass `-ApplyRetention` to enable it). This page exists so that when you
decide to opt in, you also pick the right duration for the customer's
vertical.

---

## What the toolkit does when you opt in

`PurviewConfig.psd1` ships with:

```powershell
Retention = @{
    Name         = 'SMBTool - Exchange 2-year retention'
    DurationDays = 730           # 2 years
    Action       = 'KeepAndDelete'
    Locations    = @('Exchange')
}
```

This creates a tenant-wide retention policy that:

* Applies to **every mailbox** in the tenant.
* **Deletes** any item once it is 2 years old (measured from item creation).
* Is **irreversible for non-litigation-hold mailboxes** — deleted mail
  cannot be recovered after the retention deletion sweep runs.
* Does not affect SharePoint / OneDrive (those locations are not in the
  default scope, but you can add them).

---

## Why this is risky

Two years is a sensible default for an unregulated 10-person services
firm. It is **the wrong number** for several common SMB partner segments
that the toolkit is otherwise well-suited to:

| Vertical | Typical regulatory retention requirement | Citation / source of obligation |
|---|---|---|
| **Law firms** | 7 years (and the file's life span where longer) | State bar rules of professional conduct (e.g. ABA Model Rule 1.15 in the US — varies by jurisdiction) |
| **Accounting / tax** | 7 years (often + indefinite for audit working papers) | Local tax authority rules (e.g. ATO 5 years AU; IRS 7 years US) |
| **Healthcare** | 6–10+ years (and longer for paediatric records) | HIPAA in US; equivalent national rules elsewhere |
| **Financial advisors / brokers** | 5–7 years | SEC Rule 17a-4 (US); ASIC RG 78 (AU) |
| **Construction / engineering** | 7–10 years post-completion | Statute-of-repose periods on workmanship |
| **Real estate** | 7 years | State / territory real-estate licensing acts |

The 2-year default is acceptable for **general professional services
without a regulatory framework**, and even there it should be a
**conscious choice**, not a side-effect of running the toolkit.

---

## What "lost mail" looks like in practice

Six weeks after a 2-year-default deploy, a partner's helpdesk gets a
ticket like:

> "I'm trying to find the email from [client] from 2022 about [matter].
> It's not in Outlook search, not in Deleted Items, not in Recoverable
> Items. Where is it?"

The answer, if the customer hadn't been told, is "the retention policy
deleted it three weeks ago." There is no recovery short of a Microsoft
support ticket for a backup restore from before the deletion sweep — and
those windows are short (~14 days).

For a regulated customer, the same conversation can be a **professional
liability incident**.

---

## What to do instead

Pick one of the following before deploy:

### Option A — Match the vertical (recommended)

Edit `PurviewConfig.psd1` to match the customer's regulatory floor:

```powershell
Retention = @{
    Name         = 'SMBTool - Exchange 7-year retention (law firm)'
    Comment      = 'Retains Exchange mailbox content for 7 years from creation, then deletes. Aligned to state bar record-keeping requirements.'
    DurationDays = 2555          # 7 years
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

### Option C — Don't enable retention yet (now the default)

Retention is **opt-in** as of the current toolkit version — pass
`-ApplyRetention` to enable. Run the script without it, work the
duration decision with the customer separately, then re-run **only**
the retention module once the duration is agreed:

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
Until they ship, **the partner owns the duration decision**. Document
the chosen duration on the customer record before deploy, and revisit
on every renewal.

---

## What about the existing customer mail older than the new duration?

Deploying a 2-year retention policy onto a tenant whose oldest mail is
6 years old will, over the following days, **start deleting all mail
between 2 and 6 years old**.

The deletion is **not instantaneous** — the service-side retention
sweep runs continuously and works through old mail over hours / days.
The window between deploy and "mail starts disappearing" is short
enough that customers will not notice in time to stop it.

Mitigations:

1. **Don't enable retention yet** (the default — just omit `-ApplyRetention`)
   when the tenant has mail older than the planned retention duration.
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
