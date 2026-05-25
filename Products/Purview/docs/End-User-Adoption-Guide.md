# End-User Adoption Guide

> **Audience.** Employees of an organisation where IT is rolling out the
> SMBTool Microsoft Purview baseline. **No technical background required.**
>
> **For IT / partners:** the script handles the engineering. This document
> is what you give your users **before** the rollout so the helpdesk
> doesn't get flooded. A reusable comms kit lives at the bottom. The
> partner-side playbook is in
> [`Change-Management-Playbook.md`](Change-Management-Playbook.md).

---

## 🟢 TL;DR — what's changing in one paragraph

Your organisation is turning on Microsoft's standard data-protection
features in Microsoft 365 — **sensitivity labels** in Word / Excel /
PowerPoint / Outlook, plus **Data Loss Prevention (DLP)** rules that
will eventually stop confidential files from being shared with people
outside your organisation. **For the first 30 days nothing will block
you** — IT is in monitoring mode while everyone gets used to the new
labels. After 30 days, sharing rules switch on. Optional add-ons may
also turn on: 7-year **email retention** and **Microsoft 365 Copilot**
restrictions on Highly Confidential files.

---

## 📅 The rollout in three phases

| Phase | When | What you'll notice |
|---|---|---|
| **1. Labels arrive** | Day-of rollout | A new **Sensitivity** button appears in Word / Excel / PowerPoint / Outlook. New emails default to *General*. New documents default to *Confidential — All Employees*. **Nothing is blocked.** |
| **2. Quiet monitoring** | Day 1–30 | IT collects telemetry on what *would* be blocked. **You will still not be blocked from anything.** No pop-ups, no policy tips. |
| **3. Enforcement** | Day 30+ | Sharing rules switch on (see below). You'll see policy tips in Outlook / SharePoint / OneDrive when an action is going to be blocked. |

---

## 1️⃣ Sensitivity labels — what they look like

A **Sensitivity** button (or menu) appears at the top of Word, Excel,
PowerPoint, and Outlook. The labels you can pick are:

| Label | Use for | What it does |
|---|---|---|
| **Public** | Marketing material, public press releases | Nothing — informational only |
| **General** *(default for new emails)* | Routine internal email and documents | Nothing — informational only |
| **Confidential — All Employees** *(default for new documents)* | Internal-only contracts, plans, customer data | Adds a footer *"Classified as Confidential"* once visual marking is turned on. **Blocks external sharing after Day 30.** |
| **Highly Confidential — All Employees** | Source code, pre-announce financials, customer PII, payroll | **Encrypts the file** so it can only be opened by people in your organisation. Adds a *"HIGHLY CONFIDENTIAL"* watermark when visual marking is turned on. Blocks external sharing after Day 30. |

### What if I don't pick a label?

* **New emails** auto-get *General* — fine for routine internal traffic.
* **New documents** auto-get *Confidential — All Employees* — safe default;
  it's only a problem if you intended to share externally. In that case,
  change the label to *General* or *Public* **before** sending.
* **Existing files / emails** are not relabelled retroactively. The
  default only applies to new content.

### What if I pick a lower label by mistake?

Office will ask you to type a brief reason (a *"downgrade justification"*).
Just describe why — e.g. *"This document is being approved for external
release"*. The justification is logged for audit but doesn't go to anyone
for approval — you proceed straight away.

> 📖 Microsoft Learn: [Apply sensitivity labels to your files and email](https://support.microsoft.com/office/2f96e7cd-d5a4-403b-8bd7-4cc636bae0f9) · [Sensitivity labels in Office apps](https://learn.microsoft.com/purview/sensitivity-labels-office-apps)

---

## 2️⃣ Encryption — only on *Highly Confidential*

If you pick **Highly Confidential — All Employees** on a document:

* The file is encrypted. Anyone outside your organisation who somehow
  receives it (forwarded email, USB stick, file leak) **cannot open it**.
* Inside your organisation, every employee can open, view, edit, save,
  reply, reply-all, and forward.
* **Copy, print, and macros may be disabled** depending on how IT
  configured the rollout. If you need any of those for legitimate
  business reasons, contact the helpdesk.
* If you open the file **offline**, you have **30 days** before it
  re-checks with the server. Open it once online inside 30 days to
  reset the clock.

> 📖 Microsoft Learn: [Restrict access to content with encryption](https://learn.microsoft.com/purview/encryption-sensitivity-labels)

---

## 3️⃣ Data Loss Prevention (DLP) — what gets blocked after Day 30

Once IT promotes DLP out of monitoring mode, the following sharing
attempts will be **blocked**:

| Workload | Action | Blocked? |
|---|---|---|
| **Outlook** | Send an email labelled *Confidential* or *Highly Confidential* to an external address | ✅ Blocked |
| **Outlook** | Send the same email to an internal colleague | ❌ Not blocked |
| **SharePoint / OneDrive** | Share a *Confidential* or *Highly Confidential* file with an external person (anonymous link, guest invite) | ✅ Blocked |
| **SharePoint / OneDrive** | Share the same file with an internal colleague | ❌ Not blocked |

### What blocking looks like

* **In Outlook**, you'll see a yellow banner under the To/Cc line
  *before* you click Send: *"This message contains content that
  conflicts with a policy in your organisation."* If you click Send
  anyway it's stopped, and you (and the file owner, last modifier, and
  site admin) get notified.
* **In SharePoint / OneDrive**, when you try to share, the share
  dialog displays *"This file contains content that conflicts with a
  policy in your organisation"* and the Share button is greyed out for
  external recipients.

### Can I override?

In the default configuration there is **no self-service override** — to
unblock, contact the helpdesk and explain the business need. They can
adjust the rule or share the file through an approved channel.

> 📖 Microsoft Learn: [DLP policy tips reference](https://learn.microsoft.com/purview/dlp-policy-tips-reference) · [Use notifications and policy tips](https://learn.microsoft.com/purview/use-notifications-and-policy-tips)

---

## 4️⃣ Email retention *(only if your IT enabled it)*

If IT enabled the optional 7-year retention policy:

* Mail older than **7 years** is automatically deleted from your mailbox.
* This applies to **everything in your mailbox** — Inbox, Sent Items,
  Deleted Items, and even mail you "delete" stays for 7 years before
  hard-removal.
* You don't need to do anything. There is no toggle for you, no
  warning at deletion time, and no "trash" to recover from after
  7 years.
* If you have records you must keep longer (e.g. partnership
  agreements, IP-related correspondence) — **move the file** to a
  SharePoint document library, save the email as a `.msg` or `.pdf`
  somewhere outside your mailbox, or talk to IT about a longer
  retention policy for your team.

> 📖 Microsoft Learn: [Retention policies for Exchange](https://learn.microsoft.com/purview/retention-policies-exchange)

---

## 5️⃣ Microsoft 365 Copilot *(only if your IT enabled the AI controls)*

If IT enabled the AI governance policy:

* **Microsoft 365 Copilot will ignore *Highly Confidential* files** when
  answering your questions, summarising, or grounding responses.
* If you ask Copilot *"summarise our Q4 board pack"* and the board pack
  is labelled Highly Confidential, Copilot will respond as if it doesn't
  have access. This is by design.
* **Workaround:** label the file *Confidential — All Employees* if
  Copilot grounding is needed and the content allows it. Otherwise
  open the file yourself.

> 📖 Microsoft Learn: [Microsoft Purview data security and compliance protections for Microsoft 365 Copilot](https://learn.microsoft.com/purview/ai-microsoft-purview)

---

## ❓ Frequently asked questions

**Q. Will my old documents and emails suddenly be labelled?**
No. Existing content is not relabelled automatically. Only new content
created after the rollout receives the default labels. You can label
old content manually if you choose.

**Q. Will I be unable to send any external email?**
No. Only emails you have **explicitly labelled** *Confidential* or
*Highly Confidential* are blocked externally. Routine *General* email
flows normally.

**Q. My document auto-got** *Confidential — All Employees* **but I need to
share it externally. What do I do?**
Open the document, click **Sensitivity → General** (or **Public**),
provide a brief justification when prompted, then share normally.

**Q. Will labels and DLP work outside the office / on my home laptop?**
Yes — they are tied to your Microsoft 365 identity, not the network.

**Q. Will labels work on my phone (Outlook mobile)?**
Yes — Outlook mobile supports applying and viewing sensitivity labels.

**Q. Will a labelled file open on a non-Microsoft device (Mac, iPad, web)?**
Yes for Office apps (Word/Excel/PowerPoint/Outlook on Mac, iOS, Android,
and the web). Third-party apps that don't understand Microsoft
Information Protection may struggle with encrypted (Highly Confidential)
files.

**Q. What happens if I email a labelled doc to a personal Gmail / Hotmail?**
After Day 30, blocked. During the first 30 days, allowed but logged.

**Q. I deleted an email less than 7 years old — is it really gone?**
No — under a retention policy, items "deleted" by you are kept in a
hidden recoverable-items area until the 7-year mark. After 7 years,
they're hard-deleted.

**Q. How do labels affect Teams chat?**
Files shared in Teams chat live in OneDrive and inherit the same DLP
rules as direct OneDrive shares.

**Q. Who can I ask if a file should be labelled higher / lower?**
Your manager or the helpdesk. As a rule of thumb: if it contains
employee PII, customer PII, financials, source code, contracts, or
anything regulated — use **Confidential** or higher.

---

## 🗨️ IT comms kit (templates)

> Edit the `[bracketed]` placeholders. Send via email, Teams Announcements,
> intranet, or whatever channel reaches your users. These are the
> short-form versions — the
> [Change-Management-Playbook](Change-Management-Playbook.md) has the
> partner-detail equivalents.

### Template A — 7 days before rollout

> **Subject:** Coming next week — new Sensitivity button in Office, no
> action needed
>
> Hi team,
>
> Next [DATE], IT will turn on Microsoft Purview's data-protection
> features in our Microsoft 365 tenant. **You don't need to do
> anything to prepare** — but here's what to expect.
>
> **What you'll see on Day 1:**
> * A new **Sensitivity** button at the top of Word, Excel, PowerPoint,
>   and Outlook.
> * New emails default to *General* (no protection — same as today).
> * New documents default to *Confidential — All Employees* (no
>   visible change yet).
> * **Nothing will be blocked** during the first 30 days.
>
> **What changes after 30 days:**
> Documents and emails labelled *Confidential* or *Highly
> Confidential* won't be shareable with people outside our
> organisation. You'll see a banner before you click Send.
>
> **Want detail?** [Link to this End-User Adoption Guide].
>
> Questions: [helpdesk channel].

### Template B — Day of rollout

> **Subject:** Sensitivity labels are now live in Office
>
> Hi team,
>
> The new sensitivity labels are now available in Word, Excel,
> PowerPoint, and Outlook on your machine and on mobile. Look for the
> **Sensitivity** button.
>
> **For the next 30 days, nothing is being blocked** — you can send and
> share as usual while IT monitors. On [DATE + 30 DAYS] sharing rules
> for *Confidential* and *Highly Confidential* content switch on.
>
> Detail: [Link to this guide].
> Questions: [helpdesk channel].

### Template C — Day 30, enforcement turning on

> **Subject:** Sharing rules now active — heads-up on labelled content
>
> Hi team,
>
> The 30-day monitoring window has ended. From today, content labelled
> *Confidential* or *Highly Confidential* **cannot be sent or shared
> outside [Organisation]**:
>
> * Outlook will block external recipients.
> * SharePoint / OneDrive will block external shares.
>
> You'll see a banner in the app explaining the block when it happens.
> If you have a legitimate business need to share, contact
> [helpdesk channel] and we'll review.
>
> *General* and *Public* content is unaffected — work as normal.

---

## 📎 References

| Topic | Microsoft Learn |
|---|---|
| Sensitivity labels overview | https://learn.microsoft.com/purview/sensitivity-labels |
| Sensitivity labels in Office apps | https://learn.microsoft.com/purview/sensitivity-labels-office-apps |
| Apply a label (end-user how-to) | https://support.microsoft.com/office/2f96e7cd-d5a4-403b-8bd7-4cc636bae0f9 |
| Default sensitivity labels (the spec this toolkit is based on) | https://learn.microsoft.com/purview/default-sensitivity-labels-policies |
| Encryption with sensitivity labels | https://learn.microsoft.com/purview/encryption-sensitivity-labels |
| DLP policy tips reference | https://learn.microsoft.com/purview/dlp-policy-tips-reference |
| DLP notifications and policy tips | https://learn.microsoft.com/purview/use-notifications-and-policy-tips |
| Retention policies for Exchange | https://learn.microsoft.com/purview/retention-policies-exchange |
| Copilot data protection (Purview) | https://learn.microsoft.com/purview/ai-microsoft-purview |
| Sensitivity labels on mobile (Outlook iOS / Android) | https://learn.microsoft.com/purview/sensitivity-labels-aip |

---

## What this guide does **not** cover

This guide describes only what the SMBTool Purview baseline deploys.
Your IT team may layer additional controls on top (Conditional Access,
device compliance, MFA enforcement, mailbox auto-forward block,
external-link expiry, etc.). If you encounter behaviour that's not
described above, it's likely one of those additional controls — start
with the helpdesk.
