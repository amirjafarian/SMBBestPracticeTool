---
title: Deployment Framework (Visual)
layout: default
parent: Purview
nav_order: 8
permalink: /purview/deployment-framework/
---

# Purview Deployment Framework — visual model
{: .no_toc }

An interactive, at-a-glance model of **how** this toolkit deploys the Microsoft
Purview Data Security baseline — from **pre-deployment** preparation, through the
**safe + simulated** deployment run, to **post-deployment** promotion and
operation.

It exists so that anyone — a partner delivery lead, a reviewer, or a customer
stakeholder — can understand the **method** and the **goal** in one screen,
without reading the scripts: *deploy safe, simulate, and only promote to
enforcement after a human passes a Day-30 gate.*

> 🎫 **License-aware scope.** Business Premium is the **baseline floor**, not the
> ceiling. The toolkit auto-detects the tenant's licensing and applies the
> controls that licence supports. A **BP** tenant gets Exchange +
> SharePoint/OneDrive DLP and the core baseline; on an **E5 / Microsoft Purview
> Suite** tenant license detection automatically adds **Endpoint DLP** (device
> copy / print / USB, created in simulation) and **AI governance (Copilot DLP)**.
> Higher-SKU extras like **Premium Audit** (`-EnablePremiumAudit`) and
> **retention** (`-ApplyRetention`) stay **opt-in**. E5-only workloads are
> *soft-skipped* (not failed) on BP, and `-BPOnly` hard-skips them even when the
> SKU is present.

[Open the framework full-screen ↗]({{ '/Products/Purview/docs/Deployment-Framework.html' | relative_url }}){: .btn .btn-purple target="_blank" }
[Download the standalone file ↗]({{ '/Products/Purview/docs/Deployment-Framework.html' | relative_url }}){: .btn target="_blank" download }

> 💡 The framework below is a **single self-contained HTML file**
> (`Products/Purview/docs/Deployment-Framework.html`). It has its own theme and
> needs no server, so you can share it on its own — email it, drop it in a deck
> appendix, or open it offline — and it still works.

---

<iframe
  src="{{ '/Products/Purview/docs/Deployment-Framework.html' | relative_url }}"
  title="Purview Deployment Framework"
  style="width:100%; height:1180px; border:1px solid #dedede; border-radius:12px;"
  loading="lazy">
</iframe>

---

## What the model shows

The framework breaks the deployment into **seven phases** across three stages:

| Stage | Phases | What it means |
|---|---|---|
| 🟡 **Pre-deployment** | 0 · Prepare | Scope, prerequisites, pilot plan, customer change-management — *no tenant changes yet*. |
| 🔵 **Deployment** | 1 · Connect → 2 · Assess → 3 · Configure → 4 · Soak &amp; Simulate | The app run. Zero-Trust connect, license-aware gating, idempotent baseline, and **DLP created in simulation mode** with zero user impact. |
| 🟢 **Post-deployment** | 5 · Promote → 6 · Adopt &amp; Operate | The Day-30 human gate that promotes DLP from simulation to enforcement, then end-user adoption and ongoing operation. |

Click any phase in the framework to expand **what happens**, **how the app does
it** (the method), the **safety gate**, and the **rollback path**.

## The signature method

The whole model is built around one idea that makes tenant-wide change safe for
an SMB:

> **DLP ships in *simulation* and only enforces after a Day-30 promotion gate.**

Every phase also obeys five cross-cutting principles — idempotent
read-modify-write, simulation-before-enforcement, least-privilege Zero-Trust
auth, every-disposition-audited reporting, and irreversible-operations-are-opt-in.
These are the same conventions the codebase itself is held to.

## Where the detail lives

The framework is a map, not the territory. Each phase links to the authoritative
docs:

- [Scenarios &amp; Capabilities](scenarios/) — what every task does and what's out of scope.
- [Configuration Reference](configuration-reference/) — every `PurviewConfig.psd1` knob and how to change it.
- [Change-Management Playbook](change-management-playbook/) — the day-by-day delivery runbook.
- [DLP Simulation Exit Runbook](dlp-simulation-exit-runbook/) — the Day-30 promotion gate.
- [Retention Default — Risk Note](retention-default-risk/) — before you pass `-ApplyRetention`.
- [End-User Adoption Guide](end-user-adoption-guide/) — the T-7 / T-0 / T+30 comms.
