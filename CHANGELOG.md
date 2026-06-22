---
title: Changelog
layout: default
nav_order: 90
permalink: /changelog/
---

# Changelog
{: .no_toc }

All notable, **partner-facing** changes to the SMB Best Practice Tool are
recorded here — new features, changed defaults, fixes, and anything that
affects how you run the toolkit or what lands in a customer tenant.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project aims to follow [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

1. TOC
{:toc}

---

## How versions work here

This is an operations toolkit, so SemVer (`MAJOR.MINOR.PATCH`) is read as:

| Bump | Means | Example |
|---|---|---|
| **MAJOR** | A change to behaviour, a default, or a switch that **requires partner action** or changes what happens in a tenant. | A default flips from off to on. |
| **MINOR** | A **new** feature, switch, or product — backward compatible. | A new optional `-Switch`. |
| **PATCH** | A **bug fix** with no behaviour change for correct usage. | A connect/auth reliability fix. |

Each entry is grouped under **Added / Changed / Deprecated / Removed / Fixed /
Security**, and tagged by area (e.g. `[Purview]`, `[Site]`). Changes that have
landed but not yet been tagged in a release appear under **Unreleased**.

> 🛠 **Maintainer note.** This is the *partner-facing* counterpart to the
> internal `Skills/` decision logs (which capture the *why* in detail). Keep
> entries short and operator-focused: "what changes when I run this." When you
> cut a release, rename `Unreleased` to `vX.Y.Z — YYYY-MM-DD` and create the
> matching git tag / GitHub Release.

---

## [Unreleased]

_Nothing yet — new changes land here before the next tagged release._

---

## [1.0.0] - 2026-06-22

First versioned baseline. This release establishes version tracking; it
consolidates everything shipped to date. Highlights below are grouped for
partners onboarding customer tenants.

### Added

- **[Purview] Data Security baseline deployment** (`Deploy-PurviewBestPractice.ps1`):
  tenant settings (unified audit log, SharePoint AIP integration, PDF
  labelling), sensitivity labels (Public / General / Confidential / Highly
  Confidential + sub-labels, encryption, container scope), DLP policies, and
  optional retention — all idempotent and safe to re-run.
- **[Purview] License auto-detect** — classifies the tenant (Business Premium
  vs E5 / Purview Suite) and applies the controls that licence supports.
  Business Premium is the baseline floor; E5 / Purview Suite automatically adds
  **Endpoint DLP** (in simulation) and **AI governance / Copilot DLP**.
- **[Purview] Premium Audit** (`-EnablePremiumAudit`) and **mailbox-scoped
  `SearchQueryInitiated`** auditing — opt-in.
- **[Purview] Zero-Trust connect ladder** — Graph-first connect order, WAM
  broker support, least-privilege scopes, and automatic recovery from MSAL /
  `Microsoft.Graph.Beta` version mismatches on fresh or dirty PowerShell
  sessions.
- **[Site] GitHub Pages documentation site** (Jekyll + just-the-docs) at
  <https://amirjafarian.github.io/SMBBestPracticeTool/>, including: a visual
  **Deployment Framework**, the **What's Changing — Support Team Guide**, a
  **Configuration Reference** for `PurviewConfig.psd1`, a visual
  **Change-Management Playbook** timeline, the embedded **End-User Adoption
  Guide**, and the **Scenarios & Capabilities** reference.

### Changed

- **[Purview] Container labels are now ON by default** on Business Premium
  tenants (BP includes the required Entra ID P1). Opt out with
  `-SkipContainerLabels`. The 3 published labels also carry container scope
  (`Site`, `UnifiedGroup`).
- **[Purview] AI governance (Copilot DLP) is now default-on** for E5 / Purview
  Suite tenants (covers paid Microsoft 365 Copilot and free Copilot Chat).
  Auto-skipped on Business Premium; opt out with `-SkipAIControls`.
- **[Purview] Encryption rights are now tenant-scoped** via the
  `{TenantDomain}` token (previously `AuthenticatedUsers`, which included
  external authenticated users). `Highly Confidential \ All Employees` uses the
  Co-Author rights bundle; per-label `EncryptionRightsDefinitions` overrides are
  supported. **Note:** the tighter scope is not retroactive — re-label existing
  files to re-issue the use-license.

### Deprecated

- **[Purview] `-EnableContainerLabels`** — container labels are default-on; the
  switch is a no-op kept for backward compatibility. Use `-SkipContainerLabels`
  to opt out.
- **[Purview] `-ApplyAIControls`** — AI governance is default-on; the switch is
  a deprecated no-op. Use `-SkipAIControls` / `-BPOnly` to opt out.

### Fixed

- **[Purview] Connect / auth reliability** — hardened Connect-PurviewServices
  against MSAL "method not found", WAM `RuntimeBroker` null-refs, and
  `Microsoft.Graph.Beta` strict version pins on updated module sets.
- **[Purview] Sensitivity-label priority** — corrected priority-reorder and
  phantom sub-label slot math on modern-scheme tenants.
- **[Docs] License-scope accuracy** — corrected docs that implied the toolkit
  was Business-Premium-only, that Premium Audit was auto-detected, and that
  Endpoint DLP was out of scope. Fixed the stale retention default ("2 years" →
  7 years / 2555 days).

### Security / Safety

- **DLP ships in simulation** (`TestWithoutNotifications`) by default —
  zero user impact on day 0; promote to enforce after a Day-30 review.
- **Retention is opt-in** (`-ApplyRetention`); the 7-year mail-delete default
  must be consciously enabled and confirmed against the customer's vertical.
- **Irreversible / one-way switches default to safe** — label co-authoring
  (`-EnableLabelCoAuthoring`) is opt-in; `-BPOnly` hard-blocks E5-only features.
- Every step's disposition (ran / skipped / failed) is written to a persistent
  HTML + JSON report; secrets are stripped from reports.

---

<!-- Link references — update the compare URLs as releases are tagged. -->
[Unreleased]: https://github.com/amirjafarian/SMBBestPracticeTool/compare/v1.0.0...HEAD
[1.0.0]: https://github.com/amirjafarian/SMBBestPracticeTool/releases/tag/v1.0.0
