---
title: Changelog
layout: default
nav_order: 90
permalink: /changelog/
---

# Changelog
{: .no_toc }

All notable, **operator-facing** changes to the SMB Best Practice Tool are
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
| **MAJOR** | A change to behaviour, a default, or a switch that **requires action from whoever runs the toolkit** or changes what happens in a tenant. | A default flips from off to on. |
| **MINOR** | A **new** feature, switch, or product — backward compatible. | A new optional `-Switch`. |
| **PATCH** | A **bug fix** with no behaviour change for correct usage. | A connect/auth reliability fix. |

Each entry is grouped under **Added / Changed / Deprecated / Removed / Fixed /
Security**, and tagged by area (e.g. `[Purview]`, `[Site]`). Changes that have
landed but not yet been tagged in a release appear under **Unreleased**.

> 🛠 **Maintainer note.** This is the *operator-facing* counterpart to the
> internal `Skills/` decision logs (which capture the *why* in detail). Keep
> entries short and operator-focused: "what changes when I run this." When you
> cut a release, rename `Unreleased` to `vX.Y.Z — YYYY-MM-DD` and create the
> matching git tag / GitHub Release.

---

## [Unreleased]

_Nothing yet — new changes land here before the next tagged release._

---

## [1.1.0] - 2026-06-27

### Added

- **[Purview] Modern label-scheme publishing.** On tenants migrated to the
  modern sensitivity-label scheme, the toolkit now detects label **groups** (a
  parent that has sub-labels becomes a non-publishable container) and publishes
  only their sub-labels — the service auto-includes the parent group. It also
  substitutes a group used as the document or email default with the
  appropriate child (e.g. the Outlook default falls back from `General` to
  `General\Anyone (unrestricted)`), and excludes auto-managed group entries
  from the label-policy diff so re-runs stay idempotent. **Classic-scheme
  tenants are unchanged.** Previously, deploying to a modern-scheme tenant that
  already had the Microsoft built-in labels failed to publish with
  `Label group(s) ... can not be published`.

### Fixed

- **[Purview] No longer aborts on a localized display-name collision.** When a
  configured sub-label's display name matches an existing label's *localized*
  name under the same parent (e.g. `Specific People` vs the built-in
  `Specified People`), the toolkit now adopts the existing label instead of
  failing `New-Label` — which previously cascaded into a hard
  `Sensitivity label ... not found` stop in the DLP step.
- **[Purview] Policy default label resolves when it is an adopted sub-label.**
  Fixes `Default label 'AllEmployees' was not found after creation` on tenants
  where the default sub-label was adopted from a pre-existing built-in label
  (its live internal name is a GUID, not the configured name).

---

## [1.0.0] - 2026-06-22

**Initial versioned release.** This establishes version tracking; `1.0.0` is a
concise baseline snapshot of the toolkit as it stands today. Granular pre-1.0
development history is intentionally **not** itemised here — see the
[merged pull requests](https://github.com/amirjafarian/SMBBestPracticeTool/pulls?q=is%3Apr+is%3Amerged)
and [commit log](https://github.com/amirjafarian/SMBBestPracticeTool/commits/main)
for the detail. From the next release onward, every change is listed under its
own version above.

### What's in the box

- **[Purview] Data Security baseline** — idempotent, re-runnable deployment of
  tenant settings, sensitivity labels (encryption + container scope), DLP, and
  optional retention, all driven from one config file (`PurviewConfig.psd1`).
- **[Purview] License-aware** — auto-detects Business Premium vs E5 / Purview
  Suite and applies what the licence supports (E5 / Purview Suite additionally
  gets Endpoint DLP and AI governance / Copilot DLP).
- **[Purview] Zero-Trust connect** — Graph-first auth, WAM broker, and
  automatic recovery from common MSAL / `Microsoft.Graph.Beta` module issues.
- **[Site] Documentation site** — this GitHub Pages site: deployment framework,
  support-team guide, configuration reference, change-management timeline,
  adoption guide, and scenarios reference.

### Safety defaults

- **DLP starts in simulation** — zero user impact on day 0; promote after a
  Day-30 review.
- **Destructive / irreversible actions are opt-in** — retention
  (`-ApplyRetention`) and label co-authoring (`-EnableLabelCoAuthoring`);
  `-BPOnly` hard-blocks E5-only features.
- **Every run produces an HTML + JSON report** (secrets stripped) recording
  what ran, was skipped, or failed.

> **Upgrading from an earlier (untagged) build?** `-EnableContainerLabels` and
> `-ApplyAIControls` are now deprecated no-ops — both behaviours are default-on.
> Use `-SkipContainerLabels` / `-SkipAIControls` to opt out.

---

<!-- Link references — update the compare URLs as releases are tagged. -->
[Unreleased]: https://github.com/amirjafarian/SMBBestPracticeTool/compare/v1.1.0...HEAD
[1.1.0]: https://github.com/amirjafarian/SMBBestPracticeTool/compare/v1.0.0...v1.1.0
[1.0.0]: https://github.com/amirjafarian/SMBBestPracticeTool/releases/tag/v1.0.0
