# Copilot instructions for SMBBestPracticeTool

PowerShell automation that configures Microsoft 365 tenants against Microsoft's
recommended best-practice baselines. `Products/<Product>/` is the layout for
each product; today the only shipped product is **Purview**
(`Products/Purview/`). Everything below is Purview-specific unless noted.

## Validating changes (there is no Pester/unit-test suite)

This repo has no automated test framework. Validation is two-layered:

1. **Syntax/parse-check a single file** (fast, no tenant needed) — the
   equivalent of "run one test":
   ```powershell
   $errs = $null; $toks = $null
   [System.Management.Automation.Language.Parser]::ParseFile('Products\Purview\Modules\Setup-DLP.ps1', [ref]$toks, [ref]$errs)
   if ($errs) { $errs | ForEach-Object { $_.Message } } else { 'OK' }
   ```
2. **`-WhatIf` dry run against a real (pilot) tenant** — every module wires
   `SupportsShouldProcess`, so a full `-WhatIf` pass previews every
   state-changing call without applying it:
   ```powershell
   cd Products/Purview
   .\Deploy-PurviewBestPractice.ps1 -TenantAdminUpn admin@contoso.onmicrosoft.com -WhatIf
   ```
   Each `Setup-*.ps1` module under `Modules/` is self-contained and can also be
   invoked standalone (it takes `-Config <hashtable>` from
   `Config/PurviewConfig.psd1` plus its own switches) to iterate on one task
   without running the whole orchestrator.

There is no lint config (no PSScriptAnalyzer settings file) and no CI beyond
GitHub Pages' automatic build/deploy for the docs site.

**Docs site local preview** (Jekyll, only needed when editing `*.md` under
`Products/Purview/docs/` or site config):
```powershell
bundle install          # one-time, needs Ruby
bundle exec jekyll serve # http://127.0.0.1:4000/SMBBestPracticeTool/
```

## Architecture: how a deployment run flows

`Deploy-PurviewBestPractice.ps1` is the orchestrator. It does NOT dot-source
its modules — each task is invoked as a **separate script process**
(`& $script @taskArgs`), so every `Modules/Setup-*.ps1` is independently
runnable and testable on its own:

1. `Connect-PurviewServices.ps1` — connects Graph (first, to avoid an MSAL DLL
   version race with EXO), Exchange Online, Security & Compliance (IPPS), and
   SharePoint Online. Returns/consumes a tenant-identity object used to resolve
   the `{TenantDomain}` encryption-scope token.
2. `Setup-TenantSettings.ps1` — audit log, SPO/AIP integration, PDF labels,
   container labels, label co-authoring.
3. `Setup-SensitivityLabels.ps1` — creates/adopts labels from
   `Config/PurviewConfig.psd1`, sets priority order, publishes the policy.
4. `Setup-DLP.ps1` — DLP policies/rules that reference labels **by resolved
   GUID**, never by display name.
5. `Setup-Retention.ps1` — opt-in only (`-ApplyRetention`; destructive default).
6. `Setup-AIGovernance.ps1` — Copilot DLP policies (E5/Purview Suite only).

Shared building blocks every module dot-sources:
- `Invoke-WithTransientRetry.ps1` — the ONLY retry mechanism; wraps IPPS/EXO/
  SPO/Graph calls with backoff+jitter and auto-emits run-log entries. Never
  hand-roll a retry loop.
- `PurviewRunLog.ps1` — `Add-RunLogEntry`, the structured logger every
  observable action must call (see below).
- `Write-PurviewHtmlReport.ps1` — renders the run log into the end-of-run
  HTML + JSON report (secrets stripped).

All tunables (label names/taxonomy, DLP policies, retention duration,
encryption rights) live in **`Config/PurviewConfig.psd1`** — never hardcode a
label name, policy name, or duration in a module; add/edit a config key
instead.

## Key conventions

- **Idempotency is read-modify-write, always.** `Get-*` current state first;
  if present and matching intent, no-op; if present and different, merge the
  change into the existing object (never overwrite other fields customers may
  have set by hand or with another tool). Every object the toolkit creates is
  stamped with `ManagedByTag` (`Config/PurviewConfig.psd1`,
  `'[Managed by SMBTool Purview Toolkit]'`) so re-runs can recognize their own
  objects; an unstamped existing object with the same name aborts the run
  unless `-AdoptExisting` is passed.
- **Labels are matched/adopted by a stable internal signature, not
  DisplayName.** Built-in Microsoft labels carry a `BuiltInName` field in
  config (`defa4170-0d19-0005-NNNN-bc88714345d2`) — this is what makes
  adoption work across locales and both classic/modern label schemes.
  Never match a label by its (localized, mutable) `DisplayName`.
- **DLP/AI rules bind labels by resolved GUID, never by name.** A persisted
  rule's label operand legitimately shows `name == id == <GUID>` — that's
  correct, not a bug.
- **Run-log discipline (`Add-RunLogEntry`)**: every observable action —
  including a step that was *skipped* — must emit an entry, not just a
  `Write-Host` line. `-Status` is a hard `ValidateSet`:
  `Started, Succeeded, Created, Updated, Adopted, Skipped, Failed, Retried, Info`
  — **`Warning` is NOT valid** and throws a binding error. Use `Info` (detail
  prefixed `WARNING:`) or `Skipped` instead.
- **License gating**: `-BPOnly` blocks any E5/Purview-Suite-only feature;
  `-NoLicenseAutoDetect` disables the `/subscribedSkus` auto-detect;
  per-feature `-Skip<X>` switches are the operator's opt-out. A `-Skip*`
  switch is an escape hatch, not a fix — if a feature is failing, fix the
  root cause rather than reaching for the skip switch.
- **Irreversible/one-way tenant operations must be opt-in switches**, never
  default-on, with the irreversibility called out in `.PARAMETER` help and
  linked to the Microsoft Learn page describing it (e.g.
  `-ApplyRetention`, `-EnableLabelCoAuthoring`).
- **Documentation parity**: a code change that alters operator-facing
  behaviour (defaults, licensing, opt-in switches, output) must update every
  doc describing that behaviour in the same commit —
  `Products/Purview/README.md`, `Products/Purview/docs/*.md`, and the
  matching `.html` companions (`End-User-Adoption-Guide.html`,
  `What-This-Tool-Does.html`, `Change-Management-Playbook.html` are richly
  styled standalone artifacts embedded via `<iframe>`, not generated from the
  `.md` — edit both).
- **Docs must be audience-neutral** — the toolkit is run by partners/MSPs
  *and* in-house IT teams; don't address the reader as "the partner". Prefer
  "the deployment team" / "whoever runs the toolkit" / "you".
- **Versioning (`CHANGELOG.md`, Keep a Changelog + SemVer)**: MAJOR = a new
  *product* added to the toolkit (e.g. a future Defender product); MINOR = a
  new feature or a redesign within an existing product; PATCH = a bug fix
  with no behaviour change. A changed default does not by itself force MAJOR.
- **Commit messages**: imperative-mood subject ≤72 chars; body explains *why*.
  Append `Co-authored-by: Copilot <223556219+Copilot@users.noreply.github.com>`
  on AI-assisted commits.

## Git workflow

- `main` is protected — PRs required (even for admins), no direct pushes.
- `staging` is the integration branch; work lands there first.
- Promote `staging` → `main` via PR, squash-merged; then back-merge the
  resulting `main` commit into `staging` (`git merge origin/main`) so history
  stays clean for the next cycle — this is the established pattern (see
  `git log --oneline` for prior "Back-merge origin/main into staging" commits).
- Tag releases `vX.Y.Z` on `main` after merge; a GitHub Release can be cut from
  the same tag using the CHANGELOG entry as its notes.

## Optional local context

If a gitignored `Skills/` directory is present in your checkout, it contains
much more detailed per-module decision logs and conventions
(`Skills/_CONVENTIONS.md`, `Skills/Purview/_CONVENTIONS.md`,
`Skills/Purview/<Module>.skill.md`) built up over the project's history. It is
not part of the git repository (not visible on a fresh clone), so treat it as
a bonus when present, not a dependency.
