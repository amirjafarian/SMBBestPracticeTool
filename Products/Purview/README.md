---
title: Purview
layout: default
nav_order: 2
has_children: true
permalink: /purview/
---

# Microsoft Purview Best Practice Deployment Toolkit

PowerShell automation that applies Microsoft's recommended **Data Security
baseline** to a Microsoft 365 **Business Premium** tenant. Built for
Microsoft partners who need a repeatable, idempotent way to onboard customer
tenants to Purview.

The configuration applied here is taken directly from the Microsoft "Data
Security Best Practice Deployment" guide for Business Premium.

> 🗺️ **Want the big picture first?** See the
> [**visual Deployment Framework**](docs/Deployment-Framework.html) — an
> interactive one-screen model of the whole method, from pre-deployment to
> post-deployment, showing how every tenant-wide change is piloted, applied
> idempotently, simulated, and only enforced after a Day-30 gate. Best viewed
> on the [docs site](https://amirjafarian.github.io/SMBBestPracticeTool/purview/deployment-framework/).
>
> 📖 **New here?** Read [`docs/Scenarios.md`](docs/Scenarios.md) first —
> it explains every scenario the script covers, what changes when the
> customer's licensing changes, and what's deliberately out of scope.
> No PowerShell expertise required.
>
> 📋 **About to deploy this at a customer?** Read
> [`docs/Change-Management-Playbook.md`](docs/Change-Management-Playbook.md)
> — the script handles the engineering correctly; the playbook is what
> makes it safe in production (pre-deploy, day-of, day 1–5, day-30
> promote-from-simulation gate). Pairs with
> [`docs/Retention-Default-Risk.md`](docs/Retention-Default-Risk.md) and
> [`docs/DLP-Simulation-Exit-Runbook.md`](docs/DLP-Simulation-Exit-Runbook.md).
>
> 👥 **Communicating to end users?** Send
> [`docs/End-User-Adoption-Guide.md`](docs/End-User-Adoption-Guide.md)
> to your users **before** the rollout. It explains what they'll see,
> what changes after 30 days, and includes ready-to-edit email
> templates for T-7 / T-0 / T+30.

> ⚠️ **Always pilot in a test tenant before applying to production.**
> Sensitivity-label and DLP policies are tenant-wide and can affect every
> user. Some changes can take **up to 24 hours** to fully propagate.

> 🚨 **Retention default deletes mail at 7 years.** The default policy
> deletes Exchange mail older than 7 years tenant-wide. This duration
> aligns with most common SMB regulatory frameworks (ATO / IRS / SEC /
> ASIC) but is **not appropriate for every customer** — some verticals
> (e.g. paediatric healthcare records) require longer; some customers
> want no automatic deletion at all. See
> [`docs/Retention-Default-Risk.md`](docs/Retention-Default-Risk.md)
> before deploying into a regulated tenant.

---

## What this toolkit does

| # | Task                | Default state                                                                                                        |
|---|---------------------|----------------------------------------------------------------------------------------------------------------------|
| 1 | **Tenant settings** | Enables Unified Audit Log, SharePoint AIP integration, PDF labelling                             |
| 2 | **Sensitivity labels** | Creates `Public`, `General`, `Confidential` (parent + 3 sub-labels), `Highly Confidential` (parent + 3 sub-labels). Encryption: `Highly Confidential\All Employees` uses Co-Author rights, `Highly Confidential\Internal Exception` + `Confidential\Specific People` + `Highly Confidential\Specific People` use Reviewer / UserDefined; all rights scoped to your tenant only via `{TenantDomain}`. Labels ordered, then published with `General` as the email default. The 3 published labels (`General`, `Confidential\All Employees`, `Highly Confidential\All Employees`) carry container scope (`Site, UnifiedGroup`) so they appear in the Purview portal's Scope picker for Teams, Microsoft 365 Groups, and SharePoint sites — `-SkipContainerLabels` strips those bits without dropping the labels. |
| 3 | **DLP policies**    | Two policies (per Microsoft guidance): one for Exchange and one for SharePoint + OneDrive. Both block external sharing of content labelled `Confidential\AllEmployees`. Match condition uses the label **GUID**, not the display name. |
| 4 | **Retention**       | **Opt-in** (pass `-ApplyRetention`). Exchange mailbox retention — keep 7 years, then delete (measured from item creation). |

### Optional add-ons

| Switch                     | What it does                                                                                       | Pre-requisite                                                          |
|----------------------------|----------------------------------------------------------------------------------------------------|------------------------------------------------------------------------|
| `-SkipContainerLabels`     | Opt out of `Group.Unified` `EnableMIPLabels=True` AND strip the container-scope bits (`Site`, `UnifiedGroup`) from the 3 published labels' `ContentType`. Container labels run by default (BP includes Entra ID P1, the AAD-side requirement). | None — opt-out only.                                                  |
| `-EnablePremiumAudit`      | Adds `SearchQueryInitiated` to the supplied mailbox(es) `AuditOwner`.                              | Microsoft 365 Audit (**Premium**) licence                              |
| `-AdoptExisting`           | Allows updating labels / policies that already exist but were not created by this toolkit.         | Audit existing config first.                                           |

---

## Prerequisites

### Licensing

The toolkit is designed for **Microsoft 365 Business Premium** as the
baseline. Some optional features require a higher SKU:

| Feature                                                   | Minimum license                       | How it's gated                         |
|-----------------------------------------------------------|---------------------------------------|----------------------------------------|
| Sensitivity labels (Personal / Public / General / Confidential / Highly Confidential) | Business Premium | Always on |
| Encryption + content marking on labels                    | Business Premium                      | Always on                              |
| DLP for Exchange Online                                   | Business Premium                      | Always on                              |
| DLP for SharePoint + OneDrive                             | Business Premium                      | Always on                              |
| Retention policies (Exchange)                             | Business Premium                      | Always on                              |
| Unified audit log (standard, 90-day retention)            | Business Premium                      | Always on                              |
| Container labels (Group.Unified `EnableMIPLabels`)        | Business Premium (AAD P1+)            | Default on (BP includes Entra ID P1, the AAD-side requirement); opt out with `-SkipContainerLabels`. License auto-detect skips it automatically when no recognised BP/E5/Purview Suite SKU is found. |
| Container scope on the 3 published labels (`Site`, `UnifiedGroup` on `General` / `Confidential\All Employees` / `Highly Confidential\All Employees`) | Business Premium (AAD P1+) | Default on; gated by the same `-SkipContainerLabels` switch. When stripped, the labels still ship with `File, Email` scope (no failure). Adoption uses UNION-not-replace so a customer-added scope is never lost. |
| Premium Audit (1-year retention, `SearchQueryInitiated`)  | E5 / Audit (Premium) add-on           | Opt-in via `-EnablePremiumAudit`       |
| Endpoint DLP (Devices)                                    | E5 / Purview Suite                    | Not configured by default; rejected by `-BPOnly` |
| DLP for Defender for Cloud Apps / on-prem / Power BI      | E5 / Purview Suite                    | Not configured by default; rejected by `-BPOnly` |

**Pass `-BPOnly`** to hard-block any E5-only opt-ins. The script refuses to
run if `-EnablePremiumAudit` is set, and the DLP module rejects custom
config workloads that require E5. Container labels still run under
`-BPOnly` because Business Premium includes Entra ID P1 (the AAD-side
requirement) — pass `-SkipContainerLabels` if you need to opt out.

```powershell
# Business Premium customer — strict mode
.\Deploy-PurviewBestPractice.ps1 `
    -TenantAdminUpn admin@contoso.onmicrosoft.com `
    -BPOnly
```

### Admin role on the customer tenant

The signing-in admin needs:

* **Compliance Administrator** *and* **Compliance Data Administrator**
  (sensitivity labels, DLP, retention)
* **SharePoint Administrator** (tenant settings)
* **Exchange Administrator** (audit log, mailbox audit)
* **Groups Administrator** *or* **Global Administrator** — required for
  container labels (`Group.Unified` directory setting). Pass
  `-SkipContainerLabels` to omit this role requirement.

> Or sign in as **Global Administrator** for simplicity.

### PowerShell modules

> The toolkit's `Connect-PurviewServices` helper auto-detects missing modules
> and offers to install them from PSGallery (or installs silently when the
> deploy script is invoked with `-AutoInstallModules`). You can also install
> them manually beforehand:

| Module                                                  | Required for                            | Install                                                                              |
|---------------------------------------------------------|-----------------------------------------|--------------------------------------------------------------------------------------|
| `ExchangeOnlineManagement`                              | Always (EXO + IPPS)                     | `Install-Module ExchangeOnlineManagement -Scope CurrentUser`                          |
| `Microsoft.Online.SharePoint.PowerShell`                | Tenant settings + label policy publish  | `Install-Module Microsoft.Online.SharePoint.PowerShell -Scope CurrentUser`            |
| `Microsoft.Graph.Authentication`                        | Whenever Graph is used (license auto-detect, tenant-identity confirm, container labels) | `Install-Module Microsoft.Graph.Authentication -Scope CurrentUser`                    |
| `Microsoft.Graph.Beta.Identity.DirectoryManagement`     | Container labels (default; skipped only when `-SkipContainerLabels` is passed) | `Install-Module Microsoft.Graph.Beta.Identity.DirectoryManagement -Scope CurrentUser` |

### Microsoft Graph delegated scopes (least-privilege)

The script requests only the scopes it actually needs for the run you ask for:

| When Graph is used                                                | Scopes requested                                |
|-------------------------------------------------------------------|-------------------------------------------------|
| License auto-detect + tenant-identity confirm (always when Graph is connected) | `Organization.Read.All` *(read-only)* |
| Container labels (default; skipped only when `-SkipContainerLabels` is passed) | `Organization.Read.All` + `Directory.ReadWrite.All` *(requested upfront in one consent)* |

`Directory.ReadWrite.All` is the historically-consented, known-working scope on most tenants for reading `/directorySettingTemplates` and writing `/settings` where `Group.Unified.EnableMIPLabels` lives. We did experiment with the narrower `GroupSettings.ReadWrite.All` but it triggered `403 Authorization_RequestDenied` on tenants whose admins had only ever consented to `Directory.ReadWrite.All`. The license auto-detect itself (`/subscribedSkus`, `/organization`) is read-only via `Organization.Read.All`.

### PowerShell version

**PowerShell 7+ (`pwsh.exe`) is required.** The deploy script hard-fails on
Windows PowerShell 5.1 because the Exchange Online v3 REST channel and the
Microsoft.Graph SDK rely on .NET Core APIs that PS 5.1 does not expose, which
causes silent auth and cmdlet-discovery failures mid-run.

```powershell
# Install PowerShell 7 (one-time):
winget install --id Microsoft.PowerShell --source winget
# Or download from: https://aka.ms/PowerShell-Release
```

Then run the toolkit from a `pwsh` prompt (not `powershell`). The
`Microsoft.Online.SharePoint.PowerShell` module is loaded via
`Import-Module -UseWindowsPowerShell` automatically when running under PS 7,
so no separate PS 5.1 step is needed.

### Sign-in prompts (WAM broker)

Each customer-tenant deploy needs sign-in tokens for up to four services
(Exchange Online, Security & Compliance / IPPS, SharePoint Online, Microsoft
Graph). The first run on a new admin account therefore shows several prompts.
On subsequent runs the **Windows Authentication Manager (WAM) broker** turns
most of those into single-click "Continue" confirmations instead of full
browser sign-ins.

WAM is on by default in current PowerShell modules
(`Microsoft.Graph.Authentication` 2.x and `ExchangeOnlineManagement` 3.3+)
when **all** of the following are true:

| Requirement | Why |
|---|---|
| Running on **Windows 10 1507 (build 10240)** or later, or **Windows Server 2019 (build 17763)** or later | WAM is a Windows-only OS component. |
| `pwsh.exe` was launched in your normal **interactive** desktop session (no RunAs, no scheduled task / SYSTEM, no SSH/remote PowerShell) | WAM uses the desktop user's signed-in tokens. |
| `Microsoft.Graph.Authentication` ≥ 2.0 and `ExchangeOnlineManagement` ≥ 3.3 are installed | Older versions don't have WAM integration. Refresh with `Update-Module`. |

The connect helper checks all of these at start-up and warns when WAM is not
available — `Get-PurviewRunLog` records the result as a
`SessionGuard:Startup` entry with `reason=wam-ready` or `wam-not-ready` plus
the diagnostic fields it inspected.

Even when WAM is available, the following still cause additional prompts:

* **First-time consent** — granting `Organization.Read.All` (or
  `Directory.ReadWrite.All` for container labels) on a new tenant always
  shows the full consent screen once.
* **GDAP tenant switches** — the Graph guard reauths when it detects the
  cached session belongs to a different customer tenant
  (`reason=tenant-domain-mismatch` in the run log).
* **Missing scopes** — adding a new scope to an existing cached session
  triggers a re-consent prompt (`reason=missing-scopes`).
* **SharePoint Online** — `Connect-SPOService` does not expose WAM, so the
  SPO connect always uses its own MSAL flow.

When you see more prompts than expected, run
`Get-PurviewRunLog | Where-Object Action -like 'SessionGuard:*'` after the
deploy — every prompt is preceded by a structured log entry that names
which check failed and what was expected vs observed.

### MSAL DLL mismatch (Connect-MgGraph 'Method not found')

`ExchangeOnlineManagement` and `Microsoft.Graph.Authentication` each ship
their own copy of `Microsoft.Identity.Client.dll` (MSAL) under their module
folders. When both modules are imported into the same PowerShell process,
the CLR binds to whichever copy was loaded FIRST and ignores the other.

If the two modules were compiled against different MSAL versions and a
method signature changed between them (a recurring source of breakage in
MSAL 4.x — e.g. `BaseAbstractApplicationBuilder<T>.WithLogging(IIdentity
Logger, Boolean)` moved between 4.82 and 4.83), `Connect-MgGraph` throws:

```text
InteractiveBrowserCredential authentication failed:
Method not found: '!0 Microsoft.Identity.Client.<X>.<Method>(...)'.
```

That message reads like an auth failure but is purely a DLL-binding
mismatch — no credential / scope / tenant change will fix it.

**Detection.** The connect helper runs `Test-MsalDllCompatibility` at
start-up: it locates the `Microsoft.Identity.Client.dll` bundled by each
module (PS edition-aware: `netCore` / `Dependencies\Core` on PS 7,
`netFramework` / `Dependencies\Desktop` on PS 5.1), reads each DLL's
`FileVersion`, and also checks whether MSAL is already loaded in the
process. The outcome is logged as a `SessionGuard:Startup` entry with
`reason=msal-aligned` or `msal-mismatch` plus the DLL paths/versions.

**Mitigation 1: Graph-first connect order.** The connect helper imports
`Microsoft.Graph.Authentication` and calls `Connect-MgGraph` **before**
`Connect-ExchangeOnline`, mirroring the pattern used by
[`microsoft/zerotrustassessment`](https://github.com/microsoft/zerotrustassessment/blob/main/src/powershell/public/Connect-ZtAssessment.ps1).
When Microsoft Graph loads its bundled MSAL into the AppDomain first,
`Connect-MgGraph` no longer throws `Method not found`. Verified
end-to-end on EXO 3.10.0 + Microsoft.Graph.Authentication 2.37.0 (which
ship MSAL 4.83.1.0 and 4.82.1.0 respectively).

**Mitigation 2: `-DisableWAM` for Exchange Online / IPPS.** Connecting
Graph first solves the `Connect-MgGraph` failure but introduces a new
problem: when `Connect-ExchangeOnline` runs against Graph's older
MSAL 4.82, EXO 3.10's WAM (Windows Account Manager) broker code path
throws:

```text
System.NullReferenceException: Object reference not set to an instance of an object.
   at Microsoft.Identity.Client.Platforms.Features.RuntimeBroker.RuntimeBroker..ctor(...)
```

EXO's WAM `RuntimeBroker` constructor expects MSAL 4.83's surface, and
the older MSAL doesn't satisfy it. When the helper's pre-flight check
detects a mismatch (`SessionGuard:Startup reason=msal-mismatch`), it
automatically passes `-DisableWAM` to both `Connect-ExchangeOnline` and
`Connect-IPPSSession`. WAM is bypassed in favour of the standard
interactive browser flow, which doesn't invoke `RuntimeBroker`. The
operator still gets a one-click browser sign-in via the system default
browser; only the WAM 1-click pop-up is suppressed. Logged as
`SessionGuard:EXO/IPPS reason=disable-wam-msal-mismatch`. Auto-disables
the moment the bundled MSAL versions realign (WAM returns automatically).

> **What about `-UseDeviceCode` for Graph?** Doesn't help — Graph 2.37's
> `DeviceCodeCredential` and `InteractiveBrowserCredential` constructors
> both invoke the same broken MSAL method overload, so switching auth
> flow doesn't change the JIT lookup. `microsoft/zerotrustassessment`
> has the same `#TODO: UseDeviceCode does not work with ExchangeOnline`
> caveat for the EXO side.

> **What about pre-loading Graph's older MSAL?** Doesn't work either.
> `ExchangeOnlineManagement` 3.10's module manifest strong-binds to its
> bundled MSAL 4.83.1.0, so pre-loading Graph's 4.82.1.0 with
> `[Reflection.Assembly]::LoadFrom` causes `Connect-ExchangeOnline` to
> throw `FileLoadException: manifest does not match` (HRESULT
> 0x80131040).

**Manual fallback — restart PowerShell.** If another module loaded MSAL
into the process *before* this script started running (e.g. you ran
`Connect-ExchangeOnline` manually, or imported `Az.*`, `PnP.PowerShell`,
or `Microsoft.Graph.*` first), neither mitigation can help — .NET
cannot swap a loaded assembly. The connect helper detects this in its
pre-flight check (`loadedMsalVersion` is set in the
`SessionGuard:Startup` entry) and tells the operator to:

1. **Close** the PowerShell window.
2. **Open a fresh `pwsh`** with no other Microsoft modules pre-imported.
3. **Re-run** the script.

If `Connect-MgGraph` still throws `Method not found: 'Microsoft.Identity…'`,
the helper catches the `MissingMethodException` and emits restart-pwsh
guidance with `SessionGuard:Graph reason=msal-method-not-found-restart-pwsh`.
Same for an EXO `NullReferenceException` in `RuntimeBroker` —
`SessionGuard:EXO reason=wam-runtimebroker-nullref`.

**Last resort — pin a matching EXO/Graph pair.** Microsoft realigns the
bundled MSAL versions between releases, so updating both modules with
`Update-Module ExchangeOnlineManagement -Force; Update-Module Microsoft.Graph.Authentication -Force`
will eventually close the gap. At the time of writing, no shipped
`ExchangeOnlineManagement` version on PSGallery bundles the same MSAL
as `Microsoft.Graph.Authentication` 2.37.0 (`4.82.1.0`) — EXO
3.8/3.9.0/3.9.2/3.10 ship 4.66.1/4.68.0/4.74.1/4.83.1 respectively — so
this fallback is rarely useful today. If you do want to try pinning a
matching pair manually:

```powershell
# Find an installed EXO version whose MSAL DLL matches Graph's
Get-Module ExchangeOnlineManagement -ListAvailable | ForEach-Object {
    $dll = Get-ChildItem $_.ModuleBase -Filter Microsoft.Identity.Client.dll -Recurse |
           Where-Object FullName -match 'netCore' | Select-Object -First 1
    [pscustomobject]@{
        EXO  = $_.Version
        MSAL = if ($dll) { $dll.VersionInfo.FileVersion } else { '(none)' }
    }
}

# Then pin in a fresh window before running the script:
Import-Module ExchangeOnlineManagement -RequiredVersion <picked> -Force
```

The Graph-first connect order + auto `-DisableWAM` for EXO/IPPS is the
primary fix; the pwsh-restart is the only reliable manual fallback when
MSAL is already loaded with the wrong version.

### Microsoft.Graph.Beta sub-module version pin (`Assembly with same name is already loaded`)

After updating `Microsoft.Graph.Authentication` (e.g. to fix the MSAL
mismatch above) the deployment can later fail at **step [5/5] container
labels** with:

```
The 'Get-MgBetaDirectorySetting' command was found in the module
'Microsoft.Graph.Beta.Identity.DirectoryManagement', but the module could
not be loaded due to the following error: [Could not load file or
assembly 'Microsoft.Graph.Authentication, Version=2.36.1.0, …'.
Assembly with same name is already loaded]
```

**Why it happens.** Every `Microsoft.Graph.Beta.*` sub-module's manifest
strict-pins `Microsoft.Graph.Authentication` to an **exact** version in
`RequiredModules` (not a minimum). When you update `Authentication` to a
newer version without also updating the matching Beta sub-modules,
PowerShell tries to load the older Auth version that Beta requires, but
the newer Auth is already in the AppDomain — only one version of an
assembly can be loaded per AppDomain, so `Import-Module` throws.

**Auto-detect + self-heal.** The connect helper runs `Test-GraphBetaCompat`
in the pre-flight (just before importing the Beta sub-module). It
compares the Beta module's `RequiredModules` pin against the loaded /
installed `Microsoft.Graph.Authentication` version and:

* When the pin matches: logs `SessionGuard:GraphBeta version-pin-aligned`
  and force-imports the matching version via `Import-Module
  -RequiredVersion` (so the pick is deterministic even with multiple
  Beta versions installed side-by-side).
* When the pin **does not** match: **unconditionally** installs the
  matching Beta version side-by-side
  (`Install-Module … -RequiredVersion <auth> -Scope CurrentUser -Force
  -AllowClobber`), re-validates, then force-imports it. No
  `-AutoInstallModules` flag is required — this is a deterministic,
  non-destructive recovery (one specific sub-module version, installed
  side-by-side; existing versions are untouched). Matches the existing
  PSGallery trust restore pattern.
* If `Install-Module` fails (PSGallery unreachable, locked-down
  environment, etc.): fails fast at pre-flight with the exact
  `Install-Module` command to run manually. Operators in CLM /
  no-internet environments can pre-pin the matching Beta version before
  running the script.

Log keys: `version-pin-aligned`, `version-pin-mismatch`,
`auto-installed-matching-version`, `auto-install-failed`,
`imported-matching-version`, `no-matching-version-installed`.

**Manual fix.** If you don't want the auto-install, run
`Update-Module Microsoft.Graph.Beta -Force` (updates the whole family in
one shot) or the targeted `Install-Module` printed in the warning, then
re-run the deploy.

---

## File layout

```
Configuration/Purview/
├── Deploy-PurviewBestPractice.ps1         <- master orchestrator (start here)
├── Config/
│   └── PurviewConfig.psd1                 <- all label / DLP / retention names & values
├── Modules/
│   ├── Connect-PurviewServices.ps1        <- service connection helper
│   ├── Setup-TenantSettings.ps1           <- task 1
│   ├── Setup-SensitivityLabels.ps1        <- task 2
│   ├── Setup-DLP.ps1                      <- task 3
│   └── Setup-Retention.ps1                <- task 4
└── README.md
```

Each `Setup-*.ps1` script is self-contained and can be run on its own; the
master script just orchestrates them.

---

## Quick start

```powershell
# 1. Clone / download the repo and open a PowerShell prompt in this folder.

# 2. Preview every change WITHOUT applying (SharePoint URL is auto-derived):
.\Deploy-PurviewBestPractice.ps1 `
    -TenantAdminUpn admin@contoso.onmicrosoft.com `
    -WhatIf

# 3. Apply the baseline:
.\Deploy-PurviewBestPractice.ps1 `
    -TenantAdminUpn admin@contoso.onmicrosoft.com
```

The SharePoint admin URL is auto-derived from the tenant's initial
`onmicrosoft.com` domain after Exchange Online connects. Override only when
auto-derivation fails (e.g. multi-geo or unusual domain configurations):

```powershell
.\Deploy-PurviewBestPractice.ps1 `
    -TenantAdminUpn admin@contoso.onmicrosoft.com `
    -SharePointAdminUrl https://contoso-admin.sharepoint.com
```

### Partner-delegated (GDAP) scenario

```powershell
.\Deploy-PurviewBestPractice.ps1 `
    -TenantAdminUpn partneradmin@fabrikam.onmicrosoft.com `
    -DelegatedOrganization contoso.onmicrosoft.com
```

### Selective deployment

```powershell
# Just labels and DLP — skip tenant settings (retention is opt-in)
.\Deploy-PurviewBestPractice.ps1 `
    -TenantAdminUpn admin@contoso.onmicrosoft.com `
    -SkipTenantSettings
```

### Premium audit (E5 add-on)

```powershell
.\Deploy-PurviewBestPractice.ps1 `
    -TenantAdminUpn admin@contoso.onmicrosoft.com `
    -EnablePremiumAudit -PremiumAuditMailbox 'admin@contoso.onmicrosoft.com'
```

---

## Customisation

All names, durations, label texts, encryption rights, and DLP behaviour live
in `Config/PurviewConfig.psd1`. Fork the repo, edit that file, and re-run.

The most common customisations:

* Change the default applied label (`LabelPolicy.DefaultLabel`)
* Add SharePoint / OneDrive to retention scope (`Retention.Locations`)
* Change retention from 2 → N years (`Retention.DurationDays`)
* Tighten encryption rights (`EncryptionRightsDefinitions`)

> **Don't change** the `ManagedByTag` after a deployment — it's how the
> toolkit recognises objects it owns on subsequent runs.

---

## Idempotency & safety

* Every action does a `Get-*` first and skips when the desired state is
  already in place.
* Every object created by the toolkit is stamped with
  `[Managed by SMBTool Purview Toolkit]` in its `Comment` / description.
* If a label, DLP policy, retention policy, or rule with the toolkit's name
  **already exists but is not stamped**, the run **stops with a clear error**.
  Pass `-AdoptExisting` to take ownership and update the existing object.
* `-WhatIf` prints every state-changing call without executing it.
  When run end-to-end against a clean tenant, downstream modules (DLP,
  retention, label policy publish) reference labels that do not yet exist —
  these are surfaced as `What if: ... would be created earlier in this run`
  notices with a placeholder GUID, so the preview is complete and never
  errors out. In apply mode the labels really are created in the right order.
* `-Confirm` is honoured by the underlying cmdlets but **does not** prompt
  per high-impact change in the orchestrator. The toolkit is designed for
  unattended runs (`SupportsShouldProcess` is wired with `ConfirmImpact = 'None'`,
  and every internal call passes `-Confirm:$false`). To preview without
  applying use `-WhatIf`; to gate the run on operator confirmation, leave
  the preflight `y/N` prompt enabled (i.e. do **not** pass `-NonInteractive`).
* The master script prints a preflight summary and asks for `y/N`
  confirmation before any change (skip with `-NonInteractive`).

---

## Encryption rights — tenant-scoped by default

Two encrypting Template-protected labels apply usage rights:

* **`Highly Confidential \ All Employees`** — uses Microsoft's wider
  **Co-Author** bundle (per-label override):

  ```
  VIEW, VIEWRIGHTSDATA, DOCEDIT, EDIT, EXTRACT, PRINT, OBJMODEL, REPLY, REPLYALL, FORWARD
  ```

  Co-Author adds **EXTRACT** (copy), **PRINT**, and **OBJMODEL** (Office
  object-model access — needed for macros and simultaneous editing).
  Granting OBJMODEL is **necessary but not sufficient** for Office
  multi-user co-authoring on encrypted files: the tenant-wide switch
  `Set-PolicyConfig -EnableLabelCoauth:$true` (toolkit param
  `-EnableLabelCoAuthoring`, opt-in) must also be on.

* **`Highly Confidential \ Internal Exception`** — uses the global
  default **Reviewer** bundle (no Copy, no Print, no OBJMODEL):

  ```
  VIEW, VIEWRIGHTSDATA, DOCEDIT, EDIT, REPLY, REPLYALL, FORWARD
  ```

The global default applies to any Template-encrypted label that does
NOT carry a per-label `EncryptionRightsDefinitions` field. To change
the default, edit `EncryptionRightsDefinitions` in
`PurviewConfig.psd1`. To override for a specific label, add an
`EncryptionRightsDefinitions = '...'` field on that label hashtable
(same token semantics as the global default).

The rights are scoped to **all users in your tenant only** via the
`{TenantDomain}` token at the start of `EncryptionRightsDefinitions`. At
run time the toolkit resolves the token against your auto-discovered
tenant identity (default verified domain, falling back to your initial
`*.onmicrosoft.com`). Per Entra rights-management semantics, ANY verified
domain expands to ALL verified domains in the tenant — so specifying one
is enough to cover the whole tenant, and it explicitly EXCLUDES external
`AuthenticatedUsers` from other Microsoft 365 tenants, B2B guests
attached to other tenants, social/MSA accounts, and OTP users.

If you intentionally need the broader cross-tenant scope (e.g. you
collaborate via the label with partner organizations that do NOT yet have
a B2B trust into your tenant), edit `EncryptionRightsDefinitions` to use
`{AuthenticatedUsers}` (or the literal `AuthenticatedUsers`) and document
the decision. The toolkit refuses to silently fall back to that scope —
if the `{TenantDomain}` token cannot be resolved (no Graph/EXO identity),
the labels module aborts with an actionable error.

> **Retroactive scope changes only apply to NEW labelling.** Existing
> protected files carry the use-license they had at the moment of
> labelling. Tightening the rights bundle does NOT retroactively revoke
> external access to files that were already labelled and shared. To
> tighten retroactively, re-label / re-protect the affected files. See
> [`docs/Change-Management-Playbook.md`](docs/Change-Management-Playbook.md#known-sharp-edges).

---

## Known sharp edges (read before promoting to production)

These are **not bugs**. They are correct defaults that require a customer
conversation. Full detail and mitigations are in
[`docs/Change-Management-Playbook.md`](docs/Change-Management-Playbook.md#known-sharp-edges).

| Sharp edge | Default behaviour | Why it matters |
|---|---|---|
| **Encrypted-label scope = your tenant only (not retroactive)** | The two Template-encrypted HC sub-labels grant rights to all users in your tenant via the `{TenantDomain}` token. | Files labelled BEFORE this toolkit ran (or before you tightened the scope) keep their old rights — re-label them if you need the new scope applied. B2B guests from OTHER tenants are excluded by default; if you need cross-tenant collaboration, switch to `{AuthenticatedUsers}` deliberately. |
| **`Highly Confidential\Specific People` prompts users** | Word/Excel/PowerPoint asks the user to pick who can open the file. | Most users do not know how to respond to this dialog. **Not** published to end users by default — keep it that way unless you ship user training. |
| **`Confidential\Specific People` also prompts users** | UserDefined encryption — Outlook auto-applies Do Not Forward; Office desktop apps prompt the recipient list. | Same usability caveat as the HC variant. **Not** published by default. Encryption is enforced once published. |
| **Container labels are one-way** | `Group.Unified` `EnableMIPLabels=True` is set by default on every run (BP is the licensing floor and BP includes Entra ID P1). Pass `-SkipContainerLabels` to opt out before the first run. | Microsoft does not officially support reverting once set. Treat the default-on behaviour as decision-grade — confirm with the customer up front. |
| **Endpoint DLP without device onboarding is theatre** | Endpoint DLP policy is created on E5 tenants when not `-BPOnly`. | Without Defender / Purview device onboarding, the policy enforces nothing. Looks deployed; protects nothing. |
| **7-year retention deletes mail** | Tenant-wide retention deletes Exchange mail older than 7 years. | Aligns with most SMB regulatory frameworks (ATO / IRS / SEC / ASIC), but still wrong for some verticals (e.g. paediatric healthcare) and for customers who want no automatic deletion. See [`docs/Retention-Default-Risk.md`](docs/Retention-Default-Risk.md). |
| **DLP starts in simulation** | `DlpStartInSimulation = $true`. Telemetry only — nothing is blocked. | Has to be **explicitly promoted** at day 30 via the [`docs/DLP-Simulation-Exit-Runbook.md`](docs/DLP-Simulation-Exit-Runbook.md), or it is permanent shelfware. |

---

## Troubleshooting

| Symptom                                                     | Cause / fix                                                                                  |
|-------------------------------------------------------------|----------------------------------------------------------------------------------------------|
| `Required PowerShell module 'X' is not installed`           | Re-run with `-AutoInstallModules` to install missing modules automatically, or run the matching `Install-Module` command from the prerequisites table. |
| `Connect-SPOService failed ... Fallback (UseWindowsPowerShell) also failed: ... no valid module file was found` | PS 7's `Install-Module` only installs to the PS 7 module path; the SPO module's Windows-PowerShell-proxy fallback can't see it. Open `powershell.exe` (Windows PowerShell 5.1) once and run `Install-Module Microsoft.Online.SharePoint.PowerShell -Scope CurrentUser -Force -AllowClobber`, then re-run this script from `pwsh`. |
| `Label '...' already exists but is not managed by toolkit`  | An existing label with the same name was found. Audit it, then re-run with `-AdoptExisting`. |
| `Get-SPOTenant: ... not connected`                          | Wrong `-SharePointAdminUrl`, or SPO module failed to load under PS 7 — verify `Microsoft.Online.SharePoint.PowerShell` is installed and re-run from a fresh `pwsh` prompt. |
| Users don't see new labels in Office                        | Labels can take up to 24 h to propagate; sign out / back in to force refresh.                |
| DLP not blocking external sends                             | Allow up to ~1 h enforcement window; verify rule is `Mode=Enable` in the Purview portal.     |
| `Connect-IPPSSession` fails after `Connect-ExchangeOnline`  | They are separate sessions — both must succeed; modern auth + MFA both required.             |

---

## Out of scope

This toolkit deliberately implements **only** the Business Premium baseline
from the source deck. The following are out of scope and require separate,
more advanced tooling:

* Insider Risk Management
* Communication Compliance
* eDiscovery
* Auto-labelling (service-side & client-side)
* Multi-geo configurations
* Customer-specific protection scopes (per-domain, per-group)

For the extended Purview guide referenced in the deck, see
<https://aka.ms/Purview_LightweightGuide_PDF>.

---

## Contributing

Issues and PRs welcome. Please:

* Keep changes idempotent.
* Don't introduce display-name-based matching for labels in DLP rules — use
  GUIDs.
* Validate every change in a pilot tenant before opening a PR.

---

## License

Provided as-is, without warranty of any kind. Review and test before applying
to production tenants. See the repository root for licence information.

## Disclaimer

This sample script is not supported under any Microsoft standard support
program or service. The sample script is provided AS IS without warranty of
any kind. Microsoft further disclaims all implied warranties including,
without limitation, any implied warranties of merchantability or of fitness
for a particular purpose. The entire risk arising out of the use or
performance of the sample scripts and documentation remains with you. In no
event shall Microsoft, its authors, or anyone else involved in the creation,
production, or delivery of the scripts be liable for any damages whatsoever
(including, without limitation, damages for loss of business profits,
business interruption, loss of business information, or other pecuniary loss)
arising out of the use of or inability to use the sample scripts or
documentation, even if Microsoft has been advised of the possibility of such
damages.

Please do not contact Microsoft support with any issues or concerns regarding
this script.
