# Microsoft Purview Best Practice Deployment Toolkit

PowerShell automation that applies Microsoft's recommended **Data Security
baseline** to a Microsoft 365 **Business Premium** tenant. Built for
Microsoft partners who need a repeatable, idempotent way to onboard customer
tenants to Purview.

The configuration applied here is taken directly from the Microsoft "Data
Security Best Practice Deployment" guide for Business Premium.

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
| 1 | **Tenant settings** | Enables Unified Audit Log, SharePoint AIP integration, PDF labelling, label co-authoring                             |
| 2 | **Sensitivity labels** | Creates `Personal`, `Public`, `General`, `Confidential` (with `AllEmployees` sub-label), `Highly Confidential`. Encryption applied to `Confidential`, `Confidential\AllEmployees`, and `Highly Confidential` (Co-Author rights for `AuthenticatedUsers` — internal-only). Labels ordered, then published with `General` as the default. |
| 3 | **DLP policies**    | Two policies (per Microsoft guidance): one for Exchange and one for SharePoint + OneDrive. Both block external sharing of content labelled `Confidential\AllEmployees`. Match condition uses the label **GUID**, not the display name. |
| 4 | **Retention**       | **Opt-in** (pass `-ApplyRetention`). Exchange mailbox retention — keep 7 years, then delete (measured from item creation). |

### Optional add-ons

| Switch                     | What it does                                                                                       | Pre-requisite                                                          |
|----------------------------|----------------------------------------------------------------------------------------------------|------------------------------------------------------------------------|
| `-EnableContainerLabels`   | Sets `Group.Unified` `EnableMIPLabels=True` so labels can apply to M365 Groups, Teams, SPO sites.  | `Microsoft.Graph.Beta.Identity.DirectoryManagement` module + Graph delegated scopes `Organization.Read.All` + `Directory.ReadWrite.All` |
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
| Container labels (Group.Unified `EnableMIPLabels`)        | Business Premium (AAD P1+)            | Auto-on on Business Premium / E5 / Purview Suite (opt out with `-NoLicenseAutoDetect`); switch is `-EnableContainerLabels` |
| Premium Audit (1-year retention, `SearchQueryInitiated`)  | E5 / Audit (Premium) add-on           | Opt-in via `-EnablePremiumAudit`       |
| Endpoint DLP (Devices)                                    | E5 / Purview Suite                    | Not configured by default; rejected by `-BPOnly` |
| DLP for Defender for Cloud Apps / on-prem / Power BI      | E5 / Purview Suite                    | Not configured by default; rejected by `-BPOnly` |

**Pass `-BPOnly`** to hard-block any E5-only opt-ins. The script refuses to
run if `-EnableContainerLabels` or `-EnablePremiumAudit` is also set, and
the DLP module rejects custom config workloads that require E5.

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
* **Groups Administrator** *or* **Global Administrator** — only if you use
  `-EnableContainerLabels`

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
| `Microsoft.Graph.Beta.Identity.DirectoryManagement`     | Only when `-EnableContainerLabels`      | `Install-Module Microsoft.Graph.Beta.Identity.DirectoryManagement -Scope CurrentUser` |

### Microsoft Graph delegated scopes (least-privilege)

The script requests only the scopes it actually needs for the run you ask for:

| When Graph is used                                                | Scopes requested                                |
|-------------------------------------------------------------------|-------------------------------------------------|
| License auto-detect + tenant-identity confirm (always when Graph is connected) | `Organization.Read.All` *(read-only)* |
| Container labels — `-EnableContainerLabels` passed explicitly     | `Organization.Read.All` + `Directory.ReadWrite.All` *(requested upfront in one consent)* |
| Container labels — promoted by E5/Purview Suite auto-detect       | `Organization.Read.All` first, then `Directory.ReadWrite.All` added via a second `Connect-MgGraph` call *(no extra prompt if already consented)* |

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

### Container labels + premium audit

```powershell
.\Deploy-PurviewBestPractice.ps1 `
    -TenantAdminUpn admin@contoso.onmicrosoft.com `
    -EnableContainerLabels `
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

## Encryption rights — what `AuthenticatedUsers` means

`Confidential`, `Confidential\AllEmployees`, and `Highly Confidential` apply
encryption with these usage rights to the special identity
`AuthenticatedUsers`:

```
VIEW, VIEWRIGHTSDATA, DOCEDIT, EDIT, PRINT, EXTRACT, REPLY, REPLYALL,
FORWARD, OBJMODEL
```

This bundle equates to **Co-Author** in the Microsoft documentation. The
identity `AuthenticatedUsers` includes signed-in internal users plus B2B
guests, social/MSA accounts, and one-time-passcode (OTP) users — so it is
**not an internal-only scope**.

If you need an internal-employees-only scope, replace `AuthenticatedUsers` in
`EncryptionRightsDefinitions` / `EncryptionRightsDefinitionsCoAuth` with a
Microsoft 365 group whose dynamic membership is scoped to
`user.userType -eq "Member"`. Validate in a pilot tenant before rolling out.

---

## Known sharp edges (read before promoting to production)

These are **not bugs**. They are correct defaults that require a customer
conversation. Full detail and mitigations are in
[`docs/Change-Management-Playbook.md`](docs/Change-Management-Playbook.md#known-sharp-edges).

| Sharp edge | Default behaviour | Why it matters |
|---|---|---|
| **`AuthenticatedUsers` ≠ internal only** | The 3 encrypting labels grant rights to every authenticated user in the tenant. | B2B guests (accountants / lawyers / MSPs invited as guests) **can read protected files**. Audit the guest list first. |
| **`Highly Confidential\Specific People` prompts users** | Word/Excel/PowerPoint asks the user to pick who can open the file. | Most users do not know how to respond to this dialog. **Not** published to end users by default — keep it that way unless you ship user training. |
| **Container labels are one-way** | `Group.Unified` `EnableMIPLabels=True` is set when `-EnableContainerLabels` is passed (or auto-detected on E5). | Microsoft does not officially support reverting. Treat the switch as decision-grade. |
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
