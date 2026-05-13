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

> ⚠️ **Always pilot in a test tenant before applying to production.**
> Sensitivity-label and DLP policies are tenant-wide and can affect every
> user. Some changes can take **up to 24 hours** to fully propagate.

---

## What this toolkit does

| # | Task                | Default state                                                                                                        |
|---|---------------------|----------------------------------------------------------------------------------------------------------------------|
| 1 | **Tenant settings** | Enables Unified Audit Log, SharePoint AIP integration, PDF labelling, label co-authoring                             |
| 2 | **Sensitivity labels** | Creates `Personal`, `Public`, `General`, `Confidential` (with `AllEmployees` sub-label), `Highly Confidential`. Encryption applied to `Confidential`, `Confidential\AllEmployees`, and `Highly Confidential` (Co-Author rights for `AuthenticatedUsers` — internal-only). Labels ordered, then published with `General` as the default. |
| 3 | **DLP policies**    | Two policies (per Microsoft guidance): one for Exchange and one for SharePoint + OneDrive. Both block external sharing of content labelled `Confidential\AllEmployees`. Match condition uses the label **GUID**, not the display name. |
| 4 | **Retention**       | Exchange mailbox retention — keep 2 years, then delete (measured from item creation). |

### Optional add-ons

| Switch                     | What it does                                                                                       | Pre-requisite                                                          |
|----------------------------|----------------------------------------------------------------------------------------------------|------------------------------------------------------------------------|
| `-EnableContainerLabels`   | Sets `Group.Unified` `EnableMIPLabels=True` so labels can apply to M365 Groups, Teams, SPO sites.  | `Microsoft.Graph.Beta.Identity.DirectoryManagement` module + `Directory.ReadWrite.All` |
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
| Container labels (Group.Unified `EnableMIPLabels`)        | E5 / Purview Suite (also AAD P1+)     | Opt-in via `-EnableContainerLabels`    |
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

<<<<<<< HEAD
=======
> The toolkit's `Connect-PurviewServices` helper auto-detects missing modules
> and offers to install them from PSGallery (or installs silently when the
> deploy script is invoked with `-AutoInstallModules`). You can also install
> them manually beforehand:

>>>>>>> recovery-branch
| Module                                                  | Required for                            | Install                                                                              |
|---------------------------------------------------------|-----------------------------------------|--------------------------------------------------------------------------------------|
| `ExchangeOnlineManagement`                              | Always (EXO + IPPS)                     | `Install-Module ExchangeOnlineManagement -Scope CurrentUser`                          |
| `Microsoft.Online.SharePoint.PowerShell`                | Tenant settings + label policy publish  | `Install-Module Microsoft.Online.SharePoint.PowerShell -Scope CurrentUser`            |
<<<<<<< HEAD
=======
| `Microsoft.Graph.Authentication`                        | Only when `-EnableContainerLabels`      | `Install-Module Microsoft.Graph.Authentication -Scope CurrentUser`                    |
>>>>>>> recovery-branch
| `Microsoft.Graph.Beta.Identity.DirectoryManagement`     | Only when `-EnableContainerLabels`      | `Install-Module Microsoft.Graph.Beta.Identity.DirectoryManagement -Scope CurrentUser` |

### PowerShell version

<<<<<<< HEAD
Tested on Windows PowerShell 5.1 and PowerShell 7.4+. The
`Microsoft.Online.SharePoint.PowerShell` module historically required Windows
PowerShell 5.1 — if you hit issues on PS 7, run that step from PS 5.1.
=======
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
>>>>>>> recovery-branch

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
# Just labels and DLP — skip tenant settings and retention
.\Deploy-PurviewBestPractice.ps1 `
    -TenantAdminUpn admin@contoso.onmicrosoft.com `
    -SkipTenantSettings -SkipRetention
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
* `-Confirm` prompts for each high-impact change.
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

This bundle equates to **Co-Author** in the Microsoft documentation. Because
the identity is `AuthenticatedUsers`, **only authenticated users in the
customer tenant can open these files** — meeting the deck's "internal-only"
requirement.

Want a different protection scope (e.g. specific group, partner domain)?
Edit `EncryptionRightsDefinitions` in `PurviewConfig.psd1`. Validate in a
pilot tenant before rolling out.

---

## Troubleshooting

| Symptom                                                     | Cause / fix                                                                                  |
|-------------------------------------------------------------|----------------------------------------------------------------------------------------------|
<<<<<<< HEAD
| `Required PowerShell module 'X' is not installed`           | Run the matching `Install-Module` command (see prerequisites table).                          |
| `Label '...' already exists but is not managed by toolkit`  | An existing label with the same name was found. Audit it, then re-run with `-AdoptExisting`. |
| `Get-SPOTenant: ... not connected`                          | Wrong `-SharePointAdminUrl`, or running PS 7 with an old SPO module — try Windows PowerShell 5.1. |
=======
| `Required PowerShell module 'X' is not installed`           | Re-run with `-AutoInstallModules` to install missing modules automatically, or run the matching `Install-Module` command from the prerequisites table. |
| `Connect-SPOService failed ... Fallback (UseWindowsPowerShell) also failed: ... no valid module file was found` | PS 7's `Install-Module` only installs to the PS 7 module path; the SPO module's Windows-PowerShell-proxy fallback can't see it. Open `powershell.exe` (Windows PowerShell 5.1) once and run `Install-Module Microsoft.Online.SharePoint.PowerShell -Scope CurrentUser -Force -AllowClobber`, then re-run this script from `pwsh`. |
| `Label '...' already exists but is not managed by toolkit`  | An existing label with the same name was found. Audit it, then re-run with `-AdoptExisting`. |
| `Get-SPOTenant: ... not connected`                          | Wrong `-SharePointAdminUrl`, or SPO module failed to load under PS 7 — verify `Microsoft.Online.SharePoint.PowerShell` is installed and re-run from a fresh `pwsh` prompt. |
>>>>>>> recovery-branch
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
