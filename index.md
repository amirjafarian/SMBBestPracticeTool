---
title: Home
layout: home
nav_order: 1
description: "Best-practice deployment toolkits for Microsoft 365 SMB tenants."
permalink: /
---

# SMB Best Practice Tool

PowerShell automation that configures Microsoft 365 tenants against
Microsoft's recommended best-practice baselines for **Small / Medium**
customers. Built for Microsoft partners who need a repeatable, idempotent
way to onboard customer tenants.

> ⚠️ **Always pilot in a test tenant before applying to production.** Many
> changes are tenant-wide and can take up to 24 hours to fully propagate.

---

## Available product toolkits

| Product | Toolkit | Status |
|---|---|---|
| [Microsoft Purview](purview/) — Data Security baseline for Business Premium | `Products/Purview/` | ✅ Available |
| Microsoft Entra | `Products/Entra/` | 🔜 Planned |
| Microsoft Intune | `Products/Intune/` | 🔜 Planned |
| Microsoft Defender | `Products/Defender/` | 🔜 Planned |

Pick a product from the sidebar (or the table above) for its full
documentation: what it does, prerequisites, how to run, scenarios it
covers, change-management playbook, and end-user adoption material.

---

## Common prerequisites (all toolkits)

Each toolkit documents its own detailed prerequisites. Common requirements
across all of them:

* **PowerShell 7+** (`pwsh.exe`) to **run** the toolkits — the deploy
  scripts hard-fail on Windows PowerShell 5.1 because the Exchange
  Online v3 REST channel and Microsoft.Graph SDK depend on .NET Core
  APIs that PS 5.1 doesn't expose. Install with
  `winget install --id Microsoft.PowerShell` or from
  <https://aka.ms/PowerShell-Release>.
* **Windows** host with PS 5.1 still present — the
  `Microsoft.Online.SharePoint.PowerShell` module is Windows-only and
  is loaded automatically via `Import-Module -UseWindowsPowerShell`
  (a hidden PS 5.1 sub-process) so its bundled MSAL DLL never enters
  PS 7's AppDomain. macOS and Linux are not supported.
* **Tenant admin credentials** with the appropriate role(s) for the
  product being deployed (see each product's page for the exact role map).
* **Required PowerShell modules** — the toolkits auto-detect missing
  modules and offer to install them from PSGallery on first run. Pass
  `-AutoInstallModules` to install silently.

---

## Quick start

```powershell
# Clone the repo, then run the toolkit for the product you want to configure.
# Example: Purview baseline against a Business Premium tenant.
git clone https://github.com/amirjafarian/SMBBestPracticeTool.git
cd SMBBestPracticeTool\Products\Purview
.\Deploy-PurviewBestPractice.ps1 -TenantAdminUpn admin@contoso.onmicrosoft.com -WhatIf
```

---

## Disclaimer

This sample script is **not** supported under any Microsoft standard
support program or service. The sample script is provided AS IS without
warranty of any kind. The full disclaimer and license are in the
[repository LICENSE file](https://github.com/amirjafarian/SMBBestPracticeTool/blob/main/LICENSE).

Please do not contact Microsoft support with any issues or concerns
regarding this script.
