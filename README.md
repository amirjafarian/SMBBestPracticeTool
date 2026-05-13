# SMBBestPracticeTool

PowerShell automation that configures Microsoft 365 tenants against
Microsoft's recommended best-practice baselines for Small / Medium customers.
Built for Microsoft partners who need a repeatable, idempotent way to onboard
customer tenants.

## Products

| Product | Toolkit | Status |
|---------|---------|--------|
| Microsoft Purview (Data Security baseline for Business Premium) | [`Products/Purview/`](Products/Purview/README.md) | Available |

## Prerequisites (at a glance)

Each product toolkit documents its own detailed prerequisites in its README.
Common requirements across all toolkits:

* **PowerShell 7+** (`pwsh.exe`) — Windows PowerShell 5.1 is **not supported**.
  Install with `winget install --id Microsoft.PowerShell` or from
  <https://aka.ms/PowerShell-Release>.
* **Tenant admin credentials** with the appropriate role(s) for the product
  being deployed (see each product's README for the exact role mapping).
* **Required PowerShell modules** — the toolkits auto-detect missing modules
  and offer to install them from PSGallery on first run. Pass
  `-AutoInstallModules` to install silently, or install manually beforehand
  using the commands listed in each product's README.

For the full prerequisite list (licensing, admin roles, modules) for the
Purview toolkit, see [`Products/Purview/README.md`](Products/Purview/README.md#prerequisites).

## Quick start

```powershell
# Clone the repo, then run the toolkit for the product you want to configure.
# Example: Purview baseline against a Business Premium tenant.
cd Products/Purview
.\Deploy-PurviewBestPractice.ps1 -TenantAdminUpn admin@contoso.onmicrosoft.com -WhatIf
```

> ⚠️ **Always pilot in a test tenant before applying to production.** Many
> changes are tenant-wide and can take up to 24 hours to fully propagate.

## License

See [`LICENSE`](LICENSE).
