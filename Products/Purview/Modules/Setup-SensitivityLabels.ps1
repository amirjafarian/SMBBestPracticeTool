#requires -Version 7.0
<#
.SYNOPSIS
    Creates and publishes Microsoft Purview sensitivity labels (SMB profile).

.DESCRIPTION
    SMB-tuned subset of the Microsoft default-sensitivity-labels-policies
    spec (https://learn.microsoft.com/en-us/purview/default-sensitivity-labels-policies).
    Trims the full 10-label MS spec down to 8 labels that fit a typical
    small/mid-business deployment, with encryption only at the top tier:

      * Public                                        — no protection
      * General                                       — no protection (DEFAULT for email)
      * Confidential                                  — no protection (parent)
        * Confidential \ All Employees                — Footer "Classified as Confidential"  (DEFAULT for documents)
        * Confidential \ Specific People              — Footer + UserDefined encryption (Outlook: Do Not Forward; prompt in Word/PPT/Excel)
        * Confidential \ Internal Exception           — Footer "Classified as Confidential"
      * Highly Confidential                           — Watermark "HIGHLY CONFIDENTIAL"
        * Highly Confidential \ All Employees         — Footer + Template encryption (all users in your tenant only)
        * Highly Confidential \ Specific People       — Footer + UserDefined encryption (Outlook: Do Not Forward; prompt in Word/PPT/Excel)
        * Highly Confidential \ Internal Exception    — Footer + Template encryption (all users in your tenant only)

    Encryption is applied to the two Highly Confidential Template-protected
    sub-labels and to both "Specific People" sub-labels (UserDefined).
    Confidential \ All Employees / Internal Exception carry visual markings
    (footer) but no encryption — the SMB-friendly profile (encryption on
    these breaks too many third-party integrations and external
    collaboration scenarios for typical SMB customers).

    Template encryption is scoped to the tenant via the `{TenantDomain}`
    token in `EncryptionRightsDefinitions`. The token resolves at runtime
    against the auto-discovered tenant identity (default verified domain,
    or initial `*.onmicrosoft.com` domain as fallback). Per Entra
    rights-management semantics, ANY verified domain expands to ALL
    verified domains in the tenant, so this grants encrypted-label rights
    to "all users in this tenant only" — NOT external `AuthenticatedUsers`
    from other M365 tenants. To opt in to the broad scope (e.g. you
    intentionally collaborate cross-tenant via the label), edit the config
    to use `{AuthenticatedUsers}` or the literal `AuthenticatedUsers`.

    The default rights bundle is Microsoft's "Reviewer" set (View, Edit
    Content, Save, Reply/Reply-All/Forward). If you need a wider bundle
    (e.g. the "Co-Author" set adding Copy, Print, Allow Macros for Office
    co-authoring or third-party tools that read doc metadata via the
    Office object model), edit `EncryptionRightsDefinitions` in
    PurviewConfig.psd1 directly. Validate in a pilot tenant before
    promoting — OBJMODEL access is the right that most often breaks
    third-party integrations.

    The label policy publishes all 8 labels with separate defaults for
    documents and email:
      * Default for DOCUMENTS = Confidential \ All Employees
      * Default for EMAIL     = General
    The email default is applied via the IPPS `OutlookDefaultLabel`
    advanced setting.

    Auto-labeling (client-side and service-side) is intentionally NOT
    configured. Add it deliberately via the Purview portal once the team
    has reviewed false-positive risk and user-impact trade-offs.

    Idempotency:
      * Labels are matched by Name (not DisplayName). Existing labels managed
        by this toolkit (description contains the ManagedByTag) are updated
        in place. Existing labels NOT managed by this toolkit cause the script
        to ABORT unless -AdoptExisting is passed, to prevent silently mutating
        a customer's existing baseline.

.PARAMETER Config
    Hashtable from PurviewConfig.psd1.

.PARAMETER AdoptExisting
    Update labels and policies that already exist but were not created by this
    toolkit. Use only after auditing the existing configuration.

.PARAMETER TenantIdentity
    Tenant-identity object from `Get-ActualTenantIdentity` in the driver
    script (pscustomobject with `DisplayName`, `DefaultDomain`,
    `InitialDomain`, `TenantId`). Used to resolve the `{TenantDomain}`
    token in `EncryptionRightsDefinitions` so encrypted labels grant
    rights to all users in the tenant only (not external
    `AuthenticatedUsers`). If the token is present and cannot be
    resolved, the script aborts the labels module with an actionable
    error — fall-back to broad `AuthenticatedUsers` would silently
    reintroduce the exact scope this token was added to remove.

.PARAMETER SkipContainerLabels
    When set, strip the container-scope bits (`Site`, `UnifiedGroup`) from
    each label's `ContentType` before calling `New-Label` / `Set-Label`.
    The labels still get the `File, Email` scope. Used by the driver
    script when license auto-detect cannot identify a Microsoft 365 BP
    / E5 / Purview Suite SKU, OR when the operator passes
    `-SkipContainerLabels` to `Deploy-PurviewBestPractice.ps1` to opt out.

    Rationale: container scope (Groups & sites) requires the tenant-side
    `Group.Unified EnableMIPLabels = $true` toggle, which is set by
    `Setup-TenantSettings.ps1` step [5/5]. When that step is skipped, the
    label's container bits would have no effect — so we drop them here too
    and log a one-line info message per affected label. This keeps the
    Purview portal `Edit sensitivity label -> Scope` page honest about
    what the toolkit actually provisioned.

.NOTES
    Label and policy changes can take up to 24 hours to fully propagate to
    all users and clients.
#>
[CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'None')]
param(
    [Parameter(Mandatory)]
    [hashtable] $Config,

    [Parameter()]
    [switch] $AdoptExisting,

    # [object] (not [hashtable]) so we accept both the pscustomobject from
    # Get-ActualTenantIdentity AND a plain hashtable from a partner-driver
    # wrapper. Property access via `.DefaultDomain` etc. works for both.
    [Parameter()]
    [object] $TenantIdentity,

    [Parameter()]
    [switch] $SkipContainerLabels
)

$ErrorActionPreference = 'Stop'
# Auto-confirm: this toolkit is designed for unattended/scripted runs. Use -WhatIf for dry-run.
$ConfirmPreference   = 'None'

# Shared retry helper for transient IPPS errors (502, 503, 504, 429, timeouts).
. (Join-Path $PSScriptRoot 'Invoke-WithTransientRetry.ps1')

# Extract a meaningful error message from an IPPS ErrorRecord. IPPS REST cmdlets
# sometimes leave Exception.Message empty and only populate ErrorDetails or
# FullyQualifiedErrorId, so we walk through several properties in priority order.
function Format-IPPSError {
    param([Parameter(Mandatory)] $ErrorRecord)
    if (-not $ErrorRecord) { return '(no error record)' }
    $candidates = @(
        $ErrorRecord.Exception.Message,
        $ErrorRecord.ErrorDetails.Message,
        $ErrorRecord.CategoryInfo.Reason,
        $ErrorRecord.FullyQualifiedErrorId,
        $ErrorRecord.ToString()
    )
    foreach ($c in $candidates) {
        if ($c -and $c.ToString().Trim().Length -gt 0) { return $c.ToString().Trim() }
    }
    return '(IPPS returned an empty error - check Audit logs in Purview portal)'
}

$tag = $Config.ManagedByTag
# Encryption rights bundle. Defined once in PurviewConfig.psd1 as
# `EncryptionRightsDefinitions`. Default is Microsoft's "Reviewer" set
# (View/Edit/Save/Reply/ReplyAll/Forward). Partners who need a wider
# bundle (e.g. Copy, Print, OBJMODEL for third-party integrations) edit
# the config string directly. OBJMODEL is the right that most often
# breaks third-party apps reading Office doc metadata, so the default
# is conservative.
#
# Token resolution (case-insensitive):
#   * `{TenantDomain}`       -> $TenantIdentity.DefaultDomain (preferred)
#                                or .InitialDomain (fallback). Per Entra
#                                rights-management semantics, ANY verified
#                                domain in the tenant expands to ALL
#                                verified domains in that tenant, so this
#                                scopes the rights bundle to "all users in
#                                this tenant only" (not external
#                                authenticated users from other M365
#                                tenants).
#                                If neither domain is available, the
#                                module ABORTS with an actionable error.
#                                Silent fall-back to `AuthenticatedUsers`
#                                would reintroduce the exact broad scope
#                                this token was added to remove — partners
#                                who want broad scope must opt-in via
#                                `{AuthenticatedUsers}` (or the literal
#                                `AuthenticatedUsers`) in config.
#   * `{AuthenticatedUsers}` -> the literal `AuthenticatedUsers` keyword,
#                                for explicit broad scope.
#   * Any other identity (email / `AuthenticatedUsers` already in the
#     string) passes through unchanged.
#
# A label may also override the global default by setting its own
# `EncryptionRightsDefinitions` field — same token semantics apply.
# Used to grant the wider Microsoft "Co-Author" rights bundle
# (adds EXTRACT, PRINT, OBJMODEL) to specific labels like
# `Highly Confidential\All Employees` without affecting siblings.
function Resolve-EncryptionRightsTokens {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string] $RightsDefinitions,
        [object] $TenantIdentity,
        [string] $Source = 'EncryptionRightsDefinitions'
    )
    $resolved = [string] $RightsDefinitions
    if ($resolved -match '\{TenantDomain\}') {
        $tenantDom = $null
        if ($TenantIdentity) {
            # Works for both pscustomobject and hashtable shapes.
            if ($TenantIdentity.DefaultDomain) { $tenantDom = [string] $TenantIdentity.DefaultDomain }
            elseif ($TenantIdentity.InitialDomain) { $tenantDom = [string] $TenantIdentity.InitialDomain }
        }
        if ($tenantDom) {
            $resolved = $resolved -replace '\{TenantDomain\}', $tenantDom
        } else {
            $msg = "Cannot resolve '{TenantDomain}' token in $Source : TenantIdentity was not supplied or has no DefaultDomain/InitialDomain. " +
                   "Refusing to fall back to 'AuthenticatedUsers' because that would silently grant encrypted-label access to ALL Microsoft 365 tenants (the exact scope this token was added to remove). " +
                   "Remediation: re-run via Deploy-PurviewBestPractice.ps1 so tenant identity is auto-discovered, OR (if you intentionally want broad scope) replace '{TenantDomain}' with '{AuthenticatedUsers}' in the affected config field."
            if (Get-Command Add-RunLogEntry -ErrorAction SilentlyContinue) {
                Add-RunLogEntry -Module 'Setup-SensitivityLabels' -Action "Resolve {TenantDomain} ($Source)" `
                    -Target '(unresolved)' -Status 'Failed' -Detail $msg
            }
            throw $msg
        }
    }
    if ($resolved -match '\{AuthenticatedUsers\}') {
        $resolved = $resolved -replace '\{AuthenticatedUsers\}', 'AuthenticatedUsers'
    }
    return $resolved
}

$rights = Resolve-EncryptionRightsTokens -RightsDefinitions $Config.EncryptionRightsDefinitions `
                                          -TenantIdentity $TenantIdentity `
                                          -Source 'Config.EncryptionRightsDefinitions (global default)'
if ($Config.EncryptionRightsDefinitions -match '\{TenantDomain\}') {
    $tenantDom = if ($TenantIdentity.DefaultDomain) { $TenantIdentity.DefaultDomain } else { $TenantIdentity.InitialDomain }
    Write-Host "Encryption rights bundle scoped to tenant domain '$tenantDom' (all users in this tenant only)." -ForegroundColor DarkGray
    if (Get-Command Add-RunLogEntry -ErrorAction SilentlyContinue) {
        Add-RunLogEntry -Module 'Setup-SensitivityLabels' -Action 'Resolve {TenantDomain}' `
            -Target $tenantDom -Status 'Info' `
            -Detail "Resolved {TenantDomain} token in EncryptionRightsDefinitions (global default) to '$tenantDom' (all users in this tenant only; excludes external AuthenticatedUsers)."
    }
}
$offlineDays = $Config.EncryptionOfflineAccessDays

# Cache the full label set once so we can match by DisplayName too. The IPPS
# Get-Label -Identity switch only resolves Name/ImmutableId/Guid -- not
# DisplayName -- so a tenant with a template label named "Personal" (a
# different internal Guid) would otherwise look "missing" to us and we'd
# call New-Label, which then fails the display-name uniqueness rule.
$allLabelsRaw = @(Get-Label -ErrorAction SilentlyContinue)

# ---------------------------------------------------------------------------
# Soft-delete tombstone detection + auto-rename.
#
# Remove-Label SOFT-deletes labels: they stay in Get-Label results with
# Mode='PendingDeletion' for ~30 days, but the name is reserved (so
# New-Label with the same name fails) AND the label cannot be updated
# (Set-Label returns ErrorCommonComplianceRuleIsDeletedException).
# Without this check the deploy silently ran Set-Label against tombstones,
# every cmdlet failed, and the summary still reported OK.
#
# When a tombstone blocks a configured label, we auto-rename it for this
# run by appending '-v2' (or the next free 'vN' suffix). The mutation is
# IN-MEMORY ONLY -- PurviewConfig.psd1 on disk is not changed. A remap is
# also stashed on $Config.LabelNameRemap so Setup-DLP.ps1 can rewrite
# LabelPath references like 'Confidential/AllEmployees'.
# ---------------------------------------------------------------------------
function Test-LabelSoftDeleted {
    param($Label)
    if (-not $Label) { return $false }
    if ($Label.PSObject.Properties.Name -contains 'Mode' -and $Label.Mode -eq 'PendingDeletion') { return $true }
    if ($Label.PSObject.Properties.Name -contains 'Disabled' -and $Label.Disabled -eq $true)    { return $true }
    return $false
}

function Get-FreeVersionedName {
    <#
        Find the lowest N >= 2 such that the slot 'BaseName-vN' (and matching
        DisplayName 'BaseDisplayName vN') is not held by a TOMBSTONED label.

        An existing ACTIVE label at the candidate slot is fine: the downstream
        label-creation flow will discover it via Get-Label, run Test-Owned,
        and either update it in place (toolkit-managed) or abort (foreign).
        We only need to skip slots that are blocked by a soft-delete tombstone,
        since tombstones reserve both Name and DisplayName but cannot be
        updated or referenced.
    #>
    param(
        [Parameter(Mandatory)] [string] $BaseName,
                               [string] $BaseDisplayName,
        [Parameter(Mandatory)] [array]  $AllLabels
    )
    if (-not $BaseDisplayName) { $BaseDisplayName = $BaseName }
    for ($n = 2; $n -le 99; $n++) {
        $candName    = "$BaseName-v$n"
        $candDisplay = "$BaseDisplayName v$n"
        $clashName    = $AllLabels | Where-Object { $_.Name        -eq $candName }    | Select-Object -First 1
        $clashDisplay = $AllLabels | Where-Object { $_.DisplayName -eq $candDisplay } | Select-Object -First 1
        $nameBlocked    = ($clashName    -and (Test-LabelSoftDeleted $clashName))
        $displayBlocked = ($clashDisplay -and (Test-LabelSoftDeleted $clashDisplay))
        if (-not $nameBlocked -and -not $displayBlocked) {
            return [pscustomobject]@{ Name = $candName; DisplayName = $candDisplay }
        }
    }
    throw "Could not find a free '-vN' suffix for label '$BaseName' after 99 attempts. Edit PurviewConfig.psd1 manually."
}

# Build the list of config-defined names we will manage (parents + sub-labels).
$configuredLabelNames = @()
foreach ($_lbl in $Config.Labels) {
    $configuredLabelNames += $_lbl.Name
    foreach ($_sub in @($_lbl.SubLabels)) {
        if ($_sub) { $configuredLabelNames += $_sub.Name }
    }
}

# Find tombstoned labels whose Name matches something we were going to manage.
$tombstoned = @($allLabelsRaw | Where-Object {
    $configuredLabelNames -contains $_.Name -and (Test-LabelSoftDeleted $_)
})

$labelNameRemap = @{}
if ($tombstoned.Count -gt 0) {
    $tombstonedNames = @($tombstoned | ForEach-Object { $_.Name })

    Write-Host ''
    Write-Host "  ! Detected $($tombstoned.Count) soft-deleted label tombstone(s) blocking deployment:" -ForegroundColor Yellow
    foreach ($t in $tombstoned) {
        $modeText = if ($t.PSObject.Properties.Name -contains 'Mode') { $t.Mode } else { 'Disabled' }
        Write-Host "      - '$($t.Name)' (Mode=$modeText)" -ForegroundColor Yellow
    }
    Write-Host '    Auto-renaming affected labels with the next free -vN suffix for this run.' -ForegroundColor Yellow
    Write-Host '    PurviewConfig.psd1 on disk is NOT modified; restore the original names by' -ForegroundColor DarkYellow
    Write-Host '    waiting ~30 days for the tombstone to purge then re-running.'              -ForegroundColor DarkYellow

    foreach ($lbl in $Config.Labels) {
        if ($tombstonedNames -contains $lbl.Name) {
            $bumped = Get-FreeVersionedName -BaseName $lbl.Name -BaseDisplayName $lbl.DisplayName -AllLabels $allLabelsRaw
            Write-Host "      $($lbl.Name) -> $($bumped.Name)" -ForegroundColor Yellow
            $labelNameRemap[$lbl.Name] = $bumped.Name
            $lbl.Name        = $bumped.Name
            $lbl.DisplayName = $bumped.DisplayName
        }
        foreach ($sub in @($lbl.SubLabels)) {
            if (-not $sub) { continue }
            if ($tombstonedNames -contains $sub.Name) {
                $bumped = Get-FreeVersionedName -BaseName $sub.Name -BaseDisplayName $sub.DisplayName -AllLabels $allLabelsRaw
                Write-Host "      $($sub.Name) -> $($bumped.Name)" -ForegroundColor Yellow
                $labelNameRemap[$sub.Name] = $bumped.Name
                $sub.Name        = $bumped.Name
                $sub.DisplayName = $bumped.DisplayName
            }
        }
    }

    # Bump LabelPolicy.DefaultLabel if it points to a renamed label.
    if ($Config.LabelPolicy -and $Config.LabelPolicy.DefaultLabel `
        -and $labelNameRemap.ContainsKey($Config.LabelPolicy.DefaultLabel)) {
        $newDefault = $labelNameRemap[$Config.LabelPolicy.DefaultLabel]
        Write-Host "      LabelPolicy.DefaultLabel: $($Config.LabelPolicy.DefaultLabel) -> $newDefault" -ForegroundColor Yellow
        $Config.LabelPolicy.DefaultLabel = $newDefault
    }
    # Bump LabelPolicy.DefaultLabelForEmail if it points to a renamed label.
    if ($Config.LabelPolicy -and $Config.LabelPolicy.DefaultLabelForEmail `
        -and $labelNameRemap.ContainsKey($Config.LabelPolicy.DefaultLabelForEmail)) {
        $newEmailDefault = $labelNameRemap[$Config.LabelPolicy.DefaultLabelForEmail]
        Write-Host "      LabelPolicy.DefaultLabelForEmail: $($Config.LabelPolicy.DefaultLabelForEmail) -> $newEmailDefault" -ForegroundColor Yellow
        $Config.LabelPolicy.DefaultLabelForEmail = $newEmailDefault
    }

    # Surface the remap so Setup-DLP.ps1 can rewrite LabelPath segments.
    $Config['LabelNameRemap'] = $labelNameRemap
    Write-Host ''
}

# Working cache: filter out tombstones so Get-LabelByName / DisplayName
# matching never returns one accidentally.
$allLabels = @($allLabelsRaw | Where-Object { -not (Test-LabelSoftDeleted $_) })

# ---------------------------------------------------------------------------
# Retention-tag (ComplianceTag) name-collision detection + auto-rename.
#
# Sensitivity labels and retention labels share the SAME underlying
# 'ComplianceTag' compliance-rule namespace server-side. A retention label
# named 'Confidential' silently blocks New-Label -Name 'Confidential' with:
#
#   |Microsoft.Exchange.Management.UnifiedPolicy.ComplianceRuleAlreadyExistsInScenarioException|
#   A compliance rule with name 'X' already exists in scenario(s) 'ComplianceTag'.
#
# Get-Label does NOT surface retention tags, so the tombstone check above
# never catches these. Here we query Get-ComplianceTag and apply the same
# -vN auto-rename logic to any colliding configured label name.
# ---------------------------------------------------------------------------
$retentionTags = @()
$retentionTagsLookupFailed = $false
try {
    if (Get-Command Get-ComplianceTag -ErrorAction SilentlyContinue) {
        $retentionTags = @(Get-ComplianceTag -ErrorAction Stop)
    } else {
        $retentionTagsLookupFailed = $true
        Write-Warning "  Get-ComplianceTag cmdlet is not available in this session. Skipping retention-tag collision pre-flight."
    }
} catch {
    $retentionTagsLookupFailed = $true
    Write-Warning "  Could not enumerate retention tags (Get-ComplianceTag failed: $($_.Exception.Message))."
    Write-Warning "  Skipping retention-tag collision pre-flight. If a sensitivity label fails to create with"
    Write-Warning "  'ComplianceRuleAlreadyExistsInScenarioException', a retention tag is holding the name."
}

$retentionCollisions = @()
if (-not $retentionTagsLookupFailed -and $retentionTags.Count -gt 0) {
    $retentionTagNames = @($retentionTags | ForEach-Object { $_.Name })
    $retentionCollisions = @($retentionTagNames | Where-Object { $configuredLabelNames -contains $_ })
}

if ($retentionCollisions.Count -gt 0) {
    # An existing ACTIVE sensitivity label with the same configured Name or
    # DisplayName means the label-creation flow will adopt/leave it in place
    # instead of calling New-Label. In that case the retention-tag name
    # collision is moot (we never try to allocate the colliding name in the
    # ComplianceTag scenario), so renaming would produce a needless duplicate
    # (e.g. a 'Public' Microsoft template already exists -> we'd otherwise
    # create 'Public v2'). Filter the collision list down to entries that
    # actually need a rename.
    function Test-ActiveLabelMatch {
        param([string] $LblName, [string] $LblDisplayName, [string] $ParentId, [array] $AllLabels)
        foreach ($cand in $AllLabels) {
            if (Test-LabelSoftDeleted $cand) { continue }
            $parentMatch = if ($ParentId) { $cand.ParentId -eq $ParentId } else { -not $cand.ParentId }
            if (-not $parentMatch) { continue }
            if ($cand.Name -eq $LblName)              { return $cand }
            if ($LblDisplayName -and $cand.DisplayName -eq $LblDisplayName) { return $cand }
        }
        return $null
    }

    $actionable = @()
    foreach ($lbl in $Config.Labels) {
        if ($retentionCollisions -contains $lbl.Name) {
            $adopt = Test-ActiveLabelMatch -LblName $lbl.Name -LblDisplayName $lbl.DisplayName -ParentId $null -AllLabels $allLabelsRaw
            if ($adopt) {
                Write-Host "    Retention tag named '$($lbl.Name)' exists, but an active sensitivity label '$($adopt.DisplayName)' (Id: $($adopt.Guid), Name: $($adopt.Name)) is already present — adopting it; no rename needed." -ForegroundColor DarkGray
            } else {
                $actionable += [pscustomobject]@{ Scope = 'Parent'; Lbl = $lbl; Sub = $null }
            }
        }
        foreach ($sub in @($lbl.SubLabels)) {
            if (-not $sub) { continue }
            if ($retentionCollisions -contains $sub.Name) {
                # ParentId is unknown at this point (label not yet created/looked up).
                # Match on Name or DisplayName globally; correctness-wise it is safe
                # because sub-label Names are server-globally unique compliance rules.
                $adopt = Test-ActiveLabelMatch -LblName $sub.Name -LblDisplayName $sub.DisplayName -ParentId $null -AllLabels $allLabelsRaw
                if (-not $adopt) {
                    # Try matching by DisplayName under a parent we recognise.
                    $adopt = $allLabelsRaw | Where-Object {
                        -not (Test-LabelSoftDeleted $_) -and
                        $_.DisplayName -eq $sub.DisplayName -and $_.ParentId
                    } | Select-Object -First 1
                }
                if ($adopt) {
                    Write-Host "    Retention tag named '$($sub.Name)' exists, but an active sensitivity sub-label '$($adopt.DisplayName)' (Id: $($adopt.Guid), Name: $($adopt.Name)) is already present — adopting it; no rename needed." -ForegroundColor DarkGray
                } else {
                    $actionable += [pscustomobject]@{ Scope = 'Sub'; Lbl = $lbl; Sub = $sub }
                }
            }
        }
    }

    if ($actionable.Count -eq 0) {
        Write-Host ''
        Write-Host "  i Detected $($retentionCollisions.Count) retention-tag name collision(s), but all matching sensitivity labels already exist on the tenant — no rename needed:" -ForegroundColor DarkGray
        foreach ($n in $retentionCollisions) {
            $tag = $retentionTags | Where-Object { $_.Name -eq $n } | Select-Object -First 1
            $created = if ($tag -and $tag.PSObject.Properties.Name -contains 'CreatedBy') { $tag.CreatedBy } else { '<unknown>' }
            Write-Host "      - Retention tag '$n' (created by '$created') ignored: active sensitivity label with matching Name/DisplayName will be adopted." -ForegroundColor DarkGray
        }
        Write-Host ''
    } else {
        Write-Host ''
        Write-Host "  ! Detected $($actionable.Count) retention-tag (ComplianceTag) name collision(s) blocking deployment:" -ForegroundColor Yellow
        foreach ($act in $actionable) {
            $n = if ($act.Scope -eq 'Sub') { $act.Sub.Name } else { $act.Lbl.Name }
            $tag = $retentionTags | Where-Object { $_.Name -eq $n } | Select-Object -First 1
            $created = if ($tag -and $tag.PSObject.Properties.Name -contains 'CreatedBy') { $tag.CreatedBy } else { '<unknown>' }
            $tagGuid = if ($tag -and $tag.PSObject.Properties.Name -contains 'Guid') { $tag.Guid } else { '<unknown>' }
            Write-Host "      - Retention tag '$n' (Guid: $tagGuid, created by '$created') reserves this name in the ComplianceTag scenario." -ForegroundColor Yellow
        }
        Write-Host '    Sensitivity labels and retention labels share the same server-side name space, so' -ForegroundColor Yellow
        Write-Host "    creating a sensitivity label with this name would fail with 'ComplianceRuleAlreadyExistsInScenarioException'." -ForegroundColor Yellow
        Write-Host '    No matching active sensitivity label exists to adopt, so auto-renaming with the next free -vN suffix for this run.' -ForegroundColor Yellow
        Write-Host '    PurviewConfig.psd1 on disk is NOT modified. To restore the original name, remove or rename' -ForegroundColor DarkYellow
        Write-Host '    the conflicting retention tag (e.g. via Remove-ComplianceTag) and re-run.' -ForegroundColor DarkYellow

        foreach ($act in $actionable) {
            if ($act.Scope -eq 'Parent') {
                $lbl = $act.Lbl
                $bumped = Get-FreeVersionedName -BaseName $lbl.Name -BaseDisplayName $lbl.DisplayName -AllLabels $allLabelsRaw
                Write-Host "      $($lbl.Name) -> $($bumped.Name)" -ForegroundColor Yellow
                $labelNameRemap[$lbl.Name] = $bumped.Name
                $lbl.Name        = $bumped.Name
                $lbl.DisplayName = $bumped.DisplayName
            } else {
                $sub = $act.Sub
                $bumped = Get-FreeVersionedName -BaseName $sub.Name -BaseDisplayName $sub.DisplayName -AllLabels $allLabelsRaw
                Write-Host "      $($sub.Name) -> $($bumped.Name)" -ForegroundColor Yellow
                $labelNameRemap[$sub.Name] = $bumped.Name
                $sub.Name        = $bumped.Name
                $sub.DisplayName = $bumped.DisplayName
            }
        }

        if ($Config.LabelPolicy -and $Config.LabelPolicy.DefaultLabel `
            -and $labelNameRemap.ContainsKey($Config.LabelPolicy.DefaultLabel)) {
            $newDefault = $labelNameRemap[$Config.LabelPolicy.DefaultLabel]
            Write-Host "      LabelPolicy.DefaultLabel: $($Config.LabelPolicy.DefaultLabel) -> $newDefault" -ForegroundColor Yellow
            $Config.LabelPolicy.DefaultLabel = $newDefault
        }
        if ($Config.LabelPolicy -and $Config.LabelPolicy.DefaultLabelForEmail `
            -and $labelNameRemap.ContainsKey($Config.LabelPolicy.DefaultLabelForEmail)) {
            $newEmailDefault = $labelNameRemap[$Config.LabelPolicy.DefaultLabelForEmail]
            Write-Host "      LabelPolicy.DefaultLabelForEmail: $($Config.LabelPolicy.DefaultLabelForEmail) -> $newEmailDefault" -ForegroundColor Yellow
            $Config.LabelPolicy.DefaultLabelForEmail = $newEmailDefault
        }

        # Surface remap so Setup-DLP.ps1 can rewrite LabelPath segments like 'Confidential/AllEmployees'.
        $Config['LabelNameRemap'] = $labelNameRemap
        Write-Host ''
    }
}

function Get-LabelByName {
    param(
        [string] $Name,
        [string] $DisplayName,
        [string] $ParentId,
        # Scope filter for which labels to consider:
        #   'Any'      - legacy permissive match (default for back-compat). Name
        #                match is hierarchy-agnostic; DisplayName fallback honours
        #                the supplied $ParentId (null = top-level).
        #   'TopLevel' - match only labels with no ParentId.
        #   'Parent'   - match only labels whose ParentId equals $ParentId. Requires $ParentId.
        # Use 'TopLevel' for configured-parent lookups and 'Parent' for sub-label
        # lookups under a known parent. Without an explicit scope a tenant that
        # has a sub-label with the same internal Name as a configured parent
        # (common on tenants migrated to the modern label scheme or with the
        # Microsoft-default labels enabled) will return the sub-label and the
        # caller will cache it as a "parent", which then breaks Pass 3 Phase A
        # with InvalidSubLabelPriorityException.
        [ValidateSet('Any','TopLevel','Parent')]
        [string] $Scope = 'Any'
    )
    if ($Scope -eq 'Parent' -and [string]::IsNullOrWhiteSpace($ParentId)) { return $null }

    $candidates = switch ($Scope) {
        'TopLevel' { $allLabels | Where-Object { -not $_.ParentId } }
        'Parent'   { $allLabels | Where-Object { $_.ParentId -eq $ParentId } }
        default    { $allLabels }
    }

    $byName = $candidates | Where-Object { $_.Name -eq $Name } | Select-Object -First 1
    if ($byName) { return $byName }

    if ($DisplayName) {
        if ($Scope -eq 'Any') {
            # Legacy 'Any' scope: DisplayName fallback uses the caller-supplied
            # ParentId-or-null filter (DisplayName is not tenant-globally unique
            # like Name is).
            $byDisplay = $allLabels | Where-Object {
                $_.DisplayName -eq $DisplayName -and (
                    ($ParentId -and $_.ParentId -eq $ParentId) -or
                    (-not $ParentId -and -not $_.ParentId)
                )
            } | Select-Object -First 1
        } else {
            $byDisplay = $candidates | Where-Object { $_.DisplayName -eq $DisplayName } | Select-Object -First 1
        }
        if ($byDisplay) { return $byDisplay }
    }
    return $null
}

# Read a single advanced-setting key (e.g. 'color') off a live Get-Label
# object. IPPS surfaces these as a `Settings` collection whose ToString()
# renders each entry as `[key, value]` (e.g. `[color, #13A10E]`). Parsing
# the rendered form is the most reliable approach because the underlying
# CLR type is not stable across cmdlet versions. Returns $null when the
# label, the collection, or the key is missing.
function Get-LabelAdvancedSetting {
    param(
        $Label,
        [Parameter(Mandatory)] [string] $Key
    )
    if (-not $Label) { return $null }
    $needle = $Key.Trim().ToLowerInvariant()
    foreach ($propName in @('Settings','AdvancedSettings','LocaleSettings')) {
        $prop = $Label.PSObject.Properties[$propName]
        if (-not $prop) { continue }
        $coll = $prop.Value
        if (-not $coll) { continue }
        # Try structured access first (Key/Value or Name/Value or dictionary)
        # before falling back to regex on the rendered '[key, value]' form. The
        # IPPS module version sometimes returns typed Setting objects, and a
        # mismatch in ToString() rendering would otherwise cause repeat false
        # drift detections on every run.
        if ($coll -is [System.Collections.IDictionary]) {
            foreach ($k in $coll.Keys) {
                if (([string]$k).Trim().ToLowerInvariant() -eq $needle) {
                    return [string]$coll[$k]
                }
            }
            continue
        }
        foreach ($item in @($coll)) {
            if ($null -eq $item) { continue }
            $keyProp = $null
            foreach ($kp in 'Key','Name') {
                $p = $item.PSObject.Properties[$kp]
                if ($p) { $keyProp = $p; break }
            }
            $valProp = $item.PSObject.Properties['Value']
            if ($keyProp -and $valProp) {
                if (([string]$keyProp.Value).Trim().ToLowerInvariant() -eq $needle) {
                    return [string]$valProp.Value
                }
                continue
            }
            $s = [string]$item
            if ($s -match '^\s*\[\s*([^,\]]+?)\s*,\s*(.*?)\s*\]\s*$') {
                if ($matches[1].Trim().ToLowerInvariant() -eq $needle) {
                    return $matches[2].Trim()
                }
            }
        }
    }
    return $null
}

# Resolve a configured parent label to its live Purview object. Prefers the
# Pass 1 cache ($script:createdParents) because that object came directly from
# Get-Label -Identity in New-OrUpdate-Label and is authoritative even for
# Microsoft-default labels (e.g. 'Public', 'Personal') that bulk Get-Label
# does not always surface reliably. Falls back to the bulk-cache lookup.
#
# The cached object MUST be top-level. If Pass 1 cached a sub-label (which can
# happen on tenants with name collisions between configured parents and live
# sub-labels), we return $null and let the caller surface the remediation.
# Without this guard, Phase A would push the sub-label to priority 0 and hit
# InvalidSubLabelPriorityException ("priority 0 is invalid for sub-label").
function Resolve-ConfigParentLabel {
    param([Parameter(Mandatory)] [hashtable] $LabelDef)
    if ($script:createdParents -and $script:createdParents.ContainsKey($LabelDef.Name)) {
        $cached = $script:createdParents[$LabelDef.Name]
        if ($cached -and -not $cached.ParentId) { return $cached }
        # Cached object is a sub-label - reject and fall through to bulk lookup
        # (which is also scope-restricted) so the caller never blindly trusts a
        # collision-tainted cache entry.
    }
    return Get-LabelByName -Name $LabelDef.Name -DisplayName $LabelDef.DisplayName -Scope 'TopLevel'
}

# Return the most stable identity to pass to IPPS cmdlets. The label Guid is
# immutable and unambiguous; Name can be a GUID-string (MS-default labels) or
# a human-readable token (user-created labels). Both work with -Identity, but
# Guid is the safer choice for re-lookups after mutations.
function Get-StableLabelIdentity {
    param([Parameter(Mandatory)] $LabelObject)
    if ($LabelObject.PSObject.Properties.Name -contains 'Guid' -and $LabelObject.Guid) {
        return [string]$LabelObject.Guid
    }
    return [string]$LabelObject.Name
}

# True when a string is shaped like a canonical GUID. Used to detect labels
# whose Name property is actually a GUID (Microsoft-default labels), because
# Set-Label via that GUID-shaped Name is unreliable on some tenants.
function Test-IsGuidLikeString {
    param([string] $Value)
    if ([string]::IsNullOrWhiteSpace($Value)) { return $false }
    return $Value -match '^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$'
}

# Resolve a label to its CURRENT live state using a fresh bulk Get-Label (which
# is more reliable than Get-Label -Identity for Microsoft-default labels on
# some tenants). Matches by Guid, then Name, then unique top-level DisplayName.
# Returns $null if no match. Used by both the priority setter and the
# verification pass so they cannot disagree about a label's current priority.
function Get-LiveLabelByObject {
    param([Parameter(Mandatory)] $LabelObject)
    $bulk = $null
    try {
        Invoke-WithTransientRetry -Description "Get-Label (bulk fetch for live resolve)" -Action {
            $script:_bulkLabelsForResolve = @(Get-Label -ErrorAction Stop | Where-Object { -not (Test-LabelSoftDeleted $_) })
        }
        $bulk = $script:_bulkLabelsForResolve
        Remove-Variable -Name '_bulkLabelsForResolve' -Scope Script -ErrorAction SilentlyContinue
    } catch {
        $bulk = @(Get-Label -ErrorAction SilentlyContinue | Where-Object { -not (Test-LabelSoftDeleted $_) })
    }
    if (-not $bulk) { return $null }

    if ($LabelObject.Guid) {
        try {
            if (([guid]$LabelObject.Guid) -ne [guid]::Empty) {
                $m = $bulk | Where-Object { $_.Guid -eq $LabelObject.Guid } | Select-Object -First 1
                if ($m) { return $m }
            }
        } catch {}
    }
    if ($LabelObject.Name) {
        $m = $bulk | Where-Object { $_.Name -eq [string]$LabelObject.Name } | Select-Object -First 1
        if ($m) { return $m }
    }
    if ($LabelObject.DisplayName) {
        $cands = @($bulk | Where-Object { $_.DisplayName -eq $LabelObject.DisplayName -and -not $_.ParentId })
        if ($cands.Count -eq 1) { return $cands[0] }
    }
    return $null
}

# Update label priority and VERIFY the change persisted. Tries multiple Identity
# forms because IPPS Set-Label can be a silent no-op for Microsoft-default
# labels when called by Guid (or by Name when the Name is itself the GUID).
#
# Identity precedence:
#   * Microsoft-default-shaped labels (Name == Guid OR Name looks like a GUID):
#       DisplayName (if unique top-level)  →  Name  →  Guid
#   * Everything else:
#       Name  →  DisplayName (if unique top-level)  →  Guid
#
# DisplayName is only added as a candidate for TOP-LEVEL labels, and only when
# bulk Get-Label confirms exactly one top-level label has that DisplayName AND
# it matches our target Guid/Name. Sub-label DisplayNames are excluded because
# they can legitimately repeat across different parent labels.
#
# Returns a PSObject with: Success, UsedIdentity (Name/DisplayName/Guid),
# Attempts (string[] diagnostic trail), Live (fresh label object on success).
function Set-LabelPriorityWithVerify {
    param(
        [Parameter(Mandatory)] $LabelObject,
        [Parameter(Mandatory)] [int]    $TargetPriority,
        [Parameter(Mandatory)] [string] $DisplayNameForLog,
        [switch] $IsSubLabel
    )

    $nameStr    = if ($LabelObject.Name)        { [string]$LabelObject.Name        } else { $null }
    $displayStr = if ($LabelObject.DisplayName) { [string]$LabelObject.DisplayName } else { $null }
    $guidStr    = $null
    if ($LabelObject.Guid) {
        try { if (([guid]$LabelObject.Guid) -ne [guid]::Empty) { $guidStr = [string]$LabelObject.Guid } } catch {}
    }

    $nameIsGuidLike = Test-IsGuidLikeString -Value $nameStr
    $msDefaultLike  = ($nameStr -and $guidStr -and ($nameStr -eq $guidStr)) -or $nameIsGuidLike

    # Confirm DisplayName uniqueness before allowing it as a Set-Label identity.
    $displayIsSafe = $false
    if (-not $IsSubLabel -and $displayStr) {
        $peek = @(Get-Label -ErrorAction SilentlyContinue | Where-Object { -not (Test-LabelSoftDeleted $_) })
        $same = @($peek | Where-Object { $_.DisplayName -eq $displayStr -and -not $_.ParentId })
        if ($same.Count -eq 1) {
            $hit = $same[0]
            if (($guidStr -and ($hit.Guid -eq $LabelObject.Guid)) -or
                ($nameStr -and ($hit.Name -eq $nameStr))) {
                $displayIsSafe = $true
            }
        }
    }

    $cands = New-Object System.Collections.Generic.List[object]
    if ($msDefaultLike) {
        if ($displayIsSafe) { [void]$cands.Add(@{ Kind='DisplayName'; Value=$displayStr }) }
        if ($nameStr)       { [void]$cands.Add(@{ Kind='Name';        Value=$nameStr    }) }
        if ($guidStr -and ($guidStr -ne $nameStr)) {
                              [void]$cands.Add(@{ Kind='Guid';        Value=$guidStr    }) }
    } else {
        if ($nameStr)       { [void]$cands.Add(@{ Kind='Name';        Value=$nameStr    }) }
        if ($displayIsSafe) { [void]$cands.Add(@{ Kind='DisplayName'; Value=$displayStr }) }
        if ($guidStr -and ($guidStr -ne $nameStr)) {
                              [void]$cands.Add(@{ Kind='Guid';        Value=$guidStr    }) }
    }

    $attempts = New-Object System.Collections.Generic.List[string]
    foreach ($c in $cands) {
        try {
            Invoke-WithTransientRetry -Description ("Set-Label priority=$TargetPriority '$DisplayNameForLog' via $($c.Kind)") -Action {
                Set-Label -Identity $c.Value -Priority $TargetPriority `
                    -ErrorAction Stop -WarningAction SilentlyContinue -Confirm:$false | Out-Null
            }
        } catch {
            $errMsg = Format-IPPSError $_
            [void]$attempts.Add("[$($c.Kind)='$($c.Value)'] threw: $errMsg")
            # 'not a valid priority' / 'is not valid' is the IPPS no-op error we
            # ignore in legacy code; treat as soft failure and try next identity.
            continue
        }
        $live = Get-LiveLabelByObject -LabelObject $LabelObject
        if ($live -and $live.Priority -eq $TargetPriority) {
            [void]$attempts.Add("[$($c.Kind)='$($c.Value)'] success: priority=$($live.Priority)")
            return [pscustomobject]@{
                Success      = $true
                UsedIdentity = $c.Kind
                Attempts     = @($attempts)
                Live         = $live
            }
        }
        $obs = if ($live) { $live.Priority } else { 'not-found-in-bulk' }
        [void]$attempts.Add("[$($c.Kind)='$($c.Value)'] no-op: observed priority=$obs after Set-Label.")
    }
    return [pscustomobject]@{
        Success      = $false
        UsedIdentity = $null
        Attempts     = @($attempts)
        Live         = $null
    }
}

function Test-Owned {
    param($Object, [string] $Tag)
    if (-not $Object) { return $false }
    $desc = if ($Object.PSObject.Properties.Name -contains 'Comment') { $Object.Comment }
            elseif ($Object.PSObject.Properties.Name -contains 'Description') { $Object.Description }
            else { '' }
    return ($desc -and $desc -like "*$Tag*")
}

function Invoke-IPPSCmdlet {
    <#
        IPPS REST cmdlets bypass -ErrorAction Stop. Run with
        -ErrorAction SilentlyContinue + -ErrorVariable, then re-throw any
        captured error so the caller's try/catch (or our local err check)
        sees a real terminating exception.
    #>
    param(
        [Parameter(Mandatory)] [scriptblock] $ScriptBlock,
        [string] $Description = '<unspecified>'
    )
    $err = @()
    & $ScriptBlock -ErrorVariable +err -ErrorAction SilentlyContinue 2>&1 | Out-Null
    if ($err.Count -gt 0) { throw $err[0] }
}

function Set-LabelEncryption {
    <#
        Apply encryption to a label.

        Two protection modes are supported:

          * 'Template' (default) — admin-defined template that grants the
            configured rights ($rights) to AuthenticatedUsers. Used for the
            "All Employees" sub-labels in Microsoft's default-labels spec.

          * 'UserDefined' — the user picks recipients and permissions at apply
            time. Used for the "Trusted People" / "Specific People" sub-labels.
            Office apps (Word/Excel/PowerPoint) prompt the user; Outlook
            applies a fixed behaviour (Encrypt-Only or Do Not Forward) per
            $UserDefinedOutlookBehavior.
    #>
    param(
        [Parameter(Mandatory)] [string] $Identity,
        [ValidateSet('Template','UserDefined')]
        [string] $ProtectionType = 'Template',
        [ValidateSet('EncryptOnly','DoNotForward','None')]
        [string] $UserDefinedOutlookBehavior = 'None',
        # Optional per-label override. When supplied, this rights string is
        # passed to Set-Label instead of the module-level `$rights` default.
        # Caller is responsible for resolving any `{TenantDomain}` token
        # via Resolve-EncryptionRightsTokens before passing it in.
        [string] $RightsDefinitions
    )
    $effectiveRights = if ($PSBoundParameters.ContainsKey('RightsDefinitions') -and $RightsDefinitions) {
        $RightsDefinitions
    } else {
        $rights
    }
    if ($ProtectionType -eq 'Template') {
        Invoke-WithTransientRetry -Description ("Set-Label encryption (Template) '$Identity'") -Action {
            Set-Label -Identity $Identity `
                -EncryptionEnabled $true `
                -EncryptionProtectionType 'Template' `
                -EncryptionRightsDefinitions $effectiveRights `
                -EncryptionContentExpiredOnDateInDaysOrNever 'Never' `
                -EncryptionOfflineAccessDays $offlineDays `
                -ErrorAction Stop -WarningAction SilentlyContinue -Confirm:$false | Out-Null
        }
    } else {
        $params = @{
            Identity                                    = $Identity
            EncryptionEnabled                           = $true
            EncryptionProtectionType                    = 'UserDefined'
            EncryptionPromptUser                        = $true   # Word/Excel/PowerPoint: prompt user to assign permissions
            EncryptionContentExpiredOnDateInDaysOrNever = 'Never'
            EncryptionOfflineAccessDays                 = $offlineDays
        }
        switch ($UserDefinedOutlookBehavior) {
            'EncryptOnly'   { $params['EncryptionEncryptOnly']   = $true }
            'DoNotForward'  { $params['EncryptionDoNotForward']  = $true }
            default         { } # 'None' = no Outlook-specific behaviour
        }
        Invoke-WithTransientRetry -Description ("Set-Label encryption (UserDefined) '$Identity'") -Action {
            Set-Label @params -ErrorAction Stop -WarningAction SilentlyContinue -Confirm:$false | Out-Null
        }
    }
}

function Set-LabelContentMarking {
    param(
        [Parameter(Mandatory)] [string] $Identity,
        [string] $HeaderText,
        [string] $FooterText,
        [string] $WatermarkText
    )
    $params = @{
        Identity = $Identity
        ApplyContentMarkingHeaderEnabled = [bool]$HeaderText
        ApplyContentMarkingFooterEnabled = [bool]$FooterText
        ApplyWaterMarkingEnabled         = [bool]$WatermarkText
    }
    if ($HeaderText) {
        $params['ApplyContentMarkingHeaderText'] = $HeaderText
        $params['ApplyContentMarkingHeaderAlignment'] = 'Center'
        $params['ApplyContentMarkingHeaderFontColor'] = '#FF0000'
    }
    if ($FooterText) {
        $params['ApplyContentMarkingFooterText'] = $FooterText
        $params['ApplyContentMarkingFooterAlignment'] = 'Center'
        $params['ApplyContentMarkingFooterFontColor'] = '#FF0000'
    }
    if ($WatermarkText) {
        $params['ApplyWaterMarkingText']      = $WatermarkText
        $params['ApplyWaterMarkingLayout']    = 'Diagonal'
        $params['ApplyWaterMarkingFontColor'] = '#FF0000'
    }
    Invoke-WithTransientRetry -Description ("Set-Label content marking '$($params.Identity)'") -Action {
        Set-Label @params -ErrorAction Stop -WarningAction SilentlyContinue -Confirm:$false | Out-Null
    }
}

# ---------------------------------------------------------------------------
# ContentType (label scope) helpers — issue #24.
#
# `ContentType` is the IPPS `New-Label -ContentType` value: a comma-separated
# string from the set {File, Email, Site, UnifiedGroup, PurviewAssets,
# SchematizedDataAssets}. Three published labels (General, AllEmployees,
# HCAllEmps) ship with container scope ('Site, UnifiedGroup') so they appear
# in the Purview portal's container-label picker; the rest stay File/Email-only.
#
# Helpers below normalise the comma string to a canonical SORTED-UNIQUE array
# so we can:
#   * compare config vs live without false drift from whitespace / ordering;
#   * UNION live + desired on adoption so we never strip a manually-added
#     scope (per issue #24 AC3 + AC6);
#   * strip the container bits when -SkipContainerLabels is set without
#     mutating the rest of the desired scope.
# ---------------------------------------------------------------------------
$script:ContainerContentTypeBits = @('Site', 'UnifiedGroup')

function ConvertTo-ContentTypeSet {
    [OutputType([string[]])]
    param([string] $Value)
    if ([string]::IsNullOrWhiteSpace($Value)) { return @() }
    return @(
        $Value -split ',' |
            ForEach-Object { $_.Trim() } |
            Where-Object   { $_ } |
            Sort-Object -Unique
    )
}

function Compare-ContentTypeSets {
    [OutputType([bool])]
    param(
        [Parameter(Mandatory)] [AllowEmptyCollection()] [string[]] $A,
        [Parameter(Mandatory)] [AllowEmptyCollection()] [string[]] $B
    )
    if ($A.Count -ne $B.Count) { return $false }
    for ($i = 0; $i -lt $A.Count; $i++) {
        if ($A[$i] -ne $B[$i]) { return $false }
    }
    return $true
}

function Get-DesiredContentTypeSet {
    <#
        Resolve the desired ContentType set for a label, after the
        -SkipContainerLabels gate. Returns:
          * $null  if the config did not specify a ContentType (caller
                   should leave the IPPS default in place);
          * @()    if every desired bit was stripped (caller still skips
                   the Set-Label so the IPPS default kicks in);
          * sorted-unique string[]  otherwise.
        Emits a one-line info message + Skipped run-log entry per label
        when container bits are stripped (issue #24 AC4).
    #>
    [OutputType([string[]])]
    param(
        [Parameter(Mandatory)] [hashtable] $LabelDef,
        [Parameter(Mandatory)] [bool]      $SkipContainerLabels
    )
    if (-not $LabelDef.ContainsKey('ContentType') -or
        [string]::IsNullOrWhiteSpace([string]$LabelDef.ContentType)) {
        return $null
    }
    $configured = ConvertTo-ContentTypeSet -Value ([string]$LabelDef.ContentType)
    if (-not $SkipContainerLabels) { return $configured }

    $stripped = @($configured | Where-Object { $_ -notin $script:ContainerContentTypeBits })
    $removed  = @($configured | Where-Object { $_ -in    $script:ContainerContentTypeBits })
    if ($removed.Count -gt 0) {
        Write-Host ("    [info] -SkipContainerLabels: stripped container scope bits ({0}) from label '{1}' ContentType (configured: {2}; will provision: {3}). Tenant-side Group.Unified EnableMIPLabels is not being set, so the container bits would have no effect." -f
            ($removed -join ', '),
            $LabelDef.DisplayName,
            ($configured -join ', '),
            $(if ($stripped.Count) { $stripped -join ', ' } else { '(none — IPPS default File, Email will apply)' })) -ForegroundColor DarkYellow
        Add-RunLogEntry -Module 'Setup-SensitivityLabels' -Action 'Resolve ContentType' `
            -Target $LabelDef.DisplayName -Status 'Skipped' `
            -Detail ("Container-scope bits ({0}) stripped from configured ContentType '{1}' because -SkipContainerLabels is set. Provisioning '{2}'." -f
                ($removed -join ', '),
                ($configured -join ', '),
                $(if ($stripped.Count) { $stripped -join ', ' } else { '(IPPS default)' }))
    }
    return $stripped
}

function New-OrUpdate-Label {
    param(
        [Parameter(Mandatory)] [hashtable] $LabelDef,
        [string] $ParentId
    )

    $existing = Get-LabelByName -Name $LabelDef.Name -DisplayName $LabelDef.DisplayName -ParentId $ParentId `
        -Scope $(if ($ParentId) { 'Parent' } else { 'TopLevel' })
    $owned     = Test-Owned -Object $existing -Tag $tag
    $matchedBy = $null
    $justCreated = $false   # New-Label succeeded inside this call
    $idForOps = if ($existing) { $existing.Name } else { $LabelDef.Name }

    if ($existing) {
        $matchedBy = if ($existing.Name -eq $LabelDef.Name) { 'Name' } else { 'DisplayName' }
        if ($owned) {
            Write-Host "    = Found managed label '$($LabelDef.Name)' (matched by $matchedBy). Updating." -ForegroundColor DarkGray
        } elseif ($AdoptExisting) {
            Write-Host "    ~ Found existing label '$($LabelDef.DisplayName)' (Id: $($existing.Guid), matched by $matchedBy). -AdoptExisting set; updating." -ForegroundColor Yellow
        } else {
            Write-Host "    = Found existing label '$($LabelDef.DisplayName)' (Id: $($existing.Guid), matched by $matchedBy). Leaving as-is (use -AdoptExisting to update)." -ForegroundColor DarkGray
            return $existing
        }
    }

    $tooltip = $LabelDef.Tooltip
    $comment = "$tag $tooltip"

    if (-not $existing) {
        # Cross-scope Name-collision pre-check. IPPS enforces tenant-globally
        # unique label Names, so if the configured Name collides with a live
        # label in a DIFFERENT hierarchy scope (typically: configured top-level
        # vs an existing sub-label of the same Name, common on tenants migrated
        # to the modern label scheme or with Microsoft-default labels enabled),
        # New-Label will fail with a cryptic message. Detect upfront and surface
        # an actionable remediation, otherwise Pass 3 fails later with
        # InvalidSubLabelPriorityException when the wrong object is reordered.
        $callerWantsTopLevel = -not $ParentId
        $nameCollision = $allLabels | Where-Object { $_.Name -eq $LabelDef.Name } | Select-Object -First 1
        if ($nameCollision) {
            $collisionIsSubLabel = [bool] $nameCollision.ParentId
            if ($callerWantsTopLevel -eq $collisionIsSubLabel) {
                $callerScope = if ($callerWantsTopLevel) { 'top-level' } else { "child of parent Id $ParentId" }
                $liveScope   = if ($collisionIsSubLabel) { "sub-label of parent Id $($nameCollision.ParentId)" } else { 'top-level' }
                $collisionGuid = if ($nameCollision.Guid) { [string]$nameCollision.Guid } else { 'unknown' }
                $detail = @(
                    "Cannot create configured label '$($LabelDef.Name)' as ${callerScope}: a live label with the same Name already exists in this tenant as a $liveScope (Id: $collisionGuid)."
                    "Microsoft Purview enforces tenant-globally unique label Names, and the modern label scheme strictly enforces sub-label priority ranges, so this collision must be resolved."
                    "Remediation options:"
                    "  1. Rename the configured label in Products/Purview/Config/PurviewConfig.psd1 (change Labels.Name) so it no longer collides."
                    "  2. In Purview Admin Center (https://purview.microsoft.com), delete or un-nest the colliding live label (Id: $collisionGuid), then re-run."
                    "  3. If the collision is with a Microsoft-default sensitivity label, keep the default and update the configured Name to a tenant-unique value."
                ) -join "`n    "
                Add-RunLogEntry -Module 'Setup-SensitivityLabels' -Action 'New-Label' `
                    -Target $LabelDef.DisplayName -Status 'Failed' -Detail $detail
                Write-Warning "    $detail"
                return $null
            }
        }

        if (-not $PSCmdlet.ShouldProcess($LabelDef.Name, 'New-Label')) { return $null }

        $newArgs = @{
            Name        = $LabelDef.Name
            DisplayName = $LabelDef.DisplayName
            Tooltip     = $tooltip
            Comment     = $comment
        }
        if ($ParentId) { $newArgs['ParentId'] = $ParentId }
        if (-not [string]::IsNullOrWhiteSpace([string]$LabelDef.Color)) {
            $newArgs['AdvancedSettings'] = @{ color = [string]$LabelDef.Color }
        }

        # Issue #24 — pass -ContentType through to New-Label when configured.
        # We never UNION here (the label doesn't exist yet, so there is no
        # live value to preserve); UNION applies only on the adopt/update
        # path below.
        $desiredContentTypeNew = Get-DesiredContentTypeSet -LabelDef $LabelDef -SkipContainerLabels:$SkipContainerLabels.IsPresent
        if ($null -ne $desiredContentTypeNew -and $desiredContentTypeNew.Count -gt 0) {
            $newArgs['ContentType'] = ($desiredContentTypeNew -join ', ')
        }

        # IPPS cmdlets bypass -ErrorAction Stop. Capture errors via -ErrorVariable.
        # PR4: wrap with Invoke-WithTransientRetry so 502/503/504/429 auto-retry.
        # NOT using -AlreadyExistsIsSuccess here because the catch block below
        # needs to inspect the message and extract the existing label's GUID for
        # the "Duplicate display name" recovery path.
        $err = @()
        try {
            Invoke-WithTransientRetry -Description ("New-Label '$($LabelDef.Name)'") -Action {
                New-Label @newArgs -ErrorAction Stop -WarningAction SilentlyContinue -Confirm:$false | Out-Null
            }
        } catch {
            $err = @($_)
        }

        if ($err.Count -eq 0) {
            $existing = Get-Label -Identity $LabelDef.Name -ErrorAction SilentlyContinue
            if ($existing) { $script:allLabels += $existing }
            $idForOps = $LabelDef.Name
            $justCreated = $true
            Write-Host "    + Created label '$($LabelDef.Name)'." -ForegroundColor Green
        } else {
            $msg = $(Format-IPPSError $err[0])

            # Recoverable case: a label with the same DisplayName already
            # exists (often a Microsoft template label that Get-Label
            # didn't return).
            if ($msg -match "Duplicate display name '[^']+' is already used by label '([0-9a-f-]{36}[^']*)'") {
                $existingGuid = $Matches[1]
                $found = Get-Label -Identity $existingGuid -ErrorAction SilentlyContinue
                # Validate hierarchy before adopting. Without this check, adopting
                # a sub-label as a configured top-level parent (or vice versa)
                # would cache the wrong object in $createdParents and trigger
                # InvalidSubLabelPriorityException in Phase A.
                if ($found) {
                    $callerWantsTopLevel = -not $ParentId
                    $foundIsSubLabel     = [bool] $found.ParentId
                    if ($callerWantsTopLevel -eq $foundIsSubLabel) {
                        $callerScope = if ($callerWantsTopLevel) { 'top-level' } else { "child of parent Id $ParentId" }
                        $liveScope   = if ($foundIsSubLabel) { "sub-label of parent Id $($found.ParentId)" } else { 'top-level' }
                        $detail = "Duplicate-display-name adoption for '$($LabelDef.DisplayName)' resolved to live label (Id: $existingGuid) in a DIFFERENT hierarchy scope than configured. Configured scope: $callerScope. Live scope: $liveScope. Refusing to adopt to avoid mis-pinning priority (Phase A would then fail with InvalidSubLabelPriorityException). Rename the configured label or un-nest the live label, then re-run."
                        Add-RunLogEntry -Module 'Setup-SensitivityLabels' -Action 'New-Label' `
                            -Target $LabelDef.DisplayName -Status 'Failed' -Detail $detail
                        Write-Warning "    $detail"
                        return $null
                    }
                }
                if (-not $found) {
                    $found = [pscustomobject]@{
                        Name        = $existingGuid
                        DisplayName = $LabelDef.DisplayName
                        Guid        = [guid]$existingGuid
                        Priority    = -1
                        ParentId    = $ParentId
                        Comment     = ''
                    }
                }
                $existing = $found
                $idForOps = $existingGuid
                $matchedBy = 'DisplayName'
                $script:allLabels += $found

                if ($AdoptExisting) {
                    Write-Host "    ~ Label '$($LabelDef.DisplayName)' already exists (Id: $existingGuid). -AdoptExisting set; updating." -ForegroundColor Yellow
                    Add-RunLogEntry -Module 'Setup-SensitivityLabels' -Action 'New-Label' -Target $LabelDef.DisplayName -Status 'Adopted' -Detail "Label already exists (Id: $existingGuid). -AdoptExisting set; will update."
                    # Fall through to update branch.
                } else {
                    Write-Host "    = Label '$($LabelDef.DisplayName)' already exists (Id: $existingGuid). Using existing without changes (re-run with -AdoptExisting to overwrite)." -ForegroundColor DarkGray
                    Add-RunLogEntry -Module 'Setup-SensitivityLabels' -Action 'New-Label' -Target $LabelDef.DisplayName -Status 'Skipped' -Detail "Label already exists (Id: $existingGuid). Re-run with -AdoptExisting to overwrite."
                    return $found
                }
            } elseif ($msg -match 'ComplianceRuleAlreadyExistsInScenarioException' -or
                      $msg -match "compliance rule with name '[^']+' already exists in scenario") {
                # Safety net: the retention-tag pre-flight didn't catch this
                # (e.g. Get-ComplianceTag was inaccessible at startup, or the
                # tag was created between pre-flight and now). Fail with an
                # actionable message instead of a cryptic 500.
                Write-Warning "    Failed to create label '$($LabelDef.Name)': the name is already reserved in the ComplianceTag scenario (a retention label is using it)."
                Write-Warning "    Remediation:"
                Write-Warning "      1. Inspect the colliding retention tag:"
                Write-Warning "           Get-ComplianceTag | Where-Object Name -eq '$($LabelDef.Name)'"
                Write-Warning "      2. Remove or rename it, OR change the Name in Products/Purview/Config/PurviewConfig.psd1, then re-run."
                Write-Warning "    (The pre-flight retention-tag collision check would normally auto-rename this — check earlier output for a Get-ComplianceTag warning.)"
                return $null
            } else {
                Write-Warning "    Failed to create label '$($LabelDef.Name)': $msg"
                return $null
            }
        }
    }

    # Update display / tooltip / comment for pre-existing labels we are
    # adopting or already manage. Skip when we just created the label
    # because New-Label already set those values.
    if (-not $justCreated -and $existing -and ($owned -or $AdoptExisting)) {
        if ($PSCmdlet.ShouldProcess($idForOps, 'Set-Label (display + tooltip)')) {
            try {
                Invoke-WithTransientRetry -Description ("Set-Label display/tooltip '$idForOps'") -Action {
                    Set-Label -Identity $idForOps `
                        -DisplayName $LabelDef.DisplayName `
                        -Tooltip $tooltip `
                        -Comment $comment `
                        -ErrorAction Stop -WarningAction SilentlyContinue -Confirm:$false | Out-Null
                }
                Write-Host "    ~ Updated label '$($LabelDef.DisplayName)'." -ForegroundColor Yellow
            } catch {
                Write-Warning "    Failed to update label '$($LabelDef.DisplayName)': $(Format-IPPSError $_)"
            }
        }
    }

    # Color drift correction for pre-existing labels we just adopted or
    # already manage. New labels (-justCreated) already had the colour
    # applied via New-Label -AdvancedSettings so we skip the round-trip.
    # AdvancedSettings is merge-not-replace on the IPPS side, so this only
    # touches the `color` key and leaves any other advanced settings alone.
    if (-not $justCreated -and $existing -and ($owned -or $AdoptExisting) `
        -and -not [string]::IsNullOrWhiteSpace([string]$LabelDef.Color)) {
        $configColor = ([string]$LabelDef.Color).Trim()
        # Wrap the drift-read in transient retry so a 502/503/504/429 hiccup
        # cannot masquerade as 'missing colour' and trigger an unnecessary
        # Set-Label round-trip on the next pass. On hard failure, fall back
        # to the already-cached $existing object before assuming drift.
        $live = $null
        try {
            Invoke-WithTransientRetry -Description ("Get-Label colour read '$idForOps'") -Action {
                $script:__colorReadResult = Get-Label -Identity $idForOps -ErrorAction Stop
            }
            $live = $script:__colorReadResult
        } catch {
            $live = $existing
        } finally {
            Remove-Variable -Scope script -Name '__colorReadResult' -ErrorAction SilentlyContinue
        }
        $currentColor = Get-LabelAdvancedSetting -Label $live -Key 'color'
        $needsUpdate = (-not $currentColor) -or
            ($currentColor.ToLowerInvariant() -ne $configColor.ToLowerInvariant())
        if ($needsUpdate) {
            if ($PSCmdlet.ShouldProcess($idForOps, "Set-Label color $configColor")) {
                try {
                    Invoke-WithTransientRetry -Description ("Set-Label color '$idForOps'") -Action {
                        Set-Label -Identity $idForOps `
                            -AdvancedSettings @{ color = $configColor } `
                            -ErrorAction Stop -WarningAction SilentlyContinue -Confirm:$false | Out-Null
                    }
                    $detail = if ($currentColor) {
                        "Updated label '$($LabelDef.DisplayName)' colour from $currentColor to $configColor."
                    } else {
                        "Set label '$($LabelDef.DisplayName)' colour to $configColor."
                    }
                    Write-Host "    ~ $detail" -ForegroundColor Yellow
                    Add-RunLogEntry -Module 'Setup-SensitivityLabels' -Action 'Set-Label color' -Target $LabelDef.DisplayName -Status 'Updated' -Detail $detail
                } catch {
                    $msg = Format-IPPSError $_
                    Write-Warning "    Failed to update colour for label '$($LabelDef.DisplayName)': $msg"
                    Add-RunLogEntry -Module 'Setup-SensitivityLabels' -Action 'Set-Label color' -Target $LabelDef.DisplayName -Status 'Failed' -Detail $msg
                }
            }
        }
    }

    # ContentType drift correction (issue #24).
    #
    # Only runs on the adopt/update path — when a label is freshly created,
    # New-Label above already applied the desired ContentType. For pre-
    # existing labels we use UNION-not-replace: live ContentType UNION
    # desired ContentType. This ensures:
    #   * We never strip a scope a customer manually added in the portal
    #     (issue #24 AC3 + AC6).
    #   * Re-running the deploy is a no-op when the live set already
    #     covers the desired set (sorted-set equality, no false 'Updated'
    #     log lines per issue #24 AC3).
    #
    # The -SkipContainerLabels gate runs inside Get-DesiredContentTypeSet,
    # so the UNION operand already has 'Site'/'UnifiedGroup' stripped when
    # the operator opted out — but we still preserve any container bits
    # the live label already has. We only ADD scope, never remove it.
    if (-not $justCreated -and $existing -and ($owned -or $AdoptExisting)) {
        $desiredCt = Get-DesiredContentTypeSet -LabelDef $LabelDef -SkipContainerLabels:$SkipContainerLabels.IsPresent
        if ($null -ne $desiredCt -and $desiredCt.Count -gt 0) {
            # Drift-read on a fresh Get-Label so we don't compare against a
            # potentially-stale cached object (mirrors the colour block above).
            $liveCt = $null
            try {
                Invoke-WithTransientRetry -Description ("Get-Label ContentType read '$idForOps'") -Action {
                    $script:__ctReadResult = Get-Label -Identity $idForOps -ErrorAction Stop
                }
                $liveCt = $script:__ctReadResult
            } catch {
                $liveCt = $existing
            } finally {
                Remove-Variable -Scope script -Name '__ctReadResult' -ErrorAction SilentlyContinue
            }
            $liveSet  = ConvertTo-ContentTypeSet -Value ([string]$liveCt.ContentType)
            $unionSet = @(@($liveSet + $desiredCt) | Sort-Object -Unique)
            $isNoOp   = Compare-ContentTypeSets -A $liveSet -B $unionSet
            if (-not $isNoOp) {
                if ($PSCmdlet.ShouldProcess($idForOps, "Set-Label ContentType $($unionSet -join ', ')")) {
                    try {
                        Invoke-WithTransientRetry -Description ("Set-Label ContentType '$idForOps'") -Action {
                            Set-Label -Identity $idForOps `
                                -ContentType ($unionSet -join ', ') `
                                -ErrorAction Stop -WarningAction SilentlyContinue -Confirm:$false | Out-Null
                        }
                        $added = @($unionSet | Where-Object { $_ -notin $liveSet })
                        $detail = if ($liveSet.Count -eq 0) {
                            "Set label '$($LabelDef.DisplayName)' ContentType to '$($unionSet -join ', ')'."
                        } else {
                            "Extended label '$($LabelDef.DisplayName)' ContentType from '$($liveSet -join ', ')' to '$($unionSet -join ', ')' (added: $($added -join ', ')). Live scope bits not in config were preserved (UNION-not-replace)."
                        }
                        Write-Host "    ~ $detail" -ForegroundColor Yellow
                        Add-RunLogEntry -Module 'Setup-SensitivityLabels' -Action 'Set-Label ContentType' -Target $LabelDef.DisplayName -Status 'Updated' -Detail $detail
                    } catch {
                        $msg = Format-IPPSError $_
                        Write-Warning "    Failed to update ContentType for label '$($LabelDef.DisplayName)': $msg"
                        Add-RunLogEntry -Module 'Setup-SensitivityLabels' -Action 'Set-Label ContentType' -Target $LabelDef.DisplayName -Status 'Failed' -Detail $msg
                    }
                }
            }
        }
    }

    # Encryption (newly created OR managed OR -AdoptExisting)
    if ($LabelDef.Encrypt -and $existing -and ($justCreated -or $owned -or $AdoptExisting)) {
        $protType = if ($LabelDef.ProtectionType) { $LabelDef.ProtectionType } else { 'Template' }
        $outlookBehavior = if ($LabelDef.UserDefinedOutlookBehavior) { $LabelDef.UserDefinedOutlookBehavior } else { 'None' }
        # Per-label rights bundle override. When the label config carries its own
        # `EncryptionRightsDefinitions`, resolve {TenantDomain} against the same
        # TenantIdentity and pass to Set-LabelEncryption. Otherwise the function
        # falls back to the module-level `$rights` default. Used by HCAllEmps
        # (Co-Author bundle: View/Edit/Save/Copy/Print/Allow-Macros/Reply...)
        # without affecting siblings that should stay on the Reviewer default.
        $labelRights = $null
        if ($LabelDef.EncryptionRightsDefinitions) {
            $labelRights = Resolve-EncryptionRightsTokens `
                -RightsDefinitions $LabelDef.EncryptionRightsDefinitions `
                -TenantIdentity $TenantIdentity `
                -Source "Labels.$($LabelDef.Name).EncryptionRightsDefinitions"
        }
        $shouldProcessTarget = if ($protType -eq 'Template') {
            $bundleNote = if ($labelRights) { 'custom rights' } else { "$rightsBundleName rights" }
            "Apply encryption (Template / $bundleNote)"
        } else {
            "Apply encryption (UserDefined / Outlook=$outlookBehavior)"
        }
        if ($PSCmdlet.ShouldProcess($idForOps, $shouldProcessTarget)) {
            try {
                $encParams = @{
                    Identity                   = $idForOps
                    ProtectionType             = $protType
                    UserDefinedOutlookBehavior = $outlookBehavior
                }
                if ($labelRights) { $encParams['RightsDefinitions'] = $labelRights }
                Set-LabelEncryption @encParams
                $effectiveRights = if ($labelRights) { $labelRights } else { $rights }
                $encDetail = if ($protType -eq 'Template') {
                    "Applied Template encryption to label '$($LabelDef.DisplayName)' with rights: $effectiveRights."
                } else {
                    "Applied UserDefined encryption to label '$($LabelDef.DisplayName)' (Outlook=$outlookBehavior)."
                }
                Add-RunLogEntry -Module 'Setup-SensitivityLabels' -Action 'Set-Label encryption' -Target $LabelDef.DisplayName -Status 'Updated' -Detail $encDetail
            }
            catch {
                $encMsg = Format-IPPSError $_
                Write-Warning "    Encryption update failed for '$($LabelDef.DisplayName)': $encMsg"
                Add-RunLogEntry -Module 'Setup-SensitivityLabels' -Action 'Set-Label encryption' -Target $LabelDef.DisplayName -Status 'Failed' -Detail $encMsg
            }
        }
    }

    # Content marking (newly created OR managed OR -AdoptExisting)
    # Skipped entirely when $Config.EnableContentMarking is $false (the
    # toolkit-wide master switch). Per-label `ContentMark = $true` settings
    # are honoured only when the master switch is on.
    $contentMarkingEnabled = $true
    if ($Config -and $Config.PSObject.Properties.Name -contains 'EnableContentMarking' -and $null -ne $Config.EnableContentMarking) {
        $contentMarkingEnabled = [bool] $Config.EnableContentMarking
    } elseif ($Config -is [hashtable] -and $Config.ContainsKey('EnableContentMarking')) {
        $contentMarkingEnabled = [bool] $Config['EnableContentMarking']
    }
    if ($contentMarkingEnabled -and $LabelDef.ContentMark -and $existing -and ($justCreated -or $owned -or $AdoptExisting) `
        -and $PSCmdlet.ShouldProcess($idForOps, 'Apply content marking')) {
        try {
            Set-LabelContentMarking -Identity $idForOps `
                -HeaderText    $LabelDef.HeaderText `
                -FooterText    $LabelDef.FooterText `
                -WatermarkText $LabelDef.WatermarkText
        } catch { Write-Warning "    Content-marking update failed for '$($LabelDef.DisplayName)': $($_.Exception.Message)" }
    }

    $final = Get-Label -Identity $idForOps -ErrorAction SilentlyContinue
    if ($final) { return $final } else { return $existing }
}

# ---------------------------------------------------------------------------
# Pass 0 — upfront validation (name length + colour hex)
#
# Purview enforces a 64-character maximum on label, sub-label, and label-policy
# names. The IPPS backend rejects longer names with an empty/cryptic error, so
# we validate upfront to give partners a clear, actionable diagnostic.
#
# Label colours are passed through to `New-Label/Set-Label -AdvancedSettings
# @{color=...}` and must be valid 6-digit hex triplets (`#RRGGBB`). Anything
# else (3-digit shorthand, named colours, missing `#`) is rejected upfront
# because the backend silently drops malformed values and the colour silently
# fails to appear.
# ---------------------------------------------------------------------------
foreach ($lbl in $Config.Labels) {
    if ($lbl.Name.Length -gt 64) {
        throw "Sensitivity label name '$($lbl.Name)' is $($lbl.Name.Length) characters; Microsoft Purview enforces a 64-character maximum. Edit PurviewConfig.psd1 and shorten the Labels.Name field."
    }
    if ($lbl.DisplayName -and $lbl.DisplayName.Length -gt 64) {
        throw "Sensitivity label DisplayName '$($lbl.DisplayName)' is $($lbl.DisplayName.Length) characters; Microsoft Purview enforces a 64-character maximum. Edit PurviewConfig.psd1 and shorten the Labels.DisplayName field."
    }
    if ($lbl.PSObject.Properties.Match('Color').Count -gt 0 -or ($lbl -is [hashtable] -and $lbl.ContainsKey('Color'))) {
        $c = [string]$lbl.Color
        if (-not [string]::IsNullOrWhiteSpace($c) -and $c -notmatch '^#[0-9A-Fa-f]{6}$') {
            throw "Sensitivity label '$($lbl.Name)' has invalid Color '$c'; must be a 6-digit hex triplet like '#13A10E'. Edit PurviewConfig.psd1."
        }
    }
    foreach ($sub in @($lbl.SubLabels)) {
        if (-not $sub) { continue }
        if ($sub.Name.Length -gt 64) {
            throw "Sub-label name '$($sub.Name)' (under parent '$($lbl.Name)') is $($sub.Name.Length) characters; Microsoft Purview enforces a 64-character maximum. Edit PurviewConfig.psd1."
        }
        if ($sub.DisplayName -and $sub.DisplayName.Length -gt 64) {
            throw "Sub-label DisplayName '$($sub.DisplayName)' is $($sub.DisplayName.Length) characters; Microsoft Purview enforces a 64-character maximum. Edit PurviewConfig.psd1."
        }
        if ($sub.PSObject.Properties.Match('Color').Count -gt 0 -or ($sub -is [hashtable] -and $sub.ContainsKey('Color'))) {
            $sc = [string]$sub.Color
            if (-not [string]::IsNullOrWhiteSpace($sc) -and $sc -notmatch '^#[0-9A-Fa-f]{6}$') {
                throw "Sub-label '$($sub.Name)' (under parent '$($lbl.Name)') has invalid Color '$sc'; must be a 6-digit hex triplet like '#EAA300'. Edit PurviewConfig.psd1."
            }
        }
    }
}
if ($Config.LabelPolicy -and $Config.LabelPolicy.Name -and $Config.LabelPolicy.Name.Length -gt 64) {
    throw "Label policy name '$($Config.LabelPolicy.Name)' is $($Config.LabelPolicy.Name.Length) characters; Microsoft Purview enforces a 64-character maximum. Edit PurviewConfig.psd1 and shorten the LabelPolicy.Name field."
}

# ---------------------------------------------------------------------------
# Pre-flight — container-scope sanity check (issue #24).
#
# When the operator passed -SkipContainerLabels (or license auto-detect did
# so for them), Setup-TenantSettings.ps1 step [5/5] skips the
# Group.Unified `EnableMIPLabels = $true` toggle. Without that tenant-side
# toggle on, the 'Site' / 'UnifiedGroup' bits we'd otherwise stamp on
# selected labels have no effect — Teams / Groups / SharePoint sites do
# not surface the labels in their picker.
#
# We strip those bits per-label inside Get-DesiredContentTypeSet (logged at
# Skipped status). The pre-flight below surfaces ONE roll-up info line so
# the operator sees the trade-off upfront in the console, even when the
# affected labels are deep in the config tree.
# ---------------------------------------------------------------------------
if ($SkipContainerLabels.IsPresent) {
    $configuredContainerLabels = New-Object System.Collections.Generic.List[string]
    foreach ($lbl in $Config.Labels) {
        if ($lbl.ContainsKey('ContentType') -and
            (ConvertTo-ContentTypeSet -Value ([string]$lbl.ContentType) | Where-Object { $_ -in $script:ContainerContentTypeBits })) {
            [void]$configuredContainerLabels.Add($lbl.DisplayName)
        }
        if ($lbl.SubLabels) {
            foreach ($s in $lbl.SubLabels) {
                if ($s.ContainsKey('ContentType') -and
                    (ConvertTo-ContentTypeSet -Value ([string]$s.ContentType) | Where-Object { $_ -in $script:ContainerContentTypeBits })) {
                    [void]$configuredContainerLabels.Add("$($lbl.DisplayName)\$($s.DisplayName)")
                }
            }
        }
    }
    if ($configuredContainerLabels.Count -gt 0) {
        Write-Host ("[info] -SkipContainerLabels is set. Container-scope bits (Site, UnifiedGroup) will be stripped from these label(s): {0}. The labels will still be provisioned with the remaining scope (File, Email). Re-run without -SkipContainerLabels (and ensure Setup-TenantSettings.ps1 enables Group.Unified EnableMIPLabels) to make these labels selectable in Teams / Microsoft 365 Groups / SharePoint sites." -f ($configuredContainerLabels -join ', ')) -ForegroundColor DarkYellow
        Add-RunLogEntry -Module 'Setup-SensitivityLabels' -Action 'Pre-flight ContentType' `
            -Target '(container-scope summary)' -Status 'Info' `
            -Detail ("-SkipContainerLabels is set; container-scope bits (Site, UnifiedGroup) will be stripped from {0} configured label(s): {1}." -f
                $configuredContainerLabels.Count, ($configuredContainerLabels -join ', '))
    }
}

# ---------------------------------------------------------------------------
# Pass 1 — create / update parent labels
# ---------------------------------------------------------------------------
Write-Host "Creating sensitivity labels..." -ForegroundColor Cyan
$script:createdParents = @{}
foreach ($lbl in $Config.Labels) {
    Write-Host "  Label: $($lbl.Name)" -ForegroundColor White
    $parent = New-OrUpdate-Label -LabelDef $lbl
    $script:createdParents[$lbl.Name] = $parent
}

# ---------------------------------------------------------------------------
# Pass 1.5 - preflight: enforce that every cached parent is actually a
# TOP-LEVEL live label. Pass 1's New-OrUpdate-Label already surfaces a Warning
# + null cache entry when a cross-scope Name collision is detected upfront,
# but the duplicate-display-name recovery path can also unmask a sub-label.
# This unified throw gives the operator a single actionable error before
# Pass 2 wires sub-labels under the wrong object and Pass 3 Phase A explodes
# with InvalidSubLabelPriorityException on a modern-scheme tenant.
# ---------------------------------------------------------------------------
$parentScopeCollisions = @()
foreach ($lbl in $Config.Labels) {
    $cached = $script:createdParents[$lbl.Name]
    if (-not $cached) { continue }  # Pass 1 creation failed; warning already emitted.
    if ($cached.PSObject.Properties.Name -contains 'ParentId' -and $cached.ParentId) {
        $parentScopeCollisions += [pscustomobject]@{
            ConfigName   = $lbl.Name
            DisplayName  = $lbl.DisplayName
            LiveGuid     = if ($cached.Guid) { [string]$cached.Guid } else { 'unknown' }
            LiveParentId = [string]$cached.ParentId
        }
    }
}
if ($parentScopeCollisions.Count -gt 0) {
    $lines = foreach ($c in $parentScopeCollisions) {
        "  - Configured parent label '$($c.ConfigName)' (DisplayName '$($c.DisplayName)') resolved to LIVE label (Id: $($c.LiveGuid)) that is a SUB-LABEL of parent (Id: $($c.LiveParentId))."
    }
    $detail = @(
        "Parent label scope collision detected after Pass 1. The modern label scheme strictly enforces sub-label priority ranges, so a configured top-level label that resolves to an existing sub-label cannot be reordered to priority 0."
        ($lines -join "`n")
        "Remediation options:"
        "  1. Rename the configured label in Products/Purview/Config/PurviewConfig.psd1 (Labels.Name and Labels.DisplayName) so it no longer collides with the existing sub-label."
        "  2. In Purview Admin Center (https://purview.microsoft.com), edit the colliding live sub-label to move it out from under its parent (or delete it if unused), then re-run."
        "  3. If the collision is with a Microsoft-default sensitivity label, update the configured Name to a tenant-unique value."
    ) -join "`n"
    Add-RunLogEntry -Module 'Setup-SensitivityLabels' -Action 'Preflight-ParentScope' `
        -Target 'configured parents' -Status 'Failed' -Detail $detail
    throw $detail
}

# ---------------------------------------------------------------------------
# Pass 2 — create / update sub-labels
# ---------------------------------------------------------------------------
Write-Host "Creating sub-labels..." -ForegroundColor Cyan
foreach ($lbl in $Config.Labels) {
    if (-not $lbl.SubLabels) { continue }
    foreach ($sub in $lbl.SubLabels) {
        Write-Host "  Sub-label: $($lbl.Name)/$($sub.Name)" -ForegroundColor White
        $parentObj = $script:createdParents[$lbl.Name]
        if (-not $parentObj) {
            if ($WhatIfPreference) {
                Write-Host "    What if: parent '$($lbl.Name)' does not yet exist; would create sub-label '$($sub.Name)' under it." -ForegroundColor DarkYellow
            } else {
                Write-Warning "Parent label '$($lbl.Name)' not available; skipping sub-label."
            }
            continue
        }
        $null = New-OrUpdate-Label -LabelDef $sub -ParentId $parentObj.Guid
    }
}

# ---------------------------------------------------------------------------
# Pass 3 — set label priority (least sensitive first → priority 0)
#
# Purview enforces two ordering constraints that break a naive
# "Set-Label -Priority $i" loop with a flat global counter:
#   (1) a top-level label can only swap with another top-level slot, and
#   (2) a sub-label can only move within its parent's contiguous block.
# Trying to set a child to a top-level slot (or vice versa) fails with
# InvalidLabelPriorityException / InvalidSubLabelPriorityException.
#
# Workaround — the standard Purview reorder pattern:
#   Phase A (top-level): iterate $Config.Labels in REVERSE order and push
#       each parent to priority 0. Sub-blocks move with their parents.
#       This shoves any unmanaged top-level labels (e.g. the MS-managed
#       "Personal") to the back automatically.
#   Phase B (sub-labels): for each parent, iterate its sub-labels in
#       REVERSE order and push each to (parent.Priority + 1). Within the
#       parent's block this rotates them into config order.
# Both phases pre-check whether the order is already correct so re-runs
# are no-ops (and avoid the "0 is not a valid priority for this label"
# error you get when Set-Label asks for a label's current slot).
# ---------------------------------------------------------------------------
Write-Host "Setting label priority order..." -ForegroundColor Cyan

# Identify unmanaged top-level labels (e.g. tenant-provisioned 'Personal'
# from the Microsoft default sensitivity labels policy). 'Personal' is
# pinned at priority 0 (the lowest) so it stays out of the way of users
# but is still available; other unmanaged labels follow it.
$configuredDisplayNamesEarly = @()
foreach ($lbl in $Config.Labels) {
    $configuredDisplayNamesEarly += $lbl.DisplayName
    if ($lbl.SubLabels) { $configuredDisplayNamesEarly += $lbl.SubLabels.DisplayName }
}

# Refresh the $allLabels cache with LIVE state from Purview BEFORE slot
# accounting and Phase A. A single fresh snapshot is reused for unmanaged
# top-level detection AND live sub-label counts so both views agree (and
# downstream Resolve-ConfigParentLabel / Get-LabelByName see the same data).
# The initial snapshot at the top of the script was taken before Pass 2
# created labels (and before any prior Pass 3 run shuffled priorities);
# reading priorities from a stale cache causes Phase A to skip labels that
# look "already correct" but aren't, which is how 'Public' gets stranded
# at the wrong end of the priority list on multi-run tenants.
$script:allLabels = @(Get-Label -ErrorAction SilentlyContinue | Where-Object { -not (Test-LabelSoftDeleted $_) })
$allTopLevel = @($script:allLabels | Where-Object { -not $_.ParentId })
$unmanagedTopLevel = @($allTopLevel | Where-Object { $configuredDisplayNamesEarly -notcontains $_.DisplayName })

# Total slot footprint of unmanaged top-level labels = each unmanaged parent
# PLUS its live direct children. Personal has no children in practice, but
# counting children defensively handles arbitrary unmanaged hierarchies and
# keeps configured-label slot accounting correct regardless.
$unmanagedFootprint = 0
foreach ($u in $unmanagedTopLevel) {
    $unmanagedFootprint++
    if ($u.Guid) {
        $unmanagedFootprint += @($script:allLabels | Where-Object { $_.ParentId -eq $u.Guid }).Count
    }
}

# Build pin-order: 'Personal' FIRST (so it gets pushed LAST in reverse
# iteration and lands at slot 0), then any other unmanaged labels.
$personalLbl     = @($unmanagedTopLevel | Where-Object { $_.DisplayName -eq 'Personal' })
$otherUnmanaged  = @($unmanagedTopLevel | Where-Object { $_.DisplayName -ne 'Personal' })
$pinOrder        = @()
if ($personalLbl.Count -gt 0)    { $pinOrder += $personalLbl[0] }
if ($otherUnmanaged.Count -gt 0) { $pinOrder += $otherUnmanaged }

# Compute the expected GLOBAL priority for each configured top-level label.
# Slots 0..unmanagedFootprint-1 are reserved for unmanaged top-level labels
# and their children (Personal at slot 0); configured labels start at
# $unmanagedFootprint.
#
# Each managed parent's slot footprint is 1 (parent) + LIVE direct sub-label
# count. Using LIVE count (not config count) is critical when a managed
# parent has extra "phantom" sub-labels left over from a previous failed
# run: those extras still occupy slots in the parent's block, so a config-
# only count under-reserves and downstream parents land at the wrong slot.
# Use MAX(live, config) so we don't under-reserve when the live snapshot is
# missing newly-created children due to eventual consistency.
$expectedParentPriority = @{}
$cursor = $unmanagedFootprint
foreach ($lbl in $Config.Labels) {
    $expectedParentPriority[$lbl.DisplayName] = $cursor
    $cursor++
    $parentObjForCount = Resolve-ConfigParentLabel -LabelDef $lbl
    $configChildCount = if ($lbl.SubLabels) { $lbl.SubLabels.Count } else { 0 }
    $liveChildren = @()
    if ($parentObjForCount -and $parentObjForCount.Guid) {
        $liveChildren = @($script:allLabels | Where-Object { $_.ParentId -eq $parentObjForCount.Guid })
    }
    $effectiveChildCount = if ($liveChildren.Count -gt $configChildCount) { $liveChildren.Count } else { $configChildCount }
    $cursor += $effectiveChildCount

    # Identity-based phantom detection: warn about any live sub-label whose
    # Name AND DisplayName don't match any configured sub-label under this
    # parent. They occupy slot(s) inside the parent's block but won't be
    # reordered by Phase B; admin should rename or remove them in Purview UI.
    if ($parentObjForCount -and $liveChildren.Count -gt 0) {
        $configChildNames        = @()
        $configChildDisplayNames = @()
        if ($lbl.SubLabels) {
            $configChildNames        = @($lbl.SubLabels | ForEach-Object { $_.Name })
            $configChildDisplayNames = @($lbl.SubLabels | ForEach-Object { $_.DisplayName })
        }
        $extras = @($liveChildren | Where-Object {
            ($configChildNames -notcontains $_.Name) -and ($configChildDisplayNames -notcontains $_.DisplayName)
        })
        if ($extras.Count -gt 0) {
            $extrasDesc = ($extras | ForEach-Object { "'$($_.DisplayName)' [Name=$($_.Name); Guid=$($_.Guid)]" }) -join ', '
            Write-Warning ("    Managed parent '{0}' has {1} unmanaged live sub-label(s): {2}. They occupy slot(s) in the parent's block; rename or remove them in Purview Admin if not intentional." -f $lbl.DisplayName, $extras.Count, $extrasDesc)
            Add-RunLogEntry -Module 'Setup-SensitivityLabels' -Action 'Detect-PhantomSubLabel' `
                -Target $lbl.DisplayName -Status 'Info' `
                -Detail "Live sub-label count ($($liveChildren.Count)) exceeds configured ($configChildCount). Extras: $extrasDesc"
        }
    }
}

# Pre-check: are config parents already in the right slots AND is Personal at 0?
# Use Get-LiveLabelByObject (bulk-fetch fallback) so the precheck succeeds even
# for Microsoft-default labels where Get-Label -Identity by Guid returns null.
$parentsAlreadyCorrect = $true
foreach ($lbl in $Config.Labels) {
    $obj = Resolve-ConfigParentLabel -LabelDef $lbl
    if (-not $obj) {
        $parentsAlreadyCorrect = $false
        break
    }
    $live = Get-LiveLabelByObject -LabelObject $obj
    if (-not $live) {
        $parentsAlreadyCorrect = $false
        break
    }
    if ($live.Priority -ne $expectedParentPriority[$lbl.DisplayName]) {
        $parentsAlreadyCorrect = $false
        break
    }
}
$personalAlreadyAtZero = $true
if ($personalLbl.Count -gt 0) {
    $pNow = Get-LiveLabelByObject -LabelObject $personalLbl[0]
    if ($pNow -and $pNow.Priority -ne 0) { $personalAlreadyAtZero = $false }
}

if (-not $parentsAlreadyCorrect -or -not $personalAlreadyAtZero) {
    # Phase A — config top-levels: reverse-push to 0. Final config order:
    # Config.Labels[0] at slot 0, Config.Labels[1] at slot 1, ...
    #
    # Each Set-Label is verified via a fresh bulk Get-Label and retried with
    # alternate Identity forms if the priority did not actually change. This
    # is the fix for the classic "Public stuck at the bottom" bug — IPPS
    # Set-Label silently no-ops on Microsoft-default labels when called with
    # a Guid identity, but accepts DisplayName for the same label.
    for ($i = $Config.Labels.Count - 1; $i -ge 0; $i--) {
        $lbl = $Config.Labels[$i]
        $obj = Resolve-ConfigParentLabel -LabelDef $lbl
        if (-not $obj) {
            Add-RunLogEntry -Module 'Setup-SensitivityLabels' -Action 'Set-Label priority=0' `
                -Target $lbl.DisplayName -Status 'Skipped' `
                -Detail "Configured label could not be resolved in createdParents cache or via Get-LabelByName. Bulk Get-Label may not be surfacing it (common for Microsoft-default labels)."
            continue
        }
        $identityForShouldProcess = Get-StableLabelIdentity -LabelObject $obj
        if ($PSCmdlet.ShouldProcess($identityForShouldProcess, "Set priority=0 (top-level reorder)")) {
            $r = Set-LabelPriorityWithVerify -LabelObject $obj -TargetPriority 0 -DisplayNameForLog $lbl.DisplayName
            if ($r.Success) {
                # Refresh cache so later phases / verification see the new state.
                $script:createdParents[$lbl.Name] = $r.Live
                Add-RunLogEntry -Module 'Setup-SensitivityLabels' -Action 'Set-Label priority=0' `
                    -Target $lbl.DisplayName -Status 'Succeeded' `
                    -Detail ("Used identity '{0}'. Attempts: {1}" -f $r.UsedIdentity, ($r.Attempts -join ' | '))
            } else {
                $detail = "All identity forms failed to update priority. Attempts: " + ($r.Attempts -join ' | ')
                Add-RunLogEntry -Module 'Setup-SensitivityLabels' -Action 'Set-Label priority=0' `
                    -Target $lbl.DisplayName -Status 'Failed' -Detail $detail
                throw "Label priority reorder failed for '$($lbl.DisplayName)'. $detail. Re-run after addressing the underlying error."
            }
        }
    }

    # Phase A2 — pin unmanaged top-levels (Personal first in $pinOrder so
    # it gets pushed LAST and ends up at slot 0). Uses the same verified
    # helper so MS-default unmanaged labels (e.g. 'Personal') also benefit
    # from identity-form fallback.
    for ($i = $pinOrder.Count - 1; $i -ge 0; $i--) {
        $u = $pinOrder[$i]
        $uLive = Get-LiveLabelByObject -LabelObject $u
        if (-not $uLive) {
            Add-RunLogEntry -Module 'Setup-SensitivityLabels' -Action 'Set-Label priority=0 (unmanaged)' `
                -Target $u.DisplayName -Status 'Skipped' `
                -Detail "Bulk Get-Label could not resolve unmanaged top-level label '$($u.DisplayName)'. May have been deleted between Phase A and Phase A2."
            continue
        }
        if ($PSCmdlet.ShouldProcess($uLive.Name, "Set priority=0 (pin unmanaged label)")) {
            $r = Set-LabelPriorityWithVerify -LabelObject $uLive -TargetPriority 0 -DisplayNameForLog $u.DisplayName
            if (-not $r.Success) {
                $detail = "All identity forms failed to pin unmanaged label. Attempts: " + ($r.Attempts -join ' | ')
                Add-RunLogEntry -Module 'Setup-SensitivityLabels' -Action 'Set-Label priority=0 (unmanaged)' `
                    -Target $u.DisplayName -Status 'Failed' -Detail $detail
                throw "Label priority reorder failed for unmanaged label '$($u.DisplayName)'. $detail. Re-run after addressing the underlying error."
            }
            Add-RunLogEntry -Module 'Setup-SensitivityLabels' -Action 'Set-Label priority=0 (unmanaged)' `
                -Target $u.DisplayName -Status 'Succeeded' `
                -Detail ("Used identity '{0}'." -f $r.UsedIdentity)
        }
    }
}

# Phase B — sub-label reorder within each parent's block
#
# Sub-label priorities are GLOBAL (not relative to the parent), but Purview
# enforces that a sub-label can only move within its parent's contiguous block.
# Derive the first child slot from the LIVE parent priority (refreshed via
# Get-LiveLabelByObject) and sanity-check against the expected slot so we
# never target a slot outside the parent's actual live block — which causes
# InvalidSubLabelPriorityException when Phase A's expected slot calculation
# is off (e.g. tenant has phantom unmanaged sub-labels under a managed parent).
foreach ($lbl in $Config.Labels) {
    if (-not $lbl.SubLabels -or $lbl.SubLabels.Count -eq 0) { continue }
    $parentMeta = Resolve-ConfigParentLabel -LabelDef $lbl
    if (-not $parentMeta) {
        Add-RunLogEntry -Module 'Setup-SensitivityLabels' -Action 'Phase B parent resolve' `
            -Target $lbl.DisplayName -Status 'Skipped' `
            -Detail "Parent label could not be resolved; sub-label reorder skipped for '$($lbl.DisplayName)'."
        continue
    }
    $parentObj = Get-LiveLabelByObject -LabelObject $parentMeta
    if (-not $parentObj) { $parentObj = $parentMeta }
    if (-not $parentObj.Guid) {
        Add-RunLogEntry -Module 'Setup-SensitivityLabels' -Action 'Phase B parent resolve' `
            -Target $lbl.DisplayName -Status 'Skipped' `
            -Detail "Parent label resolved but has no Guid; cannot match sub-labels by ParentId. Skipping."
        continue
    }

    # Phase B derives child slots from the LIVE parent priority (not from the
    # statically computed expected) so it stays correct even if the parent
    # ended up at a slightly different slot than expected (e.g. IPPS eventual
    # consistency right after Phase A). Sanity-check live vs expected first;
    # if they disagree after one refresh, defer Phase B for this parent so
    # the verifier/recovery can fix the parent on a subsequent pass.
    $expectedParentSlot = [int]$expectedParentPriority[$lbl.DisplayName]
    if ($parentObj.Priority -ne $expectedParentSlot) {
        Start-Sleep -Seconds 2
        $refreshed = Get-LiveLabelByObject -LabelObject $parentMeta
        if ($refreshed) { $parentObj = $refreshed }
    }
    if ($parentObj.Priority -ne $expectedParentSlot) {
        Add-RunLogEntry -Module 'Setup-SensitivityLabels' -Action 'Phase B sub-label reorder' `
            -Target $lbl.DisplayName -Status 'Skipped' `
            -Detail "Parent priority $($parentObj.Priority) does not match expected $expectedParentSlot after refresh; deferring sub-label reorder so verifier can recover parent first."
        Write-Warning "    Sub-label reorder deferred for '$($lbl.DisplayName)' (parent at slot $($parentObj.Priority), expected $expectedParentSlot)."
        continue
    }
    $firstChildSlot = [int]$parentObj.Priority + 1

    # Pre-check: are the sub-labels already in config order?
    $childrenCorrect = $true
    $expectedSlot = $firstChildSlot
    foreach ($sub in $lbl.SubLabels) {
        $subMeta = Get-LabelByName -Name $sub.Name -DisplayName $sub.DisplayName -ParentId $parentObj.Guid -Scope 'Parent'
        if (-not $subMeta) { $childrenCorrect = $false; break }
        $subLive = Get-LiveLabelByObject -LabelObject $subMeta
        if (-not $subLive -or $subLive.Priority -ne $expectedSlot) { $childrenCorrect = $false; break }
        $expectedSlot++
    }
    if ($childrenCorrect) { continue }

    for ($i = $lbl.SubLabels.Count - 1; $i -ge 0; $i--) {
        $sub = $lbl.SubLabels[$i]
        $subMeta = Get-LabelByName -Name $sub.Name -DisplayName $sub.DisplayName -ParentId $parentObj.Guid -Scope 'Parent'
        if (-not $subMeta) {
            Add-RunLogEntry -Module 'Setup-SensitivityLabels' -Action "Set-Label priority=$firstChildSlot" `
                -Target $sub.DisplayName -Status 'Skipped' `
                -Detail "Sub-label could not be resolved under parent '$($lbl.DisplayName)'."
            continue
        }
        $subIdentForShouldProcess = Get-StableLabelIdentity -LabelObject $subMeta
        if ($PSCmdlet.ShouldProcess($subIdentForShouldProcess, "Set priority=$firstChildSlot (sub-label reorder)")) {
            $r = Set-LabelPriorityWithVerify -LabelObject $subMeta -TargetPriority $firstChildSlot `
                    -DisplayNameForLog ("{0}/{1}" -f $lbl.DisplayName, $sub.DisplayName) -IsSubLabel
            if (-not $r.Success) {
                $detail = "All identity forms failed to update sub-label priority. Attempts: " + ($r.Attempts -join ' | ')
                Add-RunLogEntry -Module 'Setup-SensitivityLabels' -Action "Set-Label priority=$firstChildSlot" `
                    -Target $sub.DisplayName -Status 'Failed' -Detail $detail
                # Sub-label failures are warned but don't throw — the post-reorder
                # verification covers top-level priorities; sub-label ordering
                # within a block is best-effort and recoverable in Purview UI.
                Write-Warning "    Sub-label priority update failed for '$($sub.DisplayName)'. See run log for details."
            }
        }
    }
}

# ---------------------------------------------------------------------------
# Pass 3 verification — confirm every configured top-level label is at its
# expected priority. If not, attempt ONE recovery push, then re-verify and
# throw with a diagnostic detail if still wrong.
#
# This catches silent skips in Phase A (e.g. a Microsoft-default label that
# bulk Get-Label fails to surface), which is how 'Public' previously got
# stranded at the wrong priority without any error in the run log.
# ---------------------------------------------------------------------------
$script:allLabels = @(Get-Label -ErrorAction SilentlyContinue | Where-Object { -not (Test-LabelSoftDeleted $_) })

function Test-ParentPrioritiesCorrect {
    $mismatches = @()
    foreach ($lbl in $Config.Labels) {
        $obj = Resolve-ConfigParentLabel -LabelDef $lbl
        if (-not $obj) {
            $mismatches += [pscustomobject]@{
                Label    = $lbl
                Reason   = 'unresolved'
                Identity = $null
                Actual   = $null
                Expected = $expectedParentPriority[$lbl.DisplayName]
            }
            continue
        }
        # Use the robust bulk-fetch resolver instead of Get-Label -Identity,
        # because Get-Label -Identity by Guid returns null for some
        # Microsoft-default labels even when the label clearly exists in the
        # tenant. That false-null is what previously made the verifier
        # report "live-lookup-failed" for Public.
        $live = Get-LiveLabelByObject -LabelObject $obj
        $actual = if ($live) { $live.Priority } else { $obj.Priority }
        $expected = $expectedParentPriority[$lbl.DisplayName]
        if ($actual -ne $expected) {
            $mismatches += [pscustomobject]@{
                Label    = $lbl
                Reason   = if ($live) { 'wrong-priority' } else { 'live-lookup-failed' }
                Identity = if ($obj.Guid) { [string]$obj.Guid } else { [string]$obj.Name }
                Actual   = $actual
                Expected = $expected
            }
        }
    }
    return ,$mismatches
}

$mismatches = Test-ParentPrioritiesCorrect
if ($mismatches.Count -gt 0) {
    Write-Host "  ! Priority order off after primary reorder; attempting recovery..." -ForegroundColor Yellow
    # Reverse-iterate Config.Labels (same direction as Phase A) and push any
    # mismatched label to slot 0 using the same verified helper. The reverse
    # direction preserves intent: the LAST push wins slot 0, so we need to
    # push every label above the lowest mismatched label as well.
    $mismatchedNames = @{}
    foreach ($m in $mismatches) { $mismatchedNames[$m.Label.Name] = $true }
    for ($i = $Config.Labels.Count - 1; $i -ge 0; $i--) {
        $lbl = $Config.Labels[$i]
        if (-not $mismatchedNames.ContainsKey($lbl.Name)) { continue }
        $obj = Resolve-ConfigParentLabel -LabelDef $lbl
        if (-not $obj) {
            Add-RunLogEntry -Module 'Setup-SensitivityLabels' -Action 'Set-Label priority=0 (recovery)' `
                -Target $lbl.DisplayName -Status 'Failed' `
                -Detail "Cannot resolve label for recovery push."
            continue
        }
        $idForShouldProcess = Get-StableLabelIdentity -LabelObject $obj
        if ($PSCmdlet.ShouldProcess($idForShouldProcess, "Set priority=0 (priority recovery)")) {
            $r = Set-LabelPriorityWithVerify -LabelObject $obj -TargetPriority 0 -DisplayNameForLog $lbl.DisplayName
            if ($r.Success) {
                $script:createdParents[$lbl.Name] = $r.Live
                Add-RunLogEntry -Module 'Setup-SensitivityLabels' -Action 'Set-Label priority=0 (recovery)' `
                    -Target $lbl.DisplayName -Status 'Succeeded' `
                    -Detail ("Used identity '{0}'. Attempts: {1}" -f $r.UsedIdentity, ($r.Attempts -join ' | '))
            } else {
                $detail = "All identity forms failed during recovery. Attempts: " + ($r.Attempts -join ' | ')
                Add-RunLogEntry -Module 'Setup-SensitivityLabels' -Action 'Set-Label priority=0 (recovery)' `
                    -Target $lbl.DisplayName -Status 'Failed' -Detail $detail
                Write-Warning "    Recovery Set-Label failed for '$($lbl.DisplayName)': $detail"
            }
        }
    }
    # Re-pin unmanaged labels (Personal last so it lands at 0) after the recovery push.
    for ($i = $pinOrder.Count - 1; $i -ge 0; $i--) {
        $u = $pinOrder[$i]
        $uLive = Get-LiveLabelByObject -LabelObject $u
        if (-not $uLive) { continue }
        if ($PSCmdlet.ShouldProcess($uLive.Name, "Set priority=0 (recovery pin unmanaged)")) {
            $r = Set-LabelPriorityWithVerify -LabelObject $uLive -TargetPriority 0 -DisplayNameForLog $u.DisplayName
            if (-not $r.Success) {
                Write-Warning "    Recovery Set-Label failed for unmanaged label '$($u.DisplayName)'. See run log for diagnostic detail."
                Add-RunLogEntry -Module 'Setup-SensitivityLabels' -Action 'Set-Label priority=0 (recovery unmanaged)' `
                    -Target $u.DisplayName -Status 'Failed' `
                    -Detail ("All identity forms failed. Attempts: " + ($r.Attempts -join ' | '))
            }
        }
    }
    $script:allLabels = @(Get-Label -ErrorAction SilentlyContinue | Where-Object { -not (Test-LabelSoftDeleted $_) })
    $mismatches = Test-ParentPrioritiesCorrect
}
if ($mismatches.Count -gt 0) {
    $lines = foreach ($m in $mismatches) {
        if ($m.Reason -eq 'unresolved') {
            "  - '$($m.Label.DisplayName)' could not be resolved as a TOP-LEVEL live label (expected priority $($m.Expected)). Likely a scope collision (a sub-label with the same Name exists in this tenant). See earlier Pass 1 warnings or the Preflight-ParentScope log entry; rename the configured label or un-nest the live label, then re-run."
        } else {
            "  - '$($m.Label.DisplayName)' (Id: $($m.Identity)) is at priority $($m.Actual); expected $($m.Expected) [reason: $($m.Reason)]"
        }
    }
    $detail = "Sensitivity label priority order is incorrect after reorder + recovery:`n" + ($lines -join "`n")
    Add-RunLogEntry -Module 'Setup-SensitivityLabels' -Action 'Verify-LabelPriority' `
        -Target 'all top-level labels' -Status 'Failed' -Detail $detail
    throw $detail
}

# Surface MS-managed labels (e.g. tenant-provisioned 'Personal') that are
# not in our config. They've been pinned to the lowest priority slots
# above (Personal at 0). The warning below is informational only — they
# remain in the tenant and won't appear to users because they aren't in
# our PublishedLabels filter.
foreach ($tl in $allTopLevel) {
    if ($configuredDisplayNamesEarly -notcontains $tl.DisplayName) {
        $now = Get-Label -Identity $tl.Name -ErrorAction SilentlyContinue
        $curPri = if ($now) { $now.Priority } else { $tl.Priority }
        Write-Host "    Unmanaged top-level label '$($tl.DisplayName)' is at priority $curPri (created by '$($tl.CreatedBy)'). Not in SMBTool config — left in place." -ForegroundColor DarkGray
    }
}

# ---------------------------------------------------------------------------
# Pass 4 — publish via label policy
# ---------------------------------------------------------------------------
Write-Host "Publishing label policy..." -ForegroundColor Cyan

$policyCfg = $Config.LabelPolicy
$existingPolicy = Get-LabelPolicy -Identity $policyCfg.Name -ErrorAction SilentlyContinue
$policyOwned = Test-Owned -Object $existingPolicy -Tag $tag

if ($existingPolicy -and -not $policyOwned) {
    Write-Host "    Label policy '$($policyCfg.Name)' exists but is not tagged as toolkit-managed. Updating in place (will be re-tagged)." -ForegroundColor DarkYellow
}

# Resolve default label by name OR display name (handles adopted labels).
# The default applied label may be a sub-label, so search both parent and
# sub-label entries in the config to find the matching DisplayName.
$defaultDef = $null
foreach ($lbl in $Config.Labels) {
    if ($lbl.Name -eq $policyCfg.DefaultLabel) { $defaultDef = $lbl; break }
    foreach ($sub in @($lbl.SubLabels)) {
        if ($sub -and $sub.Name -eq $policyCfg.DefaultLabel) { $defaultDef = $sub; break }
    }
    if ($defaultDef) { break }
}
$defaultDisplay = if ($defaultDef) { $defaultDef.DisplayName } else { $policyCfg.DefaultLabel }
$defaultLabelObj = Get-LabelByName -Name $policyCfg.DefaultLabel -DisplayName $defaultDisplay
if (-not $defaultLabelObj) {
    if ($WhatIfPreference) {
        Write-Host "  What if: default label '$($policyCfg.DefaultLabel)' would be created earlier in this run; previewing publish step with placeholder GUID." -ForegroundColor DarkYellow
        $defaultLabelObj = [pscustomobject]@{
            Name = $policyCfg.DefaultLabel
            Guid = [guid]::Empty
        }
    } else {
        throw "Default label '$($policyCfg.DefaultLabel)' was not found after creation."
    }
}

# Resolve the optional Outlook-only default. When set, this becomes a
# separate per-app default for email; documents continue to use DefaultLabel.
$emailDefaultLabelObj = $null
if ($policyCfg.DefaultLabelForEmail) {
    $emailDef = $null
    foreach ($lbl in $Config.Labels) {
        if ($lbl.Name -eq $policyCfg.DefaultLabelForEmail) { $emailDef = $lbl; break }
        foreach ($sub in @($lbl.SubLabels)) {
            if ($sub -and $sub.Name -eq $policyCfg.DefaultLabelForEmail) { $emailDef = $sub; break }
        }
        if ($emailDef) { break }
    }
    $emailDisplay = if ($emailDef) { $emailDef.DisplayName } else { $policyCfg.DefaultLabelForEmail }
    $emailDefaultLabelObj = Get-LabelByName -Name $policyCfg.DefaultLabelForEmail -DisplayName $emailDisplay
    if (-not $emailDefaultLabelObj) {
        if ($WhatIfPreference) {
            Write-Host "  What if: email default label '$($policyCfg.DefaultLabelForEmail)' would be created earlier in this run; previewing publish step with placeholder GUID." -ForegroundColor DarkYellow
            $emailDefaultLabelObj = [pscustomobject]@{
                Name = $policyCfg.DefaultLabelForEmail
                Guid = [guid]::Empty
            }
        } else {
            throw "Email default label '$($policyCfg.DefaultLabelForEmail)' was not found after creation."
        }
    }
}

# Build the published-labels filter set (if configured). When sub-labels are
# listed, their parents are auto-included so the Purview hierarchy stays
# valid (Purview rejects publishing a sub-label without its parent).
$publishFilter = $null
if ($policyCfg.PublishedLabels -and @($policyCfg.PublishedLabels).Count -gt 0) {
    $publishFilter = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($n in $policyCfg.PublishedLabels) { if ($n) { [void] $publishFilter.Add($n) } }
    foreach ($lbl in $Config.Labels) {
        foreach ($s in @($lbl.SubLabels)) {
            if ($s -and $publishFilter.Contains($s.Name)) { [void] $publishFilter.Add($lbl.Name) }
        }
    }
    Write-Host "  Publishing only: $([string]::Join(', ', @($publishFilter)))" -ForegroundColor Cyan
}

# Collect every label (parents + subs) for the policy. We resolve each one
# to its actual internal Name -- which may differ from the config Name when
# matched by DisplayName on an adopted label.
$allLabelNames = @()
foreach ($lbl in $Config.Labels) {
    $resolved = Get-LabelByName -Name $lbl.Name -DisplayName $lbl.DisplayName -Scope 'TopLevel'
    $includeParent = (-not $publishFilter) -or $publishFilter.Contains($lbl.Name)
    if ($includeParent) {
        if ($resolved) {
            $allLabelNames += $resolved.Name
        } elseif ($WhatIfPreference) {
            $allLabelNames += $lbl.Name
        }
    }
    if ($lbl.SubLabels) {
        $parentId = if ($resolved) { $resolved.Guid } else { $null }
        foreach ($s in $lbl.SubLabels) {
            $subScope = if ($parentId) { 'Parent' } else { 'Any' }
            $rs = Get-LabelByName -Name $s.Name -DisplayName $s.DisplayName -ParentId $parentId -Scope $subScope
            $includeSub = (-not $publishFilter) -or $publishFilter.Contains($s.Name)
            if (-not $includeSub) { continue }
            if ($rs) {
                $allLabelNames += $rs.Name
            } elseif ($WhatIfPreference) {
                $allLabelNames += $s.Name
            }
        }
    }
}

$advanced = @{
    DefaultLabelId = $defaultLabelObj.Guid.ToString()
}
if ($emailDefaultLabelObj) {
    # IPPS advanced setting that overrides the document default just for
    # Outlook (email). With this set, new docs use DefaultLabelId and new
    # mails use OutlookDefaultLabel.
    $advanced['OutlookDefaultLabel'] = $emailDefaultLabelObj.Guid.ToString()
}
if ($policyCfg.MandatoryLabelling) { $advanced['Mandatory'] = 'True' }
if ($policyCfg.DowngradeJustification) { $advanced['RequireDowngradeJustification'] = 'True' }

if (-not $existingPolicy) {
    if ($PSCmdlet.ShouldProcess($policyCfg.Name, 'New-LabelPolicy (publish to All)')) {
        try {
            Invoke-WithTransientRetry -Description ("New-LabelPolicy '$($policyCfg.Name)'") -AlreadyExistsIsSuccess -Action {
                New-LabelPolicy `
                    -Name $policyCfg.Name `
                    -Comment "$tag $($policyCfg.Comment)" `
                    -Labels $allLabelNames `
                    -ExchangeLocation 'All' `
                    -AdvancedSettings $advanced `
                    -ErrorAction Stop -WarningAction SilentlyContinue -Confirm:$false | Out-Null
            }
            Write-Host "    + Created label policy '$($policyCfg.Name)'." -ForegroundColor Green
        } catch {
            Write-Warning "    Failed to create label policy '$($policyCfg.Name)': $(Format-IPPSError $_)"
        }
    }
} else {
    # Diff existing published labels vs target so we can REMOVE any that
    # used to be published but are no longer in PublishedLabels, AND only
    # ADD labels that aren't already published. Purview's
    # Set-LabelPolicy -AddLabels rejects the entire call with
    # LabelAlreadyPublishedException if any AddLabels entry is already
    # in the policy, so the diff is required for idempotency.
    $labelsToRemove = @()
    $labelsToAdd    = @()
    if ($existingPolicy.Labels) {
        $targetSet = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
        foreach ($n in $allLabelNames) { if ($n) { [void] $targetSet.Add($n) } }
        $existingSet = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
        foreach ($n in @($existingPolicy.Labels)) {
            if ($n) { [void] $existingSet.Add($n) }
            if ($n -and -not $targetSet.Contains($n)) { $labelsToRemove += $n }
        }
        foreach ($n in $allLabelNames) {
            if ($n -and -not $existingSet.Contains($n)) { $labelsToAdd += $n }
        }
    } else {
        $labelsToAdd = $allLabelNames
    }
    if ($PSCmdlet.ShouldProcess($policyCfg.Name, 'Set-LabelPolicy (refresh labels + advanced settings)')) {
        $setArgs = @{
            Identity         = $policyCfg.Name
            Comment          = "$tag $($policyCfg.Comment)"
            AdvancedSettings = $advanced
            ErrorAction      = 'Stop'
            WarningAction    = 'SilentlyContinue'
            Confirm          = $false
        }
        if ($labelsToAdd.Count -gt 0) {
            $setArgs['AddLabels'] = $labelsToAdd
            Write-Host "    Publishing newly-added labels: $([string]::Join(', ', $labelsToAdd))" -ForegroundColor DarkGray
        }
        if ($labelsToRemove.Count -gt 0) {
            $setArgs['RemoveLabels'] = $labelsToRemove
            Write-Host "    Unpublishing previously-published labels: $([string]::Join(', ', $labelsToRemove))" -ForegroundColor DarkYellow
        }
        try {
            Invoke-WithTransientRetry -Description ("Set-LabelPolicy '$($policyCfg.Name)'") -Action {
                Set-LabelPolicy @setArgs | Out-Null
            }
            if ($labelsToAdd.Count -eq 0 -and $labelsToRemove.Count -eq 0) {
                Write-Host "    ~ Refreshed label policy '$($policyCfg.Name)' (label set already in sync)." -ForegroundColor Yellow
            } else {
                Write-Host "    ~ Updated label policy '$($policyCfg.Name)'." -ForegroundColor Yellow
            }
        } catch {
            Write-Warning "    Failed to update label policy '$($policyCfg.Name)': $(Format-IPPSError $_)"
        }
    }
}

Write-Host "Sensitivity labels and policy complete." -ForegroundColor Green
Write-Host "NOTE: Label policy changes can take up to 24 hours to propagate to clients." -ForegroundColor DarkYellow
