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
        * Confidential \ All Employees                — Footer "Classified as Confidential" (DEFAULT for documents)
        * Confidential \ Specific People              — Footer "Classified as Confidential"
        * Confidential \ Internal Exception           — Footer "Classified as Confidential"
      * Highly Confidential                           — Watermark "HIGHLY CONFIDENTIAL"
        * Highly Confidential \ All Employees         — Footer + Reviewer/Co-Author encryption
        * Highly Confidential \ Specific People       — Footer + user-defined encryption (Outlook: Do Not Forward)
        * Highly Confidential \ Internal Exception    — Footer + Reviewer/Co-Author encryption

    Encryption is applied only to the three Highly Confidential sub-labels.
    Confidential sub-labels carry visual markings (footer) but no
    encryption, which is the SMB-friendly profile (encryption on
    Confidential breaks too many third-party integrations and external
    collaboration scenarios for typical SMB customers).

    The default rights bundle is "Reviewer" (View, Edit Content, Save,
    Reply/Reply-All/Forward). Pass -EnableCoAuth to use the full
    "Co-Author" bundle (adds Copy, Print, Allow Macros) — required if you
    want Office co-authoring (auto-save + simultaneous editing) or if
    third-party tooling reads doc metadata via the Office object model.

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

.PARAMETER EnableCoAuth
    Use Microsoft's full "Co-Author" rights bundle (View, View Rights, Edit
    Content, Save, Copy, Print, Reply, Reply All, Forward, Allow Macros)
    instead of the default "Reviewer" bundle. Required for Office
    co-authoring (auto-save + simultaneous editing) and for third-party
    tooling that uses the Office object model. Off by default to avoid
    breaking integrations that read doc metadata.

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

    [Parameter()]
    [switch] $EnableCoAuth
)

$ErrorActionPreference = 'Stop'
# Auto-confirm: this toolkit is designed for unattended/scripted runs. Use -WhatIf for dry-run.
$ConfirmPreference   = 'None'
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
# Pick the rights bundle once, up-front. The "Co-Author" bundle adds Copy
# (EXTRACT), Print (PRINT), and Allow Macros (OBJMODEL) to the default
# "Reviewer" set; OBJMODEL is the right that breaks third-party apps which
# read doc metadata via the Office object model, so we keep it off unless
# the operator explicitly opts in via -EnableCoAuth.
$rights = if ($EnableCoAuth -and $Config.EncryptionRightsDefinitionsCoAuth) {
    $Config.EncryptionRightsDefinitionsCoAuth
} else {
    $Config.EncryptionRightsDefinitions
}
$rightsBundleName = if ($EnableCoAuth) { 'Co-Author' } else { 'Reviewer' }
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
        [string] $ParentId
    )
    $byName = $allLabels | Where-Object { $_.Name -eq $Name } | Select-Object -First 1
    if ($byName) { return $byName }

    if ($DisplayName) {
        $byDisplay = $allLabels | Where-Object {
            $_.DisplayName -eq $DisplayName -and (
                ($ParentId -and $_.ParentId -eq $ParentId) -or
                (-not $ParentId -and -not $_.ParentId)
            )
        } | Select-Object -First 1
        if ($byDisplay) { return $byDisplay }
    }
    return $null
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
        [string] $UserDefinedOutlookBehavior = 'None'
    )
    $err = @()
    if ($ProtectionType -eq 'Template') {
        Set-Label -Identity $Identity `
            -EncryptionEnabled $true `
            -EncryptionProtectionType 'Template' `
            -EncryptionRightsDefinitions $rights `
            -EncryptionContentExpiredOnDateInDaysOrNever 'Never' `
            -EncryptionOfflineAccessDays $offlineDays `
            -ErrorAction SilentlyContinue -ErrorVariable err -WarningAction SilentlyContinue -Confirm:$false | Out-Null
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
        Set-Label @params -ErrorAction SilentlyContinue -ErrorVariable err -WarningAction SilentlyContinue -Confirm:$false | Out-Null
    }
    if ($err.Count -gt 0) { throw $err[0] }
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
    $err = @()
    Set-Label @params -ErrorAction SilentlyContinue -ErrorVariable err -WarningAction SilentlyContinue -Confirm:$false | Out-Null
    if ($err.Count -gt 0) { throw $err[0] }
}

function New-OrUpdate-Label {
    param(
        [Parameter(Mandatory)] [hashtable] $LabelDef,
        [string] $ParentId
    )

    $existing = Get-LabelByName -Name $LabelDef.Name -DisplayName $LabelDef.DisplayName -ParentId $ParentId
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
        if (-not $PSCmdlet.ShouldProcess($LabelDef.Name, 'New-Label')) { return $null }

        $newArgs = @{
            Name        = $LabelDef.Name
            DisplayName = $LabelDef.DisplayName
            Tooltip     = $tooltip
            Comment     = $comment
        }
        if ($ParentId) { $newArgs['ParentId'] = $ParentId }

        # IPPS cmdlets bypass -ErrorAction Stop. Capture errors via -ErrorVariable.
        $err = @()
        New-Label @newArgs -ErrorAction SilentlyContinue -ErrorVariable err -WarningAction SilentlyContinue -Confirm:$false | Out-Null

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
                    # Fall through to update branch.
                } else {
                    Write-Host "    = Label '$($LabelDef.DisplayName)' already exists (Id: $existingGuid). Using existing without changes (re-run with -AdoptExisting to overwrite)." -ForegroundColor DarkGray
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
            $serr = @()
            Set-Label -Identity $idForOps `
                -DisplayName $LabelDef.DisplayName `
                -Tooltip $tooltip `
                -Comment $comment `
                -ErrorAction SilentlyContinue -ErrorVariable serr -WarningAction SilentlyContinue -Confirm:$false | Out-Null
            if ($serr.Count -eq 0) {
                Write-Host "    ~ Updated label '$($LabelDef.DisplayName)'." -ForegroundColor Yellow
            } else {
                Write-Warning "    Failed to update label '$($LabelDef.DisplayName)': $($(Format-IPPSError $serr[0]))"
            }
        }
    }

    # Encryption (newly created OR managed OR -AdoptExisting)
    if ($LabelDef.Encrypt -and $existing -and ($justCreated -or $owned -or $AdoptExisting)) {
        $protType = if ($LabelDef.ProtectionType) { $LabelDef.ProtectionType } else { 'Template' }
        $outlookBehavior = if ($LabelDef.UserDefinedOutlookBehavior) { $LabelDef.UserDefinedOutlookBehavior } else { 'None' }
        $shouldProcessTarget = if ($protType -eq 'Template') {
            "Apply encryption (Template / $rightsBundleName rights)"
        } else {
            "Apply encryption (UserDefined / Outlook=$outlookBehavior)"
        }
        if ($PSCmdlet.ShouldProcess($idForOps, $shouldProcessTarget)) {
            try {
                Set-LabelEncryption -Identity $idForOps `
                    -ProtectionType $protType `
                    -UserDefinedOutlookBehavior $outlookBehavior
            }
            catch { Write-Warning "    Encryption update failed for '$($LabelDef.DisplayName)': $($_.Exception.Message)" }
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
# Pass 0 — upfront name-length validation
#
# Purview enforces a 64-character maximum on label, sub-label, and label-policy
# names. The IPPS backend rejects longer names with an empty/cryptic error, so
# we validate upfront to give partners a clear, actionable diagnostic.
# ---------------------------------------------------------------------------
foreach ($lbl in $Config.Labels) {
    if ($lbl.Name.Length -gt 64) {
        throw "Sensitivity label name '$($lbl.Name)' is $($lbl.Name.Length) characters; Microsoft Purview enforces a 64-character maximum. Edit PurviewConfig.psd1 and shorten the Labels.Name field."
    }
    if ($lbl.DisplayName -and $lbl.DisplayName.Length -gt 64) {
        throw "Sensitivity label DisplayName '$($lbl.DisplayName)' is $($lbl.DisplayName.Length) characters; Microsoft Purview enforces a 64-character maximum. Edit PurviewConfig.psd1 and shorten the Labels.DisplayName field."
    }
    foreach ($sub in @($lbl.SubLabels)) {
        if (-not $sub) { continue }
        if ($sub.Name.Length -gt 64) {
            throw "Sub-label name '$($sub.Name)' (under parent '$($lbl.Name)') is $($sub.Name.Length) characters; Microsoft Purview enforces a 64-character maximum. Edit PurviewConfig.psd1."
        }
        if ($sub.DisplayName -and $sub.DisplayName.Length -gt 64) {
            throw "Sub-label DisplayName '$($sub.DisplayName)' is $($sub.DisplayName.Length) characters; Microsoft Purview enforces a 64-character maximum. Edit PurviewConfig.psd1."
        }
    }
}
if ($Config.LabelPolicy -and $Config.LabelPolicy.Name -and $Config.LabelPolicy.Name.Length -gt 64) {
    throw "Label policy name '$($Config.LabelPolicy.Name)' is $($Config.LabelPolicy.Name.Length) characters; Microsoft Purview enforces a 64-character maximum. Edit PurviewConfig.psd1 and shorten the LabelPolicy.Name field."
}

# ---------------------------------------------------------------------------
# Pass 1 — create / update parent labels
# ---------------------------------------------------------------------------
Write-Host "Creating sensitivity labels..." -ForegroundColor Cyan
$createdParents = @{}
foreach ($lbl in $Config.Labels) {
    Write-Host "  Label: $($lbl.Name)" -ForegroundColor White
    $parent = New-OrUpdate-Label -LabelDef $lbl
    $createdParents[$lbl.Name] = $parent
}

# ---------------------------------------------------------------------------
# Pass 2 — create / update sub-labels
# ---------------------------------------------------------------------------
Write-Host "Creating sub-labels..." -ForegroundColor Cyan
foreach ($lbl in $Config.Labels) {
    if (-not $lbl.SubLabels) { continue }
    foreach ($sub in $lbl.SubLabels) {
        Write-Host "  Sub-label: $($lbl.Name)/$($sub.Name)" -ForegroundColor White
        $parentObj = $createdParents[$lbl.Name]
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
$allTopLevel = @(Get-Label -ErrorAction SilentlyContinue | Where-Object { -not $_.ParentId })
$unmanagedTopLevel = @($allTopLevel | Where-Object { $configuredDisplayNamesEarly -notcontains $_.DisplayName })
$unmanagedCount = $unmanagedTopLevel.Count

# Build pin-order: 'Personal' FIRST (so it gets pushed LAST in reverse
# iteration and lands at slot 0), then any other unmanaged labels.
$personalLbl     = @($unmanagedTopLevel | Where-Object { $_.DisplayName -eq 'Personal' })
$otherUnmanaged  = @($unmanagedTopLevel | Where-Object { $_.DisplayName -ne 'Personal' })
$pinOrder        = @()
if ($personalLbl.Count -gt 0)    { $pinOrder += $personalLbl[0] }
if ($otherUnmanaged.Count -gt 0) { $pinOrder += $otherUnmanaged }

# Compute the expected GLOBAL priority for each top-level config label.
# Slots 0..unmanagedCount-1 are reserved for unmanaged labels (Personal
# at 0); config labels start at $unmanagedCount.
$expectedParentPriority = @{}
$cursor = $unmanagedCount
foreach ($lbl in $Config.Labels) {
    $expectedParentPriority[$lbl.DisplayName] = $cursor
    $cursor++
    if ($lbl.SubLabels) { $cursor += $lbl.SubLabels.Count }
}

# Pre-check: are config parents already in the right slots AND is Personal at 0?
$parentsAlreadyCorrect = $true
foreach ($lbl in $Config.Labels) {
    $obj = Get-LabelByName -Name $lbl.Name -DisplayName $lbl.DisplayName
    if (-not $obj) { continue }
    if ($obj.Priority -ne $expectedParentPriority[$lbl.DisplayName]) {
        $parentsAlreadyCorrect = $false
        break
    }
}
$personalAlreadyAtZero = $true
if ($personalLbl.Count -gt 0) {
    $pNow = Get-Label -Identity $personalLbl[0].Name -ErrorAction SilentlyContinue
    if ($pNow -and $pNow.Priority -ne 0) { $personalAlreadyAtZero = $false }
}

if (-not $parentsAlreadyCorrect -or -not $personalAlreadyAtZero) {
    # Phase A — config top-levels: reverse-push to 0. Final config order:
    # Config.Labels[0] at slot 0, Config.Labels[1] at slot 1, ...
    for ($i = $Config.Labels.Count - 1; $i -ge 0; $i--) {
        $lbl = $Config.Labels[$i]
        $obj = Get-LabelByName -Name $lbl.Name -DisplayName $lbl.DisplayName
        if (-not $obj) { continue }
        if ($obj.Priority -eq 0) { continue }   # already at slot 0; Set 0 would be rejected
        if ($PSCmdlet.ShouldProcess($obj.Name, "Set priority=0 (top-level reorder)")) {
            $perr = @()
            Set-Label -Identity $obj.Name -Priority 0 `
                -ErrorAction SilentlyContinue -ErrorVariable perr -WarningAction SilentlyContinue -Confirm:$false | Out-Null
            if ($perr.Count -gt 0) {
                Write-Warning "    Priority update failed for '$($lbl.DisplayName)': $($(Format-IPPSError $perr[0]))"
            }
        }
    }

    # Phase A2 — pin unmanaged top-levels (Personal first in $pinOrder so
    # it gets pushed LAST and ends up at slot 0).
    for ($i = $pinOrder.Count - 1; $i -ge 0; $i--) {
        $u = $pinOrder[$i]
        $uObj = Get-Label -Identity $u.Name -ErrorAction SilentlyContinue
        if (-not $uObj) { continue }
        if ($uObj.Priority -eq 0) { continue }
        if ($PSCmdlet.ShouldProcess($uObj.Name, "Set priority=0 (pin unmanaged label)")) {
            $perr = @()
            Set-Label -Identity $uObj.Name -Priority 0 `
                -ErrorAction SilentlyContinue -ErrorVariable perr -WarningAction SilentlyContinue -Confirm:$false | Out-Null
            if ($perr.Count -gt 0) {
                Write-Warning "    Priority update failed for unmanaged label '$($u.DisplayName)': $($(Format-IPPSError $perr[0]))"
            }
        }
    }
}

# Phase B — sub-label reorder within each parent's block
foreach ($lbl in $Config.Labels) {
    if (-not $lbl.SubLabels -or $lbl.SubLabels.Count -eq 0) { continue }
    # Re-fetch parent to pick up any priority shift from Phase A
    $parentObj = Get-LabelByName -Name $lbl.Name -DisplayName $lbl.DisplayName
    if (-not $parentObj) { continue }
    $firstChildSlot = [int]$parentObj.Priority + 1

    # Pre-check: are the sub-labels already in config order?
    $childrenCorrect = $true
    $expectedSlot = $firstChildSlot
    foreach ($sub in $lbl.SubLabels) {
        $subObj = Get-LabelByName -Name $sub.Name -DisplayName $sub.DisplayName -ParentId $parentObj.Guid
        if (-not $subObj -or $subObj.Priority -ne $expectedSlot) { $childrenCorrect = $false; break }
        $expectedSlot++
    }
    if ($childrenCorrect) { continue }

    for ($i = $lbl.SubLabels.Count - 1; $i -ge 0; $i--) {
        $sub = $lbl.SubLabels[$i]
        $subObj = Get-LabelByName -Name $sub.Name -DisplayName $sub.DisplayName -ParentId $parentObj.Guid
        if (-not $subObj) { continue }
        if ($subObj.Priority -eq $firstChildSlot) { continue }   # already at first slot in block
        if ($PSCmdlet.ShouldProcess($subObj.Name, "Set priority=$firstChildSlot (sub-label reorder)")) {
            $sperr = @()
            Set-Label -Identity $subObj.Name -Priority $firstChildSlot `
                -ErrorAction SilentlyContinue -ErrorVariable sperr -WarningAction SilentlyContinue -Confirm:$false | Out-Null
            if ($sperr.Count -gt 0) {
                Write-Warning "    Priority update failed for '$($sub.DisplayName)': $($(Format-IPPSError $sperr[0]))"
            }
        }
    }
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
    $resolved = Get-LabelByName -Name $lbl.Name -DisplayName $lbl.DisplayName
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
            $rs = Get-LabelByName -Name $s.Name -DisplayName $s.DisplayName -ParentId $parentId
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
        $perr = @()
        New-LabelPolicy `
            -Name $policyCfg.Name `
            -Comment "$tag $($policyCfg.Comment)" `
            -Labels $allLabelNames `
            -ExchangeLocation 'All' `
            -AdvancedSettings $advanced `
            -ErrorAction SilentlyContinue -ErrorVariable perr -WarningAction SilentlyContinue -Confirm:$false | Out-Null
        if ($perr.Count -eq 0) {
            Write-Host "    + Created label policy '$($policyCfg.Name)'." -ForegroundColor Green
        } else {
            Write-Warning "    Failed to create label policy '$($policyCfg.Name)': $($(Format-IPPSError $perr[0]))"
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
        $perr = @()
        $setArgs = @{
            Identity         = $policyCfg.Name
            Comment          = "$tag $($policyCfg.Comment)"
            AdvancedSettings = $advanced
            ErrorAction      = 'SilentlyContinue'
            ErrorVariable    = 'perr'
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
        Set-LabelPolicy @setArgs | Out-Null
        if ($perr.Count -eq 0) {
            if ($labelsToAdd.Count -eq 0 -and $labelsToRemove.Count -eq 0) {
                Write-Host "    ~ Refreshed label policy '$($policyCfg.Name)' (label set already in sync)." -ForegroundColor Yellow
            } else {
                Write-Host "    ~ Updated label policy '$($policyCfg.Name)'." -ForegroundColor Yellow
            }
        } else {
            Write-Warning "    Failed to update label policy '$($policyCfg.Name)': $($(Format-IPPSError $perr[0]))"
        }
    }
}

Write-Host "Sensitivity labels and policy complete." -ForegroundColor Green
Write-Host "NOTE: Label policy changes can take up to 24 hours to propagate to clients." -ForegroundColor DarkYellow
