@{
    # =========================================================================
    # Purview Best Practice Toolkit — central configuration
    #
    # All tunables live here so partners can fork, edit, and re-run.
    # Reference: "Data Security Best Practice Deployment" — Microsoft 365
    # Business Premium Security Deployment Guide.
    # =========================================================================

    # Marker stamped in object descriptions for safe re-runs and rollback.
    ManagedByTag = '[Managed by SMBTool Purview Toolkit]'

    # ----- DLP simulation -----
    # When $true, new DLP policies are created in simulation mode
    # (Mode = TestWithoutNotifications) with Purview's native
    # "Turn the policy on if it's not edited within fifteen days of
    # simulation" flag set (StartSimulation = $true). Purview itself
    # enforces the 15-day countdown — the script does NOT manage it.
    # Set to $false to create policies directly in Enable mode.
    DlpStartInSimulation = $true

    # ----- Content marking (header / footer / watermark) -----
    # Master switch. When $false, the toolkit will SKIP applying any
    # ApplyContentMarkingHeader/Footer or ApplyWaterMarking settings
    # to labels, regardless of the per-label `ContentMark = $true`
    # entries below. The label's other behaviour (display name, tooltip,
    # priority, encryption, scope) is unaffected. Flip to $true once
    # you are ready to roll out visual markings to clients.
    EnableContentMarking = $false

    # ----- Sensitivity labels -----
    #
    # SMB-tuned subset of Microsoft's documented default sensitivity labels.
    # See: https://learn.microsoft.com/en-us/purview/default-sensitivity-labels-policies
    #
    # Order: lowest priority (least sensitive) FIRST. The script applies the
    # priority order in the sequence shown.
    #
    # Label set (8 labels, 3 parents + 5 sub-labels):
    #   * Public                                       — no protection
    #   * General                                      — no protection (default for EMAIL)
    #   * Confidential                                 — no protection (parent)
    #     * Confidential \ All Employees               — Footer only (default for DOCUMENTS)
    #     * Confidential \ Specific People             — Footer + UserDefined encryption (Outlook: Do Not Forward)
    #     * Confidential \ Internal Exception          — Footer only
    #   * Highly Confidential                          — Watermark "HIGHLY CONFIDENTIAL"
    #     * Highly Confidential \ All Employees        — Footer + Template encryption (tenant-scoped)
    #     * Highly Confidential \ Specific People      — Footer + UserDefined encryption (Outlook: Do Not Forward)
    #     * Highly Confidential \ Internal Exception   — Footer + Template encryption (tenant-scoped)
    #
    # Encryption / protection
    # -----------------------
    # Template-protected labels (HC \ All Employees, HC \ Internal Exception)
    # grant the configured rights bundle to ALL USERS IN YOUR TENANT ONLY —
    # not external authenticated identities from other Microsoft 365 tenants.
    # The toolkit auto-resolves your tenant's verified domain at runtime and
    # substitutes it into `EncryptionRightsDefinitions` (see comment at that
    # field below for the token syntax and fallback behaviour).
    #
    # UserDefined-protected labels (both Specific People sub-labels) let the
    # user pick the recipients and permissions at apply time. Outlook
    # behaviour is "Do Not Forward"; Office apps (Word, Excel, PowerPoint)
    # prompt the user to assign permissions.
    #
    # The default Template rights bundle is Microsoft's "Reviewer" set:
    # users get View, View Rights, Edit Content, Save, Reply, Reply All,
    # Forward. Co-authoring (auto-save + simultaneous editing in Office)
    # and macros / programmatic access via the Office object model are NOT
    # included by default, because OBJMODEL access is the main vector by
    # which third-party apps reading doc metadata break under encryption.
    #
    # If you need a wider rights bundle (e.g. Copy, Print, Allow Macros for
    # third-party tooling), edit `EncryptionRightsDefinitions` below
    # directly — typically by appending `,EXTRACT,PRINT,OBJMODEL` to the
    # `{TenantDomain}:` rights string. Validate in a pilot tenant before
    # rolling out, since OBJMODEL access affects every third-party app that
    # reads Office document metadata.
    #
    # Auto-labeling (client-side and service-side) is intentionally NOT
    # configured here. Add it deliberately via the Purview portal once your
    # team has reviewed false-positive risk and user-impact trade-offs.
    #
    # Sub-label Name uniqueness
    # -------------------------
    # IPPS requires every label `Name` (the internal identifier) to be unique
    # across the tenant. Because Microsoft's defaults reuse display names like
    # "All Employees" under multiple parents, we prefix each sub-label Name
    # with its parent (e.g. `HCAllEmps`). The `AllEmployees` Name on
    # Confidential is preserved unchanged so existing DLP rules with
    # `LabelPath = 'Confidential/AllEmployees'` keep resolving.
    #
    # Label color
    # -----------
    # Each label has an optional `Color = '#RRGGBB'` hex string. The toolkit
    # applies it via `New-Label`/`Set-Label -AdvancedSettings @{color=...}`
    # so the colour shows up next to the label in Office and Purview. Defaults
    # below mirror Microsoft's recommended palette (green=Public, blue=General,
    # amber=Confidential family, red=Highly Confidential family). Sub-labels
    # inherit their parent's family colour. To disable, remove the `Color`
    # entry — the toolkit will leave the label's current colour unchanged.
    Labels = @(
        @{
            Name        = 'Public'
            DisplayName = 'Public'
            Tooltip     = 'Business data that is specifically prepared and approved for public consumption.'
            Color       = '#13A10E'
            Encrypt     = $false
            ContentMark = $false
        }
        @{
            Name        = 'General'
            DisplayName = 'General'
            Tooltip     = 'Business data that is not intended for public consumption. However, this can be shared with external partners, as required. Examples include a company internal telephone directory, organizational charts, internal standards, and most internal communication.'
            Color       = '#3A96DD'
            Encrypt     = $false
            ContentMark = $false
            # Optional. Comma-separated `New-Label -ContentType` values.
            # 'File, Email' (the IPPS default) is implied when omitted; we
            # set it explicitly here only to add the container-scope bits
            # ('Site' + 'UnifiedGroup') so this label is selectable in the
            # Purview portal's Edit sensitivity label -> Scope page for
            # Microsoft 365 Groups, Teams, and SharePoint sites. Without
            # these bits a user creating a new Team cannot pick this label.
            #
            # The toolkit applies UNION-not-replace semantics on adoption:
            # any extra scope a customer has manually added in the portal
            # is preserved. Re-running the deploy is a no-op for this field
            # when the live set already covers the desired set.
            #
            # Only the 3 PUBLISHED labels (this + Confidential\AllEmployees +
            # HighlyConfidential\HCAllEmps — see LabelPolicy.PublishedLabels)
            # carry container scope. The other labels stay File/Email-only
            # because Microsoft Purview does not allow encrypted labels on
            # containers and the unpublished parent/`Specific People`/
            # `Internal Exception` labels are not in the user-visible picker.
            #
            # When -SkipContainerLabels is set on Deploy-PurviewBestPractice
            # (or auto-detect cannot identify a BP / E5 / Purview Suite SKU),
            # the 'Site' + 'UnifiedGroup' bits are stripped at deploy time
            # and a one-line info message is logged per label.
            ContentType = 'File, Email, Site, UnifiedGroup'
        }
        @{
            Name        = 'Confidential'
            DisplayName = 'Confidential'
            Tooltip     = 'Sensitive business data that could cause damage to the business if shared with unauthorized people. Examples include contracts, security reports, forecast summaries, and sales account data.'
            Color       = '#EAA300'
            Encrypt     = $false
            ContentMark = $false
            SubLabels   = @(
                @{
                    # Internal Name preserved for backward compat with the
                    # existing DLP rule LabelPath = 'Confidential/AllEmployees'.
                    Name        = 'AllEmployees'
                    DisplayName = 'All Employees'
                    Tooltip     = 'Confidential data shared internally with all employees. No encryption is applied; the label is informational and adds a footer marking.'
                    Color       = '#EAA300'
                    Encrypt     = $false
                    ContentMark = $true
                    FooterText  = 'Classified as Confidential'
                    # Published label — see ContentType notes on the General
                    # label above. Adds container scope so this label appears
                    # in the Purview Edit sensitivity label -> Scope page for
                    # M365 Groups, Teams, and SharePoint sites. Required for
                    # the SMB recommended pattern where every new Team is
                    # classified at creation time.
                    ContentType = 'File, Email, Site, UnifiedGroup'
                }
                @{
                    # Consolidated Confidential sub-label: replaces the former
                    # 'Specific People' + 'Internal Exception' sub-labels, renamed to
                    # the Microsoft built-in 'Trusted People' default (ordinal 0008) so
                    # the tool ADOPTS the existing default instead of creating duplicates.
                    # Carries the encrypted (UserDefined / Outlook Do Not Forward) protection.
                    Name        = 'TrustedPeople'
                    DisplayName = 'Trusted People'
                    Tooltip     = 'Confidential data shared with specific trusted people inside or outside the organization. Encryption is applied; trusted recipients can reshare as needed (Outlook: Encrypt-Only).'
                    Color       = '#EAA300'
                    Encrypt     = $true
                    ProtectionType = 'UserDefined'
                    UserDefinedOutlookBehavior = 'EncryptOnly'   # Outlook: Encrypt-Only (matches the MS default Trusted People; trusted people can reshare)
                    ContentMark = $true
                    FooterText  = 'Classified as Confidential'
                }
            )
        }
        @{
            Name        = 'HighlyConfidential'
            DisplayName = 'Highly Confidential'
            Tooltip     = 'Very sensitive business data that would cause damage to the business if it was shared with unauthorized people. Examples include employee and customer information, passwords, source code, and pre-announced financial reports.'
            Color       = '#A4262C'
            Encrypt     = $false
            ContentMark = $true
            WatermarkText = 'HIGHLY CONFIDENTIAL'
            SubLabels   = @(
                @{
                    Name        = 'HCAllEmps'
                    DisplayName = 'All Employees'
                    Tooltip     = 'Highly confidential data with Co-Author rights for all users in this tenant only (view, edit, save, copy, print, allow macros, reply, forward). Data owners can track and revoke content.'
                    Color       = '#A4262C'
                    Encrypt     = $true
                    ProtectionType = 'Template'
                    # Per-label override for the rights bundle. Uses the
                    # Microsoft "Co-Author" set instead of the toolkit's
                    # global Reviewer default — Co-Author adds EXTRACT
                    # (copy), PRINT, and OBJMODEL (Office object-model
                    # access, needed for macros + simultaneous editing).
                    # `{TenantDomain}` resolves to all users in this
                    # tenant only (matches the global scope; excludes
                    # external / B2B / MSA). See header comment above
                    # and Skills/Purview/_CONVENTIONS.md for the full
                    # semantics.
                    #
                    # NOTE: granting OBJMODEL is NECESSARY BUT NOT
                    # SUFFICIENT for Office multi-user co-authoring on
                    # encrypted files. The tenant-wide switch
                    # `-EnableLabelCoAuthoring` (Set-PolicyConfig
                    # -EnableLabelCoauth:$true, opt-in) must also be on.
                    # Without both, users get individual edit rights but
                    # not concurrent editing.
                    EncryptionRightsDefinitions = '{TenantDomain}:VIEW,VIEWRIGHTSDATA,EDIT,DOCEDIT,EXTRACT,PRINT,OBJMODEL,REPLY,REPLYALL,FORWARD'
                    ContentMark = $true
                    FooterText  = 'Classified as Highly Confidential'
                    # Published label — see ContentType notes on the General
                    # label above. Adds container scope so this label appears
                    # in the Purview Edit sensitivity label -> Scope page for
                    # M365 Groups, Teams, and SharePoint sites.
                    #
                    # NOTE: Microsoft Purview will not apply the encryption
                    # protection (Template / Co-Author rights) to the CONTAINER
                    # itself — encryption stays on files and emails. The
                    # container-scope bits drive the privacy / sharing /
                    # unmanaged-device behaviour of the Team / site, not its
                    # contents' RMS encryption.
                    ContentType = 'File, Email, Site, UnifiedGroup'
                }
                @{
                    Name        = 'HCSpecificPeople'
                    DisplayName = 'Specific People'
                    Tooltip     = 'Highly confidential data that requires protection and can be viewed only by people you specify and with the permission level you choose.'
                    Color       = '#A4262C'
                    Encrypt     = $true
                    ProtectionType = 'UserDefined'
                    UserDefinedOutlookBehavior = 'DoNotForward'   # Outlook: Do Not Forward; Office apps prompt user
                    ContentMark = $true
                    FooterText  = 'Classified as Highly Confidential'
                }
            )
        }
    )

    # ----- Encryption rights bundle -----
    # Microsoft's "Reviewer" bundle: View, View Rights, Edit Content, Save,
    # Reply, Reply All, Forward.
    #
    # IDENTITY token (one of):
    #   * `{TenantDomain}`        — RECOMMENDED. Resolved at runtime to the
    #     tenant's primary verified domain (e.g. `contoso.com`). Per Microsoft
    #     Entra rights-management semantics, specifying ANY verified domain
    #     in the tenant automatically expands to ALL verified domains in that
    #     tenant — so the label is accessible to every user in your tenant
    #     but NOT to external authenticated users from other M365 tenants
    #     (which `AuthenticatedUsers` would include). If the toolkit cannot
    #     resolve the tenant domain at runtime, it FAILS CLOSED (throws an
    #     error and writes a Failed run-log entry) rather than silently
    #     widening scope to `AuthenticatedUsers`. Re-run after fixing
    #     connectivity, or opt in to broad scope explicitly with
    #     `{AuthenticatedUsers}` / literal `AuthenticatedUsers`.
    #
    #   * `AuthenticatedUsers`    — Microsoft's broad "any signed-in M365
    #     identity" group. Includes B2B guests, partners, and any external
    #     Entra user. Use this only if you intentionally need to share
    #     encrypted content across tenants.
    #
    #   * `user@domain.com`       — A specific mail-enabled user / group /
    #     mailbox in your tenant. Useful for narrow-scope custom labels.
    #
    # Co-authoring (auto-save + simultaneous editing) and macro / object-
    # model access are NOT granted, which is the safe default when third-
    # party apps consume Office documents in your tenant.
    #
    # If you need a wider bundle (the Microsoft "Co-Author" set adds Copy
    # (EXTRACT), Print, Allow Macros (OBJMODEL)), edit the string below
    # directly. The "Co-Author" equivalent is:
    #   '{TenantDomain}:VIEW,VIEWRIGHTSDATA,EDIT,DOCEDIT,EXTRACT,PRINT,REPLY,REPLYALL,FORWARD,OBJMODEL'
    # OBJMODEL is the right that most often breaks third-party apps reading
    # doc metadata, so validate in a pilot tenant before promoting.
    #
    # PER-LABEL OVERRIDE:
    # Any label with `Encrypt=$true / ProtectionType='Template'` may carry
    # its own `EncryptionRightsDefinitions = '...'` field, which overrides
    # this global default JUST for that label. Same token semantics apply
    # ({TenantDomain}, {AuthenticatedUsers}, literal identity). Used by
    # `HighlyConfidential\All Employees` (HCAllEmps) to grant the wider
    # Co-Author bundle (allows copy, print, macros, Office co-authoring)
    # while sibling sub-labels stay on the narrower Reviewer default.
    EncryptionRightsDefinitions = '{TenantDomain}:VIEW,VIEWRIGHTSDATA,EDIT,DOCEDIT,REPLY,REPLYALL,FORWARD'

    EncryptionContentExpiredOnDateInDaysOrNever = 'Never'
    EncryptionOfflineAccessDays = 30

    # ----- Label publishing policy -----
    LabelPolicy = @{
        Name           = 'SMBTool - Default Label Policy'
        Comment        = 'Publishes the SMBTool baseline sensitivity labels to all users.'
        # Default applied label for DOCUMENTS (Word, Excel, PowerPoint, and
        # service-side defaults). Per the SMB profile, this is
        # 'Confidential\All Employees' (Name = 'AllEmployees') so every new
        # document gets footer marking by default. Resolved by Name at
        # runtime; sub-label Names are tenant-unique so this resolves cleanly.
        DefaultLabel   = 'AllEmployees'
        # Default applied label for EMAIL (Outlook). Set separately so users
        # don't have to think about labelling routine internal email; only
        # documents inherit the higher Confidential default. Mapped to the
        # IPPS advanced setting `OutlookDefaultLabel`. Set to $null to omit
        # an Outlook-specific default and fall back to DefaultLabel.
        DefaultLabelForEmail = 'General'
        # Subset of label Names to PUBLISH to end users via this policy.
        # All labels in the Labels array are still CREATED in the tenant,
        # but only these are visible/applicable in clients. Sub-label Names
        # may be listed; the script auto-includes their parents so the
        # Purview hierarchy stays valid.
        # Set to $null or an empty array to publish every label that's
        # created.
        PublishedLabels = @(
            'Public'
            'General'
            'AllEmployees'   # Confidential \ All Employees
            'HCAllEmps'      # Highly Confidential \ All Employees
        )
        # Mandatory labelling is ON by default: every Office app (Word /
        # Excel / PowerPoint / Outlook) will prompt the user to pick a
        # sensitivity label before they can save a new document or send a
        # new email. This closes the "untagged content" hole that breaks
        # DLP rules, auto-classification, and Copilot exclusions, all of
        # which key off the label. Set to $false in your fork only if the
        # customer explicitly cannot tolerate the prompt during rollout
        # (a documented end-user training plan is the better answer).
        # See docs/End-User-Adoption-Guide.md for the user-facing impact.
        MandatoryLabelling = $true
        # Justification required when downgrading sensitivity.
        DowngradeJustification = $true
    }

    # ----- DLP policies -----
    # Two policies (Microsoft's recommendation): one for Exchange, one for SPO + OneDrive.
    #
    # Workloads supported under Microsoft 365 Business Premium:
    #   * 'Exchange'              - mailboxes
    #   * 'SharePointOneDrive'    - SPO sites + OneDrive for Business
    #
    # E5 / Purview Suite ONLY (rejected when Deploy-PurviewBestPractice.ps1 is
    # run with -BPOnly):
    #   * 'Endpoint' / 'Devices'  - Endpoint DLP
    #   * 'OnPremisesScanner'     - on-prem file shares & SP servers
    #   * 'DefenderForCloudApps'  - 3rd party apps via MCAS
    #   * 'PowerBI'               - Power BI tenants
    DlpPolicies = @(
        @{
            Name        = 'SMBTool - DLP - Confidential and HC external (EXO)'
            Comment     = 'Blocks Exchange messages labelled with any Confidential or Highly Confidential sub-label from being sent outside the organisation.'
            Workload    = 'Exchange'
            RuleName    = 'SMBTool - DLP Rule - Confidential and HC - Exchange'
            # All Confidential + Highly Confidential sub-labels are OR-matched.
            # Resolved to GUIDs at runtime.
            LabelPaths  = @(
                'Confidential/AllEmployees'
                'Confidential/TrustedPeople'
                'HighlyConfidential/HCAllEmps'
                'HighlyConfidential/HCSpecificPeople'
            )
            BlockAccess = $true
            # IMPORTANT — DO NOT DELETE 'BlockAccessScope' on the Exchange rule.
            # On Exchange, enforcement is driven entirely by AccessScope='NotInOrganization'
            # (set in Setup-DLP.ps1 line ~496). The IPPS engine IGNORES BlockAccessScope
            # for Exchange rules at evaluation time — it is read only by Purview's web
            # UI rule-editor to highlight the matching radio button ("Block only people
            # outside your organization"). If you remove this line:
            #   * Enforcement is unchanged (Exchange still blocks external recipients).
            #   * The Purview UI shows the radio group EMPTY when an admin opens the
            #     rule, making it look misconfigured, and -AdoptExisting may flag it
            #     as drift the next time the toolkit runs.
            # Keep the value at 'PerUser' for UI parity with the radio "Block only
            # people outside your organization". The SPO/ODFB rule below uses the same
            # field but there the engine DOES read it — see the comment on that rule.
            BlockAccessScope = 'PerUser'
            NotifyUser  = @('SiteAdmin','LastModifier','Owner')
            GenerateIncidentReport = @('SiteAdmin')
        }
        @{
            Name        = 'SMBTool - DLP - Confidential and HC external (SPO+ODB)'
            Comment     = 'Blocks SharePoint and OneDrive files labelled with any Confidential or Highly Confidential sub-label from being shared externally.'
            Workload    = 'SharePointOneDrive'
            RuleName    = 'SMBTool - DLP Rule - Confidential and HC - SPO ODFB'
            LabelPaths  = @(
                'Confidential/AllEmployees'
                'Confidential/TrustedPeople'
                'HighlyConfidential/HCAllEmps'
                'HighlyConfidential/HCSpecificPeople'
            )
            BlockAccess = $true
            # SPO/ODFB: 'PerUser' = "Block only people outside your organization".
            # 'All' would mean "Block everyone" (incl. internal users).
            # 'PerAnonymousUser' would only block anonymous link recipients.
            BlockAccessScope = 'PerUser'
            NotifyUser  = @('SiteAdmin','LastModifier','Owner')
            GenerateIncidentReport = @('SiteAdmin')
        }
        # -----------------------------------------------------------------
        # Endpoint DLP — audit copy/print/USB/network-share actions on
        # devices when content carries any Confidential or Highly
        # Confidential sub-label.
        #
        # LICENSING: requires Microsoft 365 E5 / Purview Suite. The toolkit
        # rejects this policy when run with -BPOnly (Business Premium only).
        #
        # MODE: created in simulation (TestWithoutNotifications) by default
        # via DlpStartInSimulation = $true. After validating in simulation,
        # toggle the Purview portal "Turn the policy on if it's not edited
        # within fifteen days of simulation" checkbox or set
        # DlpStartInSimulation = $false to enforce.
        #
        # ACTIONS (EndpointDlpRestrictions): default 'Audit' so simulation
        # produces telemetry without interrupting users. Flip individual
        # entries to 'Block' / 'BlockOverride' / 'Warn' once the desired
        # behaviour is confirmed in DLP Activity Explorer.
        # -----------------------------------------------------------------
        @{
            Name        = 'SMBTool - DLP - Endpoint Confidential and HC'
            Comment     = 'Endpoint DLP - audits copy / print / USB / network-share / cloud-sync actions on managed devices when content is labelled Confidential or Highly Confidential.'
            Workload    = 'Endpoint'
            RuleName    = 'SMBTool - DLP Rule - Endpoint Confidential and HC'
            LabelPaths  = @(
                'Confidential/AllEmployees'
                'Confidential/TrustedPeople'
                'HighlyConfidential/HCAllEmps'
                'HighlyConfidential/HCSpecificPeople'
            )
            # Endpoint device-action restrictions. Hashtable keys are
            # case-sensitive: { Setting = '<name>'; Value = '<action>' }.
            # Valid Setting values (per the API error response — these are the
            # short forms the cmdlet actually accepts, not the longer names
            # shown in some MS Learn pages):
            #   Print, CopyPaste, ScreenCapture, RemovableMedia, NetworkShare,
            #   UnallowedApps, CloudEgress, UnallowedBluetoothTransferApps,
            #   RemoteDesktopServices, WebPagePrint, WebPageCopyPaste,
            #   WebPageSaveToLocal, PasteToBrowser, AccessByAnyAppDefault,
            #   UnallowedFtpTransferApps.
            # Valid Value values: Audit, Block, Warn, BlockOverride.
            EndpointDlpRestrictions = @(
                @{ Setting = 'CopyPaste';            Value = 'Audit' }
                @{ Setting = 'Print';                Value = 'Audit' }
                @{ Setting = 'RemovableMedia'; Value = 'Audit' }
                @{ Setting = 'NetworkShare';   Value = 'Audit' }
            )
            EnforcePortalAccess = $true
            ReportSeverityLevel = 'Medium'
            GenerateAlert       = $true
            NotifyUser  = @()
            GenerateIncidentReport = @()
        }
    )

    # ----- Retention -----
    Retention = @{
        Name      = 'SMBTool - Exchange 7-year retention'
        Comment   = 'Retains Exchange mailbox content for 7 years from creation, then deletes. Aligned with common SMB regulatory record-keeping requirements (ATO/IRS/SEC/ASIC) but partners must confirm against the customer''s vertical.'
        RuleName  = 'SMBTool - Exchange 7yr Rule'
        DurationDays = 2555               # 7 years
        DurationDisplayHint = 'Years'
        Action    = 'KeepAndDelete'
        ExpirationDateOption = 'CreationAgeInDays'
        # Locations: Exchange by default. Add 'SharePoint','OneDrive' to widen.
        Locations = @('Exchange')
    }

    # ----- AI governance & data security (default ON for E5 / Purview Suite) -----
    #
    # Applied by default. AI governance is auto-skipped on Business Premium
    # tenants ($BPOnly) because the Microsoft 365 Copilot DLP policy plane
    # is included in E5 / Purview Suite, not in Business Premium. Opt out
    # with -SkipAIControls.
    #
    # Per Microsoft Learn (https://learn.microsoft.com/purview/dlp-microsoft365-copilot-location-learn-about):
    # the Microsoft 365 Copilot DLP location protects BOTH paid Microsoft
    # 365 Copilot AND the free Microsoft 365 Copilot Chat experience, so
    # policy creation succeeds on E5 / Purview Suite tenants regardless of
    # whether paid Copilot per-user licenses are present.
    #
    # Per Microsoft Learn (New-DlpCompliancePolicy / New-DlpComplianceRule):
    #   - Locations JSON pins the Copilot location GUID
    #     (470f2276-e011-4e9d-a6ec-20768be3a4b0).
    #   - EnforcementPlanes 'CopilotExperiences' selects the Copilot enforcement
    #     surface. Add 'Agent' here when extending coverage to Agent 365.
    #   - The rule action 'ExcludeContentProcessing'='Block' prevents Copilot
    #     from processing the labelled content (it is excluded from grounding,
    #     summarisation, and search results).
    AIGovernance = @{
        DlpPolicies = @(
            # AI_054 — Block Microsoft 365 Copilot from processing
            # Highly Confidential content.
            # https://microsoft.github.io/zerotrustassessment/docs/workshop-guidance/AI/AI_054
            @{
                Name        = 'SMBTool - AI - Block Copilot for Highly Confidential'
                RuleName    = 'SMBTool - AI Rule - Block Copilot Highly Confidential'
                Comment     = 'AI_054 - Prevents Microsoft 365 Copilot from processing content labelled Highly Confidential.'
                Mode        = 'Enable'                       # Enable | TestWithNotifications | TestWithoutNotifications | Disable
                EnforcementPlanes = @('CopilotExperiences')  # Add 'Agent' to also cover Agent 365 (preview)
                # Locations: target the Microsoft 365 Copilot location.
                # Inclusions/Exclusions follow the Locations JSON schema.
                # Default = tenant-wide. Use the commented form below to
                # pilot on a security group first.
                Locations = @(
                    @{
                        Workload   = 'Applications'
                        Location   = '470f2276-e011-4e9d-a6ec-20768be3a4b0'
                        Inclusions = @(@{ Type = 'Tenant'; Identity = 'All' })
                        # Inclusions = @(@{ Type = 'Group'; Identity = 'CopilotPilotUsers@contoso.com' })
                        # Exclusions = @(@{ Type = 'Group'; Identity = 'CopilotExempt@contoso.com' })
                    }
                )
                # Sensitivity label paths to block. Resolved to GUIDs at runtime.
                LabelPaths = @('HighlyConfidential')
                # Block Copilot from processing matched content. Other valid
                # 'setting' values include 'EncryptionEnabled' and
                # 'BlockAccess'; ExcludeContentProcessing is the recommended
                # action for Copilot per Microsoft documentation.
                RestrictAccess = @(@{ setting = 'ExcludeContentProcessing'; value = 'Block' })
            }
        )
    }

    # ----- Tenant settings (foundational) -----
    TenantSettings = @{
        EnableUnifiedAuditLog        = $true
        EnableSensitivityLabelForPDF = $true
        EnableAIPIntegrationInSPO    = $true
        # Tenant-wide label co-authoring metadata-format switch
        # (Set-PolicyConfig -EnableLabelCoauth). DEFAULT-OFF and operator
        # opt-in via -EnableLabelCoAuthoring on
        # Deploy-PurviewBestPractice.ps1. This switch is ONE-WAY: once
        # enabled, label metadata moves out of custom properties; disabling
        # it later loses labels on unencrypted Office files. Any app,
        # service, scanner or script reading doc metadata from the old
        # location (AIP scanner < v3.0, OneDrive sync < 19.002, MIP SDK
        # < 1.7, custom DLP scanners, custom Exchange mail-flow rules,
        # etc.) will break. The toolkit refuses to flip this on partner
        # tenants by default to avoid taking responsibility for that risk.
        # Ref: https://learn.microsoft.com/purview/sensitivity-labels-coauthoring
        EnableLabelCoAuth            = $false
    }
}
