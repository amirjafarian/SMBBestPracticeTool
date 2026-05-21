#requires -Version 7.0
<#
.SYNOPSIS
    Renders a self-contained HTML deployment report for the Purview Best
    Practice toolkit.

.DESCRIPTION
    Tier 1 report: task-status table + run metadata (tenant identity,
    admin UPN, timestamps, parameters used, PS version, host, RunId).
    Pure renderer -- inline CSS, no JS, no external assets, no network
    calls. Output is a single .html file safe to forward over email.

    Tier 2 (future) will extend this with per-action sections fed from a
    structured RunLog. The Tier 1 surface is designed to be stable so
    Tier 2 is additive (new sections appended after the task table).

.NOTES
    Security:
      * All user-supplied strings are HTML-escaped via [System.Net.WebUtility]::HtmlEncode.
      * Parameters hashtable is filtered against a denylist
        (*password*, *token*, *secret*, *credential*, *key*) before render
        so a future param named e.g. -ClientSecret never lands in the
        report.
      * Caller controls the output path; no auto-overwrite logic here
        beyond Set-Content's default replace.

    The function is intentionally idempotent: call it from the
    orchestrator's finally block once, on success or on failure.
#>

function Write-PurviewHtmlReport {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [System.Collections.Specialized.OrderedDictionary] $Summary,
        [Parameter(Mandatory)] [string]   $OutputPath,
        [Parameter(Mandatory)] [datetime] $StartTime,
        [Parameter(Mandatory)] [datetime] $EndTime,
        [Parameter(Mandatory)] [guid]     $RunId,

        [Parameter()] [psobject]    $TenantIdentity,
        [Parameter()] [string]      $TenantAdminUpn,
        [Parameter()] [hashtable]   $Parameters,
        [Parameter()] [string]      $ScriptVersion = 'unknown',

        # Tier 2: per-action decision-point log. Each entry is a hashtable
        # with keys: Timestamp, Module, Action, Target, Status, Detail,
        # Attempt (opt), ElapsedMs (opt). Pass the output of
        # Get-PurviewRunLog from the orchestrator's finally block.
        [Parameter()] [hashtable[]] $RunLog
    )

    # ----- helpers --------------------------------------------------------
    function _Encode([string]$s) {
        if ($null -eq $s) { return '' }
        return [System.Net.WebUtility]::HtmlEncode($s)
    }

    function _FormatDuration([timespan]$span) {
        if ($span.TotalHours -ge 1) {
            return ('{0}h {1}m {2}s' -f [int]$span.TotalHours, $span.Minutes, $span.Seconds)
        } elseif ($span.TotalMinutes -ge 1) {
            return ('{0}m {1}s' -f [int]$span.TotalMinutes, $span.Seconds)
        } else {
            return ('{0}s' -f [int]$span.TotalSeconds)
        }
    }

    function _StatusClass([string]$value) {
        switch -Wildcard ($value) {
            'OK'         { 'status-ok'      ; break }
            'Skipped*'   { 'status-skipped' ; break }
            'FAILED:*'   { 'status-failed'  ; break }
            default      { 'status-other' }
        }
    }

    function _FilterParameters([hashtable]$params) {
        if (-not $params) { return @{} }
        $deny = @('*password*','*token*','*secret*','*credential*','*key*')
        $clean = @{}
        foreach ($k in $params.Keys) {
            $hit = $false
            foreach ($pattern in $deny) {
                if ($k -like $pattern) { $hit = $true; break }
            }
            if ($hit) {
                $clean[$k] = '*** (redacted) ***'
            } else {
                $v = $params[$k]
                if ($null -eq $v) {
                    $clean[$k] = '(null)'
                } elseif ($v -is [switch]) {
                    $clean[$k] = if ($v.IsPresent) { 'true' } else { 'false' }
                } elseif ($v -is [array]) {
                    $clean[$k] = ($v -join ', ')
                } else {
                    $clean[$k] = [string]$v
                }
            }
        }
        return $clean
    }

    # ----- data prep ------------------------------------------------------
    $duration = $EndTime - $StartTime
    $cleanParams = _FilterParameters $Parameters

    $okCount      = @($Summary.Values | Where-Object { $_ -eq 'OK' }).Count
    $skippedCount = @($Summary.Values | Where-Object { $_ -like 'Skipped*' }).Count
    $failedCount  = @($Summary.Values | Where-Object { $_ -like 'FAILED:*' }).Count
    $totalCount   = $Summary.Count

    $overallStatus = if ($failedCount -gt 0) {
        'Completed with errors'
    } elseif ($okCount -eq 0 -and $totalCount -gt 0) {
        'All tasks skipped'
    } elseif ($totalCount -eq 0) {
        'No tasks recorded'
    } else {
        'Completed successfully'
    }
    $overallClass = if ($failedCount -gt 0) { 'overall-failed' }
                    elseif ($okCount -eq 0)  { 'overall-skipped' }
                    else                     { 'overall-ok' }

    # ----- assemble HTML --------------------------------------------------
    $sb = [System.Text.StringBuilder]::new()
    $null = $sb.AppendLine('<!DOCTYPE html>')
    $null = $sb.AppendLine('<html lang="en"><head>')
    $null = $sb.AppendLine('<meta charset="utf-8">')
    $null = $sb.AppendLine(('<title>Purview Best Practice Deployment Report &mdash; {0}</title>' -f (_Encode $StartTime.ToString('yyyy-MM-dd HH:mm'))))
    $null = $sb.AppendLine(@'
<style>
  :root { color-scheme: light; }
  * { box-sizing: border-box; }
  body {
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
    color: #1f2328; background: #f6f8fa; margin: 0; padding: 24px;
    line-height: 1.5; font-size: 14px;
  }
  .container { max-width: 1000px; margin: 0 auto; }
  header { background: #0969da; color: #fff; padding: 20px 24px; border-radius: 8px 8px 0 0; }
  header h1 { margin: 0 0 4px 0; font-size: 20px; font-weight: 600; }
  header .subtitle { opacity: 0.9; font-size: 13px; }
  .overall-banner {
    padding: 14px 24px; font-weight: 600; font-size: 15px;
    border-radius: 0; border-left: 4px solid transparent;
  }
  .overall-ok      { background: #dafbe1; color: #116329; border-left-color: #1a7f37; }
  .overall-failed  { background: #ffebe9; color: #82071e; border-left-color: #cf222e; }
  .overall-skipped { background: #fff8c5; color: #7d4e00; border-left-color: #bf8700; }
  section {
    background: #fff; padding: 20px 24px; margin: 0;
    border-left: 1px solid #d0d7de; border-right: 1px solid #d0d7de;
  }
  section + section { border-top: 1px solid #d0d7de; }
  section:last-of-type { border-radius: 0 0 8px 8px; border-bottom: 1px solid #d0d7de; }
  h2 { font-size: 15px; font-weight: 600; margin: 0 0 12px 0; color: #1f2328;
       text-transform: uppercase; letter-spacing: 0.05em; }
  table { width: 100%; border-collapse: collapse; }
  th, td { text-align: left; padding: 8px 12px; border-bottom: 1px solid #eaeef2; }
  th { background: #f6f8fa; font-weight: 600; font-size: 12px;
       text-transform: uppercase; letter-spacing: 0.04em; color: #57606a; }
  tr:last-child td { border-bottom: none; }
  td.task-name { font-weight: 500; width: 35%; }
  .status-badge {
    display: inline-block; padding: 2px 10px; border-radius: 12px;
    font-size: 12px; font-weight: 600; font-family: ui-monospace, "Cascadia Code", monospace;
  }
  .status-ok      { background: #dafbe1; color: #116329; }
  .status-skipped { background: #fff8c5; color: #7d4e00; }
  .status-failed  { background: #ffebe9; color: #82071e; }
  .status-other   { background: #ddf4ff; color: #0969da; }
  .status-created   { background: #dafbe1; color: #116329; }
  .status-updated   { background: #ddf4ff; color: #0969da; }
  .status-adopted   { background: #fff8c5; color: #7d4e00; }
  .status-retried   { background: #fff8c5; color: #7d4e00; }
  .status-succeeded { background: #dafbe1; color: #116329; }
  .status-started   { background: #eaeef2; color: #57606a; }
  .status-info      { background: #ddf4ff; color: #0969da; }
  details.module-block { margin: 8px 0; border: 1px solid #d0d7de; border-radius: 6px; overflow: hidden; }
  details.module-block > summary {
    list-style: none; cursor: pointer; padding: 10px 14px;
    background: #f6f8fa; font-weight: 600; font-size: 13px;
    display: flex; justify-content: space-between; align-items: center; gap: 12px;
  }
  details.module-block > summary::-webkit-details-marker { display: none; }
  details.module-block > summary::before {
    content: '\25B6'; display: inline-block; transition: transform 0.15s ease;
    font-size: 10px; color: #57606a; margin-right: 6px;
  }
  details.module-block[open] > summary::before { transform: rotate(90deg); }
  details.module-block .module-counts { font-weight: 500; color: #57606a; font-size: 12px; font-family: ui-monospace, "Cascadia Code", monospace; }
  details.module-block table { font-size: 12px; }
  details.module-block th { font-size: 11px; }
  details.module-block td.ts    { font-family: ui-monospace, "Cascadia Code", monospace; color: #57606a; white-space: nowrap; }
  details.module-block td.action  { font-weight: 500; }
  details.module-block td.target  { font-family: ui-monospace, "Cascadia Code", monospace; word-break: break-word; }
  details.module-block td.detail  { color: #57606a; font-size: 11px; word-break: break-word; }
  details.module-block td.elapsed { font-family: ui-monospace, "Cascadia Code", monospace; color: #57606a; text-align: right; white-space: nowrap; }
  table.nextsteps td { vertical-align: top; }
  table.nextsteps td.ns-when { font-family: ui-monospace, "Cascadia Code", monospace; font-size: 11px; color: #0969da; white-space: nowrap; font-weight: 600; }
  table.nextsteps td.ns-what { font-weight: 600; color: #1f2328; }
  table.nextsteps code { background: #f6f8fa; padding: 1px 5px; border-radius: 3px; font-size: 11px; }
  table.nextsteps a { color: #0969da; text-decoration: none; }
  table.nextsteps a:hover { text-decoration: underline; }
  table.nextsteps .ns-why  { margin-top: 6px; color: #82071e; font-size: 11px; font-style: italic; }
  table.nextsteps .ns-link { margin-top: 6px; color: #57606a; font-size: 11px; }
  .meta-grid { display: grid; grid-template-columns: max-content 1fr; gap: 6px 16px; }
  .meta-grid dt { color: #57606a; font-weight: 500; }
  .meta-grid dd { margin: 0; font-family: ui-monospace, "Cascadia Code", monospace; word-break: break-all; }
  .domain-list { font-family: ui-monospace, "Cascadia Code", monospace; font-size: 13px; }
  .domain-list .primary { font-weight: 600; }
  .stats { display: flex; gap: 24px; flex-wrap: wrap; }
  .stat { display: flex; flex-direction: column; padding: 8px 16px; background: #f6f8fa; border-radius: 6px; min-width: 80px; }
  .stat .num { font-size: 22px; font-weight: 600; color: #1f2328; }
  .stat .lbl { font-size: 11px; color: #57606a; text-transform: uppercase; letter-spacing: 0.05em; }
  .failure-detail { color: #82071e; font-size: 12px; margin-top: 4px;
                    font-family: ui-monospace, "Cascadia Code", monospace; word-break: break-word; }
  footer { text-align: center; padding: 16px; color: #57606a; font-size: 12px; }
</style>
'@)
    $null = $sb.AppendLine('</head><body><div class="container">')

    # Header
    $headerTitle = if ($TenantIdentity -and $TenantIdentity.DisplayName) {
        _Encode $TenantIdentity.DisplayName
    } else {
        'Tenant (identity unresolved)'
    }
    $headerDomain = if ($TenantIdentity -and $TenantIdentity.DefaultDomain) {
        _Encode $TenantIdentity.DefaultDomain
    } elseif ($TenantIdentity -and $TenantIdentity.InitialDomain) {
        _Encode $TenantIdentity.InitialDomain
    } else { '' }

    $null = $sb.AppendLine('<header>')
    $null = $sb.AppendLine(('<h1>Microsoft Purview Best Practice Deployment</h1>'))
    $null = $sb.AppendLine(('<div class="subtitle">{0}{1}</div>' -f $headerTitle, $(if ($headerDomain) { " &middot; $headerDomain" } else { '' })))
    $null = $sb.AppendLine('</header>')

    # Overall banner
    $null = $sb.AppendLine(('<div class="overall-banner {0}">{1}</div>' -f $overallClass, (_Encode $overallStatus)))

    # Stats
    $null = $sb.AppendLine('<section><h2>At a glance</h2><div class="stats">')
    $null = $sb.AppendLine(('<div class="stat"><span class="num">{0}</span><span class="lbl">Completed</span></div>' -f $okCount))
    $null = $sb.AppendLine(('<div class="stat"><span class="num">{0}</span><span class="lbl">Skipped</span></div>' -f $skippedCount))
    $null = $sb.AppendLine(('<div class="stat"><span class="num">{0}</span><span class="lbl">Failed</span></div>' -f $failedCount))
    $null = $sb.AppendLine(('<div class="stat"><span class="num">{0}</span><span class="lbl">Duration</span></div>' -f (_Encode (_FormatDuration $duration))))
    $null = $sb.AppendLine('</div></section>')

    # Task status table
    $null = $sb.AppendLine('<section><h2>Task results</h2>')
    $null = $sb.AppendLine('<table><thead><tr><th>Task</th><th>Status</th></tr></thead><tbody>')
    if ($Summary.Count -eq 0) {
        $null = $sb.AppendLine('<tr><td colspan="2"><em>No tasks recorded &mdash; run aborted before any step started.</em></td></tr>')
    } else {
        foreach ($entry in $Summary.GetEnumerator()) {
            $value = [string]$entry.Value
            $cls = _StatusClass $value

            $label = $value
            $detail = $null
            if ($value -like 'FAILED:*') {
                $label = 'FAILED'
                $detail = $value.Substring(7).Trim()
            } elseif ($value -like 'Skipped*') {
                # "Skipped" plus optional "(reason)" parenthetical
                if ($value -match '^Skipped\s*(.*)$') {
                    $label = 'Skipped'
                    $rest = $Matches[1].Trim()
                    if ($rest) { $detail = $rest }
                }
            }

            $null = $sb.AppendLine('<tr>')
            $null = $sb.AppendLine(('<td class="task-name">{0}</td>' -f (_Encode $entry.Key)))
            $null = $sb.Append(('<td><span class="status-badge {0}">{1}</span>' -f $cls, (_Encode $label)))
            if ($detail) {
                $null = $sb.Append(('<div class="failure-detail">{0}</div>' -f (_Encode $detail)))
            }
            $null = $sb.AppendLine('</td>')
            $null = $sb.AppendLine('</tr>')
        }
    }
    $null = $sb.AppendLine('</tbody></table></section>')

    # ---------- "What's next" — contextual next-steps panel ------------------
    # Drives off $Summary outcomes so the partner sees a deploy-specific
    # to-do list. The Activity Explorer walkthrough comes from
    # docs/DLP-Simulation-Exit-Runbook.md so anything the partner reads here
    # is consistent with the canonical runbook.
    $next = [System.Collections.Generic.List[hashtable]]::new()

    $labelsStatus    = if ($Summary.Contains('Sensitivity labels')) { [string]$Summary['Sensitivity labels'] } else { '' }
    $dlpStatus       = if ($Summary.Contains('DLP policies'))       { [string]$Summary['DLP policies'] }       else { '' }
    $retentionStatus = if ($Summary.Contains('Retention'))          { [string]$Summary['Retention'] }          else { '' }
    $aiStatus        = if ($Summary.Contains('AI governance'))      { [string]$Summary['AI governance'] }      else { '' }
    $tenantStatus    = if ($Summary.Contains('Tenant settings'))    { [string]$Summary['Tenant settings'] }    else { '' }

    # --- DLP simulation exit ---------------------------------------------
    if ($dlpStatus -eq 'OK') {
        $next.Add(@{
            When  = 'Day 0 - 30'
            What  = 'Let the DLP policies accumulate telemetry in simulation mode.'
            How   = "DLP policies are deployed in <b>simulation</b> (<code>TestWithoutNotifications</code>) by default. They detect and log matches, but do not block or notify users. Nothing breaks; telemetry accumulates. <i>Do not promote to enforce until you've reviewed the evidence.</i>"
            Link  = $null
            Why   = $null
        })
        $next.Add(@{
            When  = 'Day 30 (recommended)'
            What  = 'Pull the &quot;what would have leaked&quot; report from Activity Explorer.'
            How   = @'
1. Open the <b>Microsoft Purview portal</b> at <a href="https://purview.microsoft.com" target="_blank" rel="noopener">purview.microsoft.com</a>.<br>
2. <b>Solutions</b> &rarr; <b>Data loss prevention</b> &rarr; <b>Activity explorer</b>.<br>
3. Filter by: <b>Activity</b> = <code>DLP rule match</code> &middot; <b>Policy</b> = (the policy you're reviewing) &middot; <b>Date range</b> = since deploy.<br>
4. Click <b>Export</b> &rarr; CSV and save alongside your customer record. This is the audit trail behind your promote-or-extend decision.
'@
            Link  = 'docs/DLP-Simulation-Exit-Runbook.md'
            Why   = 'A policy with zero telemetry is a policy you can&#39;t validate. Most partners skip this step and either flip enforce blindly or sit in simulation forever - both bad outcomes.'
        })
        $next.Add(@{
            When  = 'Day 30 (recommended)'
            What  = 'Decide per policy: promote, extend, refine, or drop.'
            How   = 'For each policy, weigh the Activity Explorer evidence against business expectations. Document the decision, the cited evidence (hit count over the 30-day window), the operator, and the next-review date in the customer record.'
            Link  = 'docs/DLP-Simulation-Exit-Runbook.md'
            Why   = 'Make the promote-from-simulation call per policy, not globally. Skip the per-policy reasoning and you will tank legitimate sharing on day 31.'
        })
    } elseif ($dlpStatus -like 'FAILED*') {
        $next.Add(@{
            When  = 'Immediate'
            What  = 'Re-run DLP deploy after resolving the failure.'
            How   = "DLP step reported: <code>$(_Encode $dlpStatus)</code>. Inspect the run log above (Setup-DLP module) for the failing action, then re-run the script. The toolkit is idempotent - already-created policies will be detected and updated."
            Link  = $null
            Why   = $null
        })
    }

    # --- Sensitivity labels propagation ----------------------------------
    if ($labelsStatus -eq 'OK') {
        $next.Add(@{
            When  = '0 - 24 hours after deploy'
            What  = 'Wait for label and policy propagation; verify in the Purview portal.'
            How   = @'
Sensitivity labels and label policies can take up to 24 hours to fully propagate to every Office client. After the wait:<br>
1. Purview portal &rarr; <b>Information protection</b> &rarr; <b>Labels</b> - confirm the labels are listed and ordered correctly.<br>
2. Open Word/Excel/Outlook as a published-policy user. The label picker (Home tab &rarr; Sensitivity) should show <i>Personal, Public, General, Confidential, Highly Confidential</i>.<br>
3. If the picker is missing, confirm the user has a Microsoft 365 Business Premium / E3 / E5 licence with Information Protection, and that they are inside the label policy scope.
'@
            Link  = $null
            Why   = $null
        })
    }

    # --- Retention: opt-in nudge ------------------------------------------
    if ($retentionStatus -like 'Skipped*') {
        $next.Add(@{
            When  = 'Before go-live'
            What  = 'Decide whether retention applies in this engagement.'
            How   = 'Retention is opt-in by default. To enable, re-run with <code>-ApplyRetention</code>. Review the configured duration and scope first - the toolkit ships a 7-year mailbox retain-then-delete default which aligns with most SMB regulatory frameworks (ATO / IRS / SEC / ASIC) but may not be appropriate for every customer.'
            Link  = 'docs/Retention-Default-Risk.md'
            Why   = 'Retention policies are notoriously hard to roll back. The Retention-Default-Risk doc covers the decision points (litigation risk, regulatory baseline, scope) you should walk through with the customer <i>before</i> enabling.'
        })
    }

    # --- AI governance follow-up ------------------------------------------
    if ($aiStatus -eq 'OK') {
        $next.Add(@{
            When  = 'Day 0 - 30'
            What  = 'Verify Copilot DLP rule matches in Activity Explorer.'
            How   = 'Activity Explorer also surfaces Copilot DLP rule matches under the same filter set. After a few days of typical Copilot usage, pull the same report and check whether <code>Highly Confidential</code>-classified content is being shielded from Copilot as expected.'
            Link  = 'docs/DLP-Simulation-Exit-Runbook.md'
            Why   = $null
        })
    } elseif ($aiStatus -like 'Skipped (-ApplyAIControls*') {
        $next.Add(@{
            When  = 'Optional'
            What  = 'Provision the Copilot DLP policies if the customer has Microsoft 365 Copilot.'
            How   = 'Re-run the script with <code>-ApplyAIControls</code> to deploy the AI governance scenarios defined in <code>PurviewConfig.psd1 -&gt; AIGovernance</code>. Without these, Copilot can summarise / reason over Highly Confidential content unrestricted.'
            Link  = $null
            Why   = $null
        })
    }

    # --- Audit log readiness ----------------------------------------------
    if ($tenantStatus -eq 'OK') {
        $next.Add(@{
            When  = 'Anytime'
            What  = 'Cross-check DLP activity with the unified audit log.'
            How   = @'
For the wider DLP picture (Exchange + SharePoint + Endpoint hits in one query), run this in <code>pwsh</code> while connected to Exchange Online:<br>
<pre style="background:#0d1117;color:#c9d1d9;padding:10px;border-radius:6px;font-size:11px;overflow-x:auto;margin:6px 0 0 0;">Search-UnifiedAuditLog -StartDate (Get-Date).AddDays(-30) -EndDate (Get-Date) `
    -RecordType ComplianceDLPExchange,ComplianceDLPSharePoint,DLPEndpoint `
    -ResultSize 5000 |
  Group-Object UserIds | Sort-Object Count -Descending |
  Select-Object Count, Name -First 20</pre>
Top-N users by hit count gives you the list of people to talk to before flipping enforce on.
'@
            Link  = 'docs/DLP-Simulation-Exit-Runbook.md'
            Why   = 'Two or three conversations beforehand save twenty helpdesk tickets after.'
        })
    }

    # --- Universal close-out -----------------------------------------------
    $next.Add(@{
        When  = 'Anytime'
        What  = 'Archive this report alongside the customer record.'
        How   = "Keep this HTML and its <code>.json</code> sidecar in the customer's deploy folder. The sidecar's <code>runId</code> is the join key if you later need to correlate against Activity Explorer exports or the unified audit log."
        Link  = $null
        Why   = $null
    })

    if ($next.Count -gt 0) {
        # Collapsible (open by default — these are the actionable follow-ups, so we
        # surface them, but the operator can collapse if they only want the run summary).
        $null = $sb.AppendLine('<section>')
        $null = $sb.AppendLine('<details class="module-block" open>')
        $null = $sb.AppendLine(('<summary><span>What&#39;s next</span><span class="module-counts">{0} recommended follow-up(s)</span></summary>' -f $next.Count))
        $null = $sb.AppendLine('<p style="margin:8px 0 12px 0;color:#57606a;font-size:12px;">Based on what this run deployed. Items link to the canonical runbooks in the repo.</p>')
        $null = $sb.AppendLine('<table class="nextsteps"><thead><tr><th style="width:14%">When</th><th style="width:30%">What</th><th>How / why</th></tr></thead><tbody>')
        foreach ($n in $next) {
            $null = $sb.AppendLine('<tr>')
            $null = $sb.AppendLine(('<td class="ns-when">{0}</td>' -f (_Encode $n.When)))
            $null = $sb.AppendLine(('<td class="ns-what">{0}</td>' -f (_Encode $n.What)))
            # 'How' fields contain intentional HTML markup (links, <code>, <pre>) — do NOT re-encode.
            $body = $n.How
            if ($n.Why) { $body += ('<div class="ns-why"><b>Why it matters:</b> {0}</div>' -f $n.Why) }
            if ($n.Link) {
                $body += ('<div class="ns-link">See: <code>{0}</code> in the repo.</div>' -f (_Encode $n.Link))
            }
            $null = $sb.AppendLine(('<td>{0}</td>' -f $body))
            $null = $sb.AppendLine('</tr>')
        }
        $null = $sb.AppendLine('</tbody></table>')
        $null = $sb.AppendLine('<p style="margin:14px 0 0 0;color:#57606a;font-size:12px;">Reference: <a href="https://learn.microsoft.com/en-us/purview/data-classification-activity-explorer" target="_blank" rel="noopener">Get started with Activity Explorer</a> &middot; <a href="https://learn.microsoft.com/en-us/purview/dlp-test-dlp-policies" target="_blank" rel="noopener">Test or simulate DLP policies</a>.</p>')
        $null = $sb.AppendLine('</details>')
        $null = $sb.AppendLine('</section>')
    }

    # ---------- Tier 2: per-action run log (collapsible per-module) ----------
    if ($RunLog -and $RunLog.Count -gt 0) {
        # Group while preserving first-seen module order.
        $moduleOrder = [System.Collections.Generic.List[string]]::new()
        $byModule    = @{}
        foreach ($e in $RunLog) {
            $m = if ($e.Module) { [string]$e.Module } else { '(unknown)' }
            if (-not $byModule.ContainsKey($m)) {
                $byModule[$m] = [System.Collections.Generic.List[hashtable]]::new()
                $moduleOrder.Add($m)
            }
            $byModule[$m].Add($e)
        }

        $null = $sb.AppendLine('<section><h2>Per-action detail</h2>')
        $null = $sb.AppendLine(('<p style="margin:0 0 10px 0;color:#57606a;font-size:12px;">{0} entries across {1} module(s). Click a module to expand.</p>' -f $RunLog.Count, $moduleOrder.Count))

        foreach ($modName in $moduleOrder) {
            $entries = $byModule[$modName]

            # Per-module counts by status (case-insensitive).
            $cFail = @($entries | Where-Object { $_.Status -eq 'Failed' }).Count
            $cRet  = @($entries | Where-Object { $_.Status -eq 'Retried' }).Count
            $cAdo  = @($entries | Where-Object { $_.Status -eq 'Adopted' }).Count
            $cCre  = @($entries | Where-Object { $_.Status -in @('Created','Succeeded') }).Count
            $cUpd  = @($entries | Where-Object { $_.Status -eq 'Updated' }).Count
            $cSki  = @($entries | Where-Object { $_.Status -eq 'Skipped' }).Count

            $countBits = @()
            if ($cCre) { $countBits += "$cCre ok" }
            if ($cUpd) { $countBits += "$cUpd updated" }
            if ($cAdo) { $countBits += "$cAdo adopted" }
            if ($cSki) { $countBits += "$cSki skipped" }
            if ($cRet) { $countBits += "$cRet retried" }
            if ($cFail){ $countBits += "$cFail failed" }
            $counts = if ($countBits.Count -gt 0) { $countBits -join ' &middot; ' } else { "$($entries.Count) entries" }

            # Auto-expand modules with failures so operators see them immediately.
            $openAttr = if ($cFail -gt 0) { ' open' } else { '' }

            $null = $sb.AppendLine(('<details class="module-block"{0}>' -f $openAttr))
            $null = $sb.AppendLine(('<summary><span>{0}</span><span class="module-counts">{1}</span></summary>' -f (_Encode $modName), $counts))
            $null = $sb.AppendLine('<table><thead><tr>')
            $null = $sb.AppendLine('<th>Time</th><th>Action</th><th>Target</th><th>Status</th><th>Detail</th><th>Att.</th><th>ms</th>')
            $null = $sb.AppendLine('</tr></thead><tbody>')

            foreach ($e in $entries) {
                $ts = ''
                if ($e.Timestamp -is [datetime]) {
                    $ts = $e.Timestamp.ToLocalTime().ToString('HH:mm:ss')
                }
                $statusLower = if ($e.Status) { ([string]$e.Status).ToLowerInvariant() } else { 'info' }
                $statusCls   = "status-$statusLower"
                $attempt     = if ($e.ContainsKey('Attempt'))   { [string]$e.Attempt }   else { '' }
                $elapsedTxt  = if ($e.ContainsKey('ElapsedMs') -and $null -ne $e.ElapsedMs) { [string]$e.ElapsedMs } else { '' }

                $null = $sb.AppendLine('<tr>')
                $null = $sb.AppendLine(('<td class="ts">{0}</td>'      -f (_Encode $ts)))
                $null = $sb.AppendLine(('<td class="action">{0}</td>'  -f (_Encode ([string]$e.Action))))
                $null = $sb.AppendLine(('<td class="target">{0}</td>'  -f (_Encode ([string]$e.Target))))
                $null = $sb.AppendLine(('<td><span class="status-badge {0}">{1}</span></td>' -f $statusCls, (_Encode ([string]$e.Status))))
                $null = $sb.AppendLine(('<td class="detail">{0}</td>'  -f (_Encode ([string]$e.Detail))))
                $null = $sb.AppendLine(('<td class="elapsed">{0}</td>' -f (_Encode $attempt)))
                $null = $sb.AppendLine(('<td class="elapsed">{0}</td>' -f (_Encode $elapsedTxt)))
                $null = $sb.AppendLine('</tr>')
            }
            $null = $sb.AppendLine('</tbody></table></details>')
        }
        $null = $sb.AppendLine('</section>')
    }

    # Tenant
    $null = $sb.AppendLine('<section><h2>Target tenant</h2><dl class="meta-grid">')
    if ($TenantIdentity) {
        $null = $sb.AppendLine(('<dt>Display name</dt><dd>{0}</dd>' -f (_Encode $TenantIdentity.DisplayName)))
        $null = $sb.AppendLine(('<dt>Tenant ID</dt><dd>{0}</dd>' -f (_Encode $TenantIdentity.TenantId)))
        $null = $sb.AppendLine(('<dt>Default domain</dt><dd>{0}</dd>' -f (_Encode $TenantIdentity.DefaultDomain)))
        $null = $sb.AppendLine(('<dt>Initial domain</dt><dd>{0}</dd>' -f (_Encode $TenantIdentity.InitialDomain)))
        $null = $sb.AppendLine(('<dt>Source</dt><dd>{0}</dd>' -f (_Encode $TenantIdentity.Source)))
        if ($TenantIdentity.AllDomains -and $TenantIdentity.AllDomains.Count -gt 0) {
            $null = $sb.AppendLine('<dt>Verified domains</dt><dd class="domain-list">')
            $primary = $TenantIdentity.DefaultDomain
            $domHtml = foreach ($d in $TenantIdentity.AllDomains) {
                $enc = _Encode $d
                if ($d -eq $primary) { "<span class=`"primary`">$enc</span>" } else { $enc }
            }
            $null = $sb.AppendLine(($domHtml -join ', '))
            $null = $sb.AppendLine('</dd>')
        }
    } else {
        $null = $sb.AppendLine('<dt>(not resolved)</dt><dd>tenant identity not captured before report generation</dd>')
    }
    if ($TenantAdminUpn) {
        $null = $sb.AppendLine(('<dt>Admin UPN</dt><dd>{0}</dd>' -f (_Encode $TenantAdminUpn)))
    }
    $null = $sb.AppendLine('</dl></section>')

    # Run metadata
    $null = $sb.AppendLine('<section><h2>Run metadata</h2><dl class="meta-grid">')
    $null = $sb.AppendLine(('<dt>Started</dt><dd>{0}</dd>' -f (_Encode $StartTime.ToString('yyyy-MM-dd HH:mm:ss zzz'))))
    $null = $sb.AppendLine(('<dt>Ended</dt><dd>{0}</dd>'   -f (_Encode $EndTime.ToString('yyyy-MM-dd HH:mm:ss zzz'))))
    $null = $sb.AppendLine(('<dt>Duration</dt><dd>{0}</dd>' -f (_Encode (_FormatDuration $duration))))
    $null = $sb.AppendLine(('<dt>Run ID</dt><dd>{0}</dd>' -f (_Encode $RunId.ToString())))
    $null = $sb.AppendLine(('<dt>Script version</dt><dd>{0}</dd>' -f (_Encode $ScriptVersion)))
    $null = $sb.AppendLine(('<dt>PowerShell</dt><dd>{0}</dd>' -f (_Encode ("$($PSVersionTable.PSVersion) ($($PSVersionTable.PSEdition))"))))
    $null = $sb.AppendLine(('<dt>Host OS</dt><dd>{0}</dd>' -f (_Encode ([System.Environment]::OSVersion.VersionString))))
    $null = $sb.AppendLine(('<dt>Machine</dt><dd>{0}</dd>' -f (_Encode ([System.Environment]::MachineName))))
    $null = $sb.AppendLine('</dl></section>')

    # Parameters
    if ($cleanParams.Count -gt 0) {
        $null = $sb.AppendLine('<section><h2>Parameters used</h2><dl class="meta-grid">')
        foreach ($key in ($cleanParams.Keys | Sort-Object)) {
            $null = $sb.AppendLine(('<dt>-{0}</dt><dd>{1}</dd>' -f (_Encode $key), (_Encode ([string]$cleanParams[$key]))))
        }
        $null = $sb.AppendLine('</dl></section>')
    }

    # Footer
    $null = $sb.AppendLine(('<footer>Generated {0} &middot; SMBBestPracticeTool {1} &middot; Run {2}</footer>' -f `
        (_Encode (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')), (_Encode $ScriptVersion), (_Encode $RunId.ToString())))
    $null = $sb.AppendLine('</div></body></html>')

    # ----- write ----------------------------------------------------------
    $dir = Split-Path -Parent $OutputPath
    if ($dir -and -not (Test-Path $dir)) {
        New-Item -ItemType Directory -Path $dir -Force | Out-Null
    }
    Set-Content -Path $OutputPath -Value $sb.ToString() -Encoding UTF8 -NoNewline:$false
    return $OutputPath
}
