#requires -Version 7.0
<#
.SYNOPSIS
    Tier-2 per-action run log for the Purview Best Practice toolkit.

.DESCRIPTION
    Provides a singleton collection of structured "decision point" entries
    that the orchestrator and individual Setup-* modules can append to
    during a run. The end-of-run HTML report renders these entries grouped
    by Module so an operator (or auditor) can see exactly what was
    Created / Updated / Skipped / Adopted / Failed and why.

    DESIGN -- WHY $global:

      The orchestrator calls each Setup-* module via the call operator
      (& $tenantScript @taskArgs), which executes the child script in its
      OWN script scope. A $script:-scoped collection in this file would
      therefore be invisible across modules. We use $global:PurviewRunLog
      as the shared store: it's a single, well-namespaced variable, scoped
      to the PowerShell session, and cleared by Initialize-PurviewRunLog
      at the start of every orchestrator run.

      Setup-* modules dot-source this file and call Add-RunLogEntry; they
      do NOT need to know about the storage mechanism.

    ENTRY SHAPE (hashtable, all fields optional except Module + Action):

        @{
            Timestamp = [datetime]  ([datetime]::UtcNow auto-stamped)
            Module    = 'Setup-DLP'
            Action    = 'New-DlpCompliancePolicy'   # what was attempted
            Target    = 'Block external sharing -- AllEmployees'  # the
                                                      # object the action
                                                      # operated on
            Status    = 'Created' | 'Updated' | 'Adopted' | 'Skipped'
                       | 'Failed'  | 'Retried' | 'Started' | 'Succeeded'
            Detail    = '...'                       # free-text context
            Attempt   = 1                           # retry attempt #
            ElapsedMs = 1234                        # wall-clock if known
        }

    EXPORTS (via dot-source):
      * Initialize-PurviewRunLog
      * Add-RunLogEntry
      * Get-PurviewRunLog
      * Clear-PurviewRunLog
      * Save-PurviewRunLogJson
#>

function Initialize-PurviewRunLog {
    <#
        Clear and re-initialise the global run log. Called once by the
        orchestrator at the start of every deploy run.
    #>
    [CmdletBinding()]
    param()
    $global:PurviewRunLog = [System.Collections.Generic.List[hashtable]]::new()
}

function Add-RunLogEntry {
    <#
        Append a single decision-point entry. Safe to call before
        Initialize-PurviewRunLog (lazy-inits the list). Designed to NEVER
        throw -- a logging bug must not crash the deploy.

        Common usage:

            Add-RunLogEntry -Module 'Setup-DLP' -Action 'New-DlpCompliancePolicy' `
                            -Target $polName -Status 'Created'

            Add-RunLogEntry -Module 'Setup-SensitivityLabels' `
                            -Action 'New-Label' -Target $disp `
                            -Status 'Adopted' -Detail 'Duplicate display name; reusing existing GUID.'
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string] $Module,
        [Parameter(Mandatory)] [string] $Action,
        [string]   $Target,
        [ValidateSet('Started','Succeeded','Created','Updated','Adopted','Skipped','Failed','Retried','Info')]
        [string]   $Status = 'Info',
        [string]   $Detail,
        [int]      $Attempt,
        [int]      $ElapsedMs
    )

    try {
        if (-not $global:PurviewRunLog) {
            $global:PurviewRunLog = [System.Collections.Generic.List[hashtable]]::new()
        }

        $entry = @{
            Timestamp = [datetime]::UtcNow
            Module    = $Module
            Action    = $Action
            Target    = $Target
            Status    = $Status
            Detail    = $Detail
        }
        if ($PSBoundParameters.ContainsKey('Attempt'))   { $entry.Attempt   = $Attempt }
        if ($PSBoundParameters.ContainsKey('ElapsedMs')) { $entry.ElapsedMs = $ElapsedMs }

        $global:PurviewRunLog.Add($entry)
    } catch {
        # Logging must never break the deploy. Swallow.
        Write-Verbose "Add-RunLogEntry failed: $($_.Exception.Message)"
    }
}

function Get-PurviewRunLog {
    <#
        Return the current run log as an array of hashtables (a copy --
        callers can iterate without worrying about concurrent mutation).
        Returns an empty array when no entries have been recorded.
    #>
    [CmdletBinding()]
    [OutputType([hashtable[]])]
    param()

    if (-not $global:PurviewRunLog) { return @() }
    # Force array output even when the list has 0 or 1 entries.
    return ,@($global:PurviewRunLog.ToArray())
}

function Clear-PurviewRunLog {
    <#
        Drop the global run log. Called by the orchestrator after the
        report has been written so the variable doesn't leak between
        runs in interactive PowerShell sessions.
    #>
    [CmdletBinding()]
    param()
    Remove-Variable -Name 'PurviewRunLog' -Scope Global -ErrorAction SilentlyContinue
}

function Save-PurviewRunLogJson {
    <#
        Dump the run log as JSON to -Path. Used by the orchestrator to
        emit a machine-readable sidecar next to the HTML report.
        Includes the run-level metadata (RunId, StartTime, EndTime,
        ScriptVersion) so the JSON is self-contained.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string]   $Path,
        [Parameter(Mandatory)] [guid]     $RunId,
        [Parameter(Mandatory)] [datetime] $StartTime,
        [Parameter(Mandatory)] [datetime] $EndTime,
        [string]                          $ScriptVersion,
        [string]                          $TenantId,
        [string]                          $TenantAdminUpn,
        $Summary
    )

    $entries = Get-PurviewRunLog
    $payload = [ordered]@{
        runId         = $RunId.ToString()
        scriptVersion = $ScriptVersion
        startTime     = $StartTime.ToString('o')
        endTime       = $EndTime.ToString('o')
        durationSec   = [int](($EndTime - $StartTime).TotalSeconds)
        tenantId      = $TenantId
        tenantAdmin   = $TenantAdminUpn
        summary       = if ($Summary) { $Summary } else { @{} }
        entryCount    = $entries.Count
        entries       = $entries | ForEach-Object {
            $e = $_
            [ordered]@{
                timestamp = $e.Timestamp.ToString('o')
                module    = $e.Module
                action    = $e.Action
                target    = $e.Target
                status    = $e.Status
                detail    = $e.Detail
                attempt   = if ($e.ContainsKey('Attempt'))   { $e.Attempt }   else { $null }
                elapsedMs = if ($e.ContainsKey('ElapsedMs')) { $e.ElapsedMs } else { $null }
            }
        }
    }

    $json = $payload | ConvertTo-Json -Depth 8
    Set-Content -Path $Path -Value $json -Encoding UTF8
    return $Path
}
