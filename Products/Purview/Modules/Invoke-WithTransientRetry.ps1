#requires -Version 7.0
<#
.SYNOPSIS
    Shared transient-error retry helper for the Purview Best Practice toolkit.

.DESCRIPTION
    Microsoft 365 backends (IPPS / Security & Compliance, EXO, SPO, Graph
    Beta directory settings) regularly return short-lived 5xx and throttling
    responses during bulk policy/label/rule operations:

      * 429 throttling under burst writes (label priority reorders, rule
        creation loops)
      * 502 / 504 gateway responses while a long-running provision is still
        in flight server-side
      * 500 / "server side error" on freshly-hydrated tenants or during
        Microsoft maintenance windows
      * 503 "Service Unavailable" during regional service incidents

    Without retry, a single transient hiccup mid-deploy leaves a tenant in
    a half-configured state (e.g. policy created but rule missing). With
    retry, the same hiccup is silently absorbed after a short backoff.

    EXPORTS (via dot-source):
      * Test-TransientServerError   - signature detector
      * Invoke-WithTransientRetry   - retry wrapper

    Auto-imports theyes Tier-2 run log helper (PurviewRunLog.ps1) when
    present, so the wrapper can emit Started / Retried / Succeeded /
    Failed entries for every retry-wrapped destructive op without the
    caller doing anything. Setup-* modules that dot-source this file
    therefore get the Add-RunLogEntry function automatically as well.

.NOTES
    Origin: extracted from Setup-TenantSettings.ps1 where this pattern was
    first proven, and promoted into a shared module so Labels, DLP,
    Retention, and AI Governance can use the same backoff and signature
    set. (Jim's PR4 feedback.)

    Usage:
        . (Join-Path $PSScriptRoot 'Invoke-WithTransientRetry.ps1')

        Invoke-WithTransientRetry -Description 'New-DlpComplianceRule X' -Action {
            New-DlpComplianceRule -Name 'X' -ErrorAction Stop | Out-Null
        }
#>

# Auto-import the Tier-2 run log helper so callers (Setup-* modules)
# get Add-RunLogEntry in their scope. Idempotent: if PurviewRunLog.ps1
# is missing (e.g. unit-test rigs that mock it out), we silently skip
# and Invoke-WithTransientRetry falls back to no-op logging via
# Get-Command detection inside the retry loop.
$_purviewRunLogPath = Join-Path $PSScriptRoot 'PurviewRunLog.ps1'
if (Test-Path $_purviewRunLogPath) {
    . $_purviewRunLogPath
}

function Test-TransientServerError {
    <#
        Returns $true when the error blob carries any of the well-known
        transient signatures emitted by IPPS/EXO/SPO/Graph. The check is
        substring-based across the full error record (message, details,
        category, FQEID, exception type name) because each service tends
        to surface the same condition through slightly different fields.

        Important: HTTP 500 + "Internal Server Error" alone is NOT enough
        to classify as transient -- IPPS wraps several deterministic
        semantic errors (e.g. InvalidSubLabelPriorityException) in a
        generic 500 envelope. We check a non-transient denylist FIRST and
        bail out before the transient pattern match if any matches.
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param([Parameter(Mandatory)] $ErrorRecord)

    $blob = @(
        $ErrorRecord.Exception.Message,
        $ErrorRecord.ErrorDetails.Message,
        $ErrorRecord.CategoryInfo.Reason,
        $ErrorRecord.FullyQualifiedErrorId,
        $ErrorRecord.Exception.GetType().FullName
    ) -join ' '

    if ([string]::IsNullOrWhiteSpace($blob)) { return $false }

    # Non-transient denylist: well-known semantic errors that IPPS sometimes
    # wraps in a 500/InternalServerError envelope. Retrying these is wasted
    # time and noise -- they're deterministic.
    $nonTransientPatterns = @(
        'InvalidSubLabelPriorityException',
        'InvalidPriorityException',
        'Duplicate display name',
        'ComplianceRuleAlreadyExistsInScenarioException',
        'LabelAlreadyPublishedException',
        'Enable-OrganizationCustomization',
        'has been deleted and cannot be modified',
        'ErrorCommonComplianceRuleIsDeletedException'
    )
    foreach ($p in $nonTransientPatterns) {
        if ($blob -match $p) { return $false }
    }

    $patterns = @(
        '\b(429|500|502|503|504)\b',
        'Service Unavailable',
        'Gateway Timeout',
        'Internal Server Error',
        'server[- ]side error',
        'could not be completed',
        'try again',
        'temporarily unavailable',
        'throttl',
        'timeout',
        'EnableSpoAipMigrationIsDisabledException',
        'A task was canceled'
    )
    foreach ($p in $patterns) {
        if ($blob -match $p) { return $true }
    }
    return $false
}

function Test-AlreadyExistsError {
    <#
        Detects "object already exists" style errors. Used by the retry
        wrapper when -AlreadyExistsIsSuccess is set: if a New-* cmdlet
        succeeded on the server but failed on the response handshake, a
        retry will see the object already there and would normally throw
        — we treat that case as success (because it IS success, just
        invisible to the client on the first attempt).

        Caveat: on attempt #1 a pre-existing object is a real condition
        the caller should know about, so the wrapper only suppresses
        already-exists from attempt #2 onward.
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param([Parameter(Mandatory)] $ErrorRecord)

    $blob = @(
        $ErrorRecord.Exception.Message,
        $ErrorRecord.ErrorDetails.Message,
        $ErrorRecord.FullyQualifiedErrorId
    ) -join ' '

    if ([string]::IsNullOrWhiteSpace($blob)) { return $false }

    $patterns = @(
        'already exist',
        'DSAlreadyExist',
        'ConfigurationItemId.*already',
        'is already in use',
        'duplicate key',
        'A label with the same name already exists',
        'A policy with the same name already exists'
    )
    foreach ($p in $patterns) {
        if ($blob -match $p) { return $true }
    }
    return $false
}

function Invoke-WithTransientRetry {
    <#
        Execute -Action; on a transient error, sleep and retry up to
        -MaxAttempts times. Non-transient errors throw immediately.

        Backoff schedule defaults to 5s -> 15s -> 30s -> 45s -> 60s.
        Total ceiling at default settings: ~155 seconds before giving up.

        Returns whatever -Action returns (so Get-* calls can be wrapped
        without their output being clobbered). On giving up (transient
        errors that outlast MaxAttempts, OR a non-transient error),
        re-throws so the caller's catch fires normally.

        -AlreadyExistsIsSuccess: opt-in flag for idempotent New-* paths.
            If retry sees an "already exists" error on attempt #2+, treat
            as success (the object was created by a prior failed attempt
            whose response we lost). On attempt #1, "already exists" is a
            real condition and propagates normally.

        -OnRetry: optional scriptblock invoked between sleeps. Used by
            callers that need to refresh stale state (e.g. re-read a
            label's Priority before the next Set-Label attempt).

        -Module / -Target: optional run-log enrichment. When the Tier-2
            PurviewRunLog is loaded (Add-RunLogEntry available), the
            helper auto-emits Started / Retried / Succeeded / Failed
            entries so every retry-wrapped destructive op shows up in the
            end-of-run HTML report without the caller having to do
            anything. Logging is silently skipped when Add-RunLogEntry
            isn't available (e.g. in standalone unit tests).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [scriptblock] $Action,
        [Parameter(Mandatory)] [string]      $Description,
        [int]                                $MaxAttempts             = 6,
        [int[]]                              $BackoffSeconds          = @(5, 15, 30, 45, 60),
        [switch]                             $AlreadyExistsIsSuccess,
        [scriptblock]                        $OnRetry,
        [string]                             $Module,
        [string]                             $Target
    )

    # Tier-2: detect whether the run-log helper is loaded in the current
    # session. Cache the result for the duration of this invocation.
    $logEnabled = [bool](Get-Command 'Add-RunLogEntry' -ErrorAction SilentlyContinue)
    $logModule  = if ($Module) { $Module } else { 'Retry' }

    $sw = [System.Diagnostics.Stopwatch]::StartNew()

    for ($attempt = 1; $attempt -le $MaxAttempts; $attempt++) {
        try {
            & $Action
            $sw.Stop()
            if ($logEnabled) {
                Add-RunLogEntry -Module $logModule -Action $Description -Target $Target `
                    -Status 'Succeeded' -Attempt $attempt -ElapsedMs ([int]$sw.ElapsedMilliseconds)
            }
            return
        } catch {
            $err = $_

            # "Already exists" branch -- only meaningful from attempt #2 onward
            # because attempt #1 catching this means the object pre-existed
            # (the caller's idempotency check should already have handled it,
            # but if it didn't, that's a real condition the caller needs to
            # know about and we should NOT swallow).
            if ($AlreadyExistsIsSuccess -and $attempt -gt 1 -and (Test-AlreadyExistsError -ErrorRecord $err)) {
                Write-Host ("      ~ '{0}' reports object already exists on attempt {1}/{2} - treating as success (likely created by an earlier failed attempt whose response was lost)." -f $Description, $attempt, $MaxAttempts) -ForegroundColor DarkGray
                $sw.Stop()
                if ($logEnabled) {
                    Add-RunLogEntry -Module $logModule -Action $Description -Target $Target `
                        -Status 'Adopted' -Attempt $attempt -ElapsedMs ([int]$sw.ElapsedMilliseconds) `
                        -Detail 'Object reported as already existing on retry; treated as success.'
                }
                return
            }

            $isTransient = Test-TransientServerError -ErrorRecord $err
            $isLast      = $attempt -ge $MaxAttempts

            if ($isTransient -and -not $isLast) {
                $sleep = $BackoffSeconds[[Math]::Min($attempt - 1, $BackoffSeconds.Count - 1)]
                $sleep += Get-Random -Minimum 0 -Maximum 3
                Write-Host ("      ~ Transient error on '{0}' (attempt {1}/{2}). Sleeping {3}s and retrying..." -f $Description, $attempt, $MaxAttempts, $sleep) -ForegroundColor DarkYellow
                Write-Host ("        {0}" -f $err.Exception.Message) -ForegroundColor DarkGray
                if ($logEnabled) {
                    Add-RunLogEntry -Module $logModule -Action $Description -Target $Target `
                        -Status 'Retried' -Attempt $attempt `
                        -Detail ("Transient: {0}. Sleeping {1}s." -f $err.Exception.Message, $sleep)
                }
                Start-Sleep -Seconds $sleep

                if ($OnRetry) {
                    try { & $OnRetry $attempt $err } catch { Write-Verbose "OnRetry callback failed: $($_.Exception.Message)" }
                }
                continue
            }

            # Non-transient OR final attempt -- bubble up.
            $sw.Stop()
            if ($logEnabled) {
                Add-RunLogEntry -Module $logModule -Action $Description -Target $Target `
                    -Status 'Failed' -Attempt $attempt -ElapsedMs ([int]$sw.ElapsedMilliseconds) `
                    -Detail $err.Exception.Message
            }
            throw
        }
    }
}
