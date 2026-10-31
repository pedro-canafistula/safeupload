#Requires -RunAsAdministrator
#Requires -Version 5.1
<#
.SYNOPSIS
Reads driver and communication diagnostics from the running SafeUpload service (administrator only, read-only).

.DESCRIPTION
The minifilter's communication port accepts a single client and the service holds it, so no other tool can read the
driver while the product runs. The service exposes read-only queries over the SYSTEM/Administrators-only pipe
\\.\pipe\SafeUpload.Agent.Diagnostics:

TimeoutSeconds (1..300, default 10) is one I/O budget for the entire query, including all deny-ring pages.
Each reply must be a newline-terminated UTF-8 JSON frame of at most 1 MiB (excluding the newline).
Timeout, incomplete, oversized or invalid replies fail the query. Completed deny-ring pages may already have
been emitted if a later page fails; an error is not a complete snapshot.

  communication-health  policy/heartbeat/audit attempts, results and sanitized failure categories.
                        No network/driver access is performed by this query. Counters reset on restart.
                        Success is not proof of central persistence, applied policy or protection.

  audit-integrity      explicit read-only scan: line counts, pending/confirmed records, oldest pending UTC,
                       and up to 20 line numbers/reasons; no event content, IDs or paths.
                       A scan exceeding the service deadline returns no partial inventory. No repair/deletion.

  audit-health         process-local failures/resumptions per queue operation, since service start.
                       No file scan, content or exception messages. Resumption does not recover failed writes.

  audit-temporaries     bounded metadata inventory of queue-name.GUID.tmp candidates; no content read.
  audit-temporary-classification bounded Windows content classification; no ownership/recovery proof.
  audit-retention-preview occurrence-age counts for confirmed lines before -OccurredBeforeUtc (explicit UTC).
                        All three are read-only. No promotion, recovery, deletion or retention policy is applied.

  counters   refusal counters, how often a path that could not resolve a name answered "the whole volume may be in
             scope", and the writer-state status (registry entries and capacity, reclaim-worker passes, sections,
             stage streams).
  deny-ring  the most recent operations the driver completed with an error status: status, operation, requesting
             process, flags, and the tail of the requested path or rename target. siteOffset is relative to the
             driver image base; resolve it against SafeUpload.pdb to name the refusing code.

.EXAMPLE
.\Get-SafeUploadDiagnostics.ps1 -Query counters

.EXAMPLE
.\Get-SafeUploadDiagnostics.ps1 -Query deny-ring | Format-Table sequence, statusName, major, processId, name
#>
[CmdletBinding()]
param(
    [ValidateSet('counters', 'deny-ring', 'communication-health', 'audit-health', 'audit-integrity', 'audit-temporaries', 'audit-temporary-classification', 'audit-retention-preview', 'help')]
    [string] $Query = 'counters',

    # deny-ring: return records with a sequence greater than this value.
    [uint64] $After = 0,

    [string] $OccurredBeforeUtc,

    [ValidateRange(1, 300)]
    [int] $TimeoutSeconds = 10
)

$ErrorActionPreference = 'Stop'
$pipeName = 'SafeUpload.Agent.Diagnostics'
$diagnosticsClock = [Diagnostics.Stopwatch]::StartNew()

function Get-DiagnosticsRemainingMilliseconds {
    $remaining = [int][Math]::Ceiling($TimeoutSeconds * 1000 - $diagnosticsClock.Elapsed.TotalMilliseconds)
    if ($remaining -le 0) { throw 'SafeUpload diagnostics: query timed out.' }
    return $remaining
}

function Wait-DiagnosticsTask([Threading.Tasks.Task] $Task) {
    $remaining = Get-DiagnosticsRemainingMilliseconds
    try { $completed = $Task.Wait($remaining) }
    catch {
        if ($_.Exception.GetBaseException() -is [TimeoutException]) { throw 'SafeUpload diagnostics: query timed out.' }
        throw 'SafeUpload diagnostics: pipe operation failed.'
    }
    if (-not $completed) {
        throw 'SafeUpload diagnostics: query timed out.'
    }
    # Some runtimes expose the internal VoidTaskResult through PowerShell reflection. Never emit it.
    [void]$Task.GetAwaiter().GetResult()
}

function Invoke-DiagnosticsQuery([hashtable] $Request) {
    $client = [IO.Pipes.NamedPipeClientStream]::new('.', $pipeName,
        [IO.Pipes.PipeDirection]::InOut, [IO.Pipes.PipeOptions]::Asynchronous)
    $frame = [IO.MemoryStream]::new()
    try {
        Wait-DiagnosticsTask ($client.ConnectAsync((Get-DiagnosticsRemainingMilliseconds)))
        $utf8 = [Text.UTF8Encoding]::new($false, $true)
        $requestBytes = $utf8.GetBytes(($Request | ConvertTo-Json -Compress) + "`n")
        Wait-DiagnosticsTask ($client.WriteAsync($requestBytes, 0, $requestBytes.Length))
        Wait-DiagnosticsTask ($client.FlushAsync())
        $buffer = New-Object byte[] 4096
        $maxReplyBytes = 1024 * 1024
        $terminated = $false
        while (-not $terminated) {
            # At most one extra byte is read to distinguish an exact-boundary LF from an oversized frame.
            $count = [Math]::Min($buffer.Length, $maxReplyBytes - [int]$frame.Length + 1)
            $readTask = $client.ReadAsync($buffer, 0, $count)
            Wait-DiagnosticsTask $readTask
            $read = $readTask.GetAwaiter().GetResult()
            if ($read -eq 0) { throw 'SafeUpload diagnostics: incomplete reply.' }
            $length = [Array]::IndexOf($buffer, [byte]10, 0, $read)
            $terminated = $length -ge 0
            if (-not $terminated) { $length = $read }
            if ($frame.Length + $length -gt $maxReplyBytes) { throw 'SafeUpload diagnostics: reply exceeds 1 MiB.' }
            $frame.Write($buffer, 0, $length)
        }
        try {
            $line = $utf8.GetString($frame.GetBuffer(), 0, [int]$frame.Length)
            $reply = $line | ConvertFrom-Json -ErrorAction Stop
            if ($null -eq $reply -or $reply -is [Array] -or $reply.ok -isnot [bool] -or
                $reply.query -ne $Request.query -or
                ($reply.ok -and $reply.PSObject.Properties.Name -notcontains 'data') -or
                (-not $reply.ok -and $reply.error -isnot [string])) { throw 'Invalid envelope.' }
        } catch { throw 'SafeUpload diagnostics: invalid reply.' }
        Get-DiagnosticsRemainingMilliseconds | Out-Null
        if (-not $reply.ok) { throw "SafeUpload diagnostics: $($reply.error)" }
        return $reply.data
    }
    finally {
        $client.Dispose()
        $frame.Dispose()
    }
}

switch ($Query) {
    'audit-health' { Invoke-DiagnosticsQuery @{ query = $Query } }
    'audit-integrity' { Invoke-DiagnosticsQuery @{ query = $Query } }
    'audit-temporaries' { Invoke-DiagnosticsQuery @{ query = $Query } }
    'audit-temporary-classification' { Invoke-DiagnosticsQuery @{ query = $Query } }
    'audit-retention-preview' {
        if ([string]::IsNullOrWhiteSpace($OccurredBeforeUtc)) { throw 'Specify -OccurredBeforeUtc as an explicit ISO 8601 UTC timestamp.' }
        Invoke-DiagnosticsQuery @{ query = $Query; occurredBeforeUtc = $OccurredBeforeUtc }
    }
    'communication-health' { Invoke-DiagnosticsQuery @{ query = $Query } }
    'counters' { Invoke-DiagnosticsQuery @{ query = 'counters' } }
    'help' { Invoke-DiagnosticsQuery @{ query = 'help' } }
    'deny-ring' {
        $cursor = $After
        for (;;) {
            $page = Invoke-DiagnosticsQuery @{ query = 'deny-ring'; after = $cursor }
            if ($page.gap) { Write-Warning 'Older records were overwritten before they could be read.' }
            $records = @($page.records)
            if ($records.Count -eq 0) { break }
            $next = $cursor
            foreach ($record in $records) {
                if ($null -eq $record.sequence -or [uint64]$record.sequence -le $next) {
                    throw 'SafeUpload diagnostics: deny-ring cursor did not advance.'
                }
                $next = [uint64]$record.sequence
            }
            $records
            $cursor = $next
        }
    }
}
