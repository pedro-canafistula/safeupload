#Requires -RunAsAdministrator
#Requires -Version 5.1
<#
.SYNOPSIS
Reads audit/driver diagnostics from the running SafeUpload service (administrator only, read-only).

.DESCRIPTION
The minifilter's communication port accepts a single client and the service holds it, so no other tool can read the
driver while the product runs. The service relays read-only queries over the SYSTEM/Administrators-only pipe
\\.\pipe\SafeUpload.Agent.Diagnostics:

  audit-health  queue failure/recovery counters since service start (also without a driver).
                No event contents, paths or exception messages. Successful retries do not restore lost events.
  audit-integrity  read-only scan of the current queue, including invalid lines and unknown record types.
                  Returns counts and at most 20 line numbers/reason codes, never record contents.
                  queueBytes samples file length before scanning. Pending/dispatched counts are valid lines,
                  including duplicates, not unique IDs; oldestPendingUtc excludes missing timestamps reported
                  in pendingWithoutTimestamp. Unknown/invalid lines are counted separately, never assumed sent.
                  Shares the queue lock; a large scan can delay writes or exceed the service's five-second deadline.
                  External writers are not locked. No automatic scan, retention or deletion is performed.
  audit-temporaries  metadata-only inventory of queue-name.GUID.tmp candidates, without content or filenames.
                     Reports bytes, unreadable candidates, skipped links and completeness; maximum 10000 entries.
                     Does not prove abandonment, delete files or recover incomplete confirmations.

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
    [ValidateSet('counters', 'deny-ring', 'audit-health', 'audit-integrity', 'audit-temporaries', 'help')]
    [string] $Query = 'counters',

    # deny-ring: return records with a sequence greater than this value.
    [uint64] $After = 0,

    [int] $TimeoutSeconds = 10
)

$ErrorActionPreference = 'Stop'
$pipeName = 'SafeUpload.Agent.Diagnostics'

function Invoke-DiagnosticsQuery([hashtable] $Request) {
    $client = New-Object System.IO.Pipes.NamedPipeClientStream('.', $pipeName, [System.IO.Pipes.PipeDirection]::InOut)
    try {
        $client.Connect($TimeoutSeconds * 1000)
        $utf8 = New-Object System.Text.UTF8Encoding($false)
        $writer = New-Object System.IO.StreamWriter($client, $utf8, 1024, $true)
        $writer.NewLine = "`n"
        $writer.WriteLine(($Request | ConvertTo-Json -Compress))
        $writer.Flush()
        $reader = New-Object System.IO.StreamReader($client, $utf8, $false, 1024, $true)
        $line = $reader.ReadLine()
        if ([string]::IsNullOrEmpty($line)) { throw 'The service closed the pipe without a reply.' }
        $reply = $line | ConvertFrom-Json
        if (-not $reply.ok) { throw "SafeUpload diagnostics: $($reply.error)" }
        return $reply.data
    }
    finally {
        $client.Dispose()
    }
}

switch ($Query) {
    'counters' { Invoke-DiagnosticsQuery @{ query = 'counters' } }
    'help' { Invoke-DiagnosticsQuery @{ query = 'help' } }
    'audit-health' { Invoke-DiagnosticsQuery @{ query = 'audit-health' } }
    'audit-integrity' { Invoke-DiagnosticsQuery @{ query = 'audit-integrity' } }
    'audit-temporaries' { Invoke-DiagnosticsQuery @{ query = 'audit-temporaries' } }
    'deny-ring' {
        $cursor = $After
        for (;;) {
            $page = Invoke-DiagnosticsQuery @{ query = 'deny-ring'; after = $cursor }
            if ($page.gap) { Write-Warning 'Older records were overwritten before they could be read.' }
            $records = @($page.records)
            if ($records.Count -eq 0) { break }
            $records
            $cursor = [uint64]$records[$records.Count - 1].sequence
        }
    }
}
