<#
T4 save-cycle coordinator (SYSTEM). Drives cycles-actor.ps1 (a standard user) through N save cycles in one boot and checks every
outcome from outside the actor's private namespace:
  clean content  -> the public file holds exactly the new bytes (approved and published);
  CPF content    -> a new hand-back with exactly those bytes appears in the actor's profile, and the public file never holds them.
Every SampleEvery cycles (and at the start and the end) it records the driver's own pool use as Driver Verifier counts it, our pool
tags, total nonpaged pool, the driver's stage-lifetime counters, the stage files on disk and the journal size.
After the last cycle it waits for the stage worker to settle, stops the actor, and samples twice more 60 s apart (idle check).
-BlockHeavy blocks three cycles in four instead of one. -HandbackDiagnostic (owner-authorized, non-qualifying, 2026-10-13) runs
after the purged sample: it records which processes hold the kept files open, deletes only the hand-backs, and samples again
before and after a second purge, to tell whether retained contexts follow those files' Windows lifetime or a driver reference.
Results: C:\T4\cycles.jsonl (one line per cycle), C:\T4\samples.jsonl, C:\T4\result.json.
#>
param(
    [int]$Cycles = 10000,
    [int]$SampleEvery = 500,
    [string]$ActorUser = 't4actor',
    [string]$ActorTask = 't4-actor',
    [string]$Diagnostics = 'C:\Users\vika\Documents\Get-SafeUploadDiagnostics.ps1',
    [switch]$RequireVerifierPool,
    [switch]$MemoryDiagnostic,
    [switch]$BlockHeavy,
    [switch]$HandbackDiagnostic
)
$ErrorActionPreference = 'Stop'
function Read-T4ControlText([string]$Path) {
    $deadline = [Diagnostics.Stopwatch]::GetTimestamp() + 5 * [Diagnostics.Stopwatch]::Frequency
    for (;;) {
        try {
            $stream = [IO.FileStream]::new($Path, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]'ReadWrite, Delete')
            try { $reader = [IO.StreamReader]::new($stream); try { return $reader.ReadToEnd() } finally { $reader.Dispose() } }
            finally { $stream.Dispose() }
        } catch [IO.IOException] {
            $ioFailure = $_.Exception
            while ($ioFailure.InnerException) { $ioFailure = $ioFailure.InnerException }
            if (($ioFailure.HResult -band 0xffff) -notin @(32,33) -or [Diagnostics.Stopwatch]::GetTimestamp() -ge $deadline) { throw }
            Start-Sleep -Milliseconds 2
        }
    }
}
function Write-T4ResultLine([string]$Path, [string]$Line) {
    # One coordinator owns each append log. PowerShell 5.1 Add-Content opens
    # with sharing that refuses an already-open reader, even a share-all one.
    # Write exactly once through an explicitly shared stream; no I/O retry can
    # duplicate an outcome record or hide a diagnostic write failure.
    $bytes = [Text.UTF8Encoding]::new($false).GetBytes($Line + "`r`n")
    $stream = [IO.FileStream]::new($Path, [IO.FileMode]::Append, [IO.FileAccess]::Write, [IO.FileShare]'ReadWrite, Delete')
    try { $stream.Write($bytes, 0, $bytes.Length); $stream.Flush() } finally { $stream.Dispose() }
}
. (Join-Path $PSScriptRoot 'failure-evidence.ps1')
if ($MemoryDiagnostic) { . (Join-Path $PSScriptRoot 't4-memory-debugger.ps1') }
$out = 'C:\T4'; $control = Join-Path $out 'control'; $root = 'C:\Protected\t4'
$handback = $null   # the actor's profile, resolved from its SID once the actor has logged on
$stageDir = 'C:\ProgramData\SafeUpload\staging'; $journalDir = 'C:\ProgramData\SafeUpload\staging-journal'
Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
public static class T4Pool {
    [DllImport("ntdll.dll")]
    static extern int NtQuerySystemInformation(int infoClass, IntPtr buffer, int length, out int returned);
    // SYSTEM_POOLTAG (x64): Tag, PagedAllocs, PagedFrees, pad, PagedUsed, NonPagedAllocs, NonPagedFrees, NonPagedUsed = 40 bytes.
    public static long[] Tag(string tag) {
        int length = 1 << 20;
        for (;;) {
            IntPtr buffer = Marshal.AllocHGlobal(length);
            try {
                int returned;
                int status = NtQuerySystemInformation(22, buffer, length, out returned);
                if (status == unchecked((int)0xC0000004)) { length *= 2; continue; }
                if (status != 0) throw new InvalidOperationException("NtQuerySystemInformation 0x" + status.ToString("X8"));
                int count = Marshal.ReadInt32(buffer);
                byte[] want = System.Text.Encoding.ASCII.GetBytes(tag);
                for (int i = 0; i < count; ++i) {
                    IntPtr entry = buffer + 8 + i * 40;
                    bool match = true;
                    for (int b = 0; b < 4; ++b) if (Marshal.ReadByte(entry, b) != want[b]) { match = false; break; }
                    if (!match) continue;
                    return new long[] { Marshal.ReadInt32(entry, 24), Marshal.ReadInt32(entry, 28), Marshal.ReadInt64(entry, 32),
                        Marshal.ReadInt32(entry, 4), Marshal.ReadInt32(entry, 8), Marshal.ReadInt64(entry, 16) };
                }
                return new long[] { 0, 0, 0, 0, 0, 0 };
            } finally { Marshal.FreeHGlobal(buffer); }
        }
    }
}
'@

function ConvertFrom-T4VerifierPool([string]$Text) {
    $sections = [regex]::Matches($Text, '(?ims)^\s*MODULE:\s*SafeUpload\.sys\b.*?(?=^\s*MODULE:|\z)')
    if ($sections.Count -gt 1) { throw 'Ambiguous SafeUpload Verifier module statistics.' }
    $section = if ($sections.Count -eq 1) { $sections[0].Value } else { '' }
    $value = { param($label) $m = [regex]::Match($section, '(?im)^\s*' + $label + '\s*:\s*(\d+)'); if ($m.Success) { [int64]$m.Groups[1].Value } else { $null } }
    # Actual Windows 19045 verifier.exe /query uses ordered (NonPaged / Paged)
    # pairs, not the old separate-label format. Never take another module's
    # bytes or the global summary as this driver's own pool.
    $pairs = @{}
    foreach ($label in 'Current Pool Bytes', 'Current Pool Allocations', 'Peak Pool Bytes') {
        $match = [regex]::Match($section, '(?im)^\s*' + $label + '\s*:\s*\(\s*(\d+)\s*/\s*(\d+)\s*\)\s*$')
        if ($match.Success) { $pairs[$label] = @([int64]$match.Groups[1].Value, [int64]$match.Groups[2].Value) }
    }
    $pool = [ordered]@{
        Verified = $section.Length -gt 0
        Flags = [regex]::Match($Text, '(?im)^\s*Verifier Flags:\s*(0x[0-9a-f]+)').Groups[1].Value
        PoolFormat = $(if ($pairs.Count) { 'NonPaged/Paged pairs' } else { 'Separate labels' })
        NonPagedBytes = $(if ($pairs.ContainsKey('Current Pool Bytes')) { $pairs['Current Pool Bytes'][0] } else { & $value 'Current Non-?Paged Pool Usage \(bytes\)' })
        NonPagedAllocations = $(if ($pairs.ContainsKey('Current Pool Allocations')) { $pairs['Current Pool Allocations'][0] } else { & $value 'Current Non-?Paged Pool Allocations' })
        PagedBytes = $(if ($pairs.ContainsKey('Current Pool Bytes')) { $pairs['Current Pool Bytes'][1] } else { & $value 'Current Paged Pool Usage \(bytes\)' })
        PeakNonPagedBytes = $(if ($pairs.ContainsKey('Peak Pool Bytes')) { $pairs['Peak Pool Bytes'][0] } else { & $value 'Peak Non-?Paged Pool Usage \(bytes\)' })
        AllocationFailures = & $value 'Pool Allocation Failures'
    }
    if ($pool.Verified -and @('NonPagedBytes', 'NonPagedAllocations', 'PagedBytes', 'PeakNonPagedBytes' | Where-Object { $null -eq $pool[$_] }).Count) {
        throw 'Incomplete SafeUpload Verifier pool statistics.'
    }
    return $pool
}

function Get-Sample([int]$Cycle, [string]$Label) {
    $sample = [ordered]@{ Cycle = $Cycle; Label = $Label; Utc = [DateTime]::UtcNow.ToString('o'); Qpc = [Diagnostics.Stopwatch]::GetTimestamp() }
    try {
        $raw = Join-Path $out ('verifier-' + $Cycle + '-' + $Label + '.txt')
        $text = (& verifier.exe /query 2>&1 | Out-String)
        [IO.File]::WriteAllText($raw, $text, [Text.UTF8Encoding]::new($false))
        $sample.VerifierOutputFile = $raw
        $sample.Verifier = ConvertFrom-T4VerifierPool $text
    } catch { $sample.VerifierError = $_.Exception.Message }
    try {
        # Include the writer registry and writer-node tags, so growth outside
        # the reclaimed stage versions can be attributed from the same sample.
        foreach ($tag in 'SpUs', 'SUfl', 'SwUr', 'SUwH') { $t = [T4Pool]::Tag($tag); $sample['Tag' + $tag] = [ordered]@{ NonPagedAllocs = $t[0]; NonPagedFrees = $t[1]; NonPagedUsed = $t[2]; PagedAllocs = $t[3]; PagedFrees = $t[4]; PagedUsed = $t[5] } }
    } catch { $sample.TagError = $_.Exception.Message }
    try { $sample.PoolNonpagedBytes = [int64](Get-CimInstance Win32_PerfRawData_PerfOS_Memory).PoolNonpagedBytes } catch { $sample.PoolError = $_.Exception.Message }
    try { $c = & $Diagnostics -Query counters; $sample.StageWorker = $c.stageWorker; $sample.ReclaimPasses = $c.reclaimWorker.passes; $sample.RegistryReclaim = $c.reclaimWorker; $sample.WriterState = $c.writerState } catch { $sample.CountersError = $_.Exception.Message }
    $sample.StageFiles = @(Get-ChildItem -LiteralPath $stageDir -File -Force -ErrorAction SilentlyContinue).Count
    $sample.JournalFiles = @(Get-ChildItem -LiteralPath $journalDir -Filter *.json -File -Force -ErrorAction SilentlyContinue).Count
    $sample.Handbacks = @(Get-ChildItem -LiteralPath $handback -File -Force -ErrorAction SilentlyContinue).Count
    Write-T4ResultLine (Join-Path $out 'samples.jsonl') ($sample | ConvertTo-Json -Depth 6 -Compress)
    if ($MemoryDiagnostic -and $Label -in @('start','cycle','idle')) {
        $null = Save-T4MemorySnapshot ('cycles-' + $Cycle + '-' + $Label)
    }
    $sample
}

function Invoke-T4MemoryPurge {
    # The coordinator runs as SYSTEM. Record all native statuses, including
    # failures, so a refused purge cannot prevent the final sample/report.
    # The hand-back diagnostic purges a second time; compile the declarations once.
    if (-not ('T4MemoryPurge' -as [type])) { Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
public static class T4MemoryPurge {
    [DllImport("ntdll.dll", ExactSpelling = true)]
    public static extern int RtlAdjustPrivilege(uint privilege,
        [MarshalAs(UnmanagedType.U1)] bool enable,
        [MarshalAs(UnmanagedType.U1)] bool currentThread,
        [MarshalAs(UnmanagedType.U1)] out bool previouslyEnabled);
    [DllImport("ntdll.dll", ExactSpelling = true)]
    public static extern int NtSetSystemInformation(int infoClass, ref int command, int length);
}
'@ }
    foreach ($privilege in 13, 5) {
        $previous = $false
        $status = [T4MemoryPurge]::RtlAdjustPrivilege($privilege, $true, $false, [ref]$previous)
        [pscustomobject]@{ Operation = 'RtlAdjustPrivilege'; Privilege = $privilege; NTSTATUS = $status;
            StatusHex = '0x' + $status.ToString('X8'); Succeeded = $status -ge 0 }
    }
    # SYSTEM_MEMORY_LIST_COMMAND: empty working sets, flush modified list,
    # purge standby list. This opens no handles and makes no driver calls.
    foreach ($command in 2, 3, 4) {
        $value = [int]$command
        $status = [T4MemoryPurge]::NtSetSystemInformation(80, [ref]$value, 4)
        [pscustomobject]@{ Operation = 'NtSetSystemInformation'; Command = $command; NTSTATUS = $status;
            StatusHex = '0x' + $status.ToString('X8'); Succeeded = $status -ge 0 }
    }
}

function Get-T4FileHolders([string]$Category, [string[]]$Paths) {
    # Restart Manager reports the processes that hold any of these files open (handles or mapped images); it opens no
    # handle to the files and makes no driver call. Kernel-only references are invisible to it by design.
    if (-not ('T4Holders' -as [type])) {
        Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
public static class T4Holders {
    [StructLayout(LayoutKind.Sequential)]
    public struct RM_UNIQUE_PROCESS { public int dwProcessId; public System.Runtime.InteropServices.ComTypes.FILETIME ProcessStartTime; }
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    public struct RM_PROCESS_INFO {
        public RM_UNIQUE_PROCESS Process;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 256)] public string strAppName;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 64)] public string strServiceShortName;
        public int ApplicationType; public uint AppStatus; public uint TSSessionId;
        [MarshalAs(UnmanagedType.Bool)] public bool bRestartable;
    }
    [DllImport("rstrtmgr.dll", CharSet = CharSet.Unicode)]
    public static extern int RmStartSession(out uint handle, int flags, System.Text.StringBuilder key);
    [DllImport("rstrtmgr.dll")]
    public static extern int RmEndSession(uint handle);
    [DllImport("rstrtmgr.dll", CharSet = CharSet.Unicode)]
    public static extern int RmRegisterResources(uint handle, uint fileCount, string[] files, uint appCount, IntPtr apps, uint serviceCount, IntPtr services);
    [DllImport("rstrtmgr.dll")]
    public static extern int RmGetList(uint handle, out uint needed, ref uint count, [In, Out] RM_PROCESS_INFO[] info, out uint rebootReasons);
}
'@
    }
    $row = [ordered]@{ Category = $Category; Files = $Paths.Count; Holders = @(); Error = $null }
    if (-not $Paths.Count) { return [pscustomobject]$row }
    $handle = [uint32]0; $key = New-Object Text.StringBuilder 64
    $status = [T4Holders]::RmStartSession([ref]$handle, 0, $key)
    if ($status -ne 0) { $row.Error = 'RmStartSession ' + $status; return [pscustomobject]$row }
    try {
        for ($offset = 0; $offset -lt $Paths.Count; $offset += 500) {
            $batch = [string[]]($Paths[$offset..([math]::Min($offset + 499, $Paths.Count - 1))])
            $status = [T4Holders]::RmRegisterResources($handle, [uint32]$batch.Count, $batch, 0, [IntPtr]::Zero, 0, [IntPtr]::Zero)
            if ($status -ne 0) { $row.Error = 'RmRegisterResources ' + $status; return [pscustomobject]$row }
        }
        $needed = [uint32]0; $count = [uint32]0; $reasons = [uint32]0
        $status = [T4Holders]::RmGetList($handle, [ref]$needed, [ref]$count, $null, [ref]$reasons)
        if ($status -eq 234) {   # ERROR_MORE_DATA: size the array, then read
            $count = $needed; $info = New-Object 'T4Holders+RM_PROCESS_INFO[]' $count
            $status = [T4Holders]::RmGetList($handle, [ref]$needed, [ref]$count, $info, [ref]$reasons)
            if ($status -eq 0) {
                $row.Holders = @(for ($j = 0; $j -lt $count; ++$j) {
                    [pscustomobject]@{ Pid = $info[$j].Process.dwProcessId; App = $info[$j].strAppName; Service = $info[$j].strServiceShortName; Type = $info[$j].ApplicationType }
                })
            }
        }
        if ($status -ne 0) { $row.Error = 'RmGetList ' + $status }
    } finally { [void][T4Holders]::RmEndSession($handle) }
    [pscustomobject]$row
}

function Invoke-T4HandbackDiagnostic {
    $diagnostic = [ordered]@{}
    $sets = [ordered]@{
        Handbacks = @(Get-ChildItem -LiteralPath $handback -File -Force -ErrorAction SilentlyContinue | ForEach-Object { $_.FullName })
        Journals = @(Get-ChildItem -LiteralPath $journalDir -File -Force -ErrorAction SilentlyContinue | ForEach-Object { $_.FullName })
        Public = @(Get-ChildItem -LiteralPath $root -File -Force -ErrorAction SilentlyContinue | ForEach-Object { $_.FullName })
    }
    $diagnostic.Holders = @(foreach ($category in $sets.Keys) {
        try { Get-T4FileHolders $category $sets[$category] } catch { [pscustomobject]@{ Category = $category; Files = $sets[$category].Count; Holders = @(); Error = $_.Exception.Message } }
    })
    $deleted = 0; $failed = 0; $errors = @()
    foreach ($path in $sets.Handbacks) {
        try { [IO.File]::Delete($path); ++$deleted }
        catch { ++$failed; if ($errors.Count -lt 5) { $errors += ($path + ': ' + $_.Exception.Message) } }
    }
    $diagnostic.HandbacksDeleted = $deleted; $diagnostic.HandbackDeleteFailures = $failed; $diagnostic.HandbackDeleteErrors = $errors
    $diagnostic.HandbacksLeft = @(Get-ChildItem -LiteralPath $handback -File -Force -ErrorAction SilentlyContinue).Count
    Start-Sleep -Seconds 30
    $diagnostic.AfterDelete = Get-Sample $Cycles 'handbacks-deleted'
    $diagnostic.Purge = @(Invoke-T4MemoryPurge)
    Start-Sleep -Seconds 30
    $diagnostic.AfterDeletePurged = Get-Sample $Cycles 'handbacks-deleted-purged'
    $diagnostic
}

function Read-Public([string]$Path) {
    try {
        $stream = New-Object IO.FileStream($Path, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]'ReadWrite, Delete')
        try { $buffer = New-Object byte[] $stream.Length; $read = 0; while ($read -lt $buffer.Length) { $n = $stream.Read($buffer, $read, $buffer.Length - $read); if ($n -le 0) { break }; $read += $n }; , $buffer } finally { $stream.Dispose() }
    } catch [IO.FileNotFoundException] { $null } catch [IO.IOException] { , @() }
}

function Same([byte[]]$A, [byte[]]$B) { if ($null -eq $A -or $null -eq $B -or $A.Length -ne $B.Length) { return $false }; for ($i = 0; $i -lt $A.Length; ++$i) { if ($A[$i] -ne $B[$i]) { return $false } }; $true }

New-Item -ItemType Directory -Force -Path $out, $control | Out-Null
Remove-Item -LiteralPath (Join-Path $out 'cycles.jsonl'), (Join-Path $out 'samples.jsonl'), (Join-Path $out 'result.json') -ErrorAction SilentlyContinue
$result = [ordered]@{ Cycles = $Cycles; Started = [DateTime]::UtcNow.ToString('o'); Completed = 0; Attempted = 0;
    Failures = @(); FailureCount = 0; FailureEvidence = @(); BlockedBytesPublished = $false;
    StopReason = 'coordinator-error'; Outcomes = [ordered]@{} }
$failureCounts = @{}
$actorLaunched = $false
$frequency = [Diagnostics.Stopwatch]::Frequency
try {
    Start-ScheduledTask -TaskName $ActorTask
    $actorLaunched = $true
    $deadline = [Diagnostics.Stopwatch]::GetTimestamp() + 120 * $frequency
    while (-not (Test-Path (Join-Path $control 'actor-started.txt'))) {
        if ([Diagnostics.Stopwatch]::GetTimestamp() -gt $deadline) {
            $info = Get-ScheduledTaskInfo -TaskName $ActorTask -ErrorAction SilentlyContinue
            throw ('the actor did not start: task result 0x' + ([uint32]$info.LastTaskResult).ToString('X8') + ', last run ' + $info.LastRunTime)
        }
        Start-Sleep -Milliseconds 200
    }
    $result.Actor = (Get-Content -LiteralPath (Join-Path $control 'actor-started.txt') -Raw).Trim()
    $sid = (New-Object Security.Principal.NTAccount($env:COMPUTERNAME, $ActorUser)).Translate([Security.Principal.SecurityIdentifier]).Value
    $profile = (Get-CimInstance Win32_UserProfile | Where-Object { $_.SID -eq $sid }).LocalPath
    if (-not $profile) { throw "no profile for $ActorUser ($sid)" }
    $handback = Join-Path $profile 'SafeUpload\_bloqueados'
    $result.Handback = $handback
    $startSample = Get-Sample 0 'start'
    if ($RequireVerifierPool -and (-not $startSample.Verifier.Verified -or
        $startSample.Verifier.Flags -notmatch '^0x0*13b$' -or $null -eq $startSample.Verifier.NonPagedBytes)) {
        throw 'Runtime Verifier pool evidence unavailable at the start; no cycles executed.'
    }
    $patterns = 'resave', 'new', 'replace', 'mapped'
    for ($i = 1; $i -le $Cycles; ++$i) {
        $pattern = $patterns[($i - 1) % 4]
        $sensitive = ([math]::Floor(($i - 1) / 4) % 4) -eq 3          # one cycle in four, rotating through the patterns
        if ($BlockHeavy) { $sensitive = ([math]::Floor(($i - 1) / 4) % 4) -ne 0 }   # three in four, same rotation
        $name = switch ($pattern) { 'resave' { 'same-' + ($i % 8) + '.txt' } 'new' { 'new-' + $i + '.txt' } 'replace' { 'rep-' + ($i % 8) + '.txt' } 'mapped' { 'map-' + ($i % 8) + '.txt' } }
        # A hexadecimal GUID can contain an eleven-digit valid CPF (diag2,
        # cycle 10). Encode its digits as letters so APPROVE fixtures cannot
        # accidentally satisfy the product's CPF detector. The cycle number
        # has at most five digits in the required 10,000-cycle corpus.
        $cleanNonce = [guid]::NewGuid().ToString('N')
        for ($digit = 0; $digit -lt 10; ++$digit) { $cleanNonce = $cleanNonce.Replace([string]$digit, [string][char](103 + $digit)) }
        $text = if ($sensitive) { "T4 cycle $i CPF: 529.982.247-25`r`n" } else { "T4 cycle $i clean " + $cleanNonce + "`r`n" }
        $bytes = [Text.Encoding]::ASCII.GetBytes($text)
        $payload = Join-Path $control ('payload-' + $i + '.bin'); [IO.File]::WriteAllBytes($payload, $bytes)
        $target = Join-Path $root $name
        # Hand-back publishes a GUID.txt atomically after writing .safeupload-*.tmp. Only completed copies count.
        $before = @(Get-ChildItem -LiteralPath $handback -Filter '*.txt' -File -Force -ErrorAction SilentlyContinue).Count
        $started = [Diagnostics.Stopwatch]::GetTimestamp()
        $command = Join-Path $control ('cmd-' + $i + '.txt')
        $staging = Join-Path $control ('next-' + $i + '.part')   # the actor only picks up cmd-*.txt
        Set-Content -LiteralPath $staging -Value ("$i $pattern $name $payload"); [IO.File]::Move($staging, $command)
        $ack = Join-Path $control ('ack-' + $i + '.txt')
        $deadline = $started + 60 * $frequency
        while (-not (Test-Path $ack)) { if ([Diagnostics.Stopwatch]::GetTimestamp() -gt $deadline) { break }; Start-Sleep -Milliseconds 2 }
        $acked = [Diagnostics.Stopwatch]::GetTimestamp()
        $ackText = if (Test-Path $ack) { (Read-T4ControlText $ack).Trim() } else { 'timeout' }
        $ok = $false; $why = $null
        if ($ackText -ne 'ok') { $why = 'actor: ' + $ackText }
        else {
            $deadline = $acked + 120 * $frequency
            do {
                if ($sensitive) {
                    $files = @(Get-ChildItem -LiteralPath $handback -Filter '*.txt' -File -Force -ErrorAction SilentlyContinue | Sort-Object LastWriteTimeUtc)
                    if ($files.Count -gt $before -and (Same (Read-Public $files[-1].FullName) $bytes)) { $ok = $true }
                } else { if (Same (Read-Public $target) $bytes) { $ok = $true } }
                if (-not $ok) { Start-Sleep -Milliseconds 20 }
            } while (-not $ok -and [Diagnostics.Stopwatch]::GetTimestamp() -lt $deadline)
            if (-not $ok) { $why = if ($sensitive) { 'no hand-back of the blocked bytes' } else { 'the public file never held the approved bytes' } }
            # A blocked version never reaches the public name.
            if ($sensitive -and (Same (Read-Public $target) $bytes)) { $ok = $false; $why = 'BLOCKED BYTES PUBLISHED' }
        }
        $done = [Diagnostics.Stopwatch]::GetTimestamp()
        if ($ackText -ne 'timeout') { Remove-Item -LiteralPath $payload, $ack -Force -ErrorAction SilentlyContinue }
        $key = $pattern + '-' + $(if ($sensitive) { 'block' } else { 'approve' })
        if (-not $result.Outcomes.Contains($key)) { $result.Outcomes[$key] = [ordered]@{ Ok = 0; Failed = 0 } }
        $result.Attempted = $i
        if ($ok) { $result.Completed++; $result.Outcomes[$key].Ok++ } else { $result.FailureCount++; $result.Outcomes[$key].Failed++; if ($result.Failures.Count -lt 50) { $result.Failures += ("$i $key $why") } }
        $outcome = [pscustomobject]@{ I = $i; Pattern = $pattern; Sensitive = $sensitive; Target = $target; Ok = $ok; Why = $why; AckMs = [math]::Round(($acked - $started) * 1000.0 / $frequency, 1); OutcomeMs = [math]::Round(($done - $acked) * 1000.0 / $frequency, 1) }
        Write-T4ResultLine (Join-Path $out 'cycles.jsonl') ($outcome | ConvertTo-Json -Compress)
        $decision = Get-T4FailureDecision $failureCounts $outcome
        if (-not $ok) {
            if ($why -ceq 'BLOCKED BYTES PUBLISHED') { $result.BlockedBytesPublished = $true }
            try { $result.FailureEvidence += Save-T4FailureEvidence (Join-Path $out 'failure-evidence') $journalDir $stageDir $i $target }
            catch { $result.FailureEvidence += [pscustomobject]@{ Cycle = $i; CaptureError = $_.Exception.ToString() } }
        }
        if ($i % $SampleEvery -eq 0) { $null = Get-Sample $i 'cycle' }
        if ($decision) {
            $result.StopReason = $decision.Reason
            $result.StopFailure = $decision
            throw ('T4 stopped at cycle ' + $i + ': ' + $decision.Reason + '; ' + $why)
        }
    }
    $result.StopReason = if ($result.FailureCount) { 'completed-with-failures' } else { 'completed' }
    # Settle: hand-backs, cleanups and disposals finish; the stage worker releases what nothing holds.
    Start-Sleep -Seconds 30
    $result.Settled = Get-Sample $Cycles 'settled'
    $result.ActorStopped = Stop-T4Actor $control
    Start-Sleep -Seconds 15
    $result.AfterActorExit = Get-Sample $Cycles 'actor-exited'
    Start-Sleep -Seconds 60
    $result.Idle = Get-Sample $Cycles 'idle'
    $result.Purge = @(Invoke-T4MemoryPurge)
    Start-Sleep -Seconds 30   # NTFS delayed close after cache pressure
    $result.Purged = Get-Sample $Cycles 'purged'
    if ($HandbackDiagnostic) { $result.HandbackDiagnostic = Invoke-T4HandbackDiagnostic }
} catch {
    $result.Error = $_.Exception.Message
    $result.ErrorDetail = $_.Exception.ToString()
    $result.ErrorScriptStackTrace = $_.ScriptStackTrace
} finally {
    if ($actorLaunched -and -not $result.ActorStopped) {
        try { $result.ActorStopped = Stop-T4Actor $control }
        catch { $result.ActorStopError = $_.Exception.ToString() }
    }
    $result.Finished = [DateTime]::UtcNow.ToString('o')
    $resultPart = Join-Path $out 'result.part'
    [IO.File]::WriteAllText($resultPart, ($result | ConvertTo-Json -Depth 8), [Text.UTF8Encoding]::new($false))
    [IO.File]::Move($resultPart, (Join-Path $out 'result.json'))
}
