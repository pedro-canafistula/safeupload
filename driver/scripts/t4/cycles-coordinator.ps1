<#
T4 save-cycle coordinator (SYSTEM). Drives cycles-actor.ps1 (a standard user) through N save cycles in one boot and checks every
outcome from outside the actor's private namespace:
  clean content  -> the public file holds exactly the new bytes (approved and published);
  CPF content    -> a new hand-back with exactly those bytes appears in the actor's profile, and the public file never holds them.
Every SampleEvery cycles (and at the start and the end) it records the driver's own pool use as Driver Verifier counts it, our pool
tags, total nonpaged pool, the driver's stage-lifetime counters, the stage files on disk and the journal size.
After the last cycle it waits for the stage worker to settle, stops the actor, and samples twice more 60 s apart (idle check).
Results: C:\T4\cycles.jsonl (one line per cycle), C:\T4\samples.jsonl, C:\T4\result.json.
#>
param(
    [int]$Cycles = 10000,
    [int]$SampleEvery = 500,
    [string]$ActorUser = 't4actor',
    [string]$ActorTask = 't4-actor',
    [string]$Diagnostics = 'C:\Users\vika\Documents\Get-SafeUploadDiagnostics.ps1'
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

function Get-VerifierPool {
    $text = (& verifier.exe /query 2>&1 | Out-String)
    $section = [regex]::Match($text, '(?is)MODULE:\s*SafeUpload\.sys.*?(?=MODULE:|\z)').Value
    $value = { param($label) $m = [regex]::Match($section, '(?im)^\s*' + $label + '\s*:\s*(\d+)'); if ($m.Success) { [int64]$m.Groups[1].Value } else { $null } }
    [ordered]@{
        Verified = $section.Length -gt 0
        Flags = [regex]::Match($text, '(?im)^\s*Verifier Flags:\s*(0x[0-9a-f]+)').Groups[1].Value
        NonPagedBytes = & $value 'Current Non-?Paged Pool Usage \(bytes\)'
        NonPagedAllocations = & $value 'Current Non-?Paged Pool Allocations'
        PagedBytes = & $value 'Current Paged Pool Usage \(bytes\)'
        PeakNonPagedBytes = & $value 'Peak Non-?Paged Pool Usage \(bytes\)'
        AllocationFailures = & $value 'Pool Allocation Failures'
    }
}

function Get-Sample([int]$Cycle, [string]$Label) {
    $sample = [ordered]@{ Cycle = $Cycle; Label = $Label; Utc = [DateTime]::UtcNow.ToString('o'); Qpc = [Diagnostics.Stopwatch]::GetTimestamp() }
    try { $sample.Verifier = Get-VerifierPool } catch { $sample.VerifierError = $_.Exception.Message }
    try {
        foreach ($tag in 'SpUs', 'SUfl') { $t = [T4Pool]::Tag($tag); $sample['Tag' + $tag] = [ordered]@{ NonPagedAllocs = $t[0]; NonPagedFrees = $t[1]; NonPagedUsed = $t[2]; PagedAllocs = $t[3]; PagedFrees = $t[4]; PagedUsed = $t[5] } }
    } catch { $sample.TagError = $_.Exception.Message }
    try { $sample.PoolNonpagedBytes = [int64](Get-CimInstance Win32_PerfRawData_PerfOS_Memory).PoolNonpagedBytes } catch { $sample.PoolError = $_.Exception.Message }
    try { $c = & $Diagnostics -Query counters; $sample.StageWorker = $c.stageWorker; $sample.ReclaimPasses = $c.reclaimWorker.passes } catch { $sample.CountersError = $_.Exception.Message }
    $sample.StageFiles = @(Get-ChildItem -LiteralPath $stageDir -File -Force -ErrorAction SilentlyContinue).Count
    $sample.JournalFiles = @(Get-ChildItem -LiteralPath $journalDir -Filter *.json -File -Force -ErrorAction SilentlyContinue).Count
    $sample.Handbacks = @(Get-ChildItem -LiteralPath $handback -File -Force -ErrorAction SilentlyContinue).Count
    ($sample | ConvertTo-Json -Depth 6 -Compress) | Add-Content -LiteralPath (Join-Path $out 'samples.jsonl')
    $sample
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
$result = [ordered]@{ Cycles = $Cycles; Started = [DateTime]::UtcNow.ToString('o'); Completed = 0; Failures = @(); Outcomes = [ordered]@{} }
$frequency = [Diagnostics.Stopwatch]::Frequency
try {
    Start-ScheduledTask -TaskName $ActorTask
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
    $null = Get-Sample 0 'start'
    $patterns = 'resave', 'new', 'replace', 'mapped'
    for ($i = 1; $i -le $Cycles; ++$i) {
        $pattern = $patterns[($i - 1) % 4]
        $sensitive = ([math]::Floor(($i - 1) / 4) % 4) -eq 3          # one cycle in four, rotating through the patterns
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
        Remove-Item -LiteralPath $payload, $ack -Force -ErrorAction SilentlyContinue
        $key = $pattern + '-' + $(if ($sensitive) { 'block' } else { 'approve' })
        if (-not $result.Outcomes.Contains($key)) { $result.Outcomes[$key] = [ordered]@{ Ok = 0; Failed = 0 } }
        if ($ok) { $result.Completed++; $result.Outcomes[$key].Ok++ } else { $result.Outcomes[$key].Failed++; if ($result.Failures.Count -lt 50) { $result.Failures += ("$i $key $why") } }
        ([ordered]@{ I = $i; Pattern = $pattern; Sensitive = $sensitive; Ok = $ok; Why = $why; AckMs = [math]::Round(($acked - $started) * 1000.0 / $frequency, 1); OutcomeMs = [math]::Round(($done - $acked) * 1000.0 / $frequency, 1) } | ConvertTo-Json -Compress) | Add-Content -LiteralPath (Join-Path $out 'cycles.jsonl')
        if ($i % $SampleEvery -eq 0) { $null = Get-Sample $i 'cycle' }
        if (-not $ok -and $why -eq 'BLOCKED BYTES PUBLISHED') { break }
        # Once a command times out, its actor may still be using the payload.
        # Do not enqueue another command or treat later replies as evidence.
        if ($ackText -eq 'timeout') { throw ('actor command '+$i+' timed out; task state '+(Get-ScheduledTask -TaskName $ActorTask).State) }
    }
    # Settle: hand-backs, cleanups and disposals finish; the stage worker releases what nothing holds.
    Start-Sleep -Seconds 30
    $result.Settled = Get-Sample $Cycles 'settled'
    Set-Content -LiteralPath (Join-Path $control 'cmd-stop.txt') -Value 'stop'
    $deadline = [Diagnostics.Stopwatch]::GetTimestamp() + 60 * $frequency
    while (-not (Test-Path (Join-Path $control 'actor-stopped.txt'))) { if ([Diagnostics.Stopwatch]::GetTimestamp() -gt $deadline) { break }; Start-Sleep -Milliseconds 200 }
    $result.ActorStopped = Test-Path (Join-Path $control 'actor-stopped.txt')
    Start-Sleep -Seconds 15
    $result.AfterActorExit = Get-Sample $Cycles 'actor-exited'
    Start-Sleep -Seconds 60
    $result.Idle = Get-Sample $Cycles 'idle'
} catch {
    $result.Error = $_.Exception.Message
} finally {
    $result.Finished = [DateTime]::UtcNow.ToString('o')
    ($result | ConvertTo-Json -Depth 8) | Set-Content -LiteralPath (Join-Path $out 'result.json')
}
