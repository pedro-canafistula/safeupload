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
-DeleteAttribution adds two-pass KD deletion attribution after purged; all original samples remain.
Together with -HandbackDiagnostic it inventories/deletes the existing hand-backs (requires -BlockHeavy);
otherwise it creates the separate 256-file corpus. No diagnostic observation changes a qualification gate.
-VolumeDiscriminator appends five purge/30 s samples around a 512-file NTFS VHD metadata-open/delete/teardown sequence,
without changing the original samples or gates. It needs boot Verifier and cycles < 10000, excludes -DeleteAttribution, and needs
no memory tools; classification is non-qualifying INFO, with diskpart/fltmc scripts and receipts in the failure-evidence export.
-ImmediateReopen adds a prestarted same-token child plus same-writer read/read-write probes, once after each APPROVE
public-byte observation (no open retries); records C:\T4\reopens.jsonl. Requires reopen-after-publication.ps1 beside actor.
-ReopenSequential (needs -ImmediateReopen) makes the child wait until the saving process finished and closed both of its own
opens, instead of probing at the same instant. Owner-approved 2026-10-20: two programs write-opening one protected file in the
same instant is a sharing-policy question for T5/T8, not a T4 lifetime result. Every probe, error and assertion is unchanged.
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
    [switch]$HandbackDiagnostic,
    [switch]$DeleteAttribution,
    [switch]$VolumeDiscriminator,
    [switch]$PurgeAttribution,
    [switch]$ImmediateReopen,
    [switch]$ReopenSequential
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
$purgeLoadError = $null
if ($PurgeAttribution) {
    try { . (Join-Path $PSScriptRoot 'purge-attribution.ps1') }
    catch { $purgeLoadError = $_.Exception.Message }
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

function Get-T4DeleteReleaseObservation($Start, $Purged, $Baseline, [int]$Count, [object[]]$Statuses) {
    $live = @{}
    foreach ($pair in @(@('Start',$Start),@('Purged',$Purged),@('Baseline',$Baseline))) {
        $tag = $pair[1].TagSUfl
        $live[$pair[0]] = if ($tag -and $null -ne $tag.NonPagedAllocs -and $null -ne $tag.NonPagedFrees) {
            ([long]$tag.NonPagedAllocs - [long]$tag.NonPagedFrees + 4294967296L) % 4294967296L
        } else { $null }
    }
    $delta = $null; $near = $null
    # Diagnostic comparison only: tolerate at most one quarter of the hand-back population
    # above start. m2t4hbdiag1 had +234 for 1500 hand-backs. Never certifies individual release.
    $band = [int][math]::Floor($Count / 4.0)
    if ($null -ne $live.Start -and $null -ne $live.Baseline -and $Count -gt 0) {
        $delta = $live.Baseline - $live.Start; $near = $delta -le $band
    }
    $purgedOk = $Statuses.Count -eq 5 -and @($Statuses | Where-Object { -not $_.Succeeded }).Count -eq 0
    [pscustomobject]@{ StartSUfl=$live.Start; PurgedSUfl=$live.Purged; BaselineSUfl=$live.Baseline;
        Handbacks=$Count; ResidualAboveStart=$delta; NearStartBand=$band; NearStart=$near;
        FreshPurgeSucceeded=$purgedOk; ReleaseProxyObserved=($purgedOk -and $near -eq $true);
        IndividualContextReleaseConfirmed=$false;
        Interpretation='Global SUfl proxy only; no per-file release proof. Missing/high counts mean the intended precondition is unconfirmed; KD identity deltas remain diagnostic.' }
}

function Invoke-T4DeleteAttribution($StartSample, $PurgedSample) {
    $diagnostic = [ordered]@{ NonQualifying=$true; Mode=$(if ($HandbackDiagnostic) { 'Handbacks' } else { 'Corpus' });
        CorpusCount=0; Deleted=0; DeleteErrors=@(); Errors=@(); Snapshots=@(); Samples=@(); Purges=@();
        CorpusIdentities=$null; ReleasePrecondition=$null; HandbackDiagnostic=$null }
    $corpus = @(); $baseline = $null
    try {
        if (-not $MemoryDiagnostic -or -not $RequireVerifierPool -or $Cycles -ge 10000 -or ($HandbackDiagnostic -and -not $BlockHeavy)) {
            throw 'Delete attribution requires memory tools, boot Verifier launcher, cycles < 10000, and BlockHeavy for hand-backs.'
        }
        if ($HandbackDiagnostic) {
            # Metadata-only opens, all closed before the fresh purge/baseline. Do not create a new corpus.
            Get-T4HandbackIdentities $handback | ForEach-Object { $corpus += $_ }
            if (-not $corpus.Count) { throw 'No hand-backs available for delete attribution.' }
            $identities = Join-Path $script:T4MemoryRoot 'output\handback-identities.json'
            $sets = [ordered]@{
                Handbacks = @($corpus | ForEach-Object { $_.Path })
                Journals = @(Get-ChildItem -LiteralPath $journalDir -File -Force -ErrorAction SilentlyContinue | ForEach-Object { $_.FullName })
                Public = @(Get-ChildItem -LiteralPath $root -File -Force -ErrorAction SilentlyContinue | ForEach-Object { $_.FullName })
            }
            $diagnostic.HandbackDiagnostic = [ordered]@{ Holders=@(); HandbacksDeleted=0; HandbackDeleteFailures=0;
                HandbackDeleteErrors=@(); HandbacksLeft=$corpus.Count; AfterDelete=$null; AfterDeletePurged=$null; Purge=@() }
            $diagnostic.HandbackDiagnostic.Holders = @(foreach ($category in $sets.Keys) {
                try { Get-T4FileHolders $category $sets[$category] }
                catch { [pscustomobject]@{ Category=$category; Files=$sets[$category].Count; Holders=@(); Error=$_.Exception.Message } }
            })
        } else {
            $directory = Join-Path $script:T4MemoryRoot 'delete-corpus'
            # Keep partial receipts on failure, but never delete an incompletely verified inventory.
            New-T4DeleteCorpus $directory | ForEach-Object { $corpus += $_ }
            if ($corpus.Count -ne 256) { throw 'Incomplete delete corpus.' }
            $identities = Join-Path $script:T4MemoryRoot 'output\delete-corpus-identities.json'
            try { $diagnostic.Holders=Get-T4FileHolders 'DeleteCorpus' @($corpus | ForEach-Object { $_.Path }) }
            catch { $diagnostic.Errors += ('Holder query: ' + $_.Exception.Message) }
        }
        $diagnostic.CorpusCount=$corpus.Count
        Write-T4DeleteEvidence $identities (ConvertTo-Json -InputObject @($corpus) -Depth 4)
        $diagnostic.CorpusIdentities=$identities
        foreach ($label in 'del-baseline','del-after','del-after-purge') {
            $statuses = @()
            if ($label -eq 'del-after') {
                # Delete only the fixed, recorded inventory; no re-open between baseline and deletion.
                foreach ($item in $corpus) {
                    try { [IO.File]::Delete($item.Path); $diagnostic.Deleted++ }
                    catch { $diagnostic.DeleteErrors += [pscustomobject]@{ Path=$item.Path; Error=$_.Exception.Message } }
                }
                if ($HandbackDiagnostic) {
                    $hb = $diagnostic.HandbackDiagnostic
                    $hb.HandbacksDeleted=$diagnostic.Deleted; $hb.HandbackDeleteFailures=$diagnostic.DeleteErrors.Count
                    $hb.HandbackDeleteErrors=@($diagnostic.DeleteErrors)
                    $hb.HandbacksLeft=@(Get-ChildItem -LiteralPath $handback -File -Force -ErrorAction SilentlyContinue).Count
                }
            } else {
                try { $statuses=@(Invoke-T4MemoryPurge) }
                catch { $diagnostic.Errors += ($label + ' purge: ' + $_.Exception.Message) }
                $diagnostic.Purges += [pscustomobject]@{ Before=$label; Statuses=$statuses }
                if ($HandbackDiagnostic -and $label -eq 'del-after-purge') { $diagnostic.HandbackDiagnostic.Purge=$statuses }
            }
            Start-Sleep -Seconds 30
            # Preserve both original hand-back samples and the del-* samples before their KD sessions.
            if ($HandbackDiagnostic -and $label -ne 'del-baseline') {
                try {
                    if ($label -eq 'del-after') { $diagnostic.HandbackDiagnostic.AfterDelete=Get-Sample $Cycles 'handbacks-deleted' }
                    else { $diagnostic.HandbackDiagnostic.AfterDeletePurged=Get-Sample $Cycles 'handbacks-deleted-purged' }
                } catch { $diagnostic.Errors += ('Hand-back sample: ' + $_.Exception.Message) }
            }
            $sample = $null
            try { $sample=Get-Sample $Cycles $label; $diagnostic.Samples += $sample }
            catch { $diagnostic.Errors += ($label + ' sample: ' + $_.Exception.Message) }
            if ($HandbackDiagnostic -and $label -eq 'del-baseline') {
                $diagnostic.ReleasePrecondition=Get-T4DeleteReleaseObservation $StartSample $PurgedSample $sample $corpus.Count $statuses
                if (-not $diagnostic.ReleasePrecondition.ReleaseProxyObserved) {
                    $diagnostic.Errors += 'Hand-back release precondition unconfirmed; this row cannot establish reproduction of m2t4hbdiag1.'
                }
            }
            try {
                $snapshot = Save-T4DeleteSnapshot $label $corpus $baseline
                if ($label -eq 'del-baseline') { $baseline=$snapshot.Census }
                $diagnostic.Snapshots += [pscustomobject]@{ Label=$label; Counts=$snapshot.Counts;
                    Classification=$snapshot.Classification; Errors=$snapshot.Errors;
                    SummaryFile=(Join-Path $script:T4MemoryRoot ('output\' + $label + '.summary.json')) }
            } catch { $diagnostic.Errors += ($label + ' KD: ' + $_.Exception.ToString()) }
        }
    } catch { $diagnostic.Errors += $_.Exception.ToString() }
    finally {
        $diagnostic.CorpusCount=$corpus.Count
        try {
            $partial = Join-Path $script:T4MemoryRoot 'output\delete-attribution.json'
            Write-T4DeleteEvidence $partial (@{ Result=$diagnostic; Corpus=$corpus } | ConvertTo-Json -Depth 12)
        } catch { $diagnostic.Errors += ('Attribution result write: ' + $_.Exception.Message) }
    }
    $diagnostic
}

function Initialize-T4VolumeIdentity {
    if ('T4VolumeIdentity' -as [type]) { return }
    Add-Type -TypeDefinition @'
using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;
public static class T4VolumeIdentity {
    [DllImport("kernel32.dll", CharSet=CharSet.Unicode, ExactSpelling=true, SetLastError=true)]
    static extern SafeFileHandle CreateFileW(string path, uint access, uint share, IntPtr security,
        uint disposition, uint flags, IntPtr template);
    [DllImport("kernel32.dll", ExactSpelling=true, SetLastError=true)]
    static extern bool GetFileInformationByHandleEx(SafeFileHandle file, int kind, [Out] byte[] data, uint size);
    public static string Read(string path) {
        // FILE_READ_ATTRIBUTES only; share READ/WRITE/DELETE; OPEN_EXISTING. No data or enumeration opens.
        using (SafeFileHandle file = CreateFileW(path, 0x80, 7, IntPtr.Zero, 3, 0x00200000, IntPtr.Zero)) {
            if (file.IsInvalid) throw new Win32Exception(Marshal.GetLastWin32Error());
            byte[] id = new byte[24]; // FILE_ID_INFO: volume serial + full 128-bit FileId
            if (!GetFileInformationByHandleEx(file, 18, id, 24))
                throw new Win32Exception(Marshal.GetLastWin32Error());
            return BitConverter.ToString(id).Replace("-", "");
        }
    }
}
'@
}

function Invoke-T4VolumeNative($Diagnostic, [string]$Directory, [string]$Label,
    [string]$File, [string[]]$Arguments, [string[]]$Commands = @()) {
    $base = Join-Path $Directory $Label
    $receipt = [ordered]@{ Label=$Label; File=$File; Arguments=$Arguments; Script=$null;
        Stdout=($base + '.stdout.txt'); Stderr=($base + '.stderr.txt'); ExitCode=$null; Error=$null }
    $Diagnostic.NativeReceipts += $receipt
    $process = $null
    try {
        if ($Commands.Count) {
            $receipt.Script = $base + '.diskpart.txt'
            [IO.File]::WriteAllLines($receipt.Script, $Commands, [Text.Encoding]::ASCII)
            $Arguments = @('/s', ('"' + $receipt.Script + '"'))
            $receipt.Arguments = $Arguments
        }
        $process = Start-Process -FilePath $File -ArgumentList $Arguments -PassThru -NoNewWindow `
            -RedirectStandardOutput $receipt.Stdout -RedirectStandardError $receipt.Stderr
        $null = $process.Handle # retain for PowerShell 5.1 ExitCode after WaitForExit
        $deadline = [Diagnostics.Stopwatch]::GetTimestamp() + 120 * [Diagnostics.Stopwatch]::Frequency
        while (-not $process.HasExited) {
            if ([Diagnostics.Stopwatch]::GetTimestamp() -ge $deadline) { throw ($Label + ' exceeded 120 s') }
            Start-Sleep -Milliseconds 100
        }
        $process.WaitForExit()
        $receipt.ExitCode = $process.ExitCode
        if ($receipt.ExitCode -ne 0) { throw ($Label + ' exit ' + $receipt.ExitCode) }
        if ($Commands.Count) {
            # Diskpart can return zero after a script error; storage postconditions are verified by the caller too.
            $text = [IO.File]::ReadAllText($receipt.Stdout) + [IO.File]::ReadAllText($receipt.Stderr)
            if ($text -match '(?im)DiskPart has encountered an error|Virtual Disk Service error|DiskPart failed') {
                throw ($Label + ': diskpart reported a script error; see full output')
            }
        }
    } catch {
        $receipt.Error = $_.Exception.Message
        throw
    } finally {
        if ($null -ne $process) {
            try {
                if (-not $process.HasExited) {
                    $process.Kill()
                    if (-not $process.WaitForExit(10000)) { throw 'Native process still running after kill' }
                }
                $receipt.ExitCode = $process.ExitCode
            } catch { $Diagnostic.Errors += ($Label + ' process cleanup: ' + $_.Exception.Message) }
            finally { $process.Dispose() }
        }
        # Persist even a timeout/launch failure before attempting another command or cleanup.
        [IO.File]::WriteAllText(($base + '.receipt.json'), ($receipt | ConvertTo-Json -Depth 4), [Text.UTF8Encoding]::new($false))
    }
    [pscustomobject]$receipt
}

function Get-T4VolumeObservation($Diagnostic) {
    $live = [ordered]@{}
    foreach ($label in 'vol-s0','vol-s1','vol-s2','vol-s3','vol-s4') {
        $samples = @($Diagnostic.Samples | Where-Object { $_.Label -eq $label })
        $tag = $null
        if ($samples.Count -eq 1) { $tag = $samples[0].TagSUfl }
        $live[$label] = if ($tag -and $null -ne $tag.NonPagedAllocs -and $null -ne $tag.NonPagedFrees) {
            ([long]$tag.NonPagedAllocs - [long]$tag.NonPagedFrees + 4294967296L) % 4294967296L
        } else { $null }
    }
    $observation = [ordered]@{ LiveSUfl=$live; Growth=$null; DeleteRelease=$null;
        TeardownRelease=$null; Residual=$null; Classification='Inconclusive' }
    foreach ($delta in @(@('Growth','vol-s2','vol-s1'), @('DeleteRelease','vol-s2','vol-s3'),
                         @('TeardownRelease','vol-s3','vol-s4'), @('Residual','vol-s4','vol-s1'))) {
        if ($null -ne $live[$delta[1]] -and $null -ne $live[$delta[2]]) {
            $observation[$delta[0]] = $live[$delta[1]] - $live[$delta[2]]
        }
    }
    if (@($live.Keys | Where-Object { $null -eq $live[$_] }).Count -eq 0 -and
        $Diagnostic.Errors.Count -eq 0 -and $Diagnostic.FilterAttached.First -eq $true -and
        $Diagnostic.FilterAttached.Second -eq $true -and $observation.Growth -ge $Diagnostic.N / 2) {
        if ($observation.Residual -le $Diagnostic.N / 8) { $observation.Classification='StreamRetention' }
        else { $observation.Classification='DriverReference' }
    }
    [pscustomobject]$observation
}

function Invoke-T4VolumeDiscriminator {
    $diagnostic = [ordered]@{ NonQualifying=$true; Letter=$null; N=512;
        FilterAttached=[ordered]@{ First=$null; Second=$null }; Samples=@(); Purges=@();
        NativeReceipts=@(); Errors=@(); Created=0; Opened=0; Deleted=0; AttachedAtEnd=$null;
        LiveSUfl=$null; Growth=$null; DeleteRelease=$null; TeardownRelease=$null; Residual=$null;
        Classification='Inconclusive' }
    $vhd = 'C:\T4\volume-discriminator.vhdx'
    $directory = Join-Path $out 'failure-evidence\volume-discriminator'
    $owned = $false
    $select = 'select vdisk file="' + $vhd + '"'
    function Invoke-VolumeDiskpart([string]$Label, [string[]]$Commands) {
        $null = Invoke-T4VolumeNative $diagnostic $directory $Label 'diskpart.exe' @() ($Commands + @('exit'))
    }
    function Get-VolumeImage {
        $image = Get-DiskImage -ImagePath $vhd -ErrorAction Stop
        if ($null -eq $image.Attached) { throw 'VHD attachment state unavailable' }
        $diagnostic.AttachedAtEnd = [bool]$image.Attached
        $image
    }
    function Assert-VolumeMounted {
        $image = Get-VolumeImage
        if (-not $image.Attached) { throw 'VHD did not attach' }
        $partition = Get-Partition -DiskNumber $image.Number -PartitionNumber 1 -ErrorAction Stop
        $volume = $partition | Get-Volume -ErrorAction Stop
        if ($partition.DriveLetter -ne $diagnostic.Letter -or $volume.FileSystem -ne 'NTFS' -or $volume.FileSystemLabel -ne 'T4DISC') {
            throw 'VHD letter, NTFS format or label does not match the diagnostic volume'
        }
    }
    function Assert-VolumeFilter([string]$Attach) {
        $diagnostic.FilterAttached[$Attach] = $false
        $receipt = Invoke-T4VolumeNative $diagnostic $directory ('fltmc-' + $Attach) 'fltmc.exe' @('instances','-v', ($diagnostic.Letter + ':'))
        $attached = [IO.File]::ReadAllText($receipt.Stdout) -match '(?im)^\s*SafeUpload\s+'
        $diagnostic.FilterAttached[$Attach] = $attached
        if (-not $attached) { throw ('SafeUpload instance absent on ' + $Attach + ' attach') }
    }
    function Save-VolumeSample([string]$Label) {
        $statuses = @(Invoke-T4MemoryPurge)
        $diagnostic.Purges += [pscustomobject]@{ Before=$Label; Statuses=$statuses }
        if ($statuses.Count -ne 5 -or @($statuses | Where-Object { -not $_.Succeeded }).Count) {
            $diagnostic.Errors += ($Label + ': purge incomplete or refused')
        }
        $deadline = [Diagnostics.Stopwatch]::GetTimestamp() + 30 * [Diagnostics.Stopwatch]::Frequency
        while ([Diagnostics.Stopwatch]::GetTimestamp() -lt $deadline) { Start-Sleep -Milliseconds 100 }
        $diagnostic.Samples += Get-Sample $Cycles $Label
    }
    try {
        New-Item -ItemType Directory -Path $directory -Force | Out-Null
        if (-not $RequireVerifierPool -or $Cycles -ge 10000 -or $DeleteAttribution) {
            throw 'Volume discriminator requires boot Verifier launcher, cycles < 10000, and no DeleteAttribution'
        }
        if ([Security.Principal.WindowsIdentity]::GetCurrent().User.Value -ne 'S-1-5-18') { throw 'Volume discriminator must run as SYSTEM' }
        Initialize-T4VolumeIdentity
        Save-VolumeSample 'vol-s0'
        if (Test-Path -LiteralPath $vhd) { throw 'Volume discriminator VHDX already exists; never reuse or remove it' }
        $used = @([IO.Directory]::GetLogicalDrives() | ForEach-Object { $_.Substring(0,1) })
        $used += @(Get-PSDrive -PSProvider FileSystem | ForEach-Object { $_.Name })
        $free = @(90..68 | ForEach-Object { [string][char]$_ } | Where-Object { $_ -notin $used })
        if (-not $free.Count) { throw 'No free drive letter for volume discriminator' }
        $diagnostic.Letter = $free[0]
        $owned = $true  # only this invocation may clean up its newly created VHDX
        Invoke-VolumeDiskpart 'diskpart-create' @(
            ('create vdisk file="' + $vhd + '" maximum=1024 type=expandable'),
            'attach vdisk', 'create partition primary', 'format fs=ntfs quick label=T4DISC', ('assign letter=' + $diagnostic.Letter))
        Assert-VolumeMounted
        Assert-VolumeFilter 'First'
        $corpus = $diagnostic.Letter + ':\corpus'
        [IO.Directory]::CreateDirectory($corpus) | Out-Null
        for ($i=0; $i -lt $diagnostic.N; $i++) {
            $path = Join-Path $corpus ('f-{0:D3}.txt' -f $i)
            $bytes = [Text.Encoding]::ASCII.GetBytes(('T4 volume discriminator {0:D3}' -f $i).PadRight(64, '.'))
            $stream = [IO.FileStream]::new($path, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
            try { $stream.Write($bytes, 0, $bytes.Length) } finally { $stream.Dispose() }
            $diagnostic.Created++
        }
        Invoke-VolumeDiskpart 'diskpart-detach-baseline' @($select, 'detach vdisk')
        if ((Get-VolumeImage).Attached) { throw 'Baseline detach did not remove VHD' }
        Save-VolumeSample 'vol-s1'
        Invoke-VolumeDiskpart 'diskpart-reattach' @($select, 'attach vdisk')
        $image = Get-VolumeImage
        if (-not $image.Attached) { throw 'Second attach did not attach VHD' }
        $partition = Get-Partition -DiskNumber $image.Number -PartitionNumber 1 -ErrorAction Stop
        # Mount Manager may restore the same letter automatically. Do not assign an already assigned letter.
        if ($partition.DriveLetter -ne $diagnostic.Letter) {
            Invoke-VolumeDiskpart 'diskpart-reassign' @($select, 'select partition 1', ('assign letter=' + $diagnostic.Letter))
        }
        Assert-VolumeMounted
        Assert-VolumeFilter 'Second'
        $identities = @(for ($i=0; $i -lt $diagnostic.N; $i++) {
            $path = Join-Path $corpus ('f-{0:D3}.txt' -f $i)
            $id = [T4VolumeIdentity]::Read($path)
            $diagnostic.Opened++
            [pscustomobject]@{ Path=$path; FileIdInfo=$id }
        })
        [IO.File]::WriteAllText((Join-Path $directory 'identities.json'), (ConvertTo-Json -InputObject $identities -Depth 3), [Text.UTF8Encoding]::new($false))
        Save-VolumeSample 'vol-s2'
        for ($i=0; $i -lt $diagnostic.N / 2; $i++) {
            [IO.File]::Delete((Join-Path $corpus ('f-{0:D3}.txt' -f $i)))
            $diagnostic.Deleted++
        }
        Save-VolumeSample 'vol-s3'
        Invoke-VolumeDiskpart 'diskpart-detach-final' @($select, 'detach vdisk')
        if ((Get-VolumeImage).Attached) { throw 'Final detach did not remove VHD' }
        Save-VolumeSample 'vol-s4'
    } catch { $diagnostic.Errors += $_.Exception.ToString() }
    finally {
        if ($owned) {
            try {
                if (Test-Path -LiteralPath $vhd) {
                    $image = $null
                    try { $image = Get-VolumeImage }
                    catch { $diagnostic.Errors += ('Cleanup attachment query: ' + $_.Exception.Message) }
                    # An uncertain failed attach still needs a detach attempt. An already detached VHD needs none.
                    if ($null -eq $image -or $image.Attached) {
                        try { Invoke-VolumeDiskpart 'diskpart-cleanup-detach' @($select, 'detach vdisk') }
                        catch { $diagnostic.Errors += ('Cleanup detach: ' + $_.Exception.Message) }
                    }
                    if ((Get-VolumeImage).Attached) { throw 'Cleanup failed: VHDX is still attached' }
                    [IO.File]::Delete($vhd)
                    if (Test-Path -LiteralPath $vhd) { throw 'Cleanup failed: VHDX still exists' }
                }
            } catch { $diagnostic.Errors += ('Volume cleanup: ' + $_.Exception.ToString()) }
        }
        $observation = Get-T4VolumeObservation $diagnostic
        foreach ($property in $observation.PSObject.Properties) { $diagnostic[$property.Name] = $property.Value }
        try {
            [IO.File]::WriteAllText((Join-Path $directory 'result.json'), ($diagnostic | ConvertTo-Json -Depth 8), [Text.UTF8Encoding]::new($false))
        } catch {
            $diagnostic.Errors += ('Volume receipt write: ' + $_.Exception.Message)
            $diagnostic.Classification = 'Inconclusive'
        }
    }
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
$result = [ordered]@{ Cycles = $Cycles; ImmediateReopen = [bool]$ImmediateReopen; ReopenOrder = $(if (-not $ImmediateReopen) { 'none' } elseif ($ReopenSequential) { 'sequential' } else { 'simultaneous' }); Started = [DateTime]::UtcNow.ToString('o'); Completed = 0; Attempted = 0;
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
        $actorPattern = if ($ImmediateReopen -and -not $sensitive) { $pattern + $(if ($ReopenSequential) { '-reopen-seq' } else { '-reopen' }) } else { $pattern }
        Set-Content -LiteralPath $staging -Value ("$i $actorPattern $name $payload"); [IO.File]::Move($staging, $command)
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
            if ($ImmediateReopen -and -not $sensitive -and $ok) {
                $prefix = Join-Path $control ('reopen-' + $i)
                $signalQpc = [Diagnostics.Stopwatch]::GetTimestamp()
                [IO.File]::WriteAllText(($prefix + '.go'), [string]$signalQpc)
                $reopenDeadline = $signalQpc + 30 * $frequency
                while (-not [IO.File]::Exists($prefix + '.result.json') -or -not [IO.File]::Exists($prefix + '.owner.json')) {
                    if ([Diagnostics.Stopwatch]::GetTimestamp() -ge $reopenDeadline) { break }
                    Start-Sleep -Milliseconds 2
                }
                if (-not [IO.File]::Exists($prefix + '.result.json') -or -not [IO.File]::Exists($prefix + '.owner.json')) {
                    $ok = $false; $why = 'immediate reopen observer timed out'
                } else {
                    $probe = [IO.File]::ReadAllText($prefix + '.result.json') | ConvertFrom-Json
                    $ownerProbe = [IO.File]::ReadAllText($prefix + '.owner.json') | ConvertFrom-Json
                    $probe | Add-Member -NotePropertyName Owner -NotePropertyValue $ownerProbe
                    $probe | Add-Member -NotePropertyName PublicationObservedQpc -NotePropertyValue $signalQpc
                    Write-T4ResultLine (Join-Path $out 'reopens.jsonl') ($probe | ConvertTo-Json -Depth 6 -Compress)
                    if ($ownerProbe.Error -or -not $ownerProbe.TerminationConfirmed -or $ownerProbe.ReadError -ne 0 -or $ownerProbe.ReadWriteError -ne 0 -or
                        $probe.Error -or $probe.ObserverPid -eq $probe.WriterPid -or
                        $probe.Read.OpenError -ne 0 -or $probe.Read.CloseError -ne 0 -or $probe.Read.Error -or -not $probe.Read.BytesMatch -or
                        $probe.ReadWrite.OpenError -ne 0 -or $probe.ReadWrite.CloseError -ne 0 -or $probe.ReadWrite.Error -or -not $probe.ReadWrite.BytesMatch) {
                        $ok = $false; $why = 'immediate cross-process read/read-write failed (see reopens.jsonl)'
                    }
                }
            }
            if (-not $ok -and -not $why) { $why = if ($sensitive) { 'no hand-back of the blocked bytes' } else { 'the public file never held the approved bytes' } }
            # A blocked version never reaches the public name.
            if ($sensitive -and (Same (Read-Public $target) $bytes)) { $ok = $false; $why = 'BLOCKED BYTES PUBLISHED' }
        }
        if ($ImmediateReopen -and -not $sensitive -and -not $ok) {
            [IO.File]::WriteAllText((Join-Path $control ('reopen-' + $i + '.abort')), 'publication/reopen failed')
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
    if ($PurgeAttribution -and -not $purgeLoadError) {
        $result.PurgeAttribution = New-T4PurgeAttribution
        $attribution = $result.PurgeAttribution
        Wait-T4PurgeTimeline $attribution 'settled' 30
        $result.Settled = Get-Sample $Cycles 'settled'
        $exitWindow = Invoke-T4PurgeAction $attribution 'exit start' { Start-T4PurgeWindow $attribution 'exit' }
        $result.ActorStopped = Stop-T4Actor $control
        Wait-T4PurgeTimeline $attribution 'exit' 15 $exitWindow
        Invoke-T4PurgeAction $attribution 'exit stop' { Stop-T4PurgeWindow $attribution $exitWindow }
        $result.AfterActorExit = Get-Sample $Cycles 'actor-exited'
        $idleWindow = Invoke-T4PurgeAction $attribution 'idle start' { Start-T4PurgeWindow $attribution 'idle' }
        Wait-T4PurgeTimeline $attribution 'idle' 60 $idleWindow
        Invoke-T4PurgeAction $attribution 'idle stop' { Stop-T4PurgeWindow $attribution $idleWindow }
        $result.Idle = Get-Sample $Cycles 'idle'
        $purgeWindow = Invoke-T4PurgeAction $attribution 'purge start' { Start-T4PurgeWindow $attribution 'purge' }
        $result.Purge = @(Invoke-T4MemoryPurge)
        Wait-T4PurgeTimeline $attribution 'purge' 30 $purgeWindow
        Invoke-T4PurgeAction $attribution 'purge stop' { Stop-T4PurgeWindow $attribution $purgeWindow }
        $result.Purged = Get-Sample $Cycles 'purged'
        Invoke-T4PurgeAction $attribution 'parse' { Complete-T4PurgeParse $attribution }
        Invoke-T4PurgeAction $attribution 'controls' {
            Invoke-T4PurgeControls $attribution $Cycles (Join-Path $PSScriptRoot 't4-agent-readiness.ps1')
        }
    } else {
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
    }
    if ($PurgeAttribution -and $purgeLoadError) {
        $result.PurgeAttribution = [ordered]@{ NonQualifying=$true; Windows=@(); Controls=@{}; Errors=@($purgeLoadError) }
    }
    if ($DeleteAttribution) {
        $result.DeleteAttribution = Invoke-T4DeleteAttribution $startSample $result.Purged
        if ($HandbackDiagnostic) { $result.HandbackDiagnostic = $result.DeleteAttribution.HandbackDiagnostic }
    } elseif ($HandbackDiagnostic) { $result.HandbackDiagnostic = Invoke-T4HandbackDiagnostic }
    if ($VolumeDiscriminator) { $result.VolumeDiscriminator = Invoke-T4VolumeDiscriminator }
} catch {
    $result.Error = $_.Exception.Message
    $result.ErrorDetail = $_.Exception.ToString()
    $result.ErrorScriptStackTrace = $_.ScriptStackTrace
} finally {
    if ($ImmediateReopen -and $i -gt 0) {
        try { [IO.File]::WriteAllText((Join-Path $control ('reopen-' + $i + '.abort')), 'coordinator finished') }
        catch { $result.ReopenAbortError = $_.Exception.ToString() }
    }
    if ($actorLaunched -and -not $result.ActorStopped) {
        try { $result.ActorStopped = Stop-T4Actor $control }
        catch { $result.ActorStopError = $_.Exception.ToString() }
    }
    if ($PurgeAttribution -and $result.PurgeAttribution -and -not $purgeLoadError) {
        foreach ($window in $result.PurgeAttribution.Windows) {
            if (-not $window.Stopped) {
                Invoke-T4PurgeAction $result.PurgeAttribution 'final session stop' { Stop-T4PurgeWindow $result.PurgeAttribution $window }
            }
        }
    }
    $result.Finished = [DateTime]::UtcNow.ToString('o')
    $resultPart = Join-Path $out 'result.part'
    [IO.File]::WriteAllText($resultPart, ($result | ConvertTo-Json -Depth 8), [Text.UTF8Encoding]::new($false))
    [IO.File]::Move($resultPart, (Join-Path $out 'result.json'))
}
