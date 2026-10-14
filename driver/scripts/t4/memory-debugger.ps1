<# Optional T4 attribution experiment. All debugger commands read memory.
   Runs only on the throwaway disk; it never grants cleanup authority.
   Local KD snapshots are not atomic and do not qualify a product assertion. #>
$script:T4MemoryRoot = 'C:\T4Memory'

function Initialize-T4MemoryIdentity {
    if ('T4MemoryIdentity' -as [type]) { return }
    Add-Type -TypeDefinition @'
using System;
using System.ComponentModel;
using System.IO;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;
public static class T4MemoryIdentity {
    [DllImport("kernel32.dll", SetLastError=true)]
    static extern bool GetFileInformationByHandleEx(SafeFileHandle file, int kind,
        [Out] byte[] buffer, uint length);
    public static string OpenAndClose(string path) {
        using (var file = new FileStream(path, FileMode.Open, FileAccess.ReadWrite,
                FileShare.ReadWrite | FileShare.Delete)) {
            byte[] identity = new byte[24]; // FILE_ID_INFO: volume serial + full 128-bit ID
            if (!GetFileInformationByHandleEx(file.SafeFileHandle, 18, identity, 24))
                throw new Win32Exception(Marshal.GetLastWin32Error());
            return BitConverter.ToString(identity);
        }
    }
}
'@
}

function Get-T4MemoryCommands {
    @'
.echo T4_MEMORY_BEGIN
version
.reload /f nt
.reload /f fltmgr.sys
.reload /f SafeUpload.sys
lmvm SafeUpload
dt SafeUpload!_SAFEUPLOAD_DATA SafeUpload!SafeUploadData Filter
!fltkd.filters 7
!poolused 2 SUfl
!poolused 2 SwUr
!verifier 3 SafeUpload.sys
.echo T4_MEMORY_END
q
'@
}

function Save-T4MemorySnapshot {
    param([Parameter(Mandatory=$true)][ValidatePattern('^[a-z0-9-]{1,60}$')][string]$Label,
          [switch]$AllowUnloaded)
    $out = Join-Path $script:T4MemoryRoot 'output'
    [void](New-Item -ItemType Directory -Force -Path $out)
    $commands = Join-Path $out ($Label + '.commands.txt')
    $stdout = Join-Path $out ($Label + '.stdout.txt')
    $stderr = Join-Path $out ($Label + '.stderr.txt')
    [IO.File]::WriteAllText($commands, (Get-T4MemoryCommands), [Text.Encoding]::ASCII)
    $kd = Join-Path $script:T4MemoryRoot 'x64\kd.exe'
    if (-not (Test-Path -LiteralPath $kd)) { throw 'T4 memory debugger is missing.' }
    $symbols = $script:T4MemoryRoot + '\symbols;srv*' + $script:T4MemoryRoot + '\symcache*https://msdl.microsoft.com/download/symbols'
    $arguments = '-kl -y "' + $symbols + '" -c "$$><' + $commands + '"'
    $timer = [Diagnostics.Stopwatch]::StartNew()
    $process = Start-Process -FilePath $kd -ArgumentList $arguments -PassThru -NoNewWindow `
        -RedirectStandardOutput $stdout -RedirectStandardError $stderr
    $null = $process.Handle # retain the handle so PowerShell 5.1 can read ExitCode after WaitForExit
    $finished = $process.WaitForExit(180000)
    if (-not $finished) { $process.Kill(); $process.WaitForExit() }
    $process.Refresh()
    $text = [IO.File]::ReadAllText($stdout)
    $record = [ordered]@{ Label=$Label; Utc=[DateTime]::UtcNow.ToString('o');
        ElapsedMs=$timer.ElapsedMilliseconds; Finished=$finished; ExitCode=$process.ExitCode;
        Complete=($text -match '(?m)^T4_MEMORY_END\s*$'); AllowUnloaded=[bool]$AllowUnloaded;
        KernelAttached=($text -match 'Windows .*Kernel Version');
        PrivateSymbols=($text -match 'SafeUpload[^\r\n]*\(private pdb symbols\)') }
    [IO.File]::WriteAllText((Join-Path $out ($Label + '.result.json')),
        ($record | ConvertTo-Json -Compress), [Text.UTF8Encoding]::new($false))
    if (-not $finished -or -not $record.Complete -or $process.ExitCode -ne 0) {
        throw ('T4 memory debugger failed: ' + $Label + '; inspect retained stdout/stderr.')
    }
    if (-not $record.KernelAttached -or (-not $AllowUnloaded -and -not $record.PrivateSymbols)) {
        throw 'T4 memory debugger lacks the kernel connection or exact private driver symbols.'
    }
    'T4MemorySnapshot=' + $Label
}

function New-T4MemoryCorpus {
    param([Parameter(Mandatory=$true)][string]$Directory, [int]$Count=32)
    Initialize-T4MemoryIdentity
    if (Test-Path -LiteralPath $Directory) { throw 'Memory corpus already exists.' }
    [void](New-Item -ItemType Directory -Path $Directory)
    $corpus = @{}
    for ($i=0; $i -lt $Count; $i++) {
        $path = Join-Path $Directory ($i.ToString('D3') + '.bin')
        [IO.File]::WriteAllBytes($path, [Text.Encoding]::ASCII.GetBytes('T4 memory identity control'))
        $corpus[$path] = [T4MemoryIdentity]::OpenAndClose($path)
    }
    return $corpus
}

function Test-T4MemoryCorpus {
    param([Parameter(Mandatory=$true)][hashtable]$Corpus, [int]$Rounds=16)
    Initialize-T4MemoryIdentity
    for ($round=0; $round -lt $Rounds; $round++) {
        foreach ($path in $Corpus.Keys) {
            if ([T4MemoryIdentity]::OpenAndClose($path) -cne $Corpus[$path]) {
                throw ('Physical identity changed in memory control: ' + $path)
            }
        }
    }
    return ($Rounds * $Corpus.Count)
}

function Invoke-T4MemoryControls {
    $out = Join-Path $script:T4MemoryRoot 'output'
    Save-T4MemorySnapshot 'control-idle-before'
    Start-Sleep -Seconds 30
    Save-T4MemorySnapshot 'control-idle-after'
    $corpus = New-T4MemoryCorpus (Join-Path $script:T4MemoryRoot 'fixed-corpus')
    Save-T4MemorySnapshot 'control-fixed-created'
    $opens = Test-T4MemoryCorpus $corpus
    Save-T4MemorySnapshot 'control-fixed-first'
    $opens += Test-T4MemoryCorpus $corpus
    Save-T4MemorySnapshot 'control-fixed-repeat'
    $disjoint = New-T4MemoryCorpus (Join-Path $script:T4MemoryRoot 'disjoint-corpus')
    $opens += Test-T4MemoryCorpus $disjoint
    Save-T4MemorySnapshot 'control-disjoint'
    Start-Sleep -Seconds 30
    Save-T4MemorySnapshot 'control-settled'
    [IO.File]::WriteAllText((Join-Path $out 'corpus-identities.json'),
        (@{ Fixed=$corpus; Disjoint=$disjoint; IdentityCheckedOpens=$opens } | ConvertTo-Json -Depth 4),
        [Text.UTF8Encoding]::new($false))
    'T4MemoryControls=PASS'
}

function Invoke-T4MemoryTeardown {
    # Called only after the original T4 observations/verdict have been exported.
    # This is additional attribution, never a way to make the cleanup row pass.
    $c = & 'C:\Users\vika\Documents\Get-SafeUploadDiagnostics.ps1' -Query counters
    # This pipe belongs to the service and will disappear when it stops. Retain the entire reply,
    # including lastUnloadVeto/lastUnloadStatus if that service build exposes them.
    Write-T4DeleteEvidence (Join-Path $script:T4MemoryRoot 'output\teardown-counters.json') ($c | ConvertTo-Json -Depth 12)
    foreach ($key in 'liveVersions','liveViews','tombstones','waitingVersions') {
        if ($null -eq $c.stageWorker.$key -or $c.stageWorker.$key -ne 0) {
            throw ('Diagnostic unload refused: outstanding ' + $key)
        }
    }
    if (@(Get-ChildItem 'C:\ProgramData\SafeUpload\staging' -File -Force).Count -ne 0) {
        throw 'Diagnostic unload refused: private stage files remain.'
    }
    Save-T4MemorySnapshot 'teardown-before'
    $service = Get-Service -Name SafeUploadAgent -ErrorAction Stop
    $service.Stop()
    $service.WaitForStatus([ServiceProcess.ServiceControllerStatus]::Stopped,
        [TimeSpan]::FromSeconds(30))
    $out = Join-Path $script:T4MemoryRoot 'output'
    $beforeVeto = Save-T4UnloadVeto 'unload-veto-before' $c
    $unload = Start-Process -FilePath fltmc.exe -ArgumentList 'unload SafeUpload' -PassThru -NoNewWindow `
        -RedirectStandardOutput (Join-Path $out 'unload.stdout.txt') `
        -RedirectStandardError (Join-Path $out 'unload.stderr.txt')
    $null = $unload.Handle
    if (-not $unload.WaitForExit(60000)) {
        # Terminating the caller does not force kernel unload. The host still restores the run disk.
        $unload.Kill()
        $null = $unload.WaitForExit(5000)
        $afterVeto = Save-T4UnloadVeto 'unload-veto-after' $null
        Write-T4DeleteEvidence (Join-Path $out 'unload.result.json') (@{ Finished=$false; ExitCode=$null; Before=$beforeVeto; After=$afterVeto } | ConvertTo-Json -Depth 12)
        throw 'Voluntary filter unload exceeded the diagnostic deadline.'
    }
    $unload.Refresh()
    $afterVeto = $null
    if ($unload.ExitCode -ne 0) { $afterVeto = Save-T4UnloadVeto 'unload-veto-after' $null }
    Write-T4DeleteEvidence (Join-Path $out 'unload.result.json') (@{ Finished=$true; ExitCode=$unload.ExitCode; Before=$beforeVeto; After=$afterVeto } | ConvertTo-Json -Depth 12)
    if ($unload.ExitCode -ne 0) {
        throw ('Voluntary filter unload was refused. Last recorded veto: ' + ($afterVeto.Veto | ConvertTo-Json -Compress) + '; inspect unload-veto-after evidence.')
    }
    Start-Sleep -Seconds 5
    Save-T4MemorySnapshot 'teardown-after' -AllowUnloaded
    'T4MemoryTeardown=PASS'
}

# Delete attribution is deliberately separate from the original memory controls.
# All r/r? assignments below change debugger pseudo-registers only, never target memory.
function Initialize-T4DeleteIdentity {
    if ('T4DeleteIdentity' -as [type]) { return }
    Add-Type -TypeDefinition @'
using System;
using System.ComponentModel;
using System.IO;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;
public static class T4DeleteIdentity {
    [StructLayout(LayoutKind.Sequential, CharSet=CharSet.Unicode)]
    struct StreamData {
        public long Size;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst=296)] public string Name;
    }
    [DllImport("kernel32.dll", SetLastError=true)]
    static extern bool GetFileInformationByHandleEx(SafeFileHandle file, int kind, [Out] byte[] data, uint size);
    [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
    static extern IntPtr FindFirstStreamW(string path, int level, out StreamData data, uint flags);
    [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
    static extern bool FindNextStreamW(IntPtr find, out StreamData data);
    [DllImport("kernel32.dll", SetLastError=true)]
    static extern bool FindClose(IntPtr find);
    [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
    static extern SafeFileHandle CreateFileW(string path, uint access, uint share, IntPtr security,
        uint disposition, uint flags, IntPtr template);
    static byte[] Identity(SafeFileHandle file, out byte[] attributes) {
        byte[] id = new byte[24]; attributes = new byte[8];
        if (!GetFileInformationByHandleEx(file, 18, id, 24) ||
            !GetFileInformationByHandleEx(file, 9, attributes, 8))
            throw new Win32Exception(Marshal.GetLastWin32Error());
        if ((BitConverter.ToUInt32(attributes, 0) & 0x410) != 0)
            throw new IOException("Delete member is a directory or reparse point.");
        return id;
    }
    static string[] Receipt(string path, byte[] id, byte[] attributes) {
        StreamData data;
        IntPtr find = FindFirstStreamW(path, 0, out data, 0);
        if (find == new IntPtr(-1)) throw new Win32Exception(Marshal.GetLastWin32Error());
        try {
            if (data.Name != "::$DATA") throw new IOException("Delete member lacks one ordinary unnamed stream.");
            if (FindNextStreamW(find, out data)) throw new IOException("Delete member has more than one stream.");
            int error = Marshal.GetLastWin32Error();
            if (error != 38) throw new Win32Exception(error); // ERROR_HANDLE_EOF
        } finally {
            if (!FindClose(find)) throw new Win32Exception(Marshal.GetLastWin32Error());
        }
        return new string[] { BitConverter.ToUInt64(id, 0).ToString("x16"),
            BitConverter.ToString(id, 8, 16).Replace("-", "").ToLowerInvariant(),
            BitConverter.ToUInt32(attributes, 0).ToString("x8") };
    }
    public static string[] Read(string path) {
        byte[] id, attributes;
        // Metadata-only OPEN_EXISTING, no data/write/DELETE grant. Do not follow a reparse member.
        // Close this handle AND stream enumeration before the fresh baseline purge, never reopen after KD baseline.
        using (SafeFileHandle file = CreateFileW(path, 0x80, 7, IntPtr.Zero, 3, 0x00200000, IntPtr.Zero)) {
            if (file.IsInvalid) throw new Win32Exception(Marshal.GetLastWin32Error());
            id = Identity(file, out attributes);
        }
        return Receipt(path, id, attributes);
    }
    public static string[] Create(string path) {
        byte[] id, attributes;
        using (var file = new FileStream(path, FileMode.CreateNew, FileAccess.ReadWrite, FileShare.None)) {
            byte[] bytes = System.Text.Encoding.ASCII.GetBytes("T4 ordinary delete attribution\r\n");
            file.Write(bytes, 0, bytes.Length); // exactly one write; no subsequent observing data opens
            id = Identity(file.SafeFileHandle, out attributes);
        }
        return Receipt(path, id, attributes);
    }
}
'@
}

function New-T4DeleteCorpus([string]$Directory) {
    Initialize-T4DeleteIdentity
    if (Test-Path -LiteralPath $Directory) { throw 'Delete corpus already exists; never reuse a diagnostic corpus.' }
    # Reject a redirected parent as well as reparse members. The launcher policy protects C:\Protected only.
    for ($parent = [IO.DirectoryInfo]::new((Split-Path $Directory -Parent)); $null -ne $parent; $parent = $parent.Parent) {
        if (($parent.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw 'Reparse corpus parent.' }
    }
    [void](New-Item -ItemType Directory -Path $Directory)
    for ($i = 0; $i -lt 256; $i++) {
        $path = Join-Path $Directory ($i.ToString('D3') + '.txt')
        $id = [T4DeleteIdentity]::Create($path)
        [pscustomobject]@{ Path=$path; VolumeSerial=$id[0]; FileId=$id[1]; Attributes=$id[2]; Streams=@('::$DATA'); HandlesClosed=$true }
    }
}

function Get-T4HandbackIdentities([string]$Directory) {
    Initialize-T4DeleteIdentity
    if (-not $Directory -or -not [IO.Directory]::Exists($Directory)) { throw 'Hand-back directory unavailable.' }
    for ($parent = [IO.DirectoryInfo]::new($Directory); $null -ne $parent; $parent = $parent.Parent) {
        if (($parent.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw 'Reparse hand-back directory/parent.' }
    }
    # Snapshot one flat set in the resolved actor hand-back directory; never recurse or create files.
    foreach ($file in @(Get-ChildItem -LiteralPath $Directory -File -Force -ErrorAction Stop | Sort-Object Name)) {
        if ($file.Extension -ine '.txt') { throw ('Unexpected hand-back member: ' + $file.FullName) }
        $id = [T4DeleteIdentity]::Read($file.FullName)
        [pscustomobject]@{ Path=$file.FullName; VolumeSerial=$id[0]; FileId=$id[1]; Attributes=$id[2];
            Streams=@('::$DATA'); HandlesClosed=$true; IdentityAccess='FILE_READ_ATTRIBUTES; OPEN_EXISTING; OPEN_REPARSE_POINT' }
    }
}

function ConvertTo-T4KdAddress([string]$Value) {
    $hex = ($Value -replace '^0x','') -replace '`',''
    if ($hex -notmatch '^[0-9a-fA-F]{1,16}$') { return $null }
    return $hex.ToLowerInvariant().PadLeft(16, '0')
}

function Get-T4KdSection([string]$Text, [string]$Name) {
    $m = [regex]::Match($Text, '(?ms)^T4_' + [regex]::Escape($Name) + '_BEGIN\r?\n(.*?)^T4_' + [regex]::Escape($Name) + '_END\s*$')
    if ($m.Success) { return $m.Groups[1].Value }
    return ''
}

function Get-T4KdErrors([string]$Text) {
    # Retain the raw output too: this recognizes common KD failures, not every possible extension message.
    @($Text -split '\r?\n' | Where-Object {
        $_ -notmatch '^\s*Pool Allocations Failed\s+0x[0-9a-f]+\s*$' -and
        $_ -match '(?i)^\s*Usage: !poolfind|numeric expression missing|error reading|corrupt|skipping.*page|failed to read critical heap|could not|couldn.t|unable to|cannot|can.t|read error|memory access error|syntax error|invalid (address|parameter)|type information missing|no export|not found|not supported|failed|terminating - searched|\?{8}'
    })
}

function ConvertFrom-T4UnloadVeto([string]$Text) {
    # StageStream.c packs Reason in the high DWORD and NTSTATUS in the low DWORD.
    # Read that value, never invoke SafeUploadStageGetUnloadStatus in the target.
    $section = Get-T4KdSection $Text 'UNLOAD_VETO'
    $m = [regex]::Match($section, '(?m)^\s*[0-9a-fA-F`]{8,17}\s+([0-9a-fA-F`]{16,17})\s*$')
    if (-not $m.Success) { return $null }
    $packed = ConvertTo-T4KdAddress $m.Groups[1].Value
    if (-not $packed) { return $null }
    $reason = [Convert]::ToUInt32($packed.Substring(0,8),16)
    $names = @('NONE','CLIENT','FENCE','STAGE_DRAIN','STAGE_OBJECTS','FENCE_COMMIT','STAGE_RENAME','STAGE_DISCARD') # Protocol.h
    [pscustomobject]@{ Reason=$reason; ReasonName=$(if ($reason -lt $names.Count) { $names[$reason] } else { 'UNRECOGNIZED' });
        NTSTATUS=('0x' + $packed.Substring(8,8)); Packed=('0x' + $packed); LastRecordedOnly=$true; NonAtomic=$true }
}

function Save-T4UnloadVeto([string]$Label, $Counters) {
    $result = [ordered]@{ Label=$Label; Veto=$null; Counters=$Counters; Session=$null; Errors=@(); NonQualifying=$true }
    try {
        # Diagnostics cannot be queried after Stop-Service. Private-symbol reads also cover builds
        # whose diagnostics JSON omits the ABI's LastUnloadVeto/LastUnloadStatus fields.
        $body = @'
.echo T4_UNLOAD_VETO_BEGIN
dq SafeUpload!StageLastUnloadVeto L1
.echo T4_UNLOAD_VETO_END
.catch { dd SafeUpload!StageStreamCount L1 }
.catch { dd SafeUpload!StageFileObjects L1 }
'@
        $result.Session = Invoke-T4DeleteKdSession $Label $body
        $result.Errors += @($result.Session.Errors)
        if ($result.Session.KernelAttached -and $result.Session.PrivateSymbols -and (Test-Path -LiteralPath $result.Session.Stdout)) {
            $result.Veto = ConvertFrom-T4UnloadVeto ([IO.File]::ReadAllText($result.Session.Stdout))
        }
        if (-not $result.Veto) { $result.Errors += 'Last unload veto unavailable; not equivalent to NONE.' }
    } catch { $result.Errors += $_.Exception.Message }
    try { Write-T4DeleteEvidence (Join-Path $script:T4MemoryRoot ('output\' + $Label + '.summary.json')) ($result | ConvertTo-Json -Depth 12) }
    catch { $result.Errors += $_.Exception.Message }
    [pscustomobject]$result
}

function ConvertFrom-T4KdTelemetry([string]$Text) {
    # These are separate, non-atomic observations, NEVER a substitute for !poolfind's address census.
    # poolused is decimal; verifier addresses, lengths and counters are explicitly hexadecimal.
    $poolUsed = @(); $allocations = @(); $stats = $null; $filters = @(); $unparsed = @()
    foreach ($line in ($Text -split '\r?\n')) {
        $m = [regex]::Match($line, '^\s*(SUfl|SwUr)\s+(-?\d+)\s+(-?\d+)\s+(-?\d+)\s+(-?\d+)')
        if ($m.Success) {
            # Decimal preserves the real SwUr underflow value 18446744073709551614 without rounding.
            $n = @(2..5 | ForEach-Object { [decimal]::Parse($m.Groups[$_].Value,[Globalization.CultureInfo]::InvariantCulture) })
            $poolUsed += [pscustomobject]@{ Tag=$m.Groups[1].Value; NonPagedAllocs=$n[0]; NonPagedBytes=$n[1];
                PagedAllocs=$n[2]; PagedBytes=$n[3]; Raw=$line; NonAtomic=$true }
        } elseif ($line -match '^\s*(SUfl|SwUr)\s') { $unparsed += $line }
    }
    $driver = [regex]::Match($Text, '(?ms)^nt!_VF_TARGET_DRIVER\s+0x[0-9a-f`]+:\s+SafeUpload\.sys \(Loaded\)\s*\r?\n(.*?)(?=^nt!_VF_TARGET_DRIVER|^T4_|\z)')
    if ($driver.Success) {
        $body = $driver.Groups[1].Value
        $a = [regex]::Match($body, 'Current Pool Allocations:\s*\( 0x([0-9a-f]+) / 0x([0-9a-f]+) \)')
        $b = [regex]::Match($body, 'Current Pool Bytes:\s*\( 0x([0-9a-f]+) / 0x([0-9a-f]+) \)')
        if ($a.Success -and $b.Success) {
            $stats = [pscustomobject]@{ NonPagedAllocs=[Convert]::ToInt64($a.Groups[1].Value,16); PagedAllocs=[Convert]::ToInt64($a.Groups[2].Value,16);
                NonPagedBytes=[Convert]::ToInt64($b.Groups[1].Value,16); PagedBytes=[Convert]::ToInt64($b.Groups[2].Value,16) }
        }
        foreach ($line in ($body -split '\r?\n')) {
            $m = [regex]::Match($line, '^\s*0x([0-9a-f`]+)\s+0x([0-9a-f]+)\s+(\S{4})\s+0x([0-9a-f`]+)\s*(.*?)\s*$')
            if ($m.Success) {
                $allocations += [pscustomobject]@{ Address=ConvertTo-T4KdAddress $m.Groups[1].Value;
                    Size=[Convert]::ToInt64($m.Groups[2].Value,16); Tag=$m.Groups[3].Value;
                    Caller=ConvertTo-T4KdAddress $m.Groups[4].Value; Symbol=$m.Groups[5].Value }
            } elseif ($line -match '^\s*0x[0-9a-f`]+\s+0x') { $unparsed += $line }
        }
    }
    # Bound each filter by the next FLT_FILTER at the same indentation. Historical files have no markers.
    foreach ($f in [regex]::Matches($Text, '(?ms)^(?<indent>[ \t]*)FLT_FILTER: (?<address>[0-9a-f`]+) "SafeUpload"[^\r\n]*\r?\n(?<body>.*?)(?=^\k<indent>FLT_FILTER:|^T4_|\z)')) {
        $body=$f.Groups['body'].Value; $usage=[ordered]@{}; $objects=@(); $registrations=@()
        foreach ($m in [regex]::Matches($body, '(?m)^\s*(References to FLT_\w+|Allocations of FLT_\w+|Open files)\s*:\s*(\d+)\s*$')) {
            $usage[$m.Groups[1].Value.Trim()]=[long]$m.Groups[2].Value
        }
        foreach ($m in [regex]::Matches($body, '(?m)^\s*FLT_VERIFIER_OBJECT:\s*([0-9a-f`]+)\s*\r?\n\s*Object:\s*([0-9a-f`]+)\s+Type:\s*(.*?)\s+RefCount:\s*([0-9a-f]+)\s*$')) {
            $objects += [pscustomobject]@{ Node=ConvertTo-T4KdAddress $m.Groups[1].Value; Object=ConvertTo-T4KdAddress $m.Groups[2].Value;
                Type=$m.Groups[3].Value; RefCountHex=$m.Groups[4].Value; RefCount=[Convert]::ToInt64($m.Groups[4].Value,16) }
        }
        foreach ($m in [regex]::Matches($body, '(?ms)^\s*ALLOCATE_CONTEXT_NODE:\s*([0-9a-f`]+)\s+\[([0-9a-f]+)\]\s+(\w+)\s*\r?\n(.*?)(?=^\s*---|^\s*ALLOCATE_CONTEXT_NODE:|\z)')) {
            $entry=$m.Groups[4].Value
            $type=[regex]::Match($entry,'ContextType\s*:\s*\[([0-9a-f]+)\]\s+(\w+)')
            $size=[regex]::Match($entry,'(?m)^\s*Size\s*:\s*(\d+)\s*$')
            $tag=[regex]::Match($entry,'(?m)^\s*PoolTag\s*:\s*(\S{4})\s*$')
            if ($type.Success -and $size.Success -and $tag.Success) {
                $registrations += [pscustomobject]@{ Address=ConvertTo-T4KdAddress $m.Groups[1].Value; Allocation=$m.Groups[3].Value;
                    ContextType=[Convert]::ToInt32($type.Groups[1].Value,16); Name=$type.Groups[2].Value; Size=[int]$size.Groups[1].Value; Tag=$tag.Groups[1].Value }
            }
        }
        $filters += [pscustomobject]@{ Address=ConvertTo-T4KdAddress $f.Groups['address'].Value; ObjectUsage=$usage;
            VerifierObjects=$objects; ContextRegistrations=$registrations }
    }
    [pscustomobject]@{ PoolUsed=$poolUsed; VerifierDriverStats=$stats; VerifierAllocations=$allocations; Filters=$filters;
        VerifierSectionComplete=[bool](Get-T4KdSection $Text 'VERIFIER'); FilterSectionComplete=[bool](Get-T4KdSection $Text 'FILTER');
        UnparsedRows=$unparsed; NonAtomic=$true }
}

function ConvertFrom-T4PoolRow([string]$Line) {
    # Two address contracts, never silently interchangeable:
    # Microsoft Learn's older format reports POOL_HEADER + rounded block size.
    # 10.0.28000 help (row 2) reports user allocation address/size, including special pool.
    # Modern formatter verified in the delivered Microsoft kdexts.dll (SHA256
    # 052171129a924bc301121486af052769f0d9b2532c4f492244f53c7229d9a881):
    # "%p :", " %-11s", " tag %c%c%c%c%s", ", size %#9I64x, ", "Nonpaged", " special", " pool".
    $m = [regex]::Match($Line, '^\s*([0-9a-fA-F`]{8,17})\s*:\s*(?:\((Allocated|Free\s*)\)\s*)?tag (?-i:SUfl)(?:\s*\(Protected\))?, size\s+(?:0x\s*)?([0-9a-fA-F]+),\s+(Nonpaged|Paged)( special)? pool(?:, quota process [0-9a-fA-F`]+)?\s*$', 'IgnoreCase')
    if ($m.Success) {
        return [pscustomobject]@{ Address=ConvertTo-T4KdAddress $m.Groups[1].Value; Size=[Convert]::ToInt64($m.Groups[3].Value,16);
            AddressKind='Allocation'; Allocated=($m.Groups[2].Value.Trim() -ne 'Free'); NonPaged=($m.Groups[4].Value -eq 'Nonpaged');
            Special=[bool]$m.Groups[5].Success; Format='Modern'; Raw=$Line }
    }
    $m = [regex]::Match($Line, '^\s*\*?([0-9a-fA-F`]{8,17})\s+size:\s*([0-9a-fA-F]+)\s+previous size:\s*[0-9a-fA-F]+\s+\((Allocated|Free)\)\s+\*?SUfl\b')
    if ($m.Success) {
        return [pscustomobject]@{ Address=ConvertTo-T4KdAddress $m.Groups[1].Value; Size=[Convert]::ToInt64($m.Groups[2].Value,16);
            AddressKind='PoolHeader'; Allocated=($m.Groups[3].Value -eq 'Allocated'); NonPaged=$true; Special=$false; Format='Legacy'; Raw=$Line }
    }
    # !pool's special-pool header has a separate data address; it need not be header+0x10.
    $m = [regex]::Match($Line, '^\s*\*?([0-9a-fA-F`]{8,17})\s+size:\s*([0-9a-fA-F]+)\s+data:\s*([0-9a-fA-F`]{8,17})\s+\((Allocated|Free)[^)]*\)\s+\*?SUfl\b')
    if ($m.Success) {
        return [pscustomobject]@{ Address=ConvertTo-T4KdAddress $m.Groups[3].Value; Size=[Convert]::ToInt64($m.Groups[2].Value,16);
            AddressKind='Allocation'; Allocated=($m.Groups[4].Value -eq 'Allocated'); NonPaged=$true; Special=$true; Format='SpecialData'; Raw=$Line }
    }
    return $null
}

function ConvertFrom-T4DeletePass1([string]$Text) {
    $pool = Get-T4KdSection $Text 'POOL'
    $blocks = @{}; $unparsed = @()
    foreach ($line in ($pool -split '\r?\n')) {
        if ($line -notmatch '\bSUfl\b') { continue }
        $row = ConvertFrom-T4PoolRow $line
        if ($row) {
            if (-not $row.NonPaged) { $unparsed += $line; continue }
            if ($row.Allocated) {
                if ($blocks.ContainsKey($row.Address) -and ($blocks[$row.Address].Size -ne $row.Size -or $blocks[$row.Address].AddressKind -ne $row.AddressKind)) {
                    $unparsed += $line # allocation changed during a non-atomic scan
                } else { $blocks[$row.Address] = $row }
            }
        } elseif ($line -notmatch '^\s*(Scanning|Searching).*pool|^\s*(?:lkd>|kd>|[0-9]+:\s*kd>)?\s*!poolfind\b') { $unparsed += $line }
    }
    $layout = $null
    $m = [regex]::Match($Text, '(?m)^T4_LAYOUT ([0-9a-f]+) ([0-9a-f]+) ([0-9a-f]+)\s*$')
    if ($m.Success) {
        $sizes = @(1..3 | ForEach-Object { [Convert]::ToInt32($m.Groups[$_].Value,16) })
        # 224 is a pool-block observation, NOT sizeof(SAFEUPLOAD_STREAM_CONTEXT).
        $rounded = [int]([math]::Ceiling(($sizes[0]+$sizes[1]+$sizes[2])/16.0)*16)
        if ($sizes[0] -eq 16 -and $sizes[1] -ge 16 -and $sizes[2] -gt 0 -and $rounded -eq 224) {
            $layout = [pscustomobject]@{ PoolHeader=$sizes[0]; ContextNode=$sizes[1]; UserData=$sizes[2]; RoundedBlock=$rounded }
        }
    }
    $anchorText = Get-T4KdSection $Text 'ANCHOR_COUNT'
    $m = [regex]::Match($anchorText, '(?m)^\s*[0-9a-fA-F`]{8,17}\s+([0-9a-fA-F]{8})\s*$')
    $anchors = $null; if ($m.Success) { $anchors = [Convert]::ToInt64($m.Groups[1].Value,16) }
    $logical = $null
    $m = [regex]::Match((Get-T4KdSection $Text 'LOGICAL'), '(?m)^T4_LOGICAL ([0-9a-f]+) ([0-9a-f]+) ([0-9a-f]+) ([0-9a-f]+)\s*$')
    if ($m.Success) {
        $n = @(1..4 | ForEach-Object { [Convert]::ToInt64($m.Groups[$_].Value,16) })
        $live = ($n[0]-$n[1]+4294967296) % 4294967296
        $storage = ($n[2]-$n[3]+4294967296) % 4294967296
        $logical = [pscustomobject]@{ Allocates=$n[0]; Frees=$n[1]; AllocateMisses=$n[2]; FreeMisses=$n[3];
            Outstanding=$live; PoolStorage=$storage; CachedEstimate=($storage-$live); NonAtomic=$true }
    }
    $walk = [regex]::Match($Text, '(?m)^T4_ANCHOR_WALK_END ([0-9a-fA-F`]+) ([0-9a-fA-F`]+)\s*$')
    $anchorWalkComplete = $walk.Success -and (ConvertTo-T4KdAddress $walk.Groups[1].Value) -eq (ConvertTo-T4KdAddress $walk.Groups[2].Value)
    $errors = @(Get-T4KdErrors $Text)
    if (-not $logical) { $errors += 'Stream logical allocator counts unavailable.' }
    if (-not $anchorWalkComplete) { $errors += 'Anchor walk truncated, failed or changed while reading.' }
    if (-not $layout) { $errors += 'Symbol sizes unavailable or inconsistent with the observed 224-byte stream block; offsets unresolved.' }
    if ($null -eq $anchors) { $errors += 'StageAnchorCount unavailable.' }
    if (-not $pool) { $errors += 'Pool scan section absent or incomplete.' }
    if ($unparsed.Count) { $errors += 'Unrecognized SUfl pool rows; census incomplete.' }
    [pscustomobject]@{ Blocks=@($blocks.Values | Sort-Object Address); Layout=$layout; Anchors=$anchors; Logical=$logical; AnchorWalkComplete=$anchorWalkComplete;
        Telemetry=ConvertFrom-T4KdTelemetry $Text;
        PoolComplete=([bool]$pool -and ($pool -match '(?i)(Searching NonPaged pool|Scanning.*pool.*(?:Tag: SUfl|tag 0x6c665553 \(SUfl\)))' -or $blocks.Count -gt 0) -and $unparsed.Count -eq 0 -and @(Get-T4KdErrors $pool).Count -eq 0);
        UnparsedPoolRows=$unparsed; Errors=$errors }
}

function Get-T4DeleteNewBlocks($Current, $Baseline) {
    if ($null -eq $Baseline -or -not $Baseline.PoolComplete -or -not $Current.PoolComplete) { return }
    $old = @{}; foreach ($block in $Baseline.Blocks) { $old[$block.Address] = $true }
    # Address-set delta only. Reuse at an old address is invisible; identity is resolved separately.
    @($Current.Blocks | Where-Object { -not $old.ContainsKey($_.Address) })
}

function Get-T4DeleteIdentityCommands {
    # $t4 must be a typed STAGE_REGISTRY_ENTRY*. Two little-endian qwords preserve all 128 ID bits.
    @'
dt SafeUpload!_STAGE_REGISTRY_ENTRY @$t4
.printf "T4_ID %016I64x %016I64x %016I64x\n", @@c++(@$t4->VolumeSerial), @@c++(*(unsigned __int64*)&@$t4->FileId.Identifier[0]), @@c++(*(unsigned __int64*)&@$t4->FileId.Identifier[8])
.printf "T4_ENTRY %p %x %x %x %x %x\n", @@c++(@$t4->Instance), @@c++(@$t4->H), @@c++(@$t4->W), @@c++(@$t4->T), @@c++(@$t4->StreamIdentityKnown), @@c++(@$t4->StreamChars)
'@
}

function Get-T4DeleteFileCommands {
    # $t6 is a FILE_OBJECT candidate. Writer/SOP tokens are non-owning and may already be stale.
    @'
.printf "T4_FILE_OBJECT %p\n", @$t6
.catch { !fileobj @$t6 }
.catch { !object @$t6 1 }
.catch { dt nt!_FILE_OBJECT @$t6 }
.catch { dt nt!_FSRTL_ADVANCED_FCB_HEADER @@c++(((nt!_FILE_OBJECT*)@$t6)->FsContext) }
.catch { .printf "T4_SCB %p\n", @@c++(((nt!_FILE_OBJECT*)@$t6)->FsContext); dt ntfs!_SCB @@c++(((nt!_FILE_OBJECT*)@$t6)->FsContext) }
.catch { r? $t7 = ((nt!_FILE_OBJECT*)@$t6)->SectionObjectPointer; .if (@@c++(@$t7 != 0)) { .printf "T4_SOP %p\n", @$t7; dt nt!_SECTION_OBJECT_POINTERS @$t7; .if (@@c++(@$t7->DataSectionObject != 0)) { .printf "T4_CONTROL_AREA %p\n", @@c++(@$t7->DataSectionObject); !ca @@c++(@$t7->DataSectionObject) }; .if (@@c++(@$t7->SharedCacheMap != 0)) { .printf "T4_SHARED_CACHE_MAP %p\n", @@c++(@$t7->SharedCacheMap); dt nt!_SHARED_CACHE_MAP @@c++(@$t7->SharedCacheMap) } } }
.catch { !fltkd.streamlist @$t6 0x3f 1 }
'@
}

function Get-T4DeleteSopCommands {
    # $t7 is a symbol-resolved SOP candidate; none of these pointers confers ownership.
    $file = (Get-T4DeleteFileCommands) -replace '\r?\n', '; '
    $commands = @'
r? $t12 = @$t7
.catch { .printf "T4_SOP %p\n", @$t7; dt nt!_SECTION_OBJECT_POINTERS @$t7 }
.catch { .if (@@c++(@$t7->SharedCacheMap != 0)) { .printf "T4_SHARED_CACHE_MAP %p\n", @@c++(@$t7->SharedCacheMap); dt nt!_SHARED_CACHE_MAP @@c++(@$t7->SharedCacheMap) } }
.catch { .if (@@c++(@$t7->DataSectionObject != 0)) { .printf "T4_CONTROL_AREA %p\n", @@c++(@$t7->DataSectionObject); !ca @@c++(@$t7->DataSectionObject); r? $t6 = (nt!_FILE_OBJECT*)(((nt!_CONTROL_AREA*)@$t7->DataSectionObject)->FilePointer.Value & ~(unsigned __int64)0xf); .if (@@c++(@$t6 != 0)) { __FILE__ } } }
.catch { .if (@@c++(@$t12->ImageSectionObject != 0)) { .printf "T4_CONTROL_AREA %p\n", @@c++(@$t12->ImageSectionObject); !ca @@c++(@$t12->ImageSectionObject) } }
.catch { .if (@@c++(@$t12->SharedCacheMap != 0)) { r? $t6 = ((nt!_SHARED_CACHE_MAP*)@$t12->SharedCacheMap)->FileObject; .if (@@c++(@$t6 != 0)) { __FILE__ } } }
'@
    $commands.Replace('__FILE__',$file)
}


# Command audit (Microsoft debugger command reference, 2026-10-13):
# https://learn.microsoft.com/en-us/windows-hardware/drivers/debuggercmds/c---numbers-and-operators
# /-if, /-for: conditions use the default evaluator; wrap the WHOLE condition in @@c++.
# /r--registers-, /pseudo-register-syntax: r? preserves C++ types; only $t0..$t19 are assigned.
# /-printf: arguments use MASM unless explicitly wrapped; %p has no modifiers, %I64x preserves IDs.
# /-catch: a read/type error skips that block, then resumes outside it; not a target exception handler.
# /-----------------------a---run-script-file-: $$>< condenses lines to one command program.
# /-poolfind (default=nonpaged; 10.0.28000 rejects positional 0), /-pool (2=one block's header), /-poolused (2=sort nonpaged), /-verifier (3=read lists).
# /dt--display-type-, /d--da--db--dc--dd--dd--df--dp--dq--du--dw--dw--dyb--dyd--display-memor:
# dt accepts type/address, dd/dq L1 reads one item; /-fileobj, /-object, /-ca only display objects.
# FltMgr flags/detail verified against THIS build's !fltkd.help in m2t4delattr1 pass1 lines 1262-1380.
# /-reload--reload-module-, /lm--list-loaded-modules-, /version--show-debugger-version-, /q--qq--quit-:
# symbol reloads are debugger-side; local KD q exits the debugger. No calls, writes or breakpoints.
function Get-T4DeleteSessionCommands([string]$Label, [string]$Body) {
    if ($Label -notmatch '^[a-z0-9-]{1,80}$') { throw 'Invalid KD evidence label.' }
    $marker = 'T4_KD_' + $Label.Replace('-','_').ToUpperInvariant() + '_END'
    # A separate process is the isolation boundary even if KD cannot recover a malformed program.
    # Each body section keeps its own evidence markers INSIDE .catch: an error cannot fabricate completion.
    (@('.expr /s masm', '.reload /f nt', '.reload /f fltmgr.sys', '.reload /f SafeUpload.sys',
        'lmvm SafeUpload', '.catch {', $Body, '}', ('.echo ' + $marker), 'q') -join "`r`n")
}

function Get-T4DeletePass1Commands([ValidateSet('layout','telemetry','logical','anchors','poolfind')][string]$Block) {
    switch ($Block) {
        'layout' { @'
dt fltmgr!_CONTEXT_NODE
dt nt!_POOL_HEADER
.printf "T4_LAYOUT %x %x %x\n", @@c++(sizeof(nt!_POOL_HEADER)), @@c++(sizeof(fltmgr!_CONTEXT_NODE)), @@c++(sizeof(SafeUpload!_SAFEUPLOAD_STREAM_CONTEXT))
.catch { dt fltmgr!_ALLOCATE_CONTEXT_HEADER }
.catch { dt fltmgr!_ALLOCATE_CONTEXT_LOOKASIDE }
'@ }
        'telemetry' {
            # Preserve all original memory commands, with local catches so an extension failure does not hide its peers.
            $base = (Get-T4MemoryCommands) -split '\r?\n' | Where-Object { $_ -notmatch '^q$|^\.echo T4_MEMORY|^\.reload|^lmvm' }
            @($base | ForEach-Object {
                if ($_ -match '^!verifier ') { '.catch { .echo T4_VERIFIER_BEGIN; ' + $_ + '; .echo T4_VERIFIER_END }' }
                else { '.catch { ' + $_ + ' }' }
            }) -join "`r`n"
            @'
.catch { !fltkd.help }
.echo T4_FILTER_BEGIN
r? $t0 = ((SafeUpload!_SAFEUPLOAD_DATA*)&SafeUpload!SafeUploadData)->Filter
!fltkd.filter @$t0 0x1f 1
.echo T4_FILTER_END
'@
        }
        'logical' { @'
r? $t0 = ((SafeUpload!_SAFEUPLOAD_DATA*)&SafeUpload!SafeUploadData)->Filter
.echo T4_LOGICAL_BEGIN
r? $t11 = (fltmgr!_ALLOCATE_CONTEXT_LOOKASIDE*)((fltmgr!_FLT_FILTER*)@$t0)->SupportedContexts[3]
.if (@@c++(@$t11 != 0 && @$t11->ContextType == 8 && @$t11->AllocationType == 1)) { dt nt!_GENERAL_LOOKASIDE @@c++(&@$t11->NonPaged.L); .printf "T4_LOGICAL %x %x %x %x\n", @@c++(@$t11->NonPaged.L.TotalAllocates), @@c++(@$t11->NonPaged.L.TotalFrees), @@c++(@$t11->NonPaged.L.AllocateMisses), @@c++(@$t11->NonPaged.L.FreeMisses) }
.echo T4_LOGICAL_END

'@ }
        'anchors' {
            $identity = (Get-T4DeleteIdentityCommands) -replace '\r?\n', '; '
            $file = (Get-T4DeleteFileCommands) -replace '\r?\n', '; '
            $body = @'
.echo T4_ANCHOR_COUNT_BEGIN
dd SafeUpload!StageAnchorCount L1
.echo T4_ANCHOR_COUNT_END
dt nt!_LIST_ENTRY @@c++(&SafeUpload!StageAnchorList)
r? $t1 = ((nt!_LIST_ENTRY*)&SafeUpload!StageAnchorList)->Flink
r $t2 = 0
.for (; @@c++(@$t1 != &SafeUpload!StageAnchorList && @$t1 != 0 && @$t2 < 64); r $t2 = @$t2 + 1) { .echo T4_ANCHOR_BEGIN; r? $t3 = (SafeUpload!_STAGE_ANCHOR*)((char*)@$t1 - (unsigned __int64)&((SafeUpload!_STAGE_ANCHOR*)0)->Link); dt SafeUpload!_STAGE_ANCHOR @$t3; .printf "T4_ANCHOR_OWNER %p %p\n", @@c++(@$t3->Handle), @@c++(@$t3->Object); r? $t4 = @$t3->Entry; .if (@@c++(@$t4 != 0)) { __IDENTITY__ }; r? $t6 = @$t3->Object; .if (@@c++(@$t6 != 0)) { __FILE__ }; .echo T4_ANCHOR_END; r? $t1 = @$t1->Flink }
.printf "T4_ANCHOR_WALK_END %p %p\n", @$t1, SafeUpload!StageAnchorList

'@
            $body.Replace('__IDENTITY__',$identity).Replace('__FILE__',$file)
        }
        'poolfind' { @'
.echo T4_POOL_BEGIN
!poolfind SUfl
.echo T4_POOL_END
'@ }
    }
}

function Get-T4DeletePass2Commands([object[]]$Blocks, $Layout) {
    $commands = @()
    $identity = (Get-T4DeleteIdentityCommands) -replace '\r?\n', '; '
    $file = (Get-T4DeleteFileCommands) -replace '\r?\n', '; '
    $sop = (Get-T4DeleteSopCommands) -replace '\r?\n', '; '
    foreach ($block in @($Blocks | Select-Object -First 64)) {
        $address = $block.Address
        if ($address -notmatch '^[0-9a-f]{16}$') { throw 'Unvalidated pool address.' }
        $commands += '.echo T4_BLOCK_BEGIN ' + $address
        $commands += '.catch { !pool 0x' + $address + ' 2 }'
        $kind = if ($block.AddressKind) { $block.AddressKind } else { 'PoolHeader' } # older retained receipts
        $commands += '.echo T4_BLOCK_INFO ' + $kind + ' ' + ([long]$block.Size).ToString('x')
        $candidates = @($address); $nodeAddress = $null
        if ($Layout) {
            $value = [Convert]::ToUInt64($address,16)
            $node = if ($kind -eq 'Allocation') { $value } else { $value + [uint64]$Layout.PoolHeader }
            $nodeAddress = $node.ToString('x16')
            $candidates = @($address,$nodeAddress,($node + [uint64]$Layout.ContextNode).ToString('x16') | Select-Object -Unique)
        }
        foreach ($candidate in $candidates) {
            $commands += '.echo T4_CTX_BEGIN ' + $candidate
            $commands += '.catch {'
            $commands += '.catch { !fltkd.ctx 0x' + $candidate + ' 1 }'
            $commands += '.catch { dt fltmgr!_CONTEXT_NODE 0x' + $candidate + ' }'
            # Only the symbol-derived node gets typed dereferences; other addresses are extension probes.
            if ($Layout -and $candidate -eq $nodeAddress) {
                $body = @'
r? $t3 = (fltmgr!_CONTEXT_NODE*)0x__NODE__
.if (@@c++(@$t3->RegInfo != 0 && @$t3->RegInfo->ContextType == 8 && @$t3->RegInfo->ContextCleanupCallback == &SafeUpload!SafeUploadStreamContextCleanup)) { .echo T4_SAFEUPLOAD_STREAM; r? $t5 = (SafeUpload!_SAFEUPLOAD_STREAM_CONTEXT*)((char*)@$t3 + sizeof(fltmgr!_CONTEXT_NODE)); dt SafeUpload!_SAFEUPLOAD_STREAM_CONTEXT @$t5; .printf "T4_PAYLOAD %p %x\n", @$t5, @@c++(sizeof(SafeUpload!_SAFEUPLOAD_STREAM_CONTEXT)); .printf "T4_WRITERS %p %p %p\n", @@c++(&@$t5->WriterObjects), @@c++(@$t5->WriterObjects.Flink), @@c++(@$t5->WriterObjects.Blink); r? $t4 = (SafeUpload!_STAGE_REGISTRY_ENTRY*)@$t5->WriterRegistryEntry; .printf "T4_REGISTRY %p\n", @$t4; .if (@@c++(@$t4 != 0)) { __IDENTITY__; r? $t7 = (nt!_SECTION_OBJECT_POINTERS*)@$t4->SectionObjectPointer; .if (@@c++(@$t7 != 0)) { __SOP__ } }; r? $t8 = @$t5->WriterObjects.Flink; r $t9 = 0; .for (; @@c++(@$t8 != &@$t5->WriterObjects && @$t8 != 0 && @$t9 < 8); r $t9 = @$t9 + 1) { r? $t10 = (SafeUpload!_STAGE_WRITER_NODE*)((char*)@$t8 - (unsigned __int64)&((SafeUpload!_STAGE_WRITER_NODE*)0)->Link); dt SafeUpload!_STAGE_WRITER_NODE @$t10; r? $t6 = @$t10->FileObject; .if (@@c++(@$t6 != 0)) { __FILE__ }; r? $t8 = @$t8->Flink }; .echo T4_STREAM_LINK_BEGIN; dt fltmgr!_STREAM_LIST_CTRL @@c++(*(void**)&@$t3->AttachedObject); !fltkd.streamlist @@c++(*(void**)&@$t3->AttachedObject) 0x3f 1; .echo T4_STREAM_LINK_END }
'@
                $commands += $body.Replace('__NODE__',$candidate).Replace('__IDENTITY__',$identity).Replace('__SOP__',$sop).Replace('__FILE__',$file)
            }
            $commands += '}', '.echo T4_CTX_END'
        }
        $commands += '.echo T4_BLOCK_END'
    }
    $commands -join "`r`n"
}

function ConvertFrom-T4DeleteIdentity([string]$Text) {
    $ids = @([regex]::Matches($Text, '(?m)^T4_ID ([0-9a-fA-F]{16}) ([0-9a-fA-F]{16}) ([0-9a-fA-F]{16})\s*$'))
    if ($ids.Count -ne 1) { return $null }
    $m = $ids[0]
    $bytes = [BitConverter]::GetBytes([Convert]::ToUInt64($m.Groups[2].Value,16)) +
        [BitConverter]::GetBytes([Convert]::ToUInt64($m.Groups[3].Value,16))
    [pscustomobject]@{ VolumeSerial=$m.Groups[1].Value.ToLowerInvariant(); FileId=([BitConverter]::ToString($bytes) -replace '-','').ToLowerInvariant() }
}

function ConvertFrom-T4DeletePass2([string]$Text, [object[]]$Corpus, [string]$AnchorText) {
    $identities = @{}; foreach ($item in $Corpus) { $identities[$item.VolumeSerial + ':' + $item.FileId] = $item.Path }
    $anchors = @(foreach ($a in [regex]::Matches($AnchorText, '(?ms)^T4_ANCHOR_BEGIN\r?\n(.*?)^T4_ANCHOR_END\s*$')) {
        $body = $a.Groups[1].Value; $id = ConvertFrom-T4DeleteIdentity $body
        $owner = [regex]::Match($body, '(?m)^T4_ANCHOR_OWNER ([0-9a-fA-F`]+) ([0-9a-fA-F`]+)\s*$')
        $handle = $null; $file = $null
        if ($owner.Success) { $handle = ConvertTo-T4KdAddress $owner.Groups[1].Value; $file = ConvertTo-T4KdAddress $owner.Groups[2].Value }
        $entry = [regex]::Match($body, '(?m)^T4_ENTRY ([0-9a-fA-F`]+) [0-9a-f]+ [0-9a-f]+ [0-9a-f]+ 1 0\s*$')
        $instance = $null; if ($entry.Success) { $instance = ConvertTo-T4KdAddress $entry.Groups[1].Value }
        $path = $null; if ($id -and $instance) { $path = $identities[$id.VolumeSerial + ':' + $id.FileId] }
        [pscustomobject]@{ Identity=$id; Instance=$instance; CorpusPath=$path; Handle=$handle; FileObject=$file;
            OwningPairObserved=([bool]$handle -and [bool]$file -and $handle -ne '0000000000000000' -and $file -ne '0000000000000000'); Errors=@(Get-T4KdErrors $body) }
    })
    $contexts = @(); $attempts = @(); $seen = @{}
    foreach ($b in [regex]::Matches($Text, '(?ms)^T4_BLOCK_BEGIN ([0-9a-f]{16})\r?\n(.*?)^T4_BLOCK_END\s*$')) {
        $block = $b.Groups[1].Value; $blockText = $b.Groups[2].Value
        # The pool may have been freed/reused between sessions. Demand a fresh allocated SUfl row.
        $info = [regex]::Match($blockText, '(?m)^T4_BLOCK_INFO (Allocation|PoolHeader) ([0-9a-f]+)\s*$')
        $kind = if ($info.Success) { $info.Groups[1].Value } else { 'PoolHeader' }
        $blockValue = [Convert]::ToUInt64($block,16)
        $poolRows = @(foreach ($line in (($blockText -split '(?m)^T4_CTX_BEGIN ')[0] -split '\r?\n')) {
            $row = ConvertFrom-T4PoolRow $line
            if ($row -and $row.Allocated -and $row.NonPaged) { $row }
        })
        $fresh = @($poolRows | Where-Object {
            $value = [Convert]::ToUInt64($_.Address,16)
            if ($kind -eq 'Allocation') {
                ($_.AddressKind -eq 'Allocation' -and $value -eq $blockValue -and $_.Size -ge 200 -and $_.Size -le 208) -or
                    ($_.AddressKind -eq 'PoolHeader' -and $value+16 -eq $blockValue -and $_.Size -eq 224)
            } else { $_.AddressKind -eq 'PoolHeader' -and $value -eq $blockValue -and $_.Size -eq 224 }
        })
        foreach ($c in [regex]::Matches($blockText, '(?ms)^T4_CTX_BEGIN ([0-9a-f]{16})\r?\n(.*?)^T4_CTX_END\s*$')) {
            $candidate = $c.Groups[1].Value; $body = $c.Groups[2].Value
            $node = [regex]::Match($body, '(?m)^\s*CONTEXT_NODE:\s*([0-9a-fA-F`]+)\s+\[0008\]\s+StreamContext\b')
            $user = [regex]::Match($body, '(?m)^\s*UserData\s*:\s*([0-9a-fA-F`]+)\s*$')
            $size = [regex]::Match($body, '(?m)^\s*UserDataSize\s*:\s*(0x[0-9a-fA-F]+|\d+)\s*$')
            $payload = [regex]::Match($body, '(?m)^T4_PAYLOAD ([0-9a-fA-F`]+) ([0-9a-f]+)\s*$')
            $parsed = $fresh.Count -eq 1 -and $node.Success -and $user.Success -and $size.Success -and $payload.Success -and
                $body -match '(?m)^T4_SAFEUPLOAD_STREAM\s*$' -and
                (ConvertTo-T4KdAddress $node.Groups[1].Value) -eq $candidate -and
                (ConvertTo-T4KdAddress $user.Groups[1].Value) -eq (ConvertTo-T4KdAddress $payload.Groups[1].Value)
            if ($parsed) {
                $userSize = if ($size.Groups[1].Value.StartsWith('0x')) { [Convert]::ToInt32($size.Groups[1].Value.Substring(2),16) } else { [int]$size.Groups[1].Value }
                $parsed = $userSize -eq [Convert]::ToInt32($payload.Groups[2].Value,16) -and $userSize -gt 0 -and
                    $userSize -eq 104
            }
            $use = [regex]::Match($body, '(?m)^\s*UseCount\s*:\s*(0x[0-9a-fA-F]+|\d+)\s*$')
            $references = $null; if ($use.Success) { $references = if ($use.Groups[1].Value.StartsWith('0x')) { [Convert]::ToInt64($use.Groups[1].Value.Substring(2),16) } else { [int64]$use.Groups[1].Value } }
            if ($parsed) {
                $blockValue = [Convert]::ToUInt64($block,16)
                $userValue = [Convert]::ToUInt64((ConvertTo-T4KdAddress $user.Groups[1].Value),16)
                $expectedNode = if ($kind -eq 'Allocation') { $blockValue } else { $blockValue+16 }
                $parsed = $references -gt 0 -and [Convert]::ToUInt64($candidate,16) -eq $expectedNode -and $userValue -eq ($expectedNode+96) -and
                    ($userValue+$userSize) -le ([Convert]::ToUInt64($fresh[0].Address,16)+$fresh[0].Size)
            }
            # A plausible dt dump or zero-ref cached node is never enough to count a live context.
            $attempts += [pscustomobject]@{ Block=$block; Candidate=$candidate; Parsed=[bool]$parsed; Errors=@(Get-T4KdErrors $body) }
            if (-not $parsed -or $seen.ContainsKey($candidate)) { continue }
            $seen[$candidate] = $true
            $id = ConvertFrom-T4DeleteIdentity $body
            $registry = [regex]::Match($body, '(?m)^T4_REGISTRY ([0-9a-fA-F`]+)\s*$')
            $entry = [regex]::Match($body, '(?m)^T4_ENTRY ([0-9a-fA-F`]+) ([0-9a-f]+) ([0-9a-f]+) ([0-9a-f]+) ([0-9a-f]+) ([0-9a-f]+)\s*$')
            $path = $null; $identityKnown = $false; $instance = $null; $h = $null; $w = $null; $t = $null
            if ($entry.Success) {
                $instance = ConvertTo-T4KdAddress $entry.Groups[1].Value
                $h = [Convert]::ToInt64($entry.Groups[2].Value,16); $w = [Convert]::ToInt64($entry.Groups[3].Value,16); $t = [Convert]::ToInt64($entry.Groups[4].Value,16)
                $identityKnown = $null -ne $id -and $entry.Groups[5].Value -eq '1' -and $entry.Groups[6].Value -eq '0'
                if ($identityKnown) { $path = $identities[$id.VolumeSerial + ':' + $id.FileId] }
            }
            $writers = [regex]::Match($body, '(?m)^T4_WRITERS ([0-9a-fA-F`]+) ([0-9a-fA-F`]+) ([0-9a-fA-F`]+)\s*$')
            $hasWriters = $null
            if ($writers.Success) { $hasWriters = (ConvertTo-T4KdAddress $writers.Groups[1].Value) -ne (ConvertTo-T4KdAddress $writers.Groups[2].Value) -or (ConvertTo-T4KdAddress $writers.Groups[1].Value) -ne (ConvertTo-T4KdAddress $writers.Groups[3].Value) }
            $attached = [regex]::Match($body, '(?m)^\s*AttachedObject\s*:\s*([0-9a-fA-F`]+)\s*$')
            $attachment = $null; if ($attached.Success) { $attachment = ConvertTo-T4KdAddress $attached.Groups[1].Value }
            $attachmentObserved = [bool]$attachment -and $attachment -ne '0000000000000000' -and $body -match '\bInTree\b'
            $beyond = $null
            if ($attachmentObserved) { $beyond = $references -gt 1 }
            $matchingAnchors = @($anchors | Where-Object { $path -and $_.CorpusPath -eq $path -and $_.Instance -eq $instance -and $_.OwningPairObserved })
            $classification = 'Unresolved'
            if ($matchingAnchors.Count) { $classification = 'SafeUpload owning anchor observed; non-atomic candidate' }
            elseif ($identityKnown -and -not $path) { $classification = 'Other identity/stream; mixed/global activity candidate' }
            elseif ($beyond -eq $true) { $classification = 'Extra context references observed; owner unresolved' }
            elseif ($path) { $classification = 'Corpus context observed; filesystem/cache/MM owner unresolved' }
            $contexts += [pscustomobject]@{ Block=$block; Node=$candidate; Payload=(ConvertTo-T4KdAddress $payload.Groups[1].Value);
                Identity=$id; IdentityKnown=$identityKnown; CorpusPath=$path; Instance=$instance;
                RegistryEntry=$(if ($registry.Success) { ConvertTo-T4KdAddress $registry.Groups[1].Value } else { $null }); H=$h; W=$w; T=$t;
                AttachedObject=$attachment; AttachmentObserved=$attachmentObserved; UseCount=$references; ReferencedBeyondAttachment=$beyond; HasWriterNodes=$hasWriters;
                MatchingAnchors=$matchingAnchors.Count; Classification=$classification;
                FileObjects=@([regex]::Matches($body,'(?m)^T4_FILE_OBJECT ([0-9a-fA-F`]+)\s*$') | ForEach-Object { ConvertTo-T4KdAddress $_.Groups[1].Value } | Select-Object -Unique);
                ControlAreas=@([regex]::Matches($body,'(?m)^T4_CONTROL_AREA ([0-9a-fA-F`]+)\s*$') | ForEach-Object { ConvertTo-T4KdAddress $_.Groups[1].Value } | Select-Object -Unique);
                SectionObjectPointers=@([regex]::Matches($body,'(?m)^T4_SOP ([0-9a-fA-F`]+)\s*$') | ForEach-Object { ConvertTo-T4KdAddress $_.Groups[1].Value } | Select-Object -Unique);
                SharedCacheMaps=@([regex]::Matches($body,'(?m)^T4_SHARED_CACHE_MAP ([0-9a-fA-F`]+)\s*$') | ForEach-Object { ConvertTo-T4KdAddress $_.Groups[1].Value } | Select-Object -Unique);
                ScbCandidates=@([regex]::Matches($body,'(?m)^T4_SCB ([0-9a-fA-F`]+)\s*$') | ForEach-Object { ConvertTo-T4KdAddress $_.Groups[1].Value } | Select-Object -Unique);
                Errors=@(Get-T4KdErrors $body) }
        }
    }
    [pscustomobject]@{ Contexts=$contexts; Attempts=$attempts; Anchors=$anchors }
}

function Write-T4DeleteEvidence([string]$Path, [string]$Text) {
    $bytes = [Text.UTF8Encoding]::new($false).GetBytes($Text)
    $stream = [IO.FileStream]::new($Path,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::Read)
    try { $stream.Write($bytes,0,$bytes.Length) } finally { $stream.Dispose() }
}

function Invoke-T4DeleteKdSession([string]$Label, [string]$Commands) {
    # Six sessions per snapshot (18 per row), plus two possible teardown veto reads. No exception may skip the coordinator's result writer.
    $out = Join-Path $script:T4MemoryRoot 'output'
    $record = [ordered]@{ Label=$Label; Finished=$false; Complete=$false; ExitCode=$null; Errors=@(); ElapsedMs=0; CompletionMarker=('T4_KD_' + $Label.Replace('-','_').ToUpperInvariant() + '_END') }
    $timer = [Diagnostics.Stopwatch]::StartNew(); $process = $null
    try {
        if ($script:T4DeleteKdUnreaped) { throw 'Earlier KD process could not be reaped; refusing overlapping debugger sessions.' }
        [void](New-Item -ItemType Directory -Force -Path $out)
        $commandPath = Join-Path $out ($Label + '.commands.txt')
        $stdout = Join-Path $out ($Label + '.stdout.txt'); $stderr = Join-Path $out ($Label + '.stderr.txt')
        foreach ($path in $commandPath,$stdout,$stderr,(Join-Path $out ($Label + '.result.json'))) { if (Test-Path -LiteralPath $path) { throw ('Refuse to overwrite KD evidence: ' + $path) } }
        $record.Stdout=$stdout; $record.Stderr=$stderr; $record.Commands=$commandPath
        Write-T4DeleteEvidence $commandPath (Get-T4DeleteSessionCommands $Label $Commands)
        $symbols = $script:T4MemoryRoot + '\symbols;srv*' + $script:T4MemoryRoot + '\symcache*https://msdl.microsoft.com/download/symbols'
        $arguments = '-kl -y "' + $symbols + '" -c "$$><' + $commandPath + '"'
        $process = Start-Process -FilePath (Join-Path $script:T4MemoryRoot 'x64\kd.exe') -ArgumentList $arguments -PassThru -NoNewWindow `
            -RedirectStandardOutput $stdout -RedirectStandardError $stderr
        $null = $process.Handle
        # WaitForExit uses elapsed time, independent of the guest clock.
        $record.Finished = $process.WaitForExit(180000)
        if (-not $record.Finished) { $process.Kill(); $null = $process.WaitForExit(5000); $record.Errors += 'KD session exceeded 180 seconds; killed, partial output retained.' }
        $process.Refresh(); if ($process.HasExited) { $record.ExitCode=$process.ExitCode }
        $text = [IO.File]::ReadAllText($stdout)
        $record.Complete = $text -match ('(?m)^' + [regex]::Escape($record.CompletionMarker) + '\s*$')
        if (-not $record.Complete -or $record.ExitCode -ne 0) { $record.Errors += 'KD session incomplete or nonzero exit.' }
        $record.KernelAttached = $text -match 'Windows .*Kernel Version'
        $record.PrivateSymbols = $text -match 'SafeUpload[^\r\n]*\(private pdb symbols\)'
        if (-not $record.KernelAttached -or -not $record.PrivateSymbols) { $record.Errors += 'Kernel attachment or matching private symbols unavailable.' }
        $record.Errors += @(Get-T4KdErrors $text)
        $errorText = [IO.File]::ReadAllText($stderr)
        if ($errorText.Trim()) { $record.Errors += $errorText }
    } catch { $record.Errors += $_.Exception.ToString() }
    finally {
        if ($process) {
            try { if (-not $process.HasExited) { $process.Kill(); $null=$process.WaitForExit(5000) } } catch { $record.Errors += $_.Exception.Message }
            try { $script:T4DeleteKdUnreaped = -not $process.HasExited } catch { $script:T4DeleteKdUnreaped=$true }
            try { $process.Dispose() } catch { $record.Errors += $_.Exception.Message }
        }
        $record.ElapsedMs=$timer.ElapsedMilliseconds
        try { Write-T4DeleteEvidence (Join-Path $out ($Label + '.result.json')) ($record | ConvertTo-Json -Depth 5) }
        catch { $record.Errors += ('KD result write failed: ' + $_.Exception.Message) }
    }
    [pscustomobject]$record
}

function Save-T4DeleteSnapshot([string]$Label, [object[]]$Corpus, $Baseline) {
    $summary = [ordered]@{ Label=$Label; NonQualifying=$true; Errors=@(); Sessions=@(); Pass2=$null; Census=$null;
        Counts=$null; Classification='Unresolved'; Contexts=@(); Attempts=@(); AnchorDetails=@(); NewBlocks=@();
        Limitations=@('Local KD is non-atomic; confirm ownership from raw walks.',
            'New means absent pool address at del-baseline; reuse at an old address is invisible.',
            'At most 64 new blocks, 64 anchors and 8 writer nodes per context; no population extrapolation.',
            'A writer/SOP pointer is non-owning. UseCount > 1 does not identify the owner.',
            'Unparsed/free/lookaside storage is not a live attached stream context.') }
    try {
        $texts = @{}; $receipts = @{}
        foreach ($block in 'layout','telemetry','logical','anchors','poolfind') {
            # Per-block catch includes command generation/output reads, not just KD startup.
            $texts[$block] = ''
            try {
                $receipt = Invoke-T4DeleteKdSession ($Label + '-' + $block) ((Get-T4DeletePass1Commands $block) -join "`r`n")
                $receipts[$block] = $receipt; $summary.Sessions += $receipt
                $summary.Errors += @($receipt.Errors)
                if ($receipt.Stdout -and (Test-Path -LiteralPath $receipt.Stdout)) {
                    $raw = [IO.File]::ReadAllText($receipt.Stdout)
                    if ($receipt.KernelAttached -and $receipt.PrivateSymbols) { $texts[$block] = $raw }
                }
            } catch { $summary.Errors += ($block + ': ' + $_.Exception.Message) }
        }
        $one = @('layout','telemetry','logical','anchors','poolfind' | ForEach-Object { $texts[$_] }) -join "`r`n"
        $census = ConvertFrom-T4DeletePass1 $one
        $poolReceipt = $receipts['poolfind']
        if (-not $poolReceipt -or -not $poolReceipt.Finished -or -not $poolReceipt.Complete -or $poolReceipt.ExitCode -ne 0) { $census.PoolComplete=$false }
        $summary.Census = $census
        $new = @(Get-T4DeleteNewBlocks $census $Baseline)
        $summary.NewBlocks=$new
        $summary.Pass2 = Invoke-T4DeleteKdSession ($Label + '-pass2') (Get-T4DeletePass2Commands $new $census.Layout)
        $summary.Sessions += $summary.Pass2
        $two = if ($summary.Pass2.Stdout -and (Test-Path -LiteralPath $summary.Pass2.Stdout)) { [IO.File]::ReadAllText($summary.Pass2.Stdout) } else { '' }
        $parseOne = $texts['anchors']
        $parseTwo = if ($summary.Pass2.KernelAttached -and $summary.Pass2.PrivateSymbols) { $two } else { '' }
        $parsed = ConvertFrom-T4DeletePass2 $parseTwo $Corpus $parseOne
        $summary.Contexts = $parsed.Contexts; $summary.Attempts = $parsed.Attempts; $summary.AnchorDetails=$parsed.Anchors
        $knownNew = $census.PoolComplete -and ($Label -eq 'del-baseline' -or ($null -ne $Baseline -and $Baseline.PoolComplete))
        $summary.Counts = [ordered]@{ ObservedPoolBlocks=$census.Blocks.Count; OutstandingPoolBlocks=$(if ($census.PoolComplete) { $census.Blocks.Count } else { $null }); NewBlocks=$(if ($knownNew) { $new.Count } else { $null });
            SelectedBlocks=[math]::Min(64,$new.Count); InspectedBlocks=[regex]::Matches($two,'(?m)^T4_BLOCK_END\s*$').Count; OmittedNewBlocks=[math]::Max(0,$new.Count-64);
            Pass2Complete=($summary.Pass2.Finished -and $summary.Pass2.Complete -and $summary.Pass2.ExitCode -eq 0);
            PoolUsedSUfl=@($census.Telemetry.PoolUsed | Where-Object { $_.Tag -ceq 'SUfl' });
            VerifierDriverStats=$census.Telemetry.VerifierDriverStats;
            ObservedVerifierSUflAllocations=$(if ($census.Telemetry.VerifierDriverStats) { @($census.Telemetry.VerifierAllocations | Where-Object { $_.Tag -ceq 'SUfl' }).Count } else { $null });
            ParsedContexts=$parsed.Contexts.Count; CorpusContexts=@($parsed.Contexts | Where-Object { $_.CorpusPath }).Count;
            Anchors=$census.Anchors; ParsedAnchors=$parsed.Anchors.Count; AnchorWalkComplete=$census.AnchorWalkComplete;
            LogicalOutstanding=$(if ($census.Logical) { $census.Logical.Outstanding } else { $null });
            LogicalPoolStorage=$(if ($census.Logical) { $census.Logical.PoolStorage } else { $null });
            LogicalCachedEstimate=$(if ($census.Logical) { $census.Logical.CachedEstimate } else { $null });
            CorpusOwningAnchors=@($parsed.Anchors | Where-Object { $_.CorpusPath -and $_.OwningPairObserved }).Count;
            ContextsWithWriterNodes=@($parsed.Contexts | Where-Object { $_.HasWriterNodes -eq $true }).Count;
            ContextsReferencedBeyondAttachment=@($parsed.Contexts | Where-Object { $_.ReferencedBeyondAttachment -eq $true }).Count;
            ContextsWithUnknownIdentity=@($parsed.Contexts | Where-Object { -not $_.IdentityKnown }).Count;
            ContextsWithUnknownWriterList=@($parsed.Contexts | Where-Object { $null -eq $_.HasWriterNodes }).Count;
            ContextsWithUnknownAttachmentReferences=@($parsed.Contexts | Where-Object { $null -eq $_.ReferencedBeyondAttachment }).Count }
        $summary.Errors += @($census.Errors) + @($summary.Pass2.Errors)
        if (-not $knownNew) { $summary.Errors += 'No complete baseline/current pool census; delta unknown, not zero.' }
        if ($summary.Counts.CorpusOwningAnchors -gt 0) { $summary.Classification='SafeUpload owning anchor observed; corroborate non-atomic identity and owner walks' }
        elseif (@($parsed.Contexts | Where-Object { $_.IdentityKnown -and -not $_.CorpusPath }).Count -gt $parsed.Contexts.Count/2) {
            $summary.Classification='Mixed/global activity in inspected sample; bounded selection is not the population'
        }
        $summary.Discriminators = [ordered]@{
            SafeUploadLifetime = $(if ($summary.Counts.CorpusOwningAnchors) { 'Corpus owning anchor candidate observed; verify raw identity/instance walks' } else { 'Unresolved; absence of an observed anchor is not absence of an owner' })
            FilesystemCacheMmRetention = 'Unresolved; raw stream/SCB, FILE_OBJECT and control-area walks require positive owner attribution'
            LookasidePoolCountMismatch = 'Unresolved; compare logical allocator counts and pool storage, not failed context parses'
            MixedGlobalActivity = $summary.Classification
        }
        # Never infer NTFS/cache ownership or lookaside storage from an empty writer list, pool delta or failed parse.
    } catch { $summary.Errors += $_.Exception.ToString() }
    try {
        Write-T4DeleteEvidence (Join-Path $script:T4MemoryRoot ('output\' + $Label + '.summary.json')) ($summary | ConvertTo-Json -Depth 12)
    } catch { $summary.Errors += ('Summary write failed: ' + $_.Exception.Message) }
    [pscustomobject]$summary
}
