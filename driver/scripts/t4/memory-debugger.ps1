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
    $unload = Start-Process -FilePath fltmc.exe -ArgumentList 'unload SafeUpload' -PassThru -NoNewWindow `
        -RedirectStandardOutput (Join-Path $out 'unload.stdout.txt') `
        -RedirectStandardError (Join-Path $out 'unload.stderr.txt')
    $null = $unload.Handle
    if (-not $unload.WaitForExit(60000)) {
        # Terminating the caller does not force kernel unload. The host still restores the run disk.
        $unload.Kill()
        throw 'Voluntary filter unload exceeded the diagnostic deadline.'
    }
    $unload.Refresh()
    if ($unload.ExitCode -ne 0) { throw 'Voluntary filter unload was refused.' }
    Start-Sleep -Seconds 5
    Save-T4MemorySnapshot 'teardown-after' -AllowUnloaded
    'T4MemoryTeardown=PASS'
}
