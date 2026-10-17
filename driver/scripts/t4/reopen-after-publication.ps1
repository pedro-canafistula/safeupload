<# Prestarted, independent process under the actor's token. The coordinator
signals .go only after observing the approved public bytes. One read CREATE
and one read/write CREATE; neither open is retried. Ready is published only
after compilation. Record native errors, caller PIDs, identity and QPC times.
Use cycles-coordinator.ps1 -ImmediateReopen and copy this beside cycles-actor.
This is an additional control, not a replacement for the original T4 rows. #>
param([Parameter(Mandatory=$true)][string]$Path,
      [Parameter(Mandatory=$true)][string]$ExpectedPath,
      [Parameter(Mandatory=$true)][string]$SignalPrefix,
      [Parameter(Mandatory=$true)][int]$WriterPid)
$ErrorActionPreference = 'Stop'
Add-Type -TypeDefinition @'
using System;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using Microsoft.Win32.SafeHandles;
public sealed class T4ReopenResult {
    public uint Access; public int OpenError; public int CloseError;
    public long StartedQpc; public long FinishedQpc; public bool BytesMatch;
    public string Identity; public string Error;
}
public static class T4Reopen {
    [StructLayout(LayoutKind.Sequential)] struct FileId { public ulong Volume, Low, High; }
    [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
    static extern IntPtr CreateFileW(string name, uint access, uint share, IntPtr sa, uint disposition, uint flags, IntPtr template);
    [DllImport("kernel32.dll", SetLastError=true)] static extern bool CloseHandle(IntPtr handle);
    [DllImport("kernel32.dll", SetLastError=true)] static extern bool GetFileInformationByHandleEx(IntPtr handle, int cls, out FileId id, uint size);
    public static T4ReopenResult Open(string path, uint access, byte[] expected) {
        var r = new T4ReopenResult { Access=access, StartedQpc=Stopwatch.GetTimestamp() };
        IntPtr h = CreateFileW(path, access, 7, IntPtr.Zero, 3 /* OPEN_EXISTING */, 0x80, IntPtr.Zero);
        if (h == new IntPtr(-1)) { r.OpenError=Marshal.GetLastWin32Error(); r.FinishedQpc=Stopwatch.GetTimestamp(); return r; }
        try {
            FileId id;
            if (!GetFileInformationByHandleEx(h, 18, out id, 24)) throw new Win32Exception(Marshal.GetLastWin32Error());
            r.Identity=id.Volume.ToString("X16")+":"+id.High.ToString("X16")+":"+id.Low.ToString("X16");
            using (var safe = new SafeFileHandle(h, false))
            using (var stream = new FileStream(safe, (access & 0x40000000u) != 0 ? FileAccess.ReadWrite : FileAccess.Read)) {
                bool same=stream.Length == expected.Length;
                byte[] actual=new byte[expected.Length]; int count=0;
                while (count < actual.Length) { int n=stream.Read(actual,count,actual.Length-count); if(n==0)break; count+=n; }
                same &= count == expected.Length;
                for(int i=0;i<count;i++) same &= actual[i] == expected[i];
                r.BytesMatch=same;
            }
        } catch (Exception ex) { r.Error=ex.ToString(); }
        finally { if(!CloseHandle(h))r.CloseError=Marshal.GetLastWin32Error(); r.FinishedQpc=Stopwatch.GetTimestamp(); }
        return r;
    }
}
'@
$result = [ordered]@{ WriterPid=$WriterPid; ObserverPid=$PID; Frequency=[Diagnostics.Stopwatch]::Frequency; Read=$null; ReadWrite=$null; Error=$null }
try {
    if ($PID -eq $WriterPid) { throw 'reopen must run in another process' }
    $expected = [IO.File]::ReadAllBytes($ExpectedPath)
    [IO.File]::WriteAllText(($SignalPrefix + '.ready'), [string]$PID)
    $deadline = [Diagnostics.Stopwatch]::GetTimestamp() + 180 * [Diagnostics.Stopwatch]::Frequency
    while (-not [IO.File]::Exists($SignalPrefix + '.go')) {
        if ([IO.File]::Exists($SignalPrefix + '.abort')) { throw 'publication observation failed' }
        if ([Diagnostics.Stopwatch]::GetTimestamp() -ge $deadline) { throw 'publication signal timeout' }
        Start-Sleep -Milliseconds 1
    }
    $result.SignalSeenQpc = [Diagnostics.Stopwatch]::GetTimestamp()
    $result.Read = [T4Reopen]::Open($Path, ([uint32]2147483648), $expected)
    $result.ReadWrite = [T4Reopen]::Open($Path, ([uint32]3221225472), $expected)
} catch { $result.Error = $_.Exception.ToString() }
[IO.File]::WriteAllText(($SignalPrefix + '.result.part'), ($result | ConvertTo-Json -Depth 6))
[IO.File]::Move(($SignalPrefix + '.result.part'), ($SignalPrefix + '.result.json'))
