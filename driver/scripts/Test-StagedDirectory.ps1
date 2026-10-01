<# Native directory pagination, buffers, patterns and observer isolation. #>
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'StagedTestAgent.ps1')
$installed = 'C:\Windows\System32\drivers\SafeUpload.sys'
$backup = 'C:\Users\vika\Documents\SafeUpload-original-before-directory.sys'
$expected = 'ADA9D05AB6AECDD2B6C521B0CE529FC06C732154ACB3EE85439FBDC8AA80DFCE'
$serviceDir = 'C:\Users\vika\Documents\stage-service-publish'
$root = 'C:\SafeUpload\Escopo Monitorado'
$journal = 'C:\ProgramData\SafeUpload\staging-journal'
$prefix = 'directory-' + [guid]::NewGuid().ToString('N') + '-'
$targets = @('approved-one.txt','approved-two.txt','private-one.txt','private-two.txt','private-three.txt') |
    ForEach-Object { Join-Path $root ($prefix + $_) }
$loaded = $false
$replaced = $false
$agent = $null
$cleanup = @()
Add-Type -TypeDefinition @'
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;
public static class SafeUploadDirectoryProbe {
    [StructLayout(LayoutKind.Sequential)]
    struct IoStatus { public IntPtr Status; public UIntPtr Information; }
    [StructLayout(LayoutKind.Sequential)]
    struct UnicodeString { public ushort Length, MaximumLength; public IntPtr Buffer; }
    [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
    static extern SafeFileHandle CreateFile(string path, uint access, uint share,
        IntPtr security, uint disposition, uint flags, IntPtr template);
    [DllImport("ntdll.dll")]
    static extern int NtQueryDirectoryFile(SafeFileHandle file, IntPtr ev, IntPtr apc,
        IntPtr context, out IoStatus io, IntPtr info, uint length, int cls,
        [MarshalAs(UnmanagedType.U1)] bool single, IntPtr pattern,
        [MarshalAs(UnmanagedType.U1)] bool restart);
    public sealed class Page {
        public uint Status; public int Bytes;
        public string[] Names; public long[] Lengths;
    }
    public static SafeFileHandle Open(string directory) {
        var handle = CreateFile(directory, 0x100001, 7, IntPtr.Zero, 3, 0x02000000, IntPtr.Zero);
        if (handle.IsInvalid) { handle.Dispose(); throw new Win32Exception(Marshal.GetLastWin32Error()); }
        return handle;
    }
    public static int Header(int cls) {
        switch(cls) {
            case 1: return 64; case 2: return 68; case 3: return 94; case 12: return 12;
            case 37: return 104; case 38: return 80; case 60: return 88; case 63: return 114;
            default: throw new ArgumentOutOfRangeException("cls");
        }
    }
    public static Page Query(SafeFileHandle file, int cls, int length,
        bool single, string expression, bool restart) {
        IntPtr buffer = Marshal.AllocHGlobal(length + 16), pattern = IntPtr.Zero, text = IntPtr.Zero;
        try {
            byte[] sentinel = new byte[length + 16];
            for (int i=0; i<sentinel.Length; ++i) sentinel[i]=0xa5;
            Marshal.Copy(sentinel, 0, buffer, sentinel.Length);
            if (expression != null) {
                text = Marshal.StringToHGlobalUni(expression);
                var unicode = new UnicodeString { Length=(ushort)(expression.Length*2),
                    MaximumLength=(ushort)(expression.Length*2+2), Buffer=text };
                pattern = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(UnicodeString)));
                Marshal.StructureToPtr(unicode, pattern, false);
            }
            IoStatus io;
            uint status = unchecked((uint)NtQueryDirectoryFile(file, IntPtr.Zero, IntPtr.Zero,
                IntPtr.Zero, out io, buffer, (uint)length, cls, single, pattern, restart));
            for (int i=length; i<length+16; ++i)
                if (Marshal.ReadByte(buffer, i)!=0xa5) throw new Exception("Directory buffer overrun");
            int bytes = checked((int)io.Information.ToUInt64());
            if (bytes<0 || bytes>length) throw new Exception("Invalid directory byte count");
            var names=new List<string>(); var lengths=new List<long>();
            int offset=0, header=Header(cls);
            if (status==0 || status==0x80000005) {
                while (bytes>offset) {
                    if (bytes-offset<header) throw new Exception("Truncated directory header");
                    IntPtr entry=IntPtr.Add(buffer,offset);
                    int nameLength=Marshal.ReadInt32(entry,cls==12 ? 8 : 60);
                    if (nameLength<0 || (nameLength&1)!=0) throw new Exception("Invalid directory name length");
                    int copied=Math.Min(nameLength,bytes-offset-header)&~1;
                    if (copied!=nameLength && status!=0x80000005) throw new Exception("Truncated successful entry");
                    names.Add(Marshal.PtrToStringUni(IntPtr.Add(entry,header),copied/2));
                    lengths.Add(cls==12 ? -1 : Marshal.ReadInt64(entry,40));
                    int next=Marshal.ReadInt32(entry,0);
                    if (next==0) break;
                    if ((next&7)!=0 || next<header || next>bytes-offset) throw new Exception("Invalid directory offset");
                    offset+=next;
                }
            }
            return new Page { Status=status, Bytes=bytes, Names=names.ToArray(), Lengths=lengths.ToArray() };
        }
        finally {
            Marshal.FreeHGlobal(buffer);
            if (pattern!=IntPtr.Zero) Marshal.FreeHGlobal(pattern);
            if (text!=IntPtr.Zero) Marshal.FreeHGlobal(text);
        }
    }
}
'@
if ((Get-FileHash $installed -Algorithm SHA256).Hash -ne $expected) { throw 'Original driver hash mismatch.' }
try {
    New-Item -ItemType Directory -Force -Path $root,$serviceDir | Out-Null
    [IO.File]::WriteAllText($targets[0], 'approved fixture one')
    [IO.File]::WriteAllText($targets[1], 'approved fixture two')
    & tar.exe -xf 'C:\Users\vika\Documents\stage-service-publish.zip' -C $serviceDir
    if ($LASTEXITCODE -ne 0) { throw 'Service extraction failed.' }
    Copy-Item $installed $backup -Force
    Copy-Item 'C:\Users\vika\Documents\SafeUpload-stage-prototype.sys' $installed -Force
    $replaced = $true
    & fltmc.exe load SafeUpload | Out-Host
    if ($LASTEXITCODE -ne 0) { throw 'Driver load failed.' }
    $loaded = $true
    $agent = Start-StagedTestAgent $serviceDir 'C:\Users\vika\Documents\stage-directory-service'
    foreach ($target in $targets[2..4]) {
        $saved = $false
        for ($attempt=0; $attempt -lt 30 -and -not $saved; $attempt++) {
            Start-Sleep -Milliseconds 250
            if ($agent.Process.HasExited) { throw 'Agent exited.' }
            try { [IO.File]::WriteAllText($target, 'CPF: 529.982.247-25'); $saved=$true }
            catch [IO.IOException] { }
            catch [UnauthorizedAccessException] { }
        }
        if (-not $saved) { throw 'Staged save failed.' }
    }
    $expectedNames=@($targets | ForEach-Object { [IO.Path]::GetFileName($_) } | Sort-Object)
    foreach ($cls in @(1,2,3,12,37,38,60,63)) {
        $handle=[SafeUploadDirectoryProbe]::Open($root)
        try {
            $names=@()
            for ($page=0; $page -lt 10; $page++) {
                $result=[SafeUploadDirectoryProbe]::Query($handle,$cls,1024,$true,($prefix+'*'),$false)
                if ($result.Status -eq [uint32]2147483654) { break }
                if ($result.Status -ne 0 -or $result.Names.Count -ne 1) {
                    throw "Single-entry query failed: class=$cls status=$($result.Status) names=$($result.Names.Count)"
                }
                $names+=$result.Names
                if ($cls -ne 12 -and $result.Names[0] -like '*private*' -and $result.Lengths[0] -ne 19) {
                    throw 'Staged entry size differs.'
                }
                if ($page -eq 0) {
                    $small=[SafeUploadDirectoryProbe]::Query($handle,$cls,([SafeUploadDirectoryProbe]::Header($cls)+16),$true,'ignored',$false)
                    if ($small.Status -ne 0 -or $small.Bytes -ne 0) { throw "Later small buffer: class=$cls status=0x$($small.Status.ToString('X8')) bytes=$($small.Bytes) names=$($small.Names -join ',')" }
                }
            }
            if (Compare-Object $expectedNames @($names | Sort-Object)) { throw "Pagination lost or duplicated entries: class=$cls" }
            $restart=[SafeUploadDirectoryProbe]::Query($handle,$cls,4096,$false,'ignored',$true)
            if ($restart.Status -ne 0 -or (Compare-Object $expectedNames @($restart.Names | Sort-Object))) {
                throw 'Restart changed the original pattern or missed entries.'
            }
        }
        finally { $handle.Dispose() }
        $handle=[SafeUploadDirectoryProbe]::Open($root)
        try {
            $partial=[SafeUploadDirectoryProbe]::Query($handle,$cls,([SafeUploadDirectoryProbe]::Header($cls)+16),$true,($prefix+'*'),$false)
            if ($partial.Status -ne [uint32]2147483653 -or $partial.Names.Count -ne 1) { throw 'First small buffer did not report overflow.' }
            $restart=[SafeUploadDirectoryProbe]::Query($handle,$cls,4096,$false,$null,$true)
            if ($restart.Status -ne 0 -or $restart.Names.Count -ne 5) { throw 'Restart after overflow lost entries.' }
        }
        finally { $handle.Dispose() }
        Write-Output "NativeDirectoryClass=$cls Pagination=True Restart=True SmallBuffers=True Sizes=True"
    }
    $observerCount=& powershell.exe -NoProfile -Command "@(Get-ChildItem -LiteralPath '$root' -Filter '$prefix*').Count"
    if ($observerCount -ne 2) { throw "Observer saw unapproved directory entries: $observerCount" }
    Write-Output 'ObserverSeesOnlyApprovedEntries=True'
}
finally {
    Stop-StagedTestAgent $agent
    Save-StagedVerifierEvidence
    if ($loaded) { & fltmc.exe unload SafeUpload | Out-Host }
    if ($replaced) { Copy-Item $backup $installed -Force }
    if ((Get-FileHash $installed -Algorithm SHA256).Hash -ne $expected) { throw 'Original driver restoration failed.' }
    if (Test-Path $journal) {
        Get-ChildItem -LiteralPath $journal -Filter '*.json' | ForEach-Object {
            $entry=Get-Content -LiteralPath $_.FullName -Raw | ConvertFrom-Json
            if ($targets -contains $entry.Transfer.DestinationPath) { $cleanup+=@($entry.Transfer.StagePath,$_.FullName) }
        }
    }
    Remove-StagedTestFiles ($cleanup+$targets)
    Write-Output 'OriginalDriverRestored=True'
}
