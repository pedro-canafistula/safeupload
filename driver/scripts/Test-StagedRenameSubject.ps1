<# Original-requestor access checks, including the isolated worker-probe build. #>
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'StagedTestAgent.ps1')
$installed = 'C:\Windows\System32\drivers\SafeUpload.sys'
$expected = 'ADA9D05AB6AECDD2B6C521B0CE529FC06C732154ACB3EE85439FBDC8AA80DFCE'
$backup = 'C:\Users\vika\Documents\SafeUpload-original-before-subject.sys'
$directory = 'C:\SafeUpload\Escopo Monitorado\subject-' + [guid]::NewGuid().ToString('N')
$source = Join-Path $directory 'source.txt'
$target = Join-Path $directory 'target.txt'
$agent = $null; $loaded = $false; $replaced = $false; $file = $null
$cleanup = @()
Add-Type -TypeDefinition @'
using System;
using System.ComponentModel;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;
using Microsoft.Win32.SafeHandles;
public static class SafeUploadSubjectProbe {
    [DllImport("kernel32.dll")] static extern IntPtr GetCurrentThread();
    [DllImport("advapi32.dll", SetLastError=true)] static extern bool ImpersonateAnonymousToken(IntPtr thread);
    [DllImport("advapi32.dll", SetLastError=true)] static extern bool RevertToSelf();
    [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
    static extern SafeFileHandle CreateFile(string path, uint access, uint share,
        IntPtr security, uint disposition, uint flags, IntPtr template);
    [DllImport("kernel32.dll", SetLastError=true)]
    static extern bool SetFileInformationByHandle(SafeFileHandle file, int cls, byte[] info, int size);
    public static SafeFileHandle Open(string path) {
        var file = CreateFile(path, 0xC0010000, 7, IntPtr.Zero, 2, 0x80, IntPtr.Zero);
        if (file.IsInvalid) throw new Win32Exception(Marshal.GetLastWin32Error());
        return file;
    }
    public static int Rename(SafeFileHandle file, string target, bool anonymous) {
        byte[] text=Encoding.Unicode.GetBytes(target);
        int offset=IntPtr.Size==8 ? 20 : 12;
        byte[] info=new byte[offset+text.Length+2];
        BitConverter.GetBytes(3).CopyTo(info,0);
        BitConverter.GetBytes(text.Length).CopyTo(info,offset-4);
        text.CopyTo(info,offset);
        if(anonymous && !ImpersonateAnonymousToken(GetCurrentThread())) throw new Win32Exception(Marshal.GetLastWin32Error());
        try { return SetFileInformationByHandle(file,22,info,info.Length) ? 0 : Marshal.GetLastWin32Error(); }
        finally { if(anonymous && !RevertToSelf()) throw new Win32Exception(Marshal.GetLastWin32Error()); }
    }
}
'@
if ($env:COMPUTERNAME -ne 'WIN10-DEBUGGED' -or
    (Get-CimInstance Win32_ComputerSystemProduct).UUID -ne '9D44EEE8-81CF-4CC1-9FBA-7670F11DEF4D') { throw 'Wrong debuggee.' }
if ((Get-FileHash $installed -Algorithm SHA256).Hash -ne $expected) { throw 'Original driver hash mismatch.' }
if ((& fltmc.exe filters) -match '^SafeUpload\s') { throw 'Expected unloaded baseline.' }
try {
    New-Item -ItemType Directory -Path $directory | Out-Null
    # Physical target lookup must not be the source of the rejection: allow
    # anonymous traversal/add-file in this disposable parent. The private
    # target keeps its creator's inherited descriptor before adding this ACE.
    Copy-Item $installed $backup -Force
    Copy-Item 'C:\Users\vika\Documents\SafeUpload-stage-prototype.sys' $installed -Force
    $replaced = $true
    & fltmc.exe load SafeUpload | Out-Host
    if ($LASTEXITCODE -ne 0) { throw 'Load failed.' }
    $loaded = $true
    $agent = Start-StagedTestAgent 'C:\Users\vika\Documents\stage-service-publish' 'C:\Users\vika\Documents\stage-subject-service'
    $ready = $false
    for ($i=0; $i -lt 40 -and -not $ready; $i++) {
        Start-Sleep -Milliseconds 250
        try { [IO.File]::WriteAllText($target,'CPF: 529.982.247-25'); $ready=$true } catch [IO.IOException] { } catch [UnauthorizedAccessException] { }
    }
    if (-not $ready) { throw 'Private target unavailable.' }
    $acl = Get-Acl -LiteralPath $directory
    $acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new(
        [Security.Principal.SecurityIdentifier]::new('S-1-5-7'),
        [Security.AccessControl.FileSystemRights]::FullControl,
        [Security.AccessControl.AccessControlType]::Allow))
    Set-Acl -LiteralPath $directory -AclObject $acl
    $file = [SafeUploadSubjectProbe]::Open($source)
    $denied = [SafeUploadSubjectProbe]::Rename($file,$target,$true)
    if ($denied -ne 5) { throw "Anonymous rename expected ERROR_ACCESS_DENIED; received $denied." }
    Write-Output 'ImpersonatedAnonymousPrivateReplacementDenied=True'
    # An ordinary authorized request on the same forced worker proves the
    # probe queued successfully, rather than blanket-denying all renames.
    $allowed = [SafeUploadSubjectProbe]::Rename($file,$target,$false)
    if ($allowed -ne 0) { throw "Authorized native replacement failed: $allowed" }
    Write-Output 'OriginalCallerPrivateReplacementAllowed=True'
    $file.Dispose(); $file=$null
}
finally {
    if ($null -ne $file) { $file.Dispose() }
    Stop-StagedTestAgent $agent
    if ($replaced) { Restore-StagedTestDriver $backup $loaded }
    foreach ($path in (Get-ChildItem 'C:\ProgramData\SafeUpload\staging-journal' -Filter '*.json')) {
        $entry = Get-Content -LiteralPath $path.FullName -Raw | ConvertFrom-Json
        if ($entry.Transfer.DestinationPath.StartsWith($directory,[StringComparison]::OrdinalIgnoreCase)) {
            $cleanup += @($entry.Transfer.StagePath,$path.FullName)
        }
    }
    Remove-StagedTestFiles ($cleanup + @($source,$target))
    Remove-Item -LiteralPath $directory -Force
    Write-Output 'SubjectFixturesRemoved=True'
}
