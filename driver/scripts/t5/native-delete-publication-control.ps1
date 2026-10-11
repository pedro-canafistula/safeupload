#requires -Version 5.1
# Unprotected NTFS control for the existing publication rename, not a product gate.
$ErrorActionPreference = 'Stop'
Add-Type -TypeDefinition @'
using System;
using System.ComponentModel;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;
using Microsoft.Win32.SafeHandles;
public static class NativeDeletePublicationControl {
 [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
 static extern SafeFileHandle CreateFileW(string path, uint access, uint share,
  IntPtr security, uint disposition, uint flags, IntPtr template);
 [DllImport("kernel32.dll", SetLastError=true)]
 static extern bool GetFileInformationByHandleEx(SafeFileHandle file, int kind, byte[] data, uint size);
 [DllImport("kernel32.dll", SetLastError=true)]
 static extern bool SetFileInformationByHandle(SafeFileHandle file, int kind, byte[] data, uint size);
 public static SafeFileHandle Open(string path, bool scheduled, bool writer) {
  uint access = writer ? 0x40010000U : (scheduled ? 0x80010000U : 0x80000000U);
  var file = CreateFileW(path, access, writer ? 0U : 7U, IntPtr.Zero, 3,
   scheduled ? 0x04000080U : 0x80U, IntPtr.Zero);
  if (file.IsInvalid) { int error=Marshal.GetLastWin32Error(); file.Dispose(); throw new Win32Exception(error); }
  return file;
 }
 public static string Identity(SafeFileHandle file) {
  byte[] data = new byte[24]; // FILE_ID_INFO: volume serial + full FILE_ID_128
  if (!GetFileInformationByHandleEx(file, 18, data, (uint)data.Length))
   throw new Win32Exception(Marshal.GetLastWin32Error());
  return BitConverter.ToString(data).Replace("-", "");
 }
 public static byte[] RenameBuffer(string destination) {
  byte[] name = Encoding.Unicode.GetBytes(Path.GetFullPath(destination));
  int offset = IntPtr.Size == 8 ? 20 : 12;
  byte[] data = new byte[checked(offset + name.Length + sizeof(char))];
  BitConverter.GetBytes(3U).CopyTo(data, 0); // existing REPLACE_IF_EXISTS | POSIX_SEMANTICS
  BitConverter.GetBytes(name.Length).CopyTo(data, offset - sizeof(uint));
  name.CopyTo(data, offset);
  return data;
 }
 public static int Rename(SafeFileHandle file, string destination) {
  byte[] data=RenameBuffer(destination);
  return SetFileInformationByHandle(file, 22, data, (uint)data.Length) ? 0 : Marshal.GetLastWin32Error();
 }
 public static int Probe(string path) {
  using (var file=CreateFileW(path, 0x80, 7, IntPtr.Zero, 3, 0x80, IntPtr.Zero))
   return file.IsInvalid ? Marshal.GetLastWin32Error() : 0;
 }
}
'@
$script:Assertions = 0
function Assert-Control([bool]$Condition, [string]$Message) {
    $script:Assertions++
    if (-not $Condition) { throw $Message }
}
'Builder=' + $env:COMPUTERNAME
'PSVersion=' + $PSVersionTable.PSVersion
$root = Join-Path ([IO.Path]::GetTempPath()) ('safeupload-native-delete-publish-' + [guid]::NewGuid().ToString('N'))
$volume = Get-Volume -DriveLetter ([IO.Path]::GetPathRoot($root).Substring(0, 1))
'NativeControlFileSystem=' + $volume.FileSystem
Assert-Control ($volume.FileSystem -eq 'NTFS') 'NTFS is required'
$null = New-Item -ItemType Directory -Path $root
try {
    # Self-check the actual rename encoder against the layout used by publication.
    $fixture = Join-Path $root 'encoder.txt'
    $buffer = [NativeDeletePublicationControl]::RenameBuffer($fixture)
    $offset = if ([IntPtr]::Size -eq 8) { 20 } else { 12 }
    $nameLength = [Text.Encoding]::Unicode.GetByteCount([IO.Path]::GetFullPath($fixture))
    Assert-Control ([BitConverter]::ToUInt32($buffer, 0) -eq 3) 'Rename flags differ from publication'
    Assert-Control ([BitConverter]::ToInt32($buffer, $offset - 4) -eq $nameLength) 'Rename name length mismatch'
    Assert-Control ($buffer.Length -eq $offset + $nameLength + 2) 'Rename buffer length mismatch'
    Assert-Control ([Text.Encoding]::Unicode.GetString($buffer, $offset, $nameLength) -eq $fixture) 'Rename name mismatch'
    'NativeDeletePublicationSelfCheck=PASS'

    foreach ($phase in @('before-creator-cleanup', 'after-creator-cleanup')) {
        $target = Join-Path $root ($phase + '.txt')
        $temporary = Join-Path $root ($phase + '-new.txt')
        [IO.File]::WriteAllText($target, 'original-pre-open')
        [IO.File]::WriteAllText($temporary, 'approved-successor')
        $creator = $null; $reader = $null; $replacement = $null; $check = $null
        try {
            $reader = [NativeDeletePublicationControl]::Open($target, $false, $false)
            $originalId = [NativeDeletePublicationControl]::Identity($reader)
            $creator = [NativeDeletePublicationControl]::Open($target, $true, $false)
            Assert-Control ([NativeDeletePublicationControl]::Identity($creator) -eq $originalId) 'Creator is not the original object'
            $replacement = [NativeDeletePublicationControl]::Open($temporary, $false, $true)
            $newId = [NativeDeletePublicationControl]::Identity($replacement)
            Assert-Control ($originalId.Length -eq 48 -and $newId.Length -eq 48 -and $originalId -ne $newId) 'Full identities are not distinct'
            $probeBefore = [NativeDeletePublicationControl]::Probe($target)
            Assert-Control ($probeBefore -eq 0) 'Scheduled CREATE unexpectedly made native name pending before cleanup'
            if ($phase -eq 'after-creator-cleanup') { $creator.Dispose(); $creator = $null }
            $probeAtRename = [NativeDeletePublicationControl]::Probe($target)
            $renameError = [NativeDeletePublicationControl]::Rename($replacement, $target)
            'Case=' + $phase + ';OriginalIdentity=' + $originalId + ';ReplacementIdentity=' + $newId +
                ';ProbeAtRenameWin32=' + $probeAtRename + ';PosixRenameWin32=' + $renameError
            Assert-Control ($renameError -eq 0) ('Existing publication cannot replace this native target: ' + $phase + ', Win32=' + $renameError)
            $replacement.Dispose(); $replacement = $null
            $check = [NativeDeletePublicationControl]::Open($target, $false, $false)
            Assert-Control ([NativeDeletePublicationControl]::Identity($check) -eq $newId) 'Public replacement identity mismatch'
            $check.Dispose(); $check = $null
            if ($null -ne $creator) { $creator.Dispose(); $creator = $null }
            Assert-Control ([NativeDeletePublicationControl]::Identity($reader) -eq $originalId) 'Old reader changed object'
            $reader.Dispose(); $reader = $null
            $check = [NativeDeletePublicationControl]::Open($target, $false, $false)
            $finalId = [NativeDeletePublicationControl]::Identity($check)
            $check.Dispose(); $check = $null
            Assert-Control ($finalId -eq $newId) 'Old native cleanup removed or replaced the successor'
            Assert-Control ([IO.File]::ReadAllText($target) -eq 'approved-successor') 'Final public bytes differ'
            'Case=' + $phase + ';OldHandlesClosed=True;FinalIdentity=' + $finalId + ';SuccessorBytesExact=True;Verdict=PASS'
        } finally {
            foreach ($handle in @($check, $replacement, $creator, $reader)) {
                if ($null -ne $handle) { $handle.Dispose() }
            }
        }
    }
    'NativeDeletePublicationControl=PASS;Assertions=' + $script:Assertions + ';ProductQualified=False;ProtectedDestination=False'
} finally { Remove-Item -LiteralPath $root -Recurse -Force }
