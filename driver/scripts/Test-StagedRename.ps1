<# Staged temporary-file rename test. Runs only on the isolated debuggee. #>
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'StagedTestAgent.ps1')
$installed = 'C:\Windows\System32\drivers\SafeUpload.sys'
$backup = 'C:\Users\vika\Documents\SafeUpload-original-before-rename.sys'
$expected = 'ADA9D05AB6AECDD2B6C521B0CE529FC06C732154ACB3EE85439FBDC8AA80DFCE'
$serviceDir = 'C:\Users\vika\Documents\stage-service-publish'
$root = 'C:\SafeUpload\Escopo Monitorado'
$journal = 'C:\ProgramData\SafeUpload\staging-journal'
$id = [guid]::NewGuid().ToString('N')
$targets = @()
$cleanup = @()
$agent = $null
$loaded = $false
$replaced = $false
$heldVersion = $null
if ((Get-FileHash $installed -Algorithm SHA256).Hash -ne $expected) {
    throw 'Installed driver is not the known original.'
}
Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;
using System.Text;
public static class SafeUploadRenameProbe {
    [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
    static extern SafeFileHandle CreateFile(string path, uint access, uint share,
        IntPtr security, uint disposition, uint flags, IntPtr template);
    [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
    static extern uint GetFinalPathNameByHandle(SafeFileHandle file, StringBuilder path,
        uint length, uint flags);
    [DllImport("kernel32.dll", SetLastError=true)]
    static extern bool SetFileInformationByHandle(SafeFileHandle file, int infoClass,
        IntPtr info, uint length);
    [DllImport("ntdll.dll")]
    static extern int NtQueryObject(SafeFileHandle file, uint infoClass,
        IntPtr info, uint length, out uint returned);
    [StructLayout(LayoutKind.Sequential)]
    struct IoStatus { public IntPtr Status; public UIntPtr Information; }
    [DllImport("ntdll.dll")]
    static extern int NtSetInformationFile(SafeFileHandle file, out IoStatus status,
        IntPtr info, uint length, int infoClass);
    [DllImport("ntdll.dll")]
    static extern int NtQueryInformationFile(SafeFileHandle file, out IoStatus status,
        IntPtr info, uint length, int infoClass);
    public static string AllInformationName(SafeFileHandle file) {
        IntPtr info = Marshal.AllocHGlobal(4096);
        try {
            IoStatus io;
            int status = NtQueryInformationFile(file, out io, info, 4096, 18);
            if (status != 0) throw new Exception("FileAllInformation: 0x" + status.ToString("X8"));
            int length = Marshal.ReadInt32(info, 96);
            if (length < 0 || length > 3996 || (length & 1) != 0)
                throw new Exception("Invalid FileAllInformation name length");
            return Marshal.PtrToStringUni(IntPtr.Add(info, 100), length / 2);
        }
        finally { Marshal.FreeHGlobal(info); }
    }
    public static int OpenDelete(string path) {
        using (var file = CreateFile(path, 0x10000, 7, IntPtr.Zero, 3, 0x80, IntPtr.Zero))
            return file.IsInvalid ? Marshal.GetLastWin32Error() : 0;
    }
    public static string FinalPath(string path) {
        using (var file = CreateFile(path, 0x10000, 7, IntPtr.Zero, 3, 0x80, IntPtr.Zero)) {
            if (file.IsInvalid) return "open-error:" + Marshal.GetLastWin32Error();
            var result = new StringBuilder(2048);
            return GetFinalPathNameByHandle(file, result, 2048, 0) == 0
                ? "query-error:" + Marshal.GetLastWin32Error() : result.ToString();
        }
    }
    public static string FinalPathForHandle(SafeFileHandle file) {
        var result = new StringBuilder(2048);
        if (GetFinalPathNameByHandle(file, result, 2048, 0) == 0)
            throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error());
        return result.ToString();
    }
    public static string GrantedAccess(string path) {
        using (var file = CreateFile(path, 0x10000, 7, IntPtr.Zero, 3, 0x80, IntPtr.Zero)) {
            if (file.IsInvalid) return "open-error:" + Marshal.GetLastWin32Error();
            IntPtr info = Marshal.AllocHGlobal(64);
            try {
                uint returned;
                int status = NtQueryObject(file, 0, info, 56, out returned);
                return status == 0 ? "0x" + Marshal.ReadInt32(info, 4).ToString("X8")
                                   : "query-status:0x" + status.ToString("X8");
            }
            finally { Marshal.FreeHGlobal(info); }
        }
    }
    public static int Rename(string source, string destination) {
        using (var file = CreateFile(source, 0x10000, 7, IntPtr.Zero, 3, 0x80, IntPtr.Zero)) {
            if (file.IsInvalid) return Marshal.GetLastWin32Error();
            byte[] name = Encoding.Unicode.GetBytes(destination);
            IntPtr info = Marshal.AllocHGlobal(20 + name.Length + 2);
            try {
                Marshal.Copy(new byte[20], 0, info, 20);
                Marshal.WriteInt32(info, 16, name.Length);
                Marshal.Copy(name, 0, IntPtr.Add(info, 20), name.Length);
                Marshal.WriteInt16(info, 20 + name.Length, 0);
                return SetFileInformationByHandle(file, 3, info, (uint)(20 + name.Length + 2))
                    ? 0 : Marshal.GetLastWin32Error();
            }
            finally { Marshal.FreeHGlobal(info); }
        }
    }
    public static string NtRename(string source, string destination) {
        using (var file = CreateFile(source, 0x10000, 7, IntPtr.Zero, 3, 0x80, IntPtr.Zero)) {
            if (file.IsInvalid) return "open-error:" + Marshal.GetLastWin32Error();
            byte[] name = Encoding.Unicode.GetBytes(@"\??\" + destination);
            IntPtr info = Marshal.AllocHGlobal(20 + name.Length + 2);
            try {
                Marshal.Copy(new byte[20], 0, info, 20);
                Marshal.WriteInt32(info, 16, name.Length);
                Marshal.Copy(name, 0, IntPtr.Add(info, 20), name.Length);
                Marshal.WriteInt16(info, 20 + name.Length, 0);
                IoStatus status;
                return "0x" + NtSetInformationFile(file, out status, info,
                    (uint)(20 + name.Length + 2), 10).ToString("X8");
            }
            finally { Marshal.FreeHGlobal(info); }
        }
    }
}
'@
try {
    New-Item -ItemType Directory -Force -Path $root,$serviceDir | Out-Null
    & tar.exe -xf 'C:\Users\vika\Documents\stage-service-publish.zip' -C $serviceDir
    if ($LASTEXITCODE -ne 0) { throw 'Service extraction failed.' }
    Copy-Item $installed $backup -Force
    Copy-Item 'C:\Users\vika\Documents\SafeUpload-stage-prototype.sys' $installed -Force
    $replaced = $true
    & fltmc.exe load SafeUpload | Out-Host
    if ($LASTEXITCODE -ne 0) { throw 'Driver load failed.' }
    $loaded = $true
    $agent = Start-StagedTestAgent $serviceDir 'C:\Users\vika\Documents\stage-rename-service'
    foreach ($sensitive in @($true,$false)) {
        $temporary = Join-Path $root ("rename-$id-$sensitive.tmp")
        $final = [IO.Path]::ChangeExtension($temporary, '.txt')
        $targets += @($temporary,$final)
        $content = if ($sensitive) { 'CPF: 529.982.247-25' } else { 'clean office save' }
        $saved = $false
        for ($attempt = 0; $attempt -lt 30 -and -not $saved; $attempt++) {
            Start-Sleep -Milliseconds 250
            if ($agent.Process.HasExited) { throw 'Agent exited.' }
            try { [IO.File]::WriteAllText($temporary, $content); $saved = $true }
            catch [IO.IOException] { }
            catch [UnauthorizedAccessException] { }
        }
        if (-not $saved) { throw 'Temporary-file save never succeeded.' }
        $heldVersion = [IO.FileStream]::new($temporary, [IO.FileMode]::Open,
            [IO.FileAccess]::Read, [IO.FileShare]::ReadWrite -bor [IO.FileShare]::Delete)
        Write-Output "WriterMetadataExists=$([IO.File]::Exists($temporary))"
        $writerEntries = @(Get-ChildItem -LiteralPath $root -Filter ([IO.Path]::GetFileName($temporary)))
        if ($writerEntries.Count -ne 1 -or $writerEntries[0].Length -ne [Text.Encoding]::UTF8.GetByteCount($content)) {
            throw 'The writer directory listing does not contain the staged file and size.'
        }
        Write-Output "WriterDirectoryEntryCount=$($writerEntries.Count); Length=$($writerEntries[0].Length)"
        Write-Output "NativeDeleteOpenError=$([SafeUploadRenameProbe]::OpenDelete($temporary))"
        Write-Output "NativeDeleteGrantedAccess=$([SafeUploadRenameProbe]::GrantedAccess($temporary))"
        $nativeFinalPath = [SafeUploadRenameProbe]::FinalPath($temporary)
        Write-Output "NativeFinalPath=$nativeFinalPath"
        if ($nativeFinalPath -ne ('\\?\' + $temporary)) {
            throw 'The native path query exposed the backing namespace.'
        }
        $renamed = $false
        for ($attempt = 0; $attempt -lt 40 -and -not $renamed; $attempt++) {
            try { [IO.File]::Move($temporary, $final); $renamed = $true }
            catch [IO.IOException] { Start-Sleep -Milliseconds 250 }
            catch [UnauthorizedAccessException] {
                Write-Output "NativeRenameError=$([SafeUploadRenameProbe]::Rename($temporary, $final))"
                Write-Output "NativeNtRenameStatus=$([SafeUploadRenameProbe]::NtRename($temporary, $final))"
                # Allow the asynchronous console logger to persist the
                # refusal evidence before the cleanup task stops the agent.
                Start-Sleep -Seconds 1
                throw
            }
        }
        if (-not $renamed) { throw 'Temporary-file rename never succeeded.' }
        Write-Output "RenameFinal=$final"
        if ([IO.File]::ReadAllText($final) -ne $content -or [IO.File]::Exists($temporary)) {
            throw 'Writer rename namespace is inconsistent.'
        }
        if (@(Get-ChildItem -LiteralPath $root -Filter ([IO.Path]::GetFileName($temporary))).Count -ne 0 -or
            @(Get-ChildItem -LiteralPath $root -Filter ([IO.Path]::GetFileName($final))).Count -ne 1) {
            throw 'The writer directory listing did not follow the virtual rename.'
        }
        $done = $false
        for ($attempt = 0; $attempt -lt 40 -and -not $done; $attempt++) {
            $entries = @(Get-ChildItem -LiteralPath $journal -Filter '*.json' |
                ForEach-Object { Get-Content -LiteralPath $_.FullName -Raw | ConvertFrom-Json } |
                Where-Object { $_.Transfer.DestinationPath -eq $final })
            if ($sensitive -and (& powershell.exe -NoProfile -Command "[IO.File]::Exists('$final')") -ne 'False') {
                throw 'Unapproved renamed bytes appeared at the destination.'
            }
            $expectedState = if ($sensitive) { 6 } else { 5 }
            $done = $entries.Count -eq 1 -and $entries[0].State -eq $expectedState
            if ($attempt -eq 10 -and $entries.Count -eq 1 -and $entries[0].State -eq 4 -and
                (Test-Path 'C:\Users\vika\Documents\stage-debug-tools\cdb.exe')) {
                & 'C:\Users\vika\Documents\stage-debug-tools\cdb.exe' -pv -p $agent.Process.Id `
                    -c '~* kb;qd' -logo 'C:\Users\vika\Documents\stage-publisher-stacks.log' | Out-Null
            }
            if (-not $done) { Start-Sleep -Milliseconds 250 }
        }
        if (-not $done) {
            $entries | ConvertTo-Json -Depth 8 | Write-Output
            throw 'Renamed version did not reach its inspected outcome.'
        }
        Write-Output "RenameSensitive=$sensitive; Outcome=$($entries[0].State); WriterRead=$content"
        $heldPath = [SafeUploadRenameProbe]::FinalPathForHandle($heldVersion.SafeFileHandle)
        if ($heldPath -ine ('\\?\' + $final)) { throw "Earlier handle did not follow the virtual rename: $heldPath" }
        if ($sensitive) {
            [IO.File]::AppendAllText($final, ' next version')
            $heldPath = [SafeUploadRenameProbe]::FinalPathForHandle($heldVersion.SafeFileHandle)
            if ($heldPath -ine ('\\?\' + $final)) { throw "Earlier handle leaked its backing name after rotation: $heldPath" }
            $allName = [SafeUploadRenameProbe]::AllInformationName($heldVersion.SafeFileHandle)
            if ($allName -ine $final.Substring(2)) { throw "FileAllInformation leaked its backing name: $allName" }
            $reader = [IO.StreamReader]::new($heldVersion, [Text.Encoding]::UTF8, $true, 1024, $true)
            try { $oldBytes = $reader.ReadToEnd() } finally { $reader.Dispose() }
            if ($oldBytes -ne $content) { throw 'A later save changed bytes held by the earlier version handle.' }
            Write-Output "EarlierHandleVirtualNameAfterRotation=$heldPath; EarlierVersionBytesPreserved=True"
            Write-Output "EarlierHandleAllInformationName=$allName"
        }
        $heldVersion.Dispose()
        $heldVersion = $null
        if (-not $sensitive) {
            $published = & powershell.exe -NoProfile -Command "[IO.File]::ReadAllText('$final')"
            if ($published -ne $content) { throw 'Renamed publication bytes differ.' }
        }
    }
}
finally {
    if ($heldVersion) { $heldVersion.Dispose() }
    Stop-StagedTestAgent $agent
    Save-StagedVerifierEvidence
    if ($loaded) { & fltmc.exe unload SafeUpload | Out-Host }
    if ($replaced) { Copy-Item $backup $installed -Force }
    if ((Get-FileHash $installed -Algorithm SHA256).Hash -ne $expected) {
        throw 'Original driver restoration failed.'
    }
    if (Test-Path $journal) {
        Get-ChildItem -LiteralPath $journal -Filter '*.json' | ForEach-Object {
            $entry = Get-Content -LiteralPath $_.FullName -Raw | ConvertFrom-Json
            if ($targets -contains $entry.Transfer.DestinationPath) {
                $cleanup += @($entry.Transfer.StagePath,$_.FullName)
            }
        }
    }
    Remove-StagedTestFiles ($cleanup + $targets)
    Write-Output 'OriginalDriverRestored=True'
}
