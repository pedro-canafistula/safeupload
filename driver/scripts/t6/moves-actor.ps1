<#
T6 move actor: a standard user that moves one file per command from the SYSTEM coordinator (moves-coordinator.ps1) from an
ordinary folder into the protected folder. Commands arrive as C:\T6\control\cmd-<n>.txt ("<n> <pattern> <source> <target> <payload>");
the actor first writes the payload to <source> as itself (its own file, as a user's would be), then moves it, and answers with
ack-<n>.txt: "ok", "win32 <code>" for a refused native call, or "error <message>". "stop" ends the actor.

Patterns (what each caller does when the driver answers the rename with ERROR_NOT_SAME_DEVICE):
  movefileex  MoveFileExW(MOVEFILE_COPY_ALLOWED): kernel32 copies, then deletes the source
  moveitem    PowerShell Move-Item (.NET Framework File.Move -> MoveFileW, which allows the copy)
  cmdmove     cmd.exe move
  shell       Shell.Application Folder.MoveHere: the Explorer copy engine (SHFileOperation/IFileOperation), silent flags
  rawrename   SetFileInformationByHandle(FileRenameInfo) on the source: no fallback, the caller sees Win32 17
  hardlink    CreateHardLinkW into the folder: no fallback, Win32 17
#>
param([string]$Control = 'C:\T6\control')
$ErrorActionPreference = 'Stop'
function Read-T6ControlText([string]$Path) {
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
Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
public static class T6Native {
    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    static extern bool MoveFileExW(string source, string target, uint flags);
    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    static extern bool CreateHardLinkW(string link, string existing, IntPtr sa);
    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    static extern IntPtr CreateFileW(string name, uint access, uint share, IntPtr sa, uint disposition, uint flags, IntPtr template);
    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool SetFileInformationByHandle(IntPtr h, int infoClass, IntPtr info, int size);
    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool CloseHandle(IntPtr h);
    // 0 = success, otherwise the Win32 error of the failing call.
    public static int MoveCopyAllowed(string source, string target) {
        return MoveFileExW(source, target, 2 /* MOVEFILE_COPY_ALLOWED */) ? 0 : Marshal.GetLastWin32Error();
    }
    public static int HardLink(string link, string existing) {
        return CreateHardLinkW(link, existing, IntPtr.Zero) ? 0 : Marshal.GetLastWin32Error();
    }
    public static int RawRename(string source, string target) {
        IntPtr file = CreateFileW(source, 0x00010000 /* DELETE */, 7, IntPtr.Zero, 3 /* OPEN_EXISTING */, 0x80, IntPtr.Zero);
        if (file == new IntPtr(-1)) return -Marshal.GetLastWin32Error();
        try {
            // FILE_RENAME_INFO (x64): BOOLEAN ReplaceIfExists at 0, HANDLE RootDirectory at 8, DWORD FileNameLength at 16, name at 20.
            byte[] name = System.Text.Encoding.Unicode.GetBytes(target);
            int size = 20 + name.Length + 2;
            IntPtr info = Marshal.AllocHGlobal(size);
            try {
                for (int i = 0; i < size; ++i) Marshal.WriteByte(info, i, 0);
                Marshal.WriteInt32(info, 16, name.Length);
                Marshal.Copy(name, 0, info + 20, name.Length);
                return SetFileInformationByHandle(file, 3 /* FileRenameInfo */, info, size) ? 0 : Marshal.GetLastWin32Error();
            } finally { Marshal.FreeHGlobal(info); }
        } finally { CloseHandle(file); }
    }
}
'@
try {
'ACTOR_STARTED pid=' + $PID + ' user=' + [Security.Principal.WindowsIdentity]::GetCurrent().Name + ' apartment=' +
    [Threading.Thread]::CurrentThread.GetApartmentState() | Set-Content -LiteralPath (Join-Path $Control 'actor-started.txt')
for (;;) {
    $command = Get-ChildItem -LiteralPath $Control -Filter 'cmd-*.txt' -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($null -eq $command) { Start-Sleep -Milliseconds 5; continue }
    $line = (Read-T6ControlText $command.FullName).Trim()
    if ($line -eq 'stop') { Remove-Item -LiteralPath $command.FullName -Force; break }
    $parts = $line -split ' ', 5
    $n = $parts[0]; $pattern = $parts[1]; $source = $parts[2]; $target = $parts[3]
    $result = 'ok'
    try {
        New-Item -ItemType Directory -Force -Path (Split-Path -Parent $source) | Out-Null
        [IO.File]::WriteAllBytes($source, [IO.File]::ReadAllBytes($parts[4]))
        $code = 0
        switch ($pattern) {
            'movefileex' { $code = [T6Native]::MoveCopyAllowed($source, $target) }
            'moveitem' { Move-Item -LiteralPath $source -Destination $target -ErrorAction Stop }
            'cmdmove' {
                $out = (& cmd.exe /d /c "move /y `"$source`" `"$target`"" 2>&1 | Out-String)
                if ($LASTEXITCODE -ne 0) { throw ('cmd move exit ' + $LASTEXITCODE + ': ' + ($out -replace '\s+', ' ')) }
            }
            'shell' {
                # FOF_SILENT | FOF_NOCONFIRMATION | FOF_NOCONFIRMMKDIR | FOF_NOERRORUI. MoveHere keeps the source's leaf name.
                if ((Split-Path -Leaf $source) -ne (Split-Path -Leaf $target)) { throw 'shell move needs the same leaf name' }
                $shell = New-Object -ComObject Shell.Application
                $folder = $shell.NameSpace((Split-Path -Parent $target))
                if ($null -eq $folder) { throw 'Shell.Application could not open the destination folder' }
                $folder.MoveHere($source, 0x614)
                [void][Runtime.InteropServices.Marshal]::ReleaseComObject($folder)
                [void][Runtime.InteropServices.Marshal]::ReleaseComObject($shell)
            }
            'shelldir' {
                # Move the source's whole folder: <src root>\<dir>\<leaf> -> <protected root>\<dir>\<leaf>.
                $sourceDir = Split-Path -Parent $source; $targetDir = Split-Path -Parent $target
                if ((Split-Path -Leaf $sourceDir) -ne (Split-Path -Leaf $targetDir)) { throw 'shell folder move needs the same folder name' }
                $shell = New-Object -ComObject Shell.Application
                $folder = $shell.NameSpace((Split-Path -Parent $targetDir))
                if ($null -eq $folder) { throw 'Shell.Application could not open the destination folder' }
                $folder.MoveHere($sourceDir, 0x614)
                [void][Runtime.InteropServices.Marshal]::ReleaseComObject($folder)
                [void][Runtime.InteropServices.Marshal]::ReleaseComObject($shell)
            }
            'rawrename' { $code = [T6Native]::RawRename($source, $target) }
            'hardlink' { $code = [T6Native]::HardLink($target, $source) }
            default { throw "unknown pattern $pattern" }
        }
        if ($code -ne 0) { $result = 'win32 ' + $code }
    } catch { $result = 'error ' + ($_.Exception.Message -replace '\s+', ' ') }
    $ack = Join-Path $Control ('ack-' + $n + '.txt')
    Set-Content -LiteralPath ($ack + '.tmp') -Value $result
    [IO.File]::Move(($ack + '.tmp'), $ack)
    Remove-Item -LiteralPath $command.FullName -Force
}
'ACTOR_STOPPED' | Set-Content -LiteralPath (Join-Path $Control 'actor-stopped.txt')
} catch {
    ($_ | Format-List * -Force | Out-String) + "`n" + $_.ScriptStackTrace |
        Set-Content -LiteralPath (Join-Path $Control 'actor-error.txt')
    throw
}
