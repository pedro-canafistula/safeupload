<#
T4 save-cycle actor: a standard user that performs one save per command from the SYSTEM coordinator (cycles-coordinator.ps1).
Commands arrive as C:\T4\control\cmd-<n>.txt ("<n> <pattern> <name> <payload file>"); the actor answers with ack-<n>.txt
("ok" or "error <message>") and deletes the command. "stop" ends the actor.

Patterns:
  resave   File.WriteAllBytes over an existing name (a follow-up version)
  new      File.WriteAllBytes to a new name
  replace  write a private temporary name and, through the same handle, rename it over the target (an application-style save;
           renaming after the close could race the service's inspection of the temporary version)
  mapped   open, size, map read-write, CLOSE THE HANDLE, store through the view, flush, unmap, close the section (C02's order:
           no request reaches the file system after the unmap, so the version is sealed by the stage worker's retry timer)
#>
param([string]$Control = 'C:\T4\control', [string]$Root = 'C:\Protected\t4')
$ErrorActionPreference = 'Stop'
Add-Type -TypeDefinition @'
using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
public static class T4Native {
    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool WriteFile(IntPtr h, byte[] buffer, int count, out int written, IntPtr overlapped);
    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool FlushFileBuffers(IntPtr h);
    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool SetFileInformationByHandle(IntPtr h, int infoClass, IntPtr info, int size);
    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    static extern IntPtr CreateFileW(string name, uint access, uint share, IntPtr sa, uint disposition, uint flags, IntPtr template);
    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool SetFilePointerEx(IntPtr h, long distance, IntPtr newPointer, uint method);
    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool SetEndOfFile(IntPtr h);
    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    static extern IntPtr CreateFileMappingW(IntPtr h, IntPtr sa, uint protect, uint high, uint low, string name);
    [DllImport("kernel32.dll", SetLastError = true)]
    static extern IntPtr MapViewOfFile(IntPtr section, uint access, uint high, uint low, UIntPtr length);
    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool FlushViewOfFile(IntPtr view, UIntPtr length);
    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool UnmapViewOfFile(IntPtr view);
    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool CloseHandle(IntPtr h);
    static void Check(bool ok, string step) { if (!ok) throw new Win32Exception(Marshal.GetLastWin32Error(), step); }
    public static void Replace(string temporary, string target, byte[] bytes) {
        // GENERIC_WRITE | DELETE, CREATE_ALWAYS; the rename goes through this handle before it closes.
        IntPtr file = CreateFileW(temporary, 0x40000000 | 0x00010000, 0, IntPtr.Zero, 2, 0x80, IntPtr.Zero);
        Check(file != new IntPtr(-1), "CreateFile");
        try {
            int written;
            Check(WriteFile(file, bytes, bytes.Length, out written, IntPtr.Zero) && written == bytes.Length, "WriteFile");
            Check(FlushFileBuffers(file), "FlushFileBuffers");
            // FILE_RENAME_INFO (x64): BOOLEAN ReplaceIfExists at 0, HANDLE RootDirectory at 8, DWORD FileNameLength at 16, name at 20.
            byte[] name = System.Text.Encoding.Unicode.GetBytes(target);
            int size = 20 + name.Length + 2;
            IntPtr info = Marshal.AllocHGlobal(size);
            try {
                for (int i = 0; i < size; ++i) Marshal.WriteByte(info, i, 0);
                Marshal.WriteByte(info, 0, 1);
                Marshal.WriteInt32(info, 16, name.Length);
                Marshal.Copy(name, 0, info + 20, name.Length);
                Check(SetFileInformationByHandle(file, 3 /* FileRenameInfo */, info, size), "SetFileInformationByHandle(rename)");
            } finally { Marshal.FreeHGlobal(info); }
        } finally { CloseHandle(file); }
    }
    public static void Mapped(string path, byte[] bytes) {
        IntPtr file = CreateFileW(path, 0xC0000000, 0, IntPtr.Zero, 4 /* OPEN_ALWAYS */, 0x80, IntPtr.Zero);
        Check(file != new IntPtr(-1), "CreateFile");
        IntPtr section = IntPtr.Zero, view = IntPtr.Zero;
        try {
            Check(SetFilePointerEx(file, bytes.Length, IntPtr.Zero, 0), "SetFilePointerEx");
            Check(SetEndOfFile(file), "SetEndOfFile");
            section = CreateFileMappingW(file, IntPtr.Zero, 4 /* PAGE_READWRITE */, 0, (uint)bytes.Length, null);
            Check(section != IntPtr.Zero, "CreateFileMapping");
            view = MapViewOfFile(section, 2 /* FILE_MAP_WRITE */, 0, 0, new UIntPtr((uint)bytes.Length));
            Check(view != IntPtr.Zero, "MapViewOfFile");
        } finally {
            CloseHandle(file); // the view and the section are the only upper references from here on
        }
        try {
            Marshal.Copy(bytes, 0, view, bytes.Length);
            Check(FlushViewOfFile(view, new UIntPtr((uint)bytes.Length)), "FlushViewOfFile");
        } finally {
            UnmapViewOfFile(view);
            CloseHandle(section);
        }
    }
}
'@
if (-not (Test-Path -LiteralPath $Root)) { throw "missing $Root (created before the driver loads)" }
'ACTOR_STARTED pid=' + $PID + ' user=' + [Security.Principal.WindowsIdentity]::GetCurrent().Name | Set-Content -LiteralPath (Join-Path $Control 'actor-started.txt')
for (;;) {
    $command = Get-ChildItem -LiteralPath $Control -Filter 'cmd-*.txt' -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($null -eq $command) { Start-Sleep -Milliseconds 5; continue }
    $line = (Get-Content -LiteralPath $command.FullName -Raw).Trim()
    if ($line -eq 'stop') { Remove-Item -LiteralPath $command.FullName -Force; break }
    $parts = $line -split ' ', 4
    $n = $parts[0]; $pattern = $parts[1]; $name = $parts[2]; $bytes = [IO.File]::ReadAllBytes($parts[3])
    $target = Join-Path $Root $name
    $result = 'ok'
    try {
        switch ($pattern) {
            'resave' { [IO.File]::WriteAllBytes($target, $bytes) }
            'new' { [IO.File]::WriteAllBytes($target, $bytes) }
            'replace' { [T4Native]::Replace((Join-Path $Root ('~tmp-' + $n + '.txt')), $target, $bytes) }
            'mapped' { [T4Native]::Mapped($target, $bytes) }
            default { throw "unknown pattern $pattern" }
        }
    } catch { $result = 'error ' + ($_.Exception.Message -replace '\s+', ' ') }
    $ack = Join-Path $Control ('ack-' + $n + '.txt')
    Set-Content -LiteralPath ($ack + '.tmp') -Value $result
    Move-Item -LiteralPath ($ack + '.tmp') -Destination $ack -Force
    Remove-Item -LiteralPath $command.FullName -Force
}
'ACTOR_STOPPED' | Set-Content -LiteralPath (Join-Path $Control 'actor-stopped.txt')
