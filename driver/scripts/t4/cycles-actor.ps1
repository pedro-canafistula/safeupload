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
function Stop-T4ReopenProcess([Diagnostics.Process]$Process, [string]$Prefix) {
    if (-not $Process.WaitForExit(5000)) {
        $Process.Kill()
        if (-not $Process.WaitForExit(5000)) {
            [IO.File]::WriteAllText(($Prefix + '.termination-unconfirmed.json'),
                ('{"ObserverPid":' + $Process.Id + ',"TerminationConfirmed":false}'))
            throw 'reopen observer termination not confirmed'
        }
    }
}
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
    static void Check(bool ok, string step) {
        if (!ok) {
            int error = Marshal.GetLastWin32Error();
            throw new Win32Exception(error, step + " Win32=" + error);
        }
    }
    public static int ProbeOpen(string path, uint access) {
        IntPtr file = CreateFileW(path, access, 7, IntPtr.Zero, 3, 0x80, IntPtr.Zero);
        if (file == new IntPtr(-1)) return Marshal.GetLastWin32Error();
        return CloseHandle(file) ? 0 : Marshal.GetLastWin32Error();
    }
    public static void Replace(string temporary, string target, byte[] bytes) {
        // GENERIC_WRITE | DELETE, CREATE_ALWAYS; include delete sharing for the held-handle rename (as in C04).
        IntPtr file = CreateFileW(temporary, 0x40000000 | 0x00010000, 7 /* READ | WRITE | DELETE */, IntPtr.Zero, 2, 0x80, IntPtr.Zero);
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
try {
if (-not (Test-Path -LiteralPath $Root)) { throw "missing $Root (created before the driver loads)" }
'ACTOR_STARTED pid=' + $PID + ' user=' + [Security.Principal.WindowsIdentity]::GetCurrent().Name | Set-Content -LiteralPath (Join-Path $Control 'actor-started.txt')
for (;;) {
    $command = Get-ChildItem -LiteralPath $Control -Filter 'cmd-*.txt' -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($null -eq $command) { Start-Sleep -Milliseconds 5; continue }
    $line = (Read-T4ControlText $command.FullName).Trim()
    if ($line -eq 'stop') { Remove-Item -LiteralPath $command.FullName -Force; break }
    $parts = $line -split ' ', 4
    $n = $parts[0]; $pattern = $parts[1]; $name = $parts[2]; $bytes = [IO.File]::ReadAllBytes($parts[3])
    $target = Join-Path $Root $name
    $observer = $null
    $result = 'ok'
    try {
        $sequential = $pattern.EndsWith('-reopen-seq')
        if ($sequential -or $pattern.EndsWith('-reopen')) {
            $pattern = $pattern.Substring(0, $pattern.Length - $(if ($sequential) { '-reopen-seq'.Length } else { '-reopen'.Length }))
            $prefix = Join-Path $Control ('reopen-' + $n)
            foreach ($suffix in @('.ready', '.go', '.abort', '.result.json', '.owner.json', '.owner-done')) {
                if ([IO.File]::Exists($prefix + $suffix)) { throw 'reopen requires a fresh control directory' }
            }
            $helper = Join-Path $PSScriptRoot 'reopen-after-publication.ps1'
            foreach ($argument in @($helper, $target, $parts[3], $prefix)) {
                if ($argument.Contains('"')) { throw 'invalid quote in reopen argument' }
            }
            $arguments = '-NoProfile -NonInteractive -ExecutionPolicy Bypass -File "' + $helper +
                '" -Path "' + $target + '" -ExpectedPath "' + $parts[3] + '" -SignalPrefix "' + $prefix + '" -WriterPid ' + $PID
            if ($sequential) { $arguments += ' -AfterOwner' }
            $observer = Start-Process -FilePath (Join-Path $PSHOME 'powershell.exe') -ArgumentList $arguments -PassThru -WindowStyle Hidden
            $deadline = [Diagnostics.Stopwatch]::GetTimestamp() + 30 * [Diagnostics.Stopwatch]::Frequency
            while (-not [IO.File]::Exists($prefix + '.ready')) {
                if ($observer.HasExited -or [Diagnostics.Stopwatch]::GetTimestamp() -ge $deadline) { throw 'reopen observer did not become ready' }
                Start-Sleep -Milliseconds 2
            }
        }
        switch ($pattern) {
            'resave' { [IO.File]::WriteAllBytes($target, $bytes) }
            'new' { [IO.File]::WriteAllBytes($target, $bytes) }
            'replace' { [T4Native]::Replace((Join-Path $Root ('~tmp-' + $n + '.txt')), $target, $bytes) }
            'mapped' { [T4Native]::Mapped($target, $bytes) }
            default { throw "unknown pattern $pattern" }
        }
    } catch {
        $result = 'error ' + ($_.Exception.Message -replace '\s+', ' ')
        if ($null -ne $observer) {
            try { if (-not $observer.HasExited) { $observer.Kill() }; Stop-T4ReopenProcess $observer $prefix }
            finally { $observer.Dispose(); $observer = $null }
        }
    }
    $ack = Join-Path $Control ('ack-' + $n + '.txt')
    Set-Content -LiteralPath ($ack + '.tmp') -Value $result
    [IO.File]::Move(($ack + '.tmp'), $ack)
    Remove-Item -LiteralPath $command.FullName -Force
    if ($null -ne $observer -and $result -eq 'ok') {
        # Save ACK lets the independent coordinator observe publication. The
        # original writer then probes its own namespace too: Word's reported
        # refusal can be private-view-only and invisible to the child.
        $probe = [ordered]@{ WriterPid=$PID; ReadError=$null; ReadWriteError=$null; Error=$null }
        try {
            $deadline = [Diagnostics.Stopwatch]::GetTimestamp() + 180 * [Diagnostics.Stopwatch]::Frequency
            while (-not [IO.File]::Exists($prefix + '.go')) {
                if ([IO.File]::Exists($prefix + '.abort')) { throw 'publication observation failed' }
                if ([Diagnostics.Stopwatch]::GetTimestamp() -ge $deadline) { throw 'owner publication signal timeout' }
                Start-Sleep -Milliseconds 1
            }
            $probe.SignalSeenQpc = [Diagnostics.Stopwatch]::GetTimestamp()
            $probe.ReadError = [T4Native]::ProbeOpen($target, ([uint32]2147483648))
            $probe.ReadWriteError = [T4Native]::ProbeOpen($target, ([uint32]3221225472))
            $probe.FinishedQpc = [Diagnostics.Stopwatch]::GetTimestamp()
        } catch { $probe.Error = $_.Exception.ToString() }
        # Sequential order only: the child opens after this process finished (and closed) both of its own opens.
        if ($sequential) { [IO.File]::WriteAllText(($prefix + '.owner-done'), 'done') }
        try { Stop-T4ReopenProcess $observer $prefix; $probe.TerminationConfirmed = $true }
        catch { $probe.Error = $_.Exception.ToString(); $probe.TerminationConfirmed = $false }
        finally { $observer.Dispose(); $observer = $null }
        [IO.File]::WriteAllText(($prefix + '.owner.part'), ($probe | ConvertTo-Json))
        [IO.File]::Move(($prefix + '.owner.part'), ($prefix + '.owner.json'))
    }
}
'ACTOR_STOPPED' | Set-Content -LiteralPath (Join-Path $Control 'actor-stopped.txt')
} catch {
    if ($null -ne $observer) {
        try { if (-not $observer.HasExited) { $observer.Kill() }; Stop-T4ReopenProcess $observer $prefix }
        catch { [IO.File]::WriteAllText(($prefix + '.stop-error.txt'), $_.Exception.ToString()) }
        finally { $observer.Dispose(); $observer = $null }
    }
    # A task exit alone loses the failing operation. Preserve the exception and
    # source line before rethrowing; this receipt never substitutes for an ack.
    ($_ | Format-List * -Force | Out-String) + "`n" + $_.ScriptStackTrace |
        Set-Content -LiteralPath (Join-Path $Control 'actor-error.txt')
    throw
}
