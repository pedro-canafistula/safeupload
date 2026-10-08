<# Diagnostic: with the feature driver loaded (optionally under the volatile Verifier) create suspended processes
   from several images and report Win32 error plus the NTSTATUS the process-creation path last set, to localise
   an image-load failure ("The file or directory is corrupted and unreadable") seen only under the Verifier.
   Run only on the recorded debuggee, from the experiment wrapper. #>
param([Parameter(Mandatory)] [string] $ExpectedFeatureSha256, [switch] $Verifier, [switch] $NoDriver)
$ErrorActionPreference = 'Stop'
$documents = Join-Path $env:USERPROFILE 'Documents'
. (Join-Path $documents 'StagedTestAgent.ps1')
$installed = 'C:\Windows\System32\drivers\SafeUpload.sys'
$feature = Join-Path $documents 'SafeUpload-stage-prototype.sys'
$id = [guid]::NewGuid().ToString('N')
$backup = Join-Path $documents ('SafeUpload-original-before-launch-probe-' + $id + '.sys')
$probeDirectory = Join-Path $documents ('launch-probe-' + $id)
$tempDirectory = Join-Path 'C:\Windows\Temp' ('launch-probe-' + $id)
$loaded = $false; $replaced = $false; $verifierEnabled = $false
Add-Type -TypeDefinition @'
using System; using System.Runtime.InteropServices;
public static class LaunchProbe {
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)] public struct STARTUPINFO { public int cb; public string lpReserved, lpDesktop, lpTitle; public int dwX, dwY, dwXSize, dwYSize, dwXCountChars, dwYCountChars, dwFillAttribute, dwFlags; public short wShowWindow, cbReserved2; public IntPtr lpReserved2, hStdInput, hStdOutput, hStdError; }
    [StructLayout(LayoutKind.Sequential)] public struct PROCESS_INFORMATION { public IntPtr hProcess, hThread; public int dwProcessId, dwThreadId; }
    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)] public static extern bool CreateProcessW(string app, string cmd, IntPtr pa, IntPtr ta, bool inherit, uint flags, IntPtr env, string dir, ref STARTUPINFO si, out PROCESS_INFORMATION pi);
    [DllImport("kernel32.dll")] public static extern bool TerminateProcess(IntPtr h, uint code);
    [DllImport("kernel32.dll")] public static extern bool CloseHandle(IntPtr h);
    [DllImport("ntdll.dll")] public static extern int RtlGetLastNtStatus();
    public static string Try(string path) {
        STARTUPINFO si = new STARTUPINFO(); si.cb = Marshal.SizeOf(typeof(STARTUPINFO)); PROCESS_INFORMATION pi;
        bool ok = CreateProcessW(path, null, IntPtr.Zero, IntPtr.Zero, false, 0x00000004 | 0x08000000, IntPtr.Zero, null, ref si, out pi);
        int err = Marshal.GetLastWin32Error(); int nt = RtlGetLastNtStatus();
        if (ok) { TerminateProcess(pi.hProcess, 0); CloseHandle(pi.hThread); CloseHandle(pi.hProcess); }
        return string.Format("ok={0} win32={1} ntstatus=0x{2:X8}", ok, err, nt);
    }
}
'@
function Test-Targets([string] $Label) {
    foreach ($t in $targets) {
        $hash = try { (Get-FileHash -LiteralPath $t.Path -Algorithm SHA256).Hash.Substring(0, 12) } catch { 'HASHFAIL:' + $_.Exception.Message }
        "Launch[$Label] {0} -> {1} (read sha prefix {2})" -f $t.Name, [LaunchProbe]::Try($t.Path), $hash
    }
}
if ((& fltmc.exe filters | Out-String) -match '(?m)^SafeUpload\s') { throw 'Filter must be unloaded at baseline.' }
if ((Get-FileHash -LiteralPath $feature -Algorithm SHA256).Hash -ne $ExpectedFeatureSha256.ToUpperInvariant()) { throw 'Feature hash mismatch.' }
try {
    [void][IO.Directory]::CreateDirectory($probeDirectory); [void][IO.Directory]::CreateDirectory($tempDirectory)
    Copy-Item 'C:\Windows\System32\whoami.exe' (Join-Path $probeDirectory 'whoami-copy.exe')
    $agentExe = Join-Path $documents 'stage-service-publish\SafeUpload.Agent.Service.exe'
    Copy-Item $agentExe (Join-Path $tempDirectory 'SafeUpload.Agent.Service.exe')
    $targets = @(
        @{ Name = 'agent exe in Documents'; Path = $agentExe },
        @{ Name = 'agent exe copy in Windows\Temp'; Path = (Join-Path $tempDirectory 'SafeUpload.Agent.Service.exe') },
        @{ Name = 'whoami copy in Documents'; Path = (Join-Path $probeDirectory 'whoami-copy.exe') },
        @{ Name = 'System32 whoami'; Path = 'C:\Windows\System32\whoami.exe' })
    'Mode=' + $(if ($NoDriver) { 'no driver loaded' } elseif ($Verifier) { 'feature driver under volatile Verifier 0x13B' } else { 'feature driver, no Verifier' })
    Test-Targets 'before-driver'
    if (-not $NoDriver) {
        Backup-StagedTestDriver $backup
        $replaced = $true
        Copy-Item -LiteralPath $feature -Destination $installed -Force
        if ($Verifier) {
            & verifier.exe /volatile /flags 0x13B /adddriver SafeUpload.sys | Out-Null
            if ($LASTEXITCODE -ne 0) { throw 'Verifier enable failed.' }
            $verifierEnabled = $true
        }
        & fltmc.exe load SafeUpload | Out-Null
        'FltmcLoadExit=' + $LASTEXITCODE
        $loaded = ($LASTEXITCODE -eq 0)
        Test-Targets 'driver-loaded'
        Test-Targets 'driver-loaded-second-pass'
    }
}
finally {
    if ($replaced) { Restore-StagedTestDriver $backup $loaded $verifierEnabled }
    Remove-Item -LiteralPath $backup -Force -ErrorAction SilentlyContinue
    Remove-Item -LiteralPath $probeDirectory, $tempDirectory -Recurse -Force -ErrorAction SilentlyContinue
}
