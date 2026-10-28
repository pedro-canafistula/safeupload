#Requires -RunAsAdministrator
#Requires -Version 5.1
<#
Admin client only. Native work runs in the installed original service process.
Running requires explicit owner authorization of the component-host setup.
This is not the protected first boot and does not qualify anything.
#>
[CmdletBinding()]
param([Parameter(Mandatory=$true)][string] $OutputDirectory)
$ErrorActionPreference = 'Stop'
if ($PSVersionTable.PSVersion.Major -ne 5 -or $PSVersionTable.PSVersion.Minor -ne 1 -or -not [Environment]::Is64BitProcess) { throw 'Requires x64 Windows PowerShell 5.1' }
if (Test-Path -LiteralPath $OutputDirectory) { throw 'Receipt directory already exists' }
[void](New-Item -ItemType Directory -Path $OutputDirectory)
$clock = [Diagnostics.Stopwatch]::StartNew()
function Read-Exact([IO.Stream] $Stream, [int] $Length) {
    $bytes = New-Object byte[] $Length
    $offset = 0
    while ($offset -lt $Length) {
        $pending = $Stream.BeginRead($bytes, $offset, $Length - $offset, $null, $null)
        try {
            $remaining = 120000 - [int]$clock.ElapsedMilliseconds
            if ($remaining -le 0 -or -not $pending.AsyncWaitHandle.WaitOne($remaining)) { throw 'N-U5-01 response timeout; STOP, no retry' }
            $read = $Stream.EndRead($pending)
            if ($read -eq 0) { throw 'N-U5-01 truncated response' }
            $offset += $read
        } finally { $pending.AsyncWaitHandle.Close() }
    }
    return ,$bytes
}
$pipe = New-Object IO.Pipes.NamedPipeClientStream('.', 'SafeUploadAdmissionEvidence.Capture', [IO.Pipes.PipeDirection]::InOut, [IO.Pipes.PipeOptions]::Asynchronous)
$exitCode = 1
try {
    $boot = (Get-CimInstance Win32_OperatingSystem).LastBootUpTime.ToUniversalTime().ToString('o')
    [pscustomobject]@{ PSVersion=$PSVersionTable.PSVersion.ToString(); Bits=64; Boot=$boot; ScriptSHA256=(Get-FileHash -LiteralPath $PSCommandPath -Algorithm SHA256).Hash; Kind='AdminClient' } |
        ConvertTo-Json -Compress | Set-Content -LiteralPath (Join-Path $OutputDirectory 'client.json') -Encoding UTF8
    if (-not ('Nu501PipePeer' -as [type])) {
        Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;
public static class Nu501PipePeer {
    [DllImport("kernel32.dll", SetLastError=true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool GetNamedPipeServerProcessId(SafePipeHandle pipe, out uint processId);
}
'@
    }
    # Complete slow setup before Connect starts the service's five-second
    # first-request deadline. After PID verification, write immediately.
    $service = Get-CimInstance Win32_Service -Filter "Name='SafeUploadAgent'"
    $pipe.Connect(30000)
    [uint32]$serverPid = 0
    if (-not [Nu501PipePeer]::GetNamedPipeServerProcessId($pipe.SafePipeHandle, [ref]$serverPid)) { throw 'Cannot authenticate evidence pipe server PID' }
    if ($null -eq $service -or $service.State -cne 'Running' -or $serverPid -eq 0 -or $serverPid -ne $service.ProcessId) { throw 'Evidence pipe is not owned by the installed service process' }
    $request = New-Object byte[] 72
    [BitConverter]::GetBytes([uint32]68).CopyTo($request, 0)
    [BitConverter]::GetBytes([uint32]0x3155354e).CopyTo($request, 4)
    [BitConverter]::GetBytes([uint32]1).CopyTo($request, 8)
    $pipe.Write($request, 0, $request.Length)
    [pscustomobject]@{ServerPid=$serverPid; ServicePid=$service.ProcessId; ServiceName=$service.Name; Boot=$boot} |
        ConvertTo-Json -Compress | Set-Content -LiteralPath (Join-Path $OutputDirectory 'peer.json') -Encoding UTF8
    $header = Read-Exact $pipe 8
    if ([BitConverter]::ToUInt32($header, 0) -ne 0x3155354e) { throw 'N-U5-01 response magic mismatch' }
    $length = [BitConverter]::ToUInt32($header, 4)
    if ($length -lt 2 -or $length -gt 262144) { throw 'N-U5-01 unbounded/empty receipt' }
    $raw = Read-Exact $pipe ([int]$length)
    [IO.File]::WriteAllBytes((Join-Path $OutputDirectory 'receipt.json'), $raw)
    $receipt = [Text.Encoding]::UTF8.GetString($raw) | ConvertFrom-Json
    # The host independently validates the complete receipt, not this string.
    if ($receipt.Schema -cne 'SafeUpload.N-U5-01.v1' -or $receipt.Verdict -cne 'PASS' -or $receipt.Failure -or @($receipt.Steps | Where-Object { -not $_.Passed }).Count -ne 0) { throw 'N-U5-01 service failed assertion' }
    if ((Get-CimInstance Win32_OperatingSystem).LastBootUpTime.ToUniversalTime().ToString('o') -cne $boot) { throw 'Guest rebooted during component control' }
    $exitCode = 0
} catch {
    ($_ | Out-String) | Set-Content -LiteralPath (Join-Path $OutputDirectory 'error.txt') -Encoding UTF8
} finally {
    $pipe.Dispose()
    [string]$exitCode | Set-Content -LiteralPath (Join-Path $OutputDirectory 'exit.txt') -Encoding ASCII
    $verdict = if ($exitCode -eq 0) { 'N-U5-01=PASS' } else { 'N-U5-01=FAIL' }
    $verdict | Set-Content -LiteralPath (Join-Path $OutputDirectory 'verdict.txt') -Encoding ASCII
    $verdict
}
exit $exitCode
