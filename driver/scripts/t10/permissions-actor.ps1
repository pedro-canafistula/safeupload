<#
T10 permissions actor: a standard user that runs one operation per command from the SYSTEM coordinator
(permissions-coordinator.ps1). Commands arrive as C:\T10\control\cmd-<n>.json ({"N":..,"Op":..,"Path":..,"Payload":..,"Args":[..]});
the actor answers with ack-<n>.txt: "ok", "exit <code> <output>" for a failed tool, or "error <message>". Op "stop" ends the actor.

Ops:
  write    File.WriteAllBytes(Path, bytes of Payload): a whole new version of a protected file
  hold     open Path for write, write Payload, flush and keep the handle until the next "release" (a version in progress)
  release  close the held handle
  icacls   icacls.exe Path Args...: a permission change by this user; Windows decides whether it is allowed
#>
param([string]$Control = 'C:\T10\control')
$ErrorActionPreference = 'Stop'
$held = $null
try {
'ACTOR_STARTED pid=' + $PID + ' user=' + [Security.Principal.WindowsIdentity]::GetCurrent().Name | Set-Content -LiteralPath (Join-Path $Control 'actor-started.txt')
for (;;) {
    $command = Get-ChildItem -LiteralPath $Control -Filter 'cmd-*.json' -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($null -eq $command) { Start-Sleep -Milliseconds 5; continue }
    $c = [IO.File]::ReadAllText($command.FullName) | ConvertFrom-Json
    if ($c.Op -eq 'stop') { Remove-Item -LiteralPath $command.FullName -Force; break }
    $result = 'ok'
    try {
        switch ($c.Op) {
            'write' { [IO.File]::WriteAllBytes($c.Path, [IO.File]::ReadAllBytes($c.Payload)) }
            'hold' {
                if ($null -ne $held) { throw 'a handle is already held' }
                $held = New-Object IO.FileStream($c.Path, [IO.FileMode]::Create, [IO.FileAccess]::Write, [IO.FileShare]::Read)
                $bytes = [IO.File]::ReadAllBytes($c.Payload); $held.Write($bytes, 0, $bytes.Length); $held.Flush($true)
            }
            'release' { if ($null -eq $held) { throw 'no held handle' }; $held.Dispose(); $held = $null }
            'icacls' {
                # Windows PowerShell 5.1 turns redirected native stderr into a terminating error under 'Stop'; a refusal is a result.
                $ErrorActionPreference = 'Continue'
                $out = (& icacls.exe $c.Path @($c.Args) 2>&1 | Out-String); $code = $LASTEXITCODE
                $ErrorActionPreference = 'Stop'
                if ($code -ne 0) { $result = 'exit ' + $code + ' ' + ($out -replace '\s+', ' ') }
            }
            default { throw ('unknown op ' + $c.Op) }
        }
    } catch { $result = 'error ' + ($_.Exception.Message -replace '\s+', ' ') }
    $ack = Join-Path $Control ('ack-' + $c.N + '.txt')
    Set-Content -LiteralPath ($ack + '.tmp') -Value $result
    [IO.File]::Move(($ack + '.tmp'), $ack)
    Remove-Item -LiteralPath $command.FullName -Force
}
if ($null -ne $held) { $held.Dispose() }
'ACTOR_STOPPED' | Set-Content -LiteralPath (Join-Path $Control 'actor-stopped.txt')
} catch {
    ($_ | Format-List * -Force | Out-String) + "`n" + $_.ScriptStackTrace |
        Set-Content -LiteralPath (Join-Path $Control 'actor-error.txt')
    throw
}
