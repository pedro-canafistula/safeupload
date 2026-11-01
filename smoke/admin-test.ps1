# Runs as the VM administrator after the agent started: the gate driver must refuse even an administrator.
$ErrorActionPreference = 'Continue'
$B = 'C:\SafeUpload\Envios'
$sw = [Diagnostics.Stopwatch]::StartNew()
while (-not (Test-Path 'S:\') -and $sw.Elapsed.TotalSeconds -lt 120) { Start-Sleep -Seconds 2 }
'drive S: present=' + (Test-Path 'S:\') + ' after ' + [int]$sw.Elapsed.TotalSeconds + ' s'
'gate loaded=' + [bool]((& fltmc.exe filters) -match 'SafeUpload')

try { [IO.File]::WriteAllText("$B\admin-direct.txt", 'x'); 'FAIL G1 administrator direct write was allowed' }
catch { 'PASS G1 administrator direct write refused (' + $_.Exception.InnerException.GetType().Name + $_.Exception.GetType().Name + ')' }

[IO.File]::WriteAllText('C:\Users\Public\fora.txt', 'x')
try { [IO.File]::Move('C:\Users\Public\fora.txt', "$B\fora.txt"); 'FAIL G2 rename into the protected folder was allowed' }
catch { 'PASS G2 rename into the protected folder refused' }

$readable = $false
try { $null = [IO.Directory]::GetFiles($B); $readable = $true } catch { }
if ($readable) { 'PASS G3 the protected folder stays readable' } else { 'FAIL G3 the protected folder is not readable' }
