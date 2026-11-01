# Utilidades da qualificacao (Fase 7). Rodam na sessao SSH (administrador).
$Q = 'C:\src\q'
$Svc = 'C:\src\agente\SafeUpload.Agent.Service\bin\Release\net10.0-windows\SafeUpload.Agent.Service.exe'
$App = 'C:\src\agente\SafeUpload.Agent.App\bin\Release\net10.0-windows\SafeUpload.Agent.App.exe'

function Start-Agent {
    Stop-Agent
    $cmd = "/c `"`"$Svc`" --InspecaoTls:Habilitada=true > $Q\svc.log 2>&1`""
    $action = New-ScheduledTaskAction -Execute 'cmd.exe' -Argument $cmd -WorkingDirectory (Split-Path $Svc)
    $principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
    Register-ScheduledTask -TaskName 'SUQualSvc' -Action $action -Principal $principal -Force | Out-Null
    Start-ScheduledTask -TaskName 'SUQualSvc'
    foreach ($i in 1..40) {
        if (Test-NetConnection 127.0.0.1 -Port 8877 -InformationLevel Quiet -WarningAction SilentlyContinue) { return $true }
        Start-Sleep -Milliseconds 500
    }
    return $false
}

function Stop-Agent {
    Stop-ScheduledTask -TaskName 'SUQualSvc' -ErrorAction SilentlyContinue
    Get-Process SafeUpload.Agent.Service -ErrorAction SilentlyContinue | Stop-Process -Force
}

# Roda um script na sessao interativa (console) do usuario e espera terminar.
function Invoke-Interactive([string]$Script, [int]$TimeoutSeconds = 600) {
    $done = "$Q\done.flag"
    Remove-Item $done -ErrorAction SilentlyContinue
    $wrapped = "$Q\wrapped.ps1"
    Set-Content $wrapped "try { & '$Script' *> '$Q\job.out' } catch { `$_ | Out-File '$Q\job.out' -Append } finally { Set-Content '$done' ok }"
    $action = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument "-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File $wrapped"
    $principal = New-ScheduledTaskPrincipal -UserId 'safeupload' -LogonType Interactive -RunLevel Limited
    Register-ScheduledTask -TaskName 'SUQualJob' -Action $action -Principal $principal -Force | Out-Null
    Start-ScheduledTask -TaskName 'SUQualJob'
    $sw = [Diagnostics.Stopwatch]::StartNew()
    while (-not (Test-Path $done) -and $sw.Elapsed.TotalSeconds -lt $TimeoutSeconds) { Start-Sleep 1 }
    if (-not (Test-Path $done)) { "TIMEOUT do job" }
    Get-Content "$Q\job.out" -ErrorAction SilentlyContinue
}
