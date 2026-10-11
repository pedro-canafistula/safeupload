. C:\src\q\lib.ps1
Get-Process SafeUpload.Agent.App -ErrorAction SilentlyContinue | Stop-Process -Force
Stop-Agent
Remove-Item C:\ProgramData\SafeUpload -Recurse -Force -ErrorAction SilentlyContinue
"servico no ar: " + (Start-Agent)
Start-Sleep 3
Get-Content $Q\svc.log | Select-String 'escutando|Navegadores|Exce|fail|Unauthorized|warn' | ForEach-Object { $_.Line.Trim() }
& $Svc desvio status
Get-Process SafeUpload.Agent.Service | Select-Object Id, SessionId | Format-List
Invoke-Interactive "$Q\job-app.ps1" 60
