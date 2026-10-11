# Sessao interativa: sobe o aplicativo de bandeja.
Get-Process SafeUpload.Agent.App -ErrorAction SilentlyContinue | Stop-Process -Force
Start-Process 'C:\src\agente\SafeUpload.Agent.App\bin\Release\net10.0-windows\SafeUpload.Agent.App.exe'
Start-Sleep 5
Get-Process SafeUpload.Agent.App | Select-Object Id, SessionId | Format-List
