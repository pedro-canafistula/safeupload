#Requires -Version 5.1
$ErrorActionPreference='Stop'
function Require([bool]$Condition,[string]$Message){if(-not $Condition){throw $Message}}
Require ((Get-CimInstance Win32_ComputerSystemProduct).UUID -eq '3a9992db-4644-405c-b642-9766edd10650') 'Clone inesperado.'
$root='C:\Program Files\SafeUpload\Agent'
$data='C:\ProgramData\SafeUpload'
$queue=Join-Path $data 'queue.jsonl'; $policy=Join-Path $data 'policy.json'
$quarantine='C:\SafeUpload\_bloqueados\homologacao-017-cpf-cf8e763a48d74744ac9c7549d8f2a699-20261022-194911.txt'
Require (-not (Test-Path 'HKLM:\SYSTEM\CurrentControlSet\Services\SafeUpload')) 'Driver inesperado.'
Require (-not (Get-Service SafeUploadAgent -ErrorAction SilentlyContinue)) 'Servico existente; nao sobrescrever.'
Require (-not (Test-Path (Join-Path $root 'service\SafeUpload.Agent.Service.exe'))) 'Executavel anterior inesperado.'
Require (-not (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run' -Name SafeUploadAgentConsole -ErrorAction SilentlyContinue)) 'Startup anterior inesperado.'
Require (@(Get-CimInstance Win32_Process -Filter "Name='SafeUpload.Agent.App.exe'").Count -eq 0) 'UI anterior inesperada.'
$policyHash=(Get-FileHash $policy -Algorithm SHA256).Hash
$queueHash=(Get-FileHash $queue -Algorithm SHA256).Hash
$quarantineHash=(Get-FileHash $quarantine -Algorithm SHA256).Hash
Require ($policyHash -eq '16979B6447FE37E98270729DEEAAFC5BA741AC4509BEF9730B2F11FFB093D90F') 'Politica anterior divergente.'
Require ($queueHash -eq 'DFD11C3D42F5D236E7248B267F0383BE4B84ACD90B4C12CD17B15C61143F4AAF') 'Fila anterior divergente.'
Require ($quarantineHash -eq '605A58E33E73F44BEC1E10A8B7C842A4805BB353A2544005FAFC53F2445A2E81') 'Quarentena anterior divergente.'
$events=@(Get-Content $queue | ForEach-Object {$_ | ConvertFrom-Json} | Where-Object {$_.eventId -and -not $_.type})
Require ($events.Count -eq 11 -and @($events.eventId | Select-Object -Unique).Count -eq 11) 'Esperados onze eventos unicos.'
$os=Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
[ordered]@{result='preflight-passed';collectedAtUtc=[DateTime]::UtcNow.ToString('o');vmUuid=(Get-CimInstance Win32_ComputerSystemProduct).UUID;
windowsBuild=($os.CurrentBuildNumber+'.'+$os.UBR);policyHash=$policyHash;queueHash=$queueHash;quarantineHash=$quarantineHash;
eventCount=$events.Count;eventIds=@($events.eventId);administrator=([Security.Principal.WindowsPrincipal]::new([Security.Principal.WindowsIdentity]::GetCurrent())).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator);
session=[Diagnostics.Process]::GetCurrentProcess().SessionId;dataEntries=@(Get-ChildItem -LiteralPath $data | Select-Object Name,Length,Attributes)} | ConvertTo-Json -Depth 6
