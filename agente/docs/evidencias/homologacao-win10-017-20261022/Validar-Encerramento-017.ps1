#Requires -Version 5.1
param([switch]$PreflightOnly)
$ErrorActionPreference='Stop'
function Require([bool]$Condition,[string]$Message){if(-not $Condition){throw $Message}}
Require ((Get-CimInstance Win32_ComputerSystemProduct).UUID -eq '3a9992db-4644-405c-b642-9766edd10650') 'Restrito ao clone de homologacao.'
$root='C:\Program Files\SafeUpload\Agent'
$lab='C:\Users\safeuploadlab\Desktop\Homologacao-SafeUpload-016\017'
Require ($PSScriptRoot -eq $lab) 'Pasta de ensaio inesperada.'
$installed=Get-Content (Join-Path $root 'setup\installation.json') -Raw | ConvertFrom-Json
Require ($installed.version -eq '0.1.7' -and $installed.commit -eq '39290c98609d154488d368dbf85b92f6744774e6' -and $installed.mode -eq 'FileSystemWatcher' -and [string]::IsNullOrEmpty($installed.adminBaseUrl)) 'Instalacao inesperada.'
Require (-not (Test-Path 'HKLM:\SYSTEM\CurrentControlSet\Services\SafeUpload')) 'Driver presente; interrompido.'
$service=Get-CimInstance Win32_Service -Filter "Name='SafeUploadAgent'"
Require ($service.State -eq 'Running' -and $service.StartName -eq 'LocalSystem' -and $service.PathName.StartsWith(('"'+(Join-Path $root 'service\SafeUpload.Agent.Service.exe')+'" '))) 'Servico inesperado.'
$uiPath=Join-Path $root 'ui\SafeUpload.Agent.App.exe'
function Get-LabUi { @(Get-CimInstance Win32_Process -Filter "Name='SafeUpload.Agent.App.exe'" | Where-Object ExecutablePath -eq $uiPath | Select-Object ProcessId,SessionId,CreationDate) }
$beforeUi=@(Get-LabUi)
Require ($beforeUi.Count -eq 1 -and $beforeUi[0].SessionId -eq 1) 'Esperada uma UI da sessao interativa.'
$results=Join-Path $lab 'encerramento-017'
Require (-not (Test-Path $results)) 'Resultado anterior presente; nao sobrescrever.'
if($PreflightOnly){[ordered]@{result='preflight-passed';version=$installed.version;servicePid=$service.ProcessId;uiPid=$beforeUi[0].ProcessId} | ConvertTo-Json;return}
$principal=[Security.Principal.WindowsPrincipal]::new([Security.Principal.WindowsIdentity]::GetCurrent())
Require ($principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) 'Elevacao local necessaria.'
New-Item -ItemType Directory -Path $results | Out-Null
$queue='C:\ProgramData\SafeUpload\queue.jsonl'
$policy='C:\ProgramData\SafeUpload\policy.json'
$quarantine='C:\SafeUpload\_bloqueados\homologacao-017-cpf-cf8e763a48d74744ac9c7549d8f2a699-20261022-194911.txt'
$state=[ordered]@{result='running';vmUuid=(Get-CimInstance Win32_ComputerSystemProduct).UUID;version=$installed.version;commit=$installed.commit;startedAtUtc=[DateTime]::UtcNow.ToString('o');servicePidBefore=$service.ProcessId;uiBefore=$beforeUi;uiObservation='pending';uninstallStatus='pending'}
function Save-State{$state | ConvertTo-Json -Depth 10 | Set-Content (Join-Path $results 'result.json') -Encoding UTF8}
function Queue-Ids { @((Get-Content $queue | ForEach-Object {$_ | ConvertFrom-Json} | Where-Object { $_.eventId -and -not $_.type }) | ForEach-Object eventId) }
$mustRestart=$false
try {
    $state.policyHashBefore=(Get-FileHash $policy -Algorithm SHA256).Hash
    $state.quarantineHashBefore=(Get-FileHash $quarantine -Algorithm SHA256).Hash
    $mustRestart=$true
    Stop-Service SafeUploadAgent
    (Get-Service SafeUploadAgent).WaitForStatus('Stopped',[TimeSpan]::FromSeconds(20))
    $state.stoppedAtUtc=[DateTime]::UtcNow.ToString('o')
    $state.queueHashBefore=(Get-FileHash $queue -Algorithm SHA256).Hash
    Require ($state.queueHashBefore -eq 'DFD11C3D42F5D236E7248B267F0383BE4B84ACD90B4C12CD17B15C61143F4AAF' -and $state.policyHashBefore -eq '16979B6447FE37E98270729DEEAAFC5BA741AC4509BEF9730B2F11FFB093D90F') 'Dados divergentes apos boot.';
    $state.eventIdsBefore=@(Queue-Ids)
    Require ($state.eventIdsBefore.Count -eq 11 -and @($state.eventIdsBefore | Select-Object -Unique).Count -eq 11) 'Esperados onze eventos unicos.'
    Copy-Item -LiteralPath $queue -Destination (Join-Path $results 'queue-before.jsonl')
    Copy-Item -LiteralPath $policy -Destination (Join-Path $results 'policy-before.json')
    $state.uiObservation='host-confirmed-after-boot-history-eleven';
    $currentUi=@(Get-LabUi)
    Require ($currentUi.Count -eq 1 -and $currentUi[0].ProcessId -eq $beforeUi[0].ProcessId) 'UI inesperada antes da remocao.'
    Stop-Process -Id $currentUi[0].ProcessId
    $uninstaller=Join-Path $root 'unins000.exe'
    Require ([IO.Path]::GetFullPath($uninstaller) -eq 'C:\Program Files\SafeUpload\Agent\unins000.exe') 'Destino inesperado.'
    $state.result='uninstalling';Save-State
    $remove=Start-Process $uninstaller -WindowStyle Hidden -Wait -PassThru -ArgumentList @('/VERYSILENT','/SUPPRESSMSGBOXES','/NORESTART',('/LOG="'+(Join-Path $results 'uninstall-017.log')+'"'))
    $state.uninstallExitCode=$remove.ExitCode
    Require ($remove.ExitCode -eq 0) ('Remocao falhou: '+$remove.ExitCode)
    $mustRestart=$false
    Require (-not (Get-Service SafeUploadAgent -ErrorAction SilentlyContinue)) 'Servico permanece.'
    Require (-not (Test-Path 'HKLM:\SYSTEM\CurrentControlSet\Services\SafeUploadAgent')) 'Registro do servico permanece.'
    Require (-not (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run' -Name SafeUploadAgentConsole -ErrorAction SilentlyContinue)) 'Startup permanece.'
    Require (@(Get-LabUi).Count -eq 0) 'UI permanece.'
    Require (-not (Test-Path $uiPath) -and -not (Test-Path (Join-Path $root 'service\SafeUpload.Agent.Service.exe')) -and -not (Test-Path $uninstaller)) 'Executaveis permanecem.'
    $state.queueHashAfterUninstall=(Get-FileHash $queue -Algorithm SHA256).Hash
    $state.policyHashAfterUninstall=(Get-FileHash $policy -Algorithm SHA256).Hash
    $state.quarantineHashAfterUninstall=(Get-FileHash $quarantine -Algorithm SHA256).Hash
    $state.eventIdsAfter=@(Queue-Ids)
    Require ($state.queueHashBefore -eq $state.queueHashAfterUninstall -and $state.policyHashBefore -eq $state.policyHashAfterUninstall -and $state.quarantineHashBefore -eq $state.quarantineHashAfterUninstall) 'Dados alterados pela remocao.'
    Require ($state.eventIdsAfter.Count -eq 11 -and @($state.eventIdsAfter | Select-Object -Unique).Count -eq 11) 'Historico divergente.'
    $state.uninstallStatus='passed-service-startup-ui-executables-absent-data-preserved'
    $state.result='uninstall-passed'
} catch {$state.result='failed';$state.error=$_.Exception.Message}
finally {
    if($mustRestart){try{if(Get-Service SafeUploadAgent -ErrorAction SilentlyContinue){Start-Service SafeUploadAgent;$state.recovery='existing-service-start-requested'}}catch{$state.recovery=$_.Exception.Message}}
    $state.finishedAtUtc=[DateTime]::UtcNow.ToString('o');Save-State
}

