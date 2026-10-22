#Requires -Version 5.1
$ErrorActionPreference='Stop'
function Require([bool]$Condition,[string]$Message){if(-not $Condition){throw $Message}}
Require ((Get-CimInstance Win32_ComputerSystemProduct).UUID -eq '3a9992db-4644-405c-b642-9766edd10650') 'Ensaio restrito ao clone de homologacao.'
$principal=[Security.Principal.WindowsPrincipal]::new([Security.Principal.WindowsIdentity]::GetCurrent())
Require ($principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) 'Execute com elevacao local para reiniciar o servico.'
$root=Join-Path $env:ProgramFiles 'SafeUpload\Agent'
$installed=Get-Content (Join-Path $root 'setup\installation.json') -Raw | ConvertFrom-Json
Require ($installed.version -eq '0.1.5' -and $installed.commit -eq '3fa6986b938903f9abbafc0f696f1a043124672d' -and $installed.mode -eq 'FileSystemWatcher') 'Instalacao inesperada.'
Require (-not (Test-Path 'HKLM:\SYSTEM\CurrentControlSet\Services\SafeUpload')) 'Driver presente; ensaio interrompido.'
$service=Get-CimInstance Win32_Service -Filter "Name='SafeUploadAgent'"
$expectedPath='"'+(Join-Path $root 'service\SafeUpload.Agent.Service.exe')+'" '
Require ($service.State -eq 'Running' -and $service.StartName -eq 'LocalSystem' -and $service.PathName.StartsWith($expectedPath)) 'Servico inesperado.'
$uiPath=Join-Path $root 'ui\SafeUpload.Agent.App.exe'
function Get-LabUi { @(Get-CimInstance Win32_Process -Filter "Name='SafeUpload.Agent.App.exe'" | Where-Object ExecutablePath -eq $uiPath | Select-Object ProcessId,SessionId,CreationDate) }
$beforeUi=@(Get-LabUi)
Require ($beforeUi.Count -eq 1) 'Esperada uma unica UI aberta.'
$resultDir=Join-Path $PSScriptRoot ('reconexao-'+[DateTime]::UtcNow.ToString('yyyyMMddTHHmmssZ'))
New-Item -ItemType Directory -Path $resultDir | Out-Null
$queue=Join-Path $env:ProgramData 'SafeUpload\queue.jsonl'
$policy=Join-Path $env:ProgramData 'SafeUpload\policy.json'
$state=[ordered]@{result='running';vmUuid=(Get-CimInstance Win32_ComputerSystemProduct).UUID;version=$installed.version;commit=$installed.commit;startedAtUtc=[DateTime]::UtcNow.ToString('o');servicePidBefore=$service.ProcessId;uiBefore=$beforeUi;uiObservation='pending'}
function Save-State { $state | ConvertTo-Json -Depth 8 | Set-Content (Join-Path $resultDir 'result.json') -Encoding UTF8 }
$mustRestart=$false
try {
    $state.policyHashBefore=(Get-FileHash $policy -Algorithm SHA256).Hash
    $mustRestart=$true
    Stop-Service SafeUploadAgent
    (Get-Service SafeUploadAgent).WaitForStatus('Stopped',[TimeSpan]::FromSeconds(15))
    $state.stoppedAtUtc=[DateTime]::UtcNow.ToString('o')
    $state.queueHashStopped=(Get-FileHash $queue -Algorithm SHA256).Hash
    $state.result='stopped-waiting-ui-observation'
    Save-State
    Write-Host ('Servico parado. Retorno automatico em ate 45 segundos. Resultado: '+$resultDir)
    $deadline=[DateTime]::UtcNow.AddSeconds(45)
    while([DateTime]::UtcNow -lt $deadline -and -not (Test-Path (Join-Path $resultDir 'continuar.txt'))) {Start-Sleep -Milliseconds 500}
    Start-Service SafeUploadAgent
    (Get-Service SafeUploadAgent).WaitForStatus('Running',[TimeSpan]::FromSeconds(15))
    $mustRestart=$false
    $state.runningAtUtc=[DateTime]::UtcNow.ToString('o')
    Start-Sleep -Seconds 8
    $state.queueHashAfter=(Get-FileHash $queue -Algorithm SHA256).Hash
    $state.policyHashAfter=(Get-FileHash $policy -Algorithm SHA256).Hash
    $state.uiAfter=@(Get-LabUi)
    $state.servicePidAfter=(Get-CimInstance Win32_Service -Filter "Name='SafeUploadAgent'").ProcessId
    Require ($state.queueHashStopped -eq $state.queueHashAfter) 'Fila mudou durante o ensaio sem operacoes novas.'
    Require ($state.policyHashBefore -eq $state.policyHashAfter) 'Politica mudou durante o ensaio.'
    Require ($state.uiAfter.Count -eq 1 -and $state.uiAfter[0].ProcessId -eq $beforeUi[0].ProcessId -and $state.uiAfter[0].CreationDate -eq $beforeUi[0].CreationDate) 'UI encerrou ou foi substituida.'
    Require ($state.servicePidBefore -ne $state.servicePidAfter) 'Processo do servico nao mudou.'
    $state.result='service-restarted-data-and-ui-process-preserved-ui-observation-pending'
} catch {$state.result='failed';$state.error=$_.Exception.Message;Write-Error -ErrorAction Continue $_}
finally {
    if($mustRestart){try {Start-Service SafeUploadAgent;$state.recovery='service-start-requested'} catch {$state.recovery=$_.Exception.Message}}
    $state.finishedAtUtc=[DateTime]::UtcNow.ToString('o')
    Save-State
}
