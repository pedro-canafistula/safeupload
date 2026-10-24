#Requires -Version 5.1
param([switch]$PreflightOnly)
$ErrorActionPreference='Stop'
function Require([bool]$Condition,[string]$Message){if(-not $Condition){throw $Message}}
Require ((Get-CimInstance Win32_ComputerSystemProduct).UUID -eq '3a9992db-4644-405c-b642-9766edd10650') 'Restrito ao clone de homologacao.'
Require ($PSScriptRoot -eq 'C:\Users\safeuploadlab\Desktop\Homologacao-SafeUpload-016\017') 'Laboratorio inesperado.'
$root='C:\Program Files\SafeUpload\Agent'
$data='C:\ProgramData\SafeUpload'
$queue=Join-Path $data 'queue.jsonl';$policy=Join-Path $data 'policy.json'
$results=Join-Path $PSScriptRoot 'resultado'
$installer=Join-Path $PSScriptRoot 'SafeUploadAgent-0.1.7-win-x64-setup.exe'
Require ((Get-FileHash $installer -Algorithm SHA256).Hash -eq '663B0FF9AD31A1DF0DF6896A2598E16C00C9C545B8D6F6FEAA1EF1A49347E756') 'Pacote divergente.'
$manifestPath=Join-Path $PSScriptRoot 'payload-manifest-017.json'
Require ((Get-FileHash $manifestPath -Algorithm SHA256).Hash -eq 'EE350E7FEF2AAA6713CF99EABC0909384F4BD5F3A7320ACFBCC6767C16734087') 'Manifesto divergente.'
$manifest=Get-Content $manifestPath -Raw | ConvertFrom-Json
Require ($manifest.version -eq '0.1.7' -and $manifest.commit -eq '39290c98609d154488d368dbf85b92f6744774e6' -and -not $manifest.sourceDirty -and @($manifest.files).Count -eq 724) 'Origem inesperada.'
Require (-not (Test-Path 'HKLM:\SYSTEM\CurrentControlSet\Services\SafeUpload') -and -not (Get-Service SafeUploadAgent -ErrorAction SilentlyContinue)) 'Servico/driver presente; nao sobrescrever.'
Require (-not (Test-Path (Join-Path $root 'service\SafeUpload.Agent.Service.exe')) -and -not (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run' -Name SafeUploadAgentConsole -ErrorAction SilentlyContinue)) 'Instalacao/startup anterior inesperado.'
Require (@(Get-CimInstance Win32_Process -Filter "Name='SafeUpload.Agent.App.exe'").Count -eq 0) 'UI anterior presente.'
Require (-not (Test-Path $results)) 'Resultado anterior presente; nao sobrescrever.'
if($PreflightOnly){[ordered]@{result='preflight-passed';version=$manifest.version;payloadFiles=@($manifest.files).Count} | ConvertTo-Json;return}
$principal=[Security.Principal.WindowsPrincipal]::new([Security.Principal.WindowsIdentity]::GetCurrent())
Require ($principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) 'Elevacao local necessaria.'
New-Item -ItemType Directory -Path $results | Out-Null
$state=[ordered]@{result='running';version=$manifest.version;commit=$manifest.commit;vmUuid=(Get-CimInstance Win32_ComputerSystemProduct).UUID;startedAtUtc=[DateTime]::UtcNow.ToString('o');uiObservation='pending';uninstallStatus='pending';startupAfterBoot='pending'}
function Save-State { $state | ConvertTo-Json -Depth 14 | Set-Content (Join-Path $results 'result.json') -Encoding UTF8 }
function Read-Events { @(Get-Content $queue | ForEach-Object {$_ | ConvertFrom-Json} | Where-Object {$_.eventId -and -not $_.type}) }
function Wait-Gate([string]$Name,[string]$Value,[int]$Seconds){$p=Join-Path $results $Name;$deadline=[DateTime]::UtcNow.AddSeconds($Seconds);while([DateTime]::UtcNow -lt $deadline -and -not (Test-Path $p)){Start-Sleep -Milliseconds 500};Require ((Test-Path $p) -and (Get-Content $p -Raw).Trim() -eq $Value) ('Conferencia nao recebida: '+$Name)}
function Read-Health {
    $pipe=[IO.Pipes.NamedPipeClientStream]::new('.','SafeUpload.Agent.Diagnostics',[IO.Pipes.PipeDirection]::InOut,[IO.Pipes.PipeOptions]::Asynchronous)
    $reader=$null
    try{$pipe.Connect(5000);$payload=[Text.Encoding]::UTF8.GetBytes('{"query":"audit-health"}'+"`n");$pipe.Write($payload,0,$payload.Length);$pipe.Flush();$reader=[IO.StreamReader]::new($pipe);$read=$reader.ReadLineAsync();Require ($read.Wait(5000)) 'Timeout no diagnostico';$reply=$read.Result|ConvertFrom-Json;Require ($reply.ok -eq $true) 'Diagnostico recusado';return $reply.data}
    finally{if($reader){$reader.Dispose()};$pipe.Dispose()}
}
$mustRestart=$false
try {
    $state.policyHashBefore=(Get-FileHash $policy -Algorithm SHA256).Hash
    $state.queueHashBefore=(Get-FileHash $queue -Algorithm SHA256).Hash
    Require ($state.policyHashBefore -eq '16979B6447FE37E98270729DEEAAFC5BA741AC4509BEF9730B2F11FFB093D90F' -and $state.queueHashBefore -eq 'CFCAE771B1ACC370A10850853FF18103C780C3A2D69512253D4832C87C09C9EB') 'Dados anteriores divergentes.'
    $state.originalEventIds=@(Read-Events | ForEach-Object eventId)
    Require ($state.originalEventIds.Count -eq 9 -and @($state.originalEventIds | Select-Object -Unique).Count -eq 9) 'Esperados nove eventos originais.'
    Copy-Item -LiteralPath $queue -Destination (Join-Path $results 'queue-before.jsonl')
    Copy-Item -LiteralPath $policy -Destination (Join-Path $results 'policy-before.json')
    $setup=Start-Process $installer -WindowStyle Hidden -Wait -PassThru -ArgumentList @('/VERYSILENT','/SUPPRESSMSGBOXES','/NORESTART','/SP-','/MODE=FileSystemWatcher',('/LOG="'+(Join-Path $results 'install-017.log')+'"'))
    Require ($setup.ExitCode -eq 0) ('Instalacao falhou: '+$setup.ExitCode)
    $installed=Get-Content (Join-Path $root 'setup\installation.json') -Raw|ConvertFrom-Json
    Require ($installed.version -eq $manifest.version -and $installed.commit -eq $manifest.commit -and $installed.mode -eq 'FileSystemWatcher' -and [string]::IsNullOrEmpty($installed.adminBaseUrl)) 'Instalacao resultante divergente.'
    $state.installedFilesChecked=0
    foreach($entry in $manifest.files){$p=[IO.Path]::GetFullPath((Join-Path $root $entry.path));Require ($p.StartsWith($root+'\',[StringComparison]::OrdinalIgnoreCase)) 'Payload fora do destino';Require ((Get-FileHash $p -Algorithm SHA256).Hash -eq $entry.sha256) ('Hash instalado divergente: '+$entry.path);$state.installedFilesChecked++}
    $service=Get-CimInstance Win32_Service -Filter "Name='SafeUploadAgent'"
    Require ($service.State -eq 'Running' -and $service.StartName -eq 'LocalSystem') 'Servico nao esta Running/LocalSystem.'
    $state.policyHashAfterInstall=(Get-FileHash $policy -Algorithm SHA256).Hash
    $state.queueHashAfterInstall=(Get-FileHash $queue -Algorithm SHA256).Hash
    Require ($state.policyHashBefore -eq $state.policyHashAfterInstall -and $state.queueHashBefore -eq $state.queueHashAfterInstall) 'Instalacao mudou os dados.'
    $state.healthInitial=Read-Health
    Require (-not $state.healthInitial.degraded -and $state.healthInitial.failedWriteAttempts -eq 0) 'Saude inicial divergente.'
    $state.result='installation-passed-awaiting-ui';Save-State
    Wait-Gate 'ui-pronta.txt' 'ui017-history9-confirmed' 240
    $uiPath=Join-Path $root 'ui\SafeUpload.Agent.App.exe'
    $ui=@(Get-CimInstance Win32_Process -Filter "Name='SafeUpload.Agent.App.exe'" | Where-Object ExecutablePath -eq $uiPath)
    Require ($ui.Count -eq 1 -and $ui[0].SessionId -eq 1) 'UI interativa inesperada.'
    $state.uiBefore=$ui[0] | Select-Object ProcessId,SessionId,CreationDate
    $monitored='C:\SafeUpload\Escopo Monitorado'
    $state.failedFixtureName='homologacao-017-failure-'+[Guid]::NewGuid().ToString('N')+'.txt'
    $lock=[IO.FileStream]::new($queue,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read)
    try {
        [IO.File]::WriteAllText((Join-Path $monitored $state.failedFixtureName),'CPF de teste: 529.982.247-25',[Text.UTF8Encoding]::new($false))
        for($i=0;$i -lt 40;$i++){$state.healthDegraded=Read-Health;if($state.healthDegraded.degraded -and $state.healthDegraded.failedWriteAttempts -ge 1){break};Start-Sleep -Milliseconds 250}
        Require ($state.healthDegraded.degraded -and $state.healthDegraded.failedWriteAttempts -ge 1) 'Falha de escrita nao sinalizada.'
    }finally{$lock.Dispose()}
    $state.queueHashAfterRefusal=(Get-FileHash $queue -Algorithm SHA256).Hash
    Require ($state.queueHashAfterRefusal -eq $state.queueHashBefore) 'Recusa de compartilhamento alterou fila.'
    $state.recoveryFixtureName='homologacao-017-recovery-'+[Guid]::NewGuid().ToString('N')+'.txt'
    [IO.File]::WriteAllText((Join-Path $monitored $state.recoveryFixtureName),'Relatorio sintetico sem dados pessoais.',[Text.UTF8Encoding]::new($false))
    for($i=0;$i -lt 40;$i++){$state.healthResumed=Read-Health;if(-not $state.healthResumed.degraded){break};Start-Sleep -Milliseconds 250}
    Require (-not $state.healthResumed.degraded -and $state.healthResumed.failedWriteAttempts -ge $state.healthDegraded.failedWriteAttempts) 'Retomada ou contador divergente.'
    $events=@(Read-Events)
    Require ($events.Count -eq 10 -and @($events | Where-Object fileName -eq $state.failedFixtureName).Count -eq 0) 'Quantidade inesperada apos escrita perdida.'
    $recovery=@($events | Where-Object fileName -eq $state.recoveryFixtureName)
    Require ($recovery.Count -eq 1 -and $recovery[0].verdict -eq 'Approved') 'Arquivo de retomada nao auditado.'
    $state.recoveryEventId=$recovery[0].eventId
    $logs=@(Get-WinEvent -FilterHashtable @{LogName='Application';StartTime=([DateTime]::Parse($state.startedAtUtc));Id=3101,3102} -ErrorAction SilentlyContinue | Where-Object ProviderName -eq 'SafeUpload.Agent.Service')
    Require (@($logs | Where-Object Id -eq 3101).Count -ge 1 -and @($logs | Where-Object Id -eq 3102).Count -ge 1) 'Logs 3101/3102 ausentes.'
    foreach($log in $logs){Require (-not $log.Message.Contains($data) -and -not $log.Message.Contains($state.failedFixtureName) -and -not $log.Message.Contains('529.982.247-25')) 'Dado sensivel no log de saude.'}
    $state.healthLogs=@($logs | Select-Object Id,Message)
    $state.result='health-passed-awaiting-cpf';Save-State
    Wait-Gate 'cpf-confirmado.txt' 'ui017-history11-confirmed' 240
    $events=@(Read-Events)
    Require ($events.Count -eq 11 -and @($events.eventId | Select-Object -Unique).Count -eq 11) 'Esperados onze eventos unicos.'
    foreach($id in $state.originalEventIds){Require (@($events | Where-Object eventId -eq $id).Count -eq 1) 'Evento original ausente/duplicado.'}
    $state.eventIdsBeforeRestart=@($events.eventId)
    $state.queueHashBeforeRestart=(Get-FileHash $queue -Algorithm SHA256).Hash
    $state.servicePidBeforeRestart=(Get-CimInstance Win32_Service -Filter "Name='SafeUploadAgent'").ProcessId
    $mustRestart=$true
    Stop-Service SafeUploadAgent
    (Get-Service SafeUploadAgent).WaitForStatus('Stopped',[TimeSpan]::FromSeconds(20))
    $state.stoppedAtUtc=[DateTime]::UtcNow.ToString('o');$state.result='service-stopped-awaiting-observation';Save-State
    $deadline=[DateTime]::UtcNow.AddSeconds(45)
    while([DateTime]::UtcNow -lt $deadline -and -not (Test-Path (Join-Path $results 'parada-observada.txt'))){Start-Sleep -Milliseconds 500}
    Start-Service SafeUploadAgent
    (Get-Service SafeUploadAgent).WaitForStatus('Running',[TimeSpan]::FromSeconds(20));$mustRestart=$false
    $state.runningAtUtc=[DateTime]::UtcNow.ToString('o');Start-Sleep -Seconds 8
    $state.servicePidAfterRestart=(Get-CimInstance Win32_Service -Filter "Name='SafeUploadAgent'").ProcessId
    $state.uiAfter=@(Get-CimInstance Win32_Process -Filter "Name='SafeUpload.Agent.App.exe'" | Where-Object ExecutablePath -eq $uiPath | Select-Object ProcessId,SessionId,CreationDate)
    Require ($state.uiAfter.Count -eq 1 -and $state.uiAfter[0].ProcessId -eq $state.uiBefore.ProcessId -and $state.uiAfter[0].CreationDate -eq $state.uiBefore.CreationDate) 'UI substituida no reinicio.'
    Require ($state.servicePidBeforeRestart -ne $state.servicePidAfterRestart) 'PID do servico nao mudou.'
    $state.queueHashAfterRestart=(Get-FileHash $queue -Algorithm SHA256).Hash
    $state.policyHashAfterRestart=(Get-FileHash $policy -Algorithm SHA256).Hash
    Require ($state.queueHashAfterRestart -eq $state.queueHashBeforeRestart -and $state.policyHashAfterRestart -eq $state.policyHashBefore) 'Reinicio mudou dados.'
    $state.healthAfterRestart=Read-Health
    Require (-not $state.healthAfterRestart.degraded -and $state.healthAfterRestart.failedWriteAttempts -eq 0) 'Contadores nao reiniciaram com o processo.'
    $state.result='installation-health-and-service-restart-passed-ui-final-check-pending'
}catch{$state.result='failed';$state.error=$_.Exception.Message}
finally{if($mustRestart){try{Start-Service SafeUploadAgent;$state.recovery='existing-service-start-requested'}catch{$state.recovery=$_.Exception.Message}};$state.finishedAtUtc=[DateTime]::UtcNow.ToString('o');Save-State}
