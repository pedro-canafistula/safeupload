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

$principal=[Security.Principal.WindowsPrincipal]::new([Security.Principal.WindowsIdentity]::GetCurrent()); Require ($principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) 'Elevacao local necessaria.'; $state=Get-Content (Join-Path $results 'result.json') -Raw|ConvertFrom-Json; Require ($state.result -eq 'failed' -and $state.error -eq 'Conferencia nao recebida: ui-pronta.txt') 'Estado de retomada inesperado.'; Copy-Item (Join-Path $results 'result.json') (Join-Path $results 'installation-timeout.json') -ErrorAction Stop; $oldState=$state; $state=[ordered]@{}; foreach($p in $oldState.PSObject.Properties){if($p.Name -notin @('error','finishedAtUtc')){$state[$p.Name]=$p.Value}}; Require ((Get-FileHash $queue).Hash -eq $state.queueHashBefore) 'Fila mudou antes da retomada.'; Require ((Get-FileHash $policy).Hash -eq $state.policyHashBefore) 'Politica mudou antes da retomada.'; Require ((Get-Service SafeUploadAgent).Status -eq 'Running') 'Servico nao executa.'; $state.resumedAtUtc=[DateTime]::UtcNow.ToString('o');
function Save-State { $state | ConvertTo-Json -Depth 14 | Set-Content (Join-Path $results 'result.json') -Encoding UTF8 }
function Read-Events { @(Get-Content $queue | ForEach-Object {$_ | ConvertFrom-Json} | Where-Object {$_.eventId -and -not $_.type}) }
function Wait-Gate([string]$Name,[string]$Value,[int]$Seconds){$p=Join-Path $results $Name;$deadline=[DateTime]::UtcNow.AddSeconds($Seconds);while([DateTime]::UtcNow -lt $deadline -and -not (Test-Path $p)){Start-Sleep -Milliseconds 500};Require ((Test-Path $p) -and (Get-Content $p -Raw).Trim() -eq $Value) ('Conferencia nao recebida: '+$Name)}
function Read-Health {
    $pipe=[IO.Pipes.NamedPipeClientStream]::new('.','SafeUpload.Agent.Diagnostics',[IO.Pipes.PipeDirection]::InOut,[IO.Pipes.PipeOptions]::Asynchronous)
    $reader=$null
    try{$pipe.Connect(5000);$payload=[Text.Encoding]::UTF8.GetBytes('{"query":"audit-health"}'+"`n");$pipe.Write($payload,0,$payload.Length);$pipe.Flush();$reader=[IO.StreamReader]::new($pipe);$read=$reader.ReadLineAsync();Require ($read.Wait(5000)) 'Timeout no diagnostico';$reply=$read.Result|ConvertFrom-Json;Require ($reply.ok -eq $true) 'Diagnostico recusado';return $reply.data}
    finally{if($reader){$reader.Dispose()};$pipe.Dispose()}
}

$mustRestart=$false; try {
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
    Wait-Gate 'cpf-confirmado.txt' 'ui017-history11-confirmed' 1800
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

