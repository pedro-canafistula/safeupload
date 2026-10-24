#Requires -Version 5.1
$ErrorActionPreference='Stop'
function Require([bool]$Condition,[string]$Message){if(-not $Condition){throw $Message}}
Require ((Get-CimInstance Win32_ComputerSystemProduct).UUID -eq '3a9992db-4644-405c-b642-9766edd10650') 'Clone inesperado.'
Require ($PSScriptRoot -eq 'C:\Users\safeuploadlab\Desktop\Homologacao-SafeUpload-016\0112') 'Pasta inesperada.'
Require (([Security.Principal.WindowsPrincipal]::new([Security.Principal.WindowsIdentity]::GetCurrent())).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) 'Elevacao necessaria.'
$root='C:\Program Files\SafeUpload\Agent';$data='C:\ProgramData\SafeUpload';$queue=Join-Path $data 'queue.jsonl';$policy=Join-Path $data 'policy.json'
$installed=Get-Content (Join-Path $root 'setup\installation.json') -Raw|ConvertFrom-Json
Require ($installed.version -eq '0.1.12' -and $installed.commit -eq 'b49b1d960a6d0ab0bddb989a1d0574f66974441d' -and $installed.mode -eq 'FileSystemWatcher' -and [string]::IsNullOrEmpty($installed.adminBaseUrl)) 'Instalacao inesperada.'
$initial=Get-Content (Join-Path $PSScriptRoot 'resultado\result.json') -Raw|ConvertFrom-Json
Require ($initial.result -eq 'installation-diagnostics-passed-ui-pending') 'Ensaio inicial incompleto.'
$results=Join-Path $PSScriptRoot 'reinicio-0112';Require (-not(Test-Path $results)) 'Recibo anterior; nao sobrescrever.'
New-Item -ItemType Directory -Path $results|Out-Null
$state=[ordered]@{result='running';version=$installed.version;commit=$installed.commit;startedAtUtc=[DateTime]::UtcNow.ToString('o');stoppedUiObserved=$false;reconnectedUiObserved=$false;bootStatus='pending'}
function Save-State{$state|ConvertTo-Json -Depth 14|Set-Content (Join-Path $results 'result.json') -Encoding UTF8}
function Wait-Gate([string]$Name,[int]$Seconds){$p=Join-Path $results $Name;$until=[DateTime]::UtcNow.AddSeconds($Seconds);while([DateTime]::UtcNow -lt $until -and -not(Test-Path $p)){Start-Sleep -Milliseconds 500};return (Test-Path $p)}
function Read-Diagnostic([string]$Query){$p=[IO.Pipes.NamedPipeClientStream]::new('.','SafeUpload.Agent.Diagnostics',[IO.Pipes.PipeDirection]::InOut,[IO.Pipes.PipeOptions]::Asynchronous);$r=$null;try{$p.Connect(5000);$b=[Text.Encoding]::UTF8.GetBytes((@{query=$Query}|ConvertTo-Json -Compress)+"`n");$p.Write($b,0,$b.Length);$p.Flush();$r=[IO.StreamReader]::new($p);$t=$r.ReadLineAsync();Require ($t.Wait(5000)) 'Tempo limite';$q=$t.Result|ConvertFrom-Json;Require $q.ok 'Consulta recusada';return $q.data}finally{if($r){$r.Dispose()};$p.Dispose()}}
function Get-LabUi{@(Get-CimInstance Win32_Process -Filter "Name='SafeUpload.Agent.App.exe'"|Where-Object ExecutablePath -eq (Join-Path $root 'ui\SafeUpload.Agent.App.exe')|Select-Object ProcessId,SessionId,CreationDate)}
$mustRestart=$false
try{
 $state.uiBefore=@(Get-LabUi);Require ($state.uiBefore.Count -eq 1 -and $state.uiBefore[0].SessionId -eq 1) 'UI inesperada.'
 $state.serviceBefore=Get-CimInstance Win32_Service -Filter "Name='SafeUploadAgent'"|Select-Object State,StartName,ProcessId
 Require ($state.serviceBefore.State -eq 'Running' -and $state.serviceBefore.StartName -eq 'LocalSystem') 'Servico inesperado.'
 $state.queueHash=(Get-FileHash $queue).Hash;$state.policyHash=(Get-FileHash $policy).Hash
 Require ($state.policyHash -eq $initial.baseline.policyHash) 'Politica modificada.'
 $events=@(Get-Content $queue|ForEach-Object{$_|ConvertFrom-Json}|Where-Object{$_.eventId -and -not $_.type})
 Require ($events.Count -eq 19 -and @($events.eventId|Select-Object -Unique).Count -eq 19) 'Esperados dezenove eventos unicos.'
 foreach($id in $initial.baseline.eventIds){Require (@($events|Where-Object eventId -eq $id).Count -eq 1) 'Evento anterior ausente/duplicado.'}
 $state.eventIds=@($events.eventId);$state.bootBefore=(Get-CimInstance Win32_OperatingSystem).LastBootUpTime
 $state.fixtures=$initial.fixtures
 Require ((Get-FileHash $state.fixtures.candidate).Hash -eq $state.fixtures.candidateHash -and (Get-FileHash $state.fixtures.emptyCandidate).Hash -eq $state.fixtures.emptyCandidateHash) 'Temporarios modificados.'
 Copy-Item -LiteralPath $queue -Destination (Join-Path $results 'queue-before-boot.jsonl')
 $mustRestart=$true;Stop-Service SafeUploadAgent;(Get-Service SafeUploadAgent).WaitForStatus('Stopped',[TimeSpan]::FromSeconds(20))
 $state.result='service-stopped-awaiting-observation';Save-State
 $state.stoppedUiObserved=Wait-Gate 'parada-observada.txt' 180
 Start-Service SafeUploadAgent;(Get-Service SafeUploadAgent).WaitForStatus('Running',[TimeSpan]::FromSeconds(20));$mustRestart=$false
 Start-Sleep -Seconds 8
 $state.serviceAfter=Get-CimInstance Win32_Service -Filter "Name='SafeUploadAgent'"|Select-Object State,StartName,ProcessId
 $state.uiAfter=@(Get-LabUi)
 Require ($state.serviceAfter.ProcessId -ne $state.serviceBefore.ProcessId) 'PID do servico nao mudou.'
 Require ($state.uiAfter.Count -eq 1 -and $state.uiAfter[0].ProcessId -eq $state.uiBefore[0].ProcessId -and $state.uiAfter[0].CreationDate -eq $state.uiBefore[0].CreationDate) 'UI foi substituida.'
 Require ((Get-FileHash $queue).Hash -eq $state.queueHash -and (Get-FileHash $policy).Hash -eq $state.policyHash) 'Reinicio alterou dados.'
 $state.integrity=Read-Diagnostic 'audit-integrity';Require ($state.integrity.validEvents -eq 19 -and -not $state.integrity.requiresAttention) 'Integridade divergente.'
 $state.temporaries=Read-Diagnostic 'audit-temporaries';Require ($state.temporaries.candidateFiles -eq 2 -and $state.temporaries.totalBytes -eq 25 -and $state.temporaries.skippedReparsePoints -eq 1 -and -not $state.temporaries.complete) 'Inventario divergente.'
 $state.result='reconnected-awaiting-boot-gate';Save-State
 Require (Wait-Gate 'reinicio-autorizado.txt' 1800) 'Conferencia antes do boot nao recebida.'
 $state.reconnectedUiObserved=$true;$state.result='reboot-requested';$state.bootStatus='requested';$state.requestedRebootAtUtc=[DateTime]::UtcNow.ToString('o');Save-State
 Restart-Computer -Force
}catch{$state.result='failed';$state.error=$_.Exception.Message;Save-State}
finally{if($mustRestart){Start-Service SafeUploadAgent}}

