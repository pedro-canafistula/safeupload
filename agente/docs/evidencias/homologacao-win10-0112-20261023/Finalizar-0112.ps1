#Requires -Version 5.1
$ErrorActionPreference='Stop'
function Require([bool]$Condition,[string]$Message){if(-not $Condition){throw $Message}}
Require ((Get-CimInstance Win32_ComputerSystemProduct).UUID -eq '3a9992db-4644-405c-b642-9766edd10650') 'Clone inesperado.'
Require ($PSScriptRoot -eq 'C:\Users\safeuploadlab\Desktop\Homologacao-SafeUpload-016\0112') 'Pasta inesperada.'
Require (([Security.Principal.WindowsPrincipal]::new([Security.Principal.WindowsIdentity]::GetCurrent())).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) 'Elevacao necessaria.'
Require ((Get-Content (Join-Path $PSScriptRoot 'ui-apos-boot-observada.txt') -Raw).Trim() -eq 'OBSERVADO') 'Conferencia visual apos boot pendente.'
$root='C:\Program Files\SafeUpload\Agent';$data='C:\ProgramData\SafeUpload';$queue=Join-Path $data 'queue.jsonl';$policy=Join-Path $data 'policy.json'
$installed=Get-Content (Join-Path $root 'setup\installation.json') -Raw|ConvertFrom-Json
Require ($installed.version -eq '0.1.12' -and $installed.commit -eq 'b49b1d960a6d0ab0bddb989a1d0574f66974441d' -and $installed.mode -eq 'FileSystemWatcher') 'Instalacao inesperada.'
$restart=Get-Content (Join-Path $PSScriptRoot 'reinicio-0112\result.json') -Raw|ConvertFrom-Json
Require ($restart.result -eq 'reboot-requested') 'Reinicio anterior nao solicitado.'
$results=Join-Path $PSScriptRoot 'encerramento-0112';Require (-not(Test-Path $results)) 'Recibo anterior presente; nao sobrescrever.'
New-Item -ItemType Directory -Path $results|Out-Null
$state=[ordered]@{result='running';version=$installed.version;commit=$installed.commit;startedAtUtc=[DateTime]::UtcNow.ToString('o');bootTime=(Get-CimInstance Win32_OperatingSystem).LastBootUpTime;uninstallStatus='pending'}
function Save-State{$state|ConvertTo-Json -Depth 14|Set-Content (Join-Path $results 'result.json') -Encoding UTF8}
function Read-Diagnostic([string]$Query){$p=[IO.Pipes.NamedPipeClientStream]::new('.','SafeUpload.Agent.Diagnostics',[IO.Pipes.PipeDirection]::InOut,[IO.Pipes.PipeOptions]::Asynchronous);$r=$null;try{$p.Connect(5000);$b=[Text.Encoding]::UTF8.GetBytes((@{query=$Query}|ConvertTo-Json -Compress)+"`n");$p.Write($b,0,$b.Length);$p.Flush();$r=[IO.StreamReader]::new($p);$t=$r.ReadLineAsync();Require ($t.Wait(5000)) 'Tempo limite';$q=$t.Result|ConvertFrom-Json;Require $q.ok 'Consulta recusada';return $q.data}finally{if($r){$r.Dispose()};$p.Dispose()}}
try{
 $service=Get-CimInstance Win32_Service -Filter "Name='SafeUploadAgent'";Require ($service.State -eq 'Running' -and $service.StartName -eq 'LocalSystem') 'Servico apos boot inesperado.'
 $state.serviceBeforeRemoval=$service|Select-Object State,StartName,ProcessId
 $state.policyHash=(Get-FileHash $policy).Hash;$state.queueHash=(Get-FileHash $queue).Hash
 Require ($state.policyHash -eq $restart.policyHash -and $state.queueHash -eq $restart.queueHash) 'Boot alterou politica/fila.'
 $events=@(Get-Content $queue|ForEach-Object{$_|ConvertFrom-Json}|Where-Object{$_.eventId -and -not $_.type});Require ($events.Count -eq 19 -and @($events.eventId|Select-Object -Unique).Count -eq 19) 'Historico divergente.'
 foreach($id in $restart.eventIds){Require (@($events|Where-Object eventId -eq $id).Count -eq 1) 'Evento anterior ausente/duplicado.'}
 $state.eventIds=@($events.eventId)
 $state.integrity=Read-Diagnostic 'audit-integrity';Require ($state.integrity.validEvents -eq 19 -and -not $state.integrity.requiresAttention) 'Integridade apos boot divergente.'
 $state.temporaries=Read-Diagnostic 'audit-temporaries';Require ($state.temporaries.candidateFiles -eq 2 -and $state.temporaries.totalBytes -eq 25 -and $state.temporaries.skippedReparsePoints -eq 1 -and -not $state.temporaries.complete -and $state.temporaries.requiresAttention) 'Inventario apos boot divergente.'
 $state.health=Read-Diagnostic 'audit-health';Require (-not $state.health.degraded) 'Saude degradada apos boot.'
 $fixture=$events|Where-Object{$_.fileName.StartsWith('homologacao-0112-cpf-')};Require (@($fixture).Count -eq 1) 'Fixture CPF inesperada.'
 $quarantined=@(Get-ChildItem 'C:\SafeUpload\_bloqueados' -File -Filter ([IO.Path]::GetFileNameWithoutExtension($fixture.fileName)+'-*.txt'));Require ($quarantined.Count -eq 1) 'Quarentena ausente/duplicada.'
 $oldQuarantine='C:\SafeUpload\_bloqueados\homologacao-017-cpf-cf8e763a48d74744ac9c7549d8f2a699-20261022-194911.txt'
 $initial=Get-Content (Join-Path $PSScriptRoot 'resultado\result.json') -Raw|ConvertFrom-Json
 $preserve=@(@($initial.preservedFiles|ForEach-Object path)+@($quarantined[0].FullName)|Select-Object -Unique)
 $state.preservedFiles=@($preserve|ForEach-Object{[ordered]@{path=$_;sha256=(Get-FileHash -LiteralPath $_).Hash;bytes=(Get-Item -LiteralPath $_).Length}})
 Require ($state.preservedFiles[2].sha256 -eq $restart.fixtures.candidateHash -and $state.preservedFiles[3].sha256 -eq $restart.fixtures.emptyCandidateHash) 'Temporarios alterados apos boot.'
 Require ($state.preservedFiles[4].sha256 -eq '605A58E33E73F44BEC1E10A8B7C842A4805BB353A2544005FAFC53F2445A2E81') 'Quarentena anterior alterada.'
 $state.result='boot-diagnostics-passed-removing';Save-State
 $uninstaller=Join-Path $root 'unins000.exe'
 Require (Test-Path $uninstaller) 'Desinstalador ausente.'
 $process=Start-Process $uninstaller -WindowStyle Hidden -Wait -PassThru -ArgumentList @('/VERYSILENT','/SUPPRESSMSGBOXES','/NORESTART',('/LOG="'+(Join-Path $results 'uninstall-0112.log')+'"'))
 $state.uninstallExitCode=$process.ExitCode;Require ($process.ExitCode -eq 0) 'Desinstalacao falhou.'
 Require (-not(Get-Service SafeUploadAgent -ErrorAction SilentlyContinue) -and -not(Test-Path 'HKLM:\SYSTEM\CurrentControlSet\Services\SafeUploadAgent')) 'Servico permanece.'
 Require (-not(Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run' -Name SafeUploadAgentConsole -ErrorAction SilentlyContinue)) 'Startup permanece.'
 Require (@(Get-CimInstance Win32_Process -Filter "Name='SafeUpload.Agent.App.exe'").Count -eq 0) 'UI permanece.'
 Require (-not(Test-Path (Join-Path $root 'service\SafeUpload.Agent.Service.exe')) -and -not(Test-Path (Join-Path $root 'ui\SafeUpload.Agent.App.exe'))) 'Executaveis permanecem.'
 foreach($entry in $state.preservedFiles){Require ((Get-FileHash -LiteralPath $entry.path).Hash -eq $entry.sha256) 'Dado preservado removido/alterado.'}
 Require ([bool]((Get-Item -LiteralPath $restart.fixtures.junction).Attributes -band [IO.FileAttributes]::ReparsePoint)) 'Junction preservada foi removida.'
 $state.uninstallStatus='passed';$state.result='boot-diagnostics-and-uninstall-passed'
}catch{$state.result='failed';$state.error=$_.Exception.Message}
finally{$state.finishedAtUtc=[DateTime]::UtcNow.ToString('o');Save-State}

