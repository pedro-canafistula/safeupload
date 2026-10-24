#Requires -Version 5.1
param([switch]$PreflightOnly)
$ErrorActionPreference='Stop'
function Require([bool]$Condition,[string]$Message){if(-not $Condition){throw $Message}}
Require ((Get-CimInstance Win32_ComputerSystemProduct).UUID -eq '3a9992db-4644-405c-b642-9766edd10650') 'Clone inesperado.'
Require ($PSScriptRoot -eq 'C:\Users\safeuploadlab\Desktop\Homologacao-SafeUpload-016\0113') 'Pasta inesperada.'
$root='C:\Program Files\SafeUpload\Agent';$data='C:\ProgramData\SafeUpload'
$installer=Join-Path $PSScriptRoot 'SafeUploadAgent-0.1.13-win-x64-setup.exe'
Require ((Get-FileHash $installer).Hash -eq '775A61F3BEF61BDDC84233551C343371AD9A6AAC7FC88453847B0D1ED7D8588D') 'Pacote divergente.'
$manifestPath=Join-Path $PSScriptRoot 'payload-manifest-0113.json'
Require ((Get-FileHash $manifestPath).Hash -eq '950F2A7F6B1D7E5243F6B9CB4535B1B667ECAD40EBC87254976DA4296EE41797') 'Manifesto divergente.'
$manifest=Get-Content $manifestPath -Raw|ConvertFrom-Json
Require ($manifest.version -eq '0.1.13' -and $manifest.commit -eq '008b4e367a1269bbc3b9d003e62bc1419ca0ef40' -and -not $manifest.sourceDirty -and @($manifest.files).Count -eq 724) 'Fonte inesperada.'
$results=Join-Path $PSScriptRoot 'resultado';Require (-not(Test-Path $results)) 'Recibo anterior; nao sobrescrever.'
if($PreflightOnly){[ordered]@{result='package-preflight-passed';version=$manifest.version;commit=$manifest.commit}|ConvertTo-Json;return}
Require (([Security.Principal.WindowsPrincipal]::new([Security.Principal.WindowsIdentity]::GetCurrent())).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) 'Elevacao necessaria.'
Require (-not(Get-Service SafeUploadAgent -ErrorAction SilentlyContinue) -and -not(Test-Path 'HKLM:\SYSTEM\CurrentControlSet\Services\SafeUpload')) 'Servico/driver inesperado.'
Require (-not(Test-Path $root) -and @(Get-CimInstance Win32_Process -Filter "Name='SafeUpload.Agent.App.exe'").Count -eq 0) 'Residuo de instalacao inesperado.'
Require (-not(Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run' -Name SafeUploadAgentConsole -ErrorAction SilentlyContinue)) 'Startup inesperado.'
$previous=Get-Content 'C:\Users\safeuploadlab\Desktop\Homologacao-SafeUpload-016\0112\encerramento-0112\result.json' -Raw|ConvertFrom-Json
Require ($previous.result -eq 'boot-diagnostics-and-uninstall-passed' -and $previous.uninstallStatus -eq 'passed' -and $previous.uninstallExitCode -eq 0) 'Aceite anterior divergente.'
$queue=Join-Path $data 'queue.jsonl';$policy=Join-Path $data 'policy.json'
Require ((Get-FileHash $queue).Hash -eq '8991D6C6055BF258197E48C1840640B49E5FFD1CD8D0FF84F925938B500E2C06' -and (Get-FileHash $policy).Hash -eq '16979B6447FE37E98270729DEEAAFC5BA741AC4509BEF9730B2F11FFB093D90F') 'Dados anteriores modificados.'
New-Item -ItemType Directory -Path $results|Out-Null
$state=[ordered]@{result='running';startedAtUtc=[DateTime]::UtcNow.ToString('o');version=$manifest.version;commit=$manifest.commit;uiObservation='pending';bootStatus='pending';uninstallStatus='pending'}
function Save-State{$state|ConvertTo-Json -Depth 14|Set-Content (Join-Path $results 'result.json') -Encoding UTF8}
function Read-Diagnostic([string]$Query){$p=[IO.Pipes.NamedPipeClientStream]::new('.','SafeUpload.Agent.Diagnostics',[IO.Pipes.PipeDirection]::InOut,[IO.Pipes.PipeOptions]::Asynchronous);$r=$null;try{$p.Connect(5000);$b=[Text.Encoding]::UTF8.GetBytes((@{query=$Query}|ConvertTo-Json -Compress)+"`n");$p.Write($b,0,$b.Length);$p.Flush();$r=[IO.StreamReader]::new($p);$t=$r.ReadLineAsync();Require ($t.Wait(5000)) 'Tempo limite';$q=$t.Result|ConvertFrom-Json;Require $q.ok 'Consulta recusada';return $q.data}finally{if($r){$r.Dispose()};$p.Dispose()}}
function Assert-LabBacklog($Snapshot,[int]$Expected){
 $records=@(Get-Content 'C:\ProgramData\SafeUpload\queue.jsonl'|ForEach-Object{$_|ConvertFrom-Json}|Where-Object{$_.eventId -and -not $_.type})
 $dates=@($records|Where-Object {-not $_.dispatched}|ForEach-Object{[DateTimeOffset]::Parse($_.occurredAtUtc).ToUniversalTime()}|Sort-Object)
 Require ($Snapshot.queueBytes -eq (Get-Item 'C:\ProgramData\SafeUpload\queue.jsonl').Length) 'Bytes do inventario divergentes.'
 Require ($Snapshot.validEvents -eq $Expected -and $Snapshot.pendingEvents -eq $Expected -and $Snapshot.dispatchedEvents -eq 0 -and $Snapshot.validOverrides -eq 0 -and $Snapshot.pendingOverrides -eq 0 -and $Snapshot.dispatchedOverrides -eq 0 -and $Snapshot.pendingWithoutTimestamp -eq 0) 'Contagens do inventario divergentes.'
 Require ($dates.Count -eq $Expected -and [DateTimeOffset]::Parse($Snapshot.oldestPendingUtc).ToUniversalTime() -eq $dates[0]) 'Menor data do inventario divergente.'
}
try{
 $state.preservedFiles=$previous.preservedFiles
 Require (@($state.preservedFiles).Count -eq 9 -and @($previous.eventIds).Count -eq 19) 'Baseline divergente.'
 $state.baseline=[ordered]@{policyHash=$previous.policyHash;eventIds=@($previous.eventIds)}
 $state.fixtures=(Get-Content 'C:\Users\safeuploadlab\Desktop\Homologacao-SafeUpload-016\0112\reinicio-0112\result.json' -Raw|ConvertFrom-Json).fixtures
 foreach($entry in $state.preservedFiles){Require ((Get-FileHash -LiteralPath $entry.path).Hash -eq $entry.sha256) 'Dado anterior divergente.'}
 $setup=Start-Process $installer -WindowStyle Hidden -Wait -PassThru -ArgumentList @('/VERYSILENT','/SUPPRESSMSGBOXES','/NORESTART','/SP-','/MODE=FileSystemWatcher',('/LOG="'+(Join-Path $results 'install-0113.log')+'"'));Require ($setup.ExitCode -eq 0) 'Instalacao falhou.'
 $state.installExitCode=$setup.ExitCode
 $installed=Get-Content (Join-Path $root 'setup\installation.json') -Raw|ConvertFrom-Json
 Require ($installed.version -eq $manifest.version -and $installed.commit -eq $manifest.commit -and $installed.mode -eq 'FileSystemWatcher' -and [string]::IsNullOrEmpty($installed.adminBaseUrl)) 'Instalacao divergente.'
 $state.checkedPayloadFiles=0
 foreach($entry in $manifest.files){$p=[IO.Path]::GetFullPath((Join-Path $root $entry.path));Require ($p.StartsWith($root+'\',[StringComparison]::OrdinalIgnoreCase) -and (Get-FileHash $p).Hash -eq $entry.sha256) 'Payload instalado divergente';$state.checkedPayloadFiles++}
 $service=Get-CimInstance Win32_Service -Filter "Name='SafeUploadAgent'";Require ($service.State -eq 'Running' -and $service.StartName -eq 'LocalSystem') 'Servico inesperado.'
 $state.service=$service|Select-Object State,StartName,ProcessId
 foreach($entry in $state.preservedFiles){Require ((Get-FileHash -LiteralPath $entry.path).Hash -eq $entry.sha256) 'Instalacao alterou dados.'}
 $state.integrity=Read-Diagnostic 'audit-integrity';Require ($state.integrity.validEvents -eq 19 -and -not $state.integrity.requiresAttention) 'Integridade divergente.'
 Assert-LabBacklog $state.integrity 19
 $state.temporaries=Read-Diagnostic 'audit-temporaries';Require ($state.temporaries.candidateFiles -eq 2 -and $state.temporaries.totalBytes -eq 25 -and $state.temporaries.skippedReparsePoints -eq 1 -and -not $state.temporaries.complete) 'Inventario divergente.'
 $state.result='installation-diagnostics-passed-ui-pending';Save-State
 $gate=Join-Path $PSScriptRoot 'ui-inicial-observada.txt';$until=[DateTime]::UtcNow.AddMinutes(30)
 while([DateTime]::UtcNow -lt $until -and -not(Test-Path $gate)){Start-Sleep -Milliseconds 500}
 Require ((Test-Path $gate) -and (Get-Content $gate -Raw).Trim() -eq 'OBSERVADO') 'Conferencia inicial da UI nao recebida.'
 & (Join-Path $PSScriptRoot 'Reiniciar-Validar-0113.ps1')
}catch{$state.result='failed';$state.error=$_.Exception.Message}
finally{$state.finishedAtUtc=[DateTime]::UtcNow.ToString('o');Save-State}
