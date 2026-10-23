#Requires -Version 5.1
param([switch]$PreflightOnly)
$ErrorActionPreference='Stop'
function Require([bool]$Condition,[string]$Message){if(-not $Condition){throw $Message}}
Require ($PSScriptRoot -eq 'C:\Users\safeuploadlab\Desktop\Homologacao-SafeUpload-016\019') 'Pasta inesperada.'
$before=$null
$installer=Join-Path $PSScriptRoot 'SafeUploadAgent-0.1.9-win-x64-setup.exe'
Require ((Get-FileHash $installer -Algorithm SHA256).Hash -eq '03FBC7F0372E7B6CEF5B56D32C3CEDEAC431DBB2A18CA59E01F717753E06196F') 'Pacote divergente.'
$manifestPath=Join-Path $PSScriptRoot 'payload-manifest-019.json'
Require ((Get-FileHash $manifestPath -Algorithm SHA256).Hash -eq '0F3C2EC7EA37FEE3AFB6FF4330704290F76F24CB2728E0C7ABEC37B78E480DD3') 'Manifesto divergente.'
$manifest=Get-Content $manifestPath -Raw | ConvertFrom-Json
Require ($manifest.version -eq '0.1.9' -and $manifest.commit -eq '8801944cdcd9a245a3eb02107305771c85b91a3a' -and -not $manifest.sourceDirty -and @($manifest.files).Count -eq 724) 'Origem divergente.'
$results=Join-Path $PSScriptRoot 'resultado'
Require (-not (Test-Path $results)) 'Recibo anterior presente; nao sobrescrever.'
if($PreflightOnly){[ordered]@{result='package-preflight-passed';baseline=$before;version=$manifest.version} | ConvertTo-Json -Depth 8;return}
Require (([Security.Principal.WindowsPrincipal]::new([Security.Principal.WindowsIdentity]::GetCurrent())).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) 'Elevacao necessaria.'
$before=(& (Join-Path $PSScriptRoot 'Preflight-019.ps1')) | ConvertFrom-Json
New-Item -ItemType Directory -Path $results | Out-Null
$root='C:\Program Files\SafeUpload\Agent'; $data='C:\ProgramData\SafeUpload'
$queue=Join-Path $data 'queue.jsonl'; $policy=Join-Path $data 'policy.json'
$state=[ordered]@{result='running';startedAtUtc=[DateTime]::UtcNow.ToString('o');version=$manifest.version;commit=$manifest.commit;vmUuid=$before.vmUuid;baseline=$before;uiObservation='pending';bootStatus='pending';uninstallStatus='pending'}
function Save-State{$state | ConvertTo-Json -Depth 14 | Set-Content (Join-Path $results 'result.json') -Encoding UTF8}
function Read-Diagnostic([string]$Query){
 $pipe=[IO.Pipes.NamedPipeClientStream]::new('.','SafeUpload.Agent.Diagnostics',[IO.Pipes.PipeDirection]::InOut,[IO.Pipes.PipeOptions]::Asynchronous)
 $reader=$null
 try{$pipe.Connect(5000);$payload=[Text.Encoding]::UTF8.GetBytes((@{query=$Query}|ConvertTo-Json -Compress)+"`n");$pipe.Write($payload,0,$payload.Length);$pipe.Flush();$reader=[IO.StreamReader]::new($pipe);$read=$reader.ReadLineAsync();Require ($read.Wait(5000)) 'Tempo limite do diagnostico';$reply=$read.Result|ConvertFrom-Json;Require ($reply.ok -eq $true) ('Consulta recusada: '+$Query);return $reply.data}finally{if($reader){$reader.Dispose()};$pipe.Dispose()}
}
try{
 Copy-Item -LiteralPath $queue -Destination (Join-Path $results 'queue-before.jsonl')
 Copy-Item -LiteralPath $policy -Destination (Join-Path $results 'policy-before.json')
 $setup=Start-Process $installer -WindowStyle Hidden -Wait -PassThru -ArgumentList @('/VERYSILENT','/SUPPRESSMSGBOXES','/NORESTART','/SP-','/MODE=FileSystemWatcher',('/LOG="'+(Join-Path $results 'install-019.log')+'"'))
 Require ($setup.ExitCode -eq 0) ('Instalacao falhou: '+$setup.ExitCode)
 $installed=Get-Content (Join-Path $root 'setup\installation.json') -Raw|ConvertFrom-Json
 Require ($installed.version -eq $manifest.version -and $installed.commit -eq $manifest.commit -and $installed.mode -eq 'FileSystemWatcher' -and [string]::IsNullOrEmpty($installed.adminBaseUrl)) 'Instalacao resultante divergente.'
 $state.checkedPayloadFiles=0
 foreach($entry in $manifest.files){$p=[IO.Path]::GetFullPath((Join-Path $root $entry.path));Require ($p.StartsWith($root+'\',[StringComparison]::OrdinalIgnoreCase)) 'Payload fora do destino';Require ((Get-FileHash $p -Algorithm SHA256).Hash -eq $entry.sha256) ('Arquivo instalado divergente: '+$entry.path);$state.checkedPayloadFiles++}
 $service=Get-CimInstance Win32_Service -Filter "Name='SafeUploadAgent'"
 Require ($service.State -eq 'Running' -and $service.StartName -eq 'LocalSystem') 'Servico nao esta Running/LocalSystem.'
 $state.service=$service|Select-Object Name,State,StartName,ProcessId,PathName
 Require ((Get-FileHash $queue).Hash -eq $before.queueHash -and (Get-FileHash $policy).Hash -eq $before.policyHash) 'Instalacao alterou os dados.'
 $state.health=Read-Diagnostic 'audit-health';Require (-not $state.health.degraded) 'Saude inicial degradada.'
 $state.integrity=Read-Diagnostic 'audit-integrity'
 Require ($state.integrity.validEvents -eq 11 -and $state.integrity.invalidLines -eq 0 -and $state.integrity.unknownRecords -eq 0) 'Integridade inicial divergente.'
 $state.initialTemporaries=Read-Diagnostic 'audit-temporaries'
 Require ($state.initialTemporaries.complete -and $state.initialTemporaries.candidateFiles -eq 0) 'Temporarios anteriores inesperados.'
 $candidate=$queue+'.'+[Guid]::NewGuid().ToString('N')+'.tmp'
 $emptyCandidate=$queue+'.'+[Guid]::NewGuid().ToString('N')+'.tmp'
 $link=$queue+'.'+[Guid]::NewGuid().ToString('N')+'.tmp'
 $target=Join-Path $PSScriptRoot 'alvo-junction-sintetico';New-Item -ItemType Directory -Path $target | Out-Null
 [IO.File]::WriteAllText($candidate,'SYNTHETIC_PRIVATE_CONTENT',[Text.UTF8Encoding]::new($false))
 [IO.File]::WriteAllBytes($emptyCandidate,[byte[]]@())
 New-Item -ItemType Junction -Path $link -Target $target | Out-Null
 $state.fixtures=[ordered]@{candidate=$candidate;emptyCandidate=$emptyCandidate;junction=$link;target=$target;candidateHash=(Get-FileHash $candidate).Hash;emptyCandidateHash=(Get-FileHash $emptyCandidate).Hash}
 $state.temporaries=Read-Diagnostic 'audit-temporaries'
 Require ($state.temporaries.candidateFiles -eq 2 -and $state.temporaries.totalBytes -eq 25 -and $state.temporaries.skippedReparsePoints -eq 1 -and $state.temporaries.unreadableCandidates -eq 0 -and -not $state.temporaries.complete -and $state.temporaries.requiresAttention) 'Inventario incorreto.'
 $reply=$state.temporaries|ConvertTo-Json -Depth 6
 Require (-not $reply.Contains($data) -and -not $reply.Contains([IO.Path]::GetFileName($candidate)) -and -not $reply.Contains('SYNTHETIC_PRIVATE_CONTENT')) 'Resposta expôs dados privados.'
 Require ((Get-FileHash $queue).Hash -eq $before.queueHash -and (Get-FileHash $candidate).Hash -eq $state.fixtures.candidateHash) 'Consulta alterou arquivos.'
 $state.result='installation-diagnostics-passed-ui-pending'
}catch{$state.result='failed';$state.error=$_.Exception.Message}
finally{$state.finishedAtUtc=[DateTime]::UtcNow.ToString('o');Save-State}

