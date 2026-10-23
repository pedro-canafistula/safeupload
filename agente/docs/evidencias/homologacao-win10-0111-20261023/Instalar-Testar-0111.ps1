#Requires -Version 5.1
param([switch]$PreflightOnly)
$ErrorActionPreference='Stop'
function Require([bool]$Condition,[string]$Message){if(-not $Condition){throw $Message}}
Require ((Get-CimInstance Win32_ComputerSystemProduct).UUID -eq '3a9992db-4644-405c-b642-9766edd10650') 'Clone inesperado.'
Require ($PSScriptRoot -eq 'C:\Users\safeuploadlab\Desktop\Homologacao-SafeUpload-016\0111') 'Pasta inesperada.'
$root='C:\Program Files\SafeUpload\Agent';$data='C:\ProgramData\SafeUpload'
$installer=Join-Path $PSScriptRoot 'SafeUploadAgent-0.1.11-win-x64-setup.exe'
Require ((Get-FileHash $installer).Hash -eq '66BA476103B5F9F32FAB0126F979CE60B1F85A04172EDA5BAA6C4494F951C671') 'Pacote divergente.'
$manifestPath=Join-Path $PSScriptRoot 'payload-manifest-0111.json'
Require ((Get-FileHash $manifestPath).Hash -eq '1D9C2D15EA3E26A60480CEB0D853AF5320D19B7CD143056DCEC57C1B90D71990') 'Manifesto divergente.'
$manifest=Get-Content $manifestPath -Raw|ConvertFrom-Json
Require ($manifest.version -eq '0.1.11' -and $manifest.commit -eq '42e34afd73b9e7fe8d183a032a3bcf9abc13f282' -and -not $manifest.sourceDirty -and @($manifest.files).Count -eq 724) 'Fonte inesperada.'
$results=Join-Path $PSScriptRoot 'resultado';Require (-not(Test-Path $results)) 'Recibo anterior; nao sobrescrever.'
if($PreflightOnly){[ordered]@{result='package-preflight-passed';version=$manifest.version;commit=$manifest.commit}|ConvertTo-Json;return}
Require (([Security.Principal.WindowsPrincipal]::new([Security.Principal.WindowsIdentity]::GetCurrent())).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) 'Elevacao necessaria.'
Require (-not(Get-Service SafeUploadAgent -ErrorAction SilentlyContinue) -and -not(Test-Path 'HKLM:\SYSTEM\CurrentControlSet\Services\SafeUpload')) 'Servico/driver inesperado.'
Require (-not(Test-Path $root) -and @(Get-CimInstance Win32_Process -Filter "Name='SafeUpload.Agent.App.exe'").Count -eq 0) 'Residuo de instalacao inesperado.'
Require (-not(Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run' -Name SafeUploadAgentConsole -ErrorAction SilentlyContinue)) 'Startup inesperado.'
$previous=Get-Content 'C:\Users\safeuploadlab\Desktop\Homologacao-SafeUpload-016\0110\encerramento-0110\result.json' -Raw|ConvertFrom-Json
Require ($previous.result -eq 'boot-diagnostics-and-uninstall-passed' -and $previous.uninstallStatus -eq 'passed' -and $previous.uninstallExitCode -eq 0) 'Aceite anterior divergente.'
$queue=Join-Path $data 'queue.jsonl';$policy=Join-Path $data 'policy.json'
Require ((Get-FileHash $queue).Hash -eq '0DBFD965F0992A30AF77498A1E167BDEAD9AAEF03CB061171609545CE20E1F5A' -and (Get-FileHash $policy).Hash -eq '16979B6447FE37E98270729DEEAAFC5BA741AC4509BEF9730B2F11FFB093D90F') 'Dados anteriores modificados.'
New-Item -ItemType Directory -Path $results|Out-Null
$state=[ordered]@{result='running';startedAtUtc=[DateTime]::UtcNow.ToString('o');version=$manifest.version;commit=$manifest.commit;uiObservation='pending';bootStatus='pending';uninstallStatus='pending'}
function Save-State{$state|ConvertTo-Json -Depth 14|Set-Content (Join-Path $results 'result.json') -Encoding UTF8}
function Read-Diagnostic([string]$Query){$p=[IO.Pipes.NamedPipeClientStream]::new('.','SafeUpload.Agent.Diagnostics',[IO.Pipes.PipeDirection]::InOut,[IO.Pipes.PipeOptions]::Asynchronous);$r=$null;try{$p.Connect(5000);$b=[Text.Encoding]::UTF8.GetBytes((@{query=$Query}|ConvertTo-Json -Compress)+"`n");$p.Write($b,0,$b.Length);$p.Flush();$r=[IO.StreamReader]::new($p);$t=$r.ReadLineAsync();Require ($t.Wait(5000)) 'Tempo limite';$q=$t.Result|ConvertFrom-Json;Require $q.ok 'Consulta recusada';return $q.data}finally{if($r){$r.Dispose()};$p.Dispose()}}
try{
 $state.preservedFiles=$previous.preservedFiles
 Require (@($state.preservedFiles).Count -eq 7 -and @($previous.eventIds).Count -eq 15) 'Baseline divergente.'
 $state.baseline=[ordered]@{policyHash=$previous.policyHash;eventIds=@($previous.eventIds)}
 $state.fixtures=(Get-Content 'C:\Users\safeuploadlab\Desktop\Homologacao-SafeUpload-016\0110\reinicio-0110\result.json' -Raw|ConvertFrom-Json).fixtures
 foreach($entry in $state.preservedFiles){Require ((Get-FileHash -LiteralPath $entry.path).Hash -eq $entry.sha256) 'Dado anterior divergente.'}
 $setup=Start-Process $installer -WindowStyle Hidden -Wait -PassThru -ArgumentList @('/VERYSILENT','/SUPPRESSMSGBOXES','/NORESTART','/SP-','/MODE=FileSystemWatcher',('/LOG="'+(Join-Path $results 'install-0111.log')+'"'));Require ($setup.ExitCode -eq 0) 'Instalacao falhou.'
 $state.installExitCode=$setup.ExitCode
 $installed=Get-Content (Join-Path $root 'setup\installation.json') -Raw|ConvertFrom-Json
 Require ($installed.version -eq $manifest.version -and $installed.commit -eq $manifest.commit -and $installed.mode -eq 'FileSystemWatcher' -and [string]::IsNullOrEmpty($installed.adminBaseUrl)) 'Instalacao divergente.'
 $state.checkedPayloadFiles=0
 foreach($entry in $manifest.files){$p=[IO.Path]::GetFullPath((Join-Path $root $entry.path));Require ($p.StartsWith($root+'\',[StringComparison]::OrdinalIgnoreCase) -and (Get-FileHash $p).Hash -eq $entry.sha256) 'Payload instalado divergente';$state.checkedPayloadFiles++}
 $service=Get-CimInstance Win32_Service -Filter "Name='SafeUploadAgent'";Require ($service.State -eq 'Running' -and $service.StartName -eq 'LocalSystem') 'Servico inesperado.'
 $state.service=$service|Select-Object State,StartName,ProcessId
 foreach($entry in $state.preservedFiles){Require ((Get-FileHash -LiteralPath $entry.path).Hash -eq $entry.sha256) 'Instalacao alterou dados.'}
 $state.integrity=Read-Diagnostic 'audit-integrity';Require ($state.integrity.validEvents -eq 15 -and -not $state.integrity.requiresAttention) 'Integridade divergente.'
 $state.temporaries=Read-Diagnostic 'audit-temporaries';Require ($state.temporaries.candidateFiles -eq 2 -and $state.temporaries.totalBytes -eq 25 -and $state.temporaries.skippedReparsePoints -eq 1 -and -not $state.temporaries.complete) 'Inventario divergente.'
 $state.result='installation-diagnostics-passed-ui-pending';Save-State
 $gate=Join-Path $PSScriptRoot 'ui-inicial-observada.txt';$until=[DateTime]::UtcNow.AddMinutes(30)
 while([DateTime]::UtcNow -lt $until -and -not(Test-Path $gate)){Start-Sleep -Milliseconds 500}
 Require ((Test-Path $gate) -and (Get-Content $gate -Raw).Trim() -eq 'OBSERVADO') 'Conferencia inicial da UI nao recebida.'
 & (Join-Path $PSScriptRoot 'Reiniciar-Validar-0111.ps1')
}catch{$state.result='failed';$state.error=$_.Exception.Message}
finally{$state.finishedAtUtc=[DateTime]::UtcNow.ToString('o');Save-State}
