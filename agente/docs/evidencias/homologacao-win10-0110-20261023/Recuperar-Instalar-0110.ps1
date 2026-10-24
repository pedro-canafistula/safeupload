#Requires -Version 5.1
param([switch]$PreflightOnly)
$ErrorActionPreference='Stop'
function Require([bool]$Condition,[string]$Message){if(-not $Condition){throw $Message}}
Require ((Get-CimInstance Win32_ComputerSystemProduct).UUID -eq '3a9992db-4644-405c-b642-9766edd10650') 'Clone inesperado.'
Require ($PSScriptRoot -eq 'C:\Users\safeuploadlab\Desktop\Homologacao-SafeUpload-016\0110') 'Pasta inesperada.'
$root='C:\Program Files\SafeUpload\Agent';$data='C:\ProgramData\SafeUpload'
$installer=Join-Path $PSScriptRoot 'SafeUploadAgent-0.1.10-win-x64-setup.exe'
Require ((Get-FileHash $installer).Hash -eq '2C63EC1A2BF984AB126E160428682F573BD371045AEBC7C3F19DD494D47DEDE0') 'Pacote divergente.'
$manifestPath=Join-Path $PSScriptRoot 'payload-manifest-0110.json'
Require ((Get-FileHash $manifestPath).Hash -eq '553D5F3A25D28FDFDBEEAF046F10763147F6557D54716D2DBD08BD10BFCDFA63') 'Manifesto divergente.'
$manifest=Get-Content $manifestPath -Raw|ConvertFrom-Json
Require ($manifest.version -eq '0.1.10' -and $manifest.commit -eq '135369df7ddabbbc0902658029021dc63724a307' -and -not $manifest.sourceDirty -and @($manifest.files).Count -eq 724) 'Fonte inesperada.'
$oldManifestPath=Join-Path $PSScriptRoot 'payload-manifest-019.json'
Require ((Get-FileHash $oldManifestPath).Hash -eq '0F3C2EC7EA37FEE3AFB6FF4330704290F76F24CB2728E0C7ABEC37B78E480DD3') 'Manifesto anterior divergente.'
$modulePath=Join-Path $PSScriptRoot 'SafeUpload.Setup.psm1'
$moduleEntry=@($manifest.files|Where-Object {$_.path.Replace('/','\') -eq 'setup\SafeUpload.Setup.psm1'})
Require ($moduleEntry.Count -eq 1 -and (Get-FileHash $modulePath).Hash -eq $moduleEntry[0].sha256) 'Modulo de recuperacao divergente.'
$results=Join-Path $PSScriptRoot 'resultado';Require (-not(Test-Path $results)) 'Recibo anterior; nao sobrescrever.'
if($PreflightOnly){[ordered]@{result='package-preflight-passed';version=$manifest.version;commit=$manifest.commit}|ConvertTo-Json;return}
Require (([Security.Principal.WindowsPrincipal]::new([Security.Principal.WindowsIdentity]::GetCurrent())).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) 'Elevacao necessaria.'
Require (-not(Get-Service SafeUploadAgent -ErrorAction SilentlyContinue) -and -not(Test-Path 'HKLM:\SYSTEM\CurrentControlSet\Services\SafeUpload')) 'Servico/driver inesperado.'
Require (-not(Test-Path (Join-Path $root 'unins000.exe')) -and -not(Test-Path (Join-Path $root 'setup\installation.json'))) 'Instalacao ativa inesperada.'
Require (-not(Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run' -Name SafeUploadAgentConsole -ErrorAction SilentlyContinue)) 'Startup inesperado.'
Import-Module $modulePath -Force
$null=Assert-SafeUploadDirectory -Path $root -ExpectedPath $root
Assert-SafeUploadInstallAcl (Get-Acl -LiteralPath $root)
$oldManifest=Get-Content $oldManifestPath -Raw|ConvertFrom-Json;$allowed=@{}
foreach($entry in $oldManifest.files){$allowed[$entry.path.Replace('/','\')]=$entry.sha256}
$remaining=@(Get-ChildItem -LiteralPath $root -File -Recurse)
Require ($remaining.Count -eq 77) 'Quantidade de residuos mudou; revisar.'
foreach($file in $remaining){$full=[IO.Path]::GetFullPath($file.FullName);Require ($full.StartsWith($root+'\',[StringComparison]::OrdinalIgnoreCase)) 'Residuo fora do destino';$relative=$full.Substring($root.Length+1);Require ($allowed.ContainsKey($relative) -and (Get-FileHash -LiteralPath $full).Hash -eq $allowed[$relative]) 'Residuo desconhecido/modificado.';$null=Assert-SafeUploadDirectory -Path $file.DirectoryName -ExpectedPath $file.DirectoryName;Require (-not($file.Attributes -band [IO.FileAttributes]::ReparsePoint)) 'Link inesperado.'}
$queue=Join-Path $data 'queue.jsonl';$policy=Join-Path $data 'policy.json'
Require ((Get-FileHash $queue).Hash -eq '8976987F17F58D9A0D317B0B8A4E92F09D8E0F5E9A3F3E8E9AE30AB7CDA6475E' -and (Get-FileHash $policy).Hash -eq '16979B6447FE37E98270729DEEAAFC5BA741AC4509BEF9730B2F11FFB093D90F') 'Dados anteriores modificados.'
New-Item -ItemType Directory -Path $results|Out-Null
$state=[ordered]@{result='running';startedAtUtc=[DateTime]::UtcNow.ToString('o');version=$manifest.version;commit=$manifest.commit;recovery019='pending';uiObservation='pending';bootStatus='pending';uninstallStatus='pending'}
function Save-State{$state|ConvertTo-Json -Depth 14|Set-Content (Join-Path $results 'result.json') -Encoding UTF8}
function Read-Diagnostic([string]$Query){$p=[IO.Pipes.NamedPipeClientStream]::new('.','SafeUpload.Agent.Diagnostics',[IO.Pipes.PipeDirection]::InOut,[IO.Pipes.PipeOptions]::Asynchronous);$r=$null;try{$p.Connect(5000);$b=[Text.Encoding]::UTF8.GetBytes((@{query=$Query}|ConvertTo-Json -Compress)+"`n");$p.Write($b,0,$b.Length);$p.Flush();$r=[IO.StreamReader]::new($p);$t=$r.ReadLineAsync();Require ($t.Wait(5000)) 'Tempo limite';$q=$t.Result|ConvertFrom-Json;Require $q.ok 'Consulta recusada';return $q.data}finally{if($r){$r.Dispose()};$p.Dispose()}}
try{
 $previous=Get-Content 'C:\Users\safeuploadlab\Desktop\Homologacao-SafeUpload-016\019\encerramento-019\result.json' -Raw|ConvertFrom-Json
 Require ($previous.result -eq 'failed' -and $previous.error -eq 'UI permanece.' -and $previous.uninstallExitCode -eq 0) 'Falha anterior inesperada.'
 $state.preservedFiles=$previous.preservedFiles
 $state.baseline=[ordered]@{policyHash=$previous.policyHash;eventIds=@($previous.eventIds)}
 $state.fixtures=(Get-Content 'C:\Users\safeuploadlab\Desktop\Homologacao-SafeUpload-016\019\reinicio-019\result.json' -Raw|ConvertFrom-Json).fixtures
 foreach($entry in $state.preservedFiles){Require ((Get-FileHash -LiteralPath $entry.path).Hash -eq $entry.sha256) 'Dado anterior divergente.'}
 $state.closedResidualUi=Stop-SafeUploadInstalledUi (Join-Path $root 'ui\SafeUpload.Agent.App.exe')
 Require ($state.closedResidualUi -in @(0,1)) 'Quantidade de interfaces residuais inesperada.'
 foreach($file in $remaining){Require ((Get-FileHash -LiteralPath $file.FullName).Hash -eq $allowed[$file.FullName.Substring($root.Length+1)]) 'Residuo mudou antes de remover';Remove-Item -LiteralPath $file.FullName -Force}
 # Only empty directories under the verified installation root; never recurse-delete.
 foreach($directory in @(Get-ChildItem -LiteralPath $root -Directory -Recurse|Sort-Object {$_.FullName.Length} -Descending)){$full=[IO.Path]::GetFullPath($directory.FullName);Require ($full.StartsWith($root+'\',[StringComparison]::OrdinalIgnoreCase) -and -not($directory.Attributes -band [IO.FileAttributes]::ReparsePoint)) 'Diretorio inseguro';[IO.Directory]::Delete($full,$false)}
 [IO.Directory]::Delete($root,$false)
 $state.removedResidualFiles=$remaining.Count;$state.recovery019='passed-manual-controlled-recovery';Save-State
 $setup=Start-Process $installer -WindowStyle Hidden -Wait -PassThru -ArgumentList @('/VERYSILENT','/SUPPRESSMSGBOXES','/NORESTART','/SP-','/MODE=FileSystemWatcher',('/LOG="'+(Join-Path $results 'install-0110.log')+'"'));Require ($setup.ExitCode -eq 0) 'Instalacao corrigida falhou.'
 $installed=Get-Content (Join-Path $root 'setup\installation.json') -Raw|ConvertFrom-Json
 Require ($installed.version -eq $manifest.version -and $installed.commit -eq $manifest.commit -and $installed.mode -eq 'FileSystemWatcher' -and [string]::IsNullOrEmpty($installed.adminBaseUrl)) 'Instalacao divergente.'
 $state.checkedPayloadFiles=0
 foreach($entry in $manifest.files){$p=[IO.Path]::GetFullPath((Join-Path $root $entry.path));Require ($p.StartsWith($root+'\',[StringComparison]::OrdinalIgnoreCase) -and (Get-FileHash $p).Hash -eq $entry.sha256) 'Payload instalado divergente';$state.checkedPayloadFiles++}
 $service=Get-CimInstance Win32_Service -Filter "Name='SafeUploadAgent'";Require ($service.State -eq 'Running' -and $service.StartName -eq 'LocalSystem') 'Servico inesperado.'
 $state.service=$service|Select-Object State,StartName,ProcessId
 foreach($entry in $state.preservedFiles){Require ((Get-FileHash -LiteralPath $entry.path).Hash -eq $entry.sha256) 'Recuperacao/instalacao alterou dados.'}
 $state.integrity=Read-Diagnostic 'audit-integrity';Require ($state.integrity.validEvents -eq 13 -and -not $state.integrity.requiresAttention) 'Integridade divergente.'
 $state.temporaries=Read-Diagnostic 'audit-temporaries';Require ($state.temporaries.candidateFiles -eq 2 -and $state.temporaries.totalBytes -eq 25 -and $state.temporaries.skippedReparsePoints -eq 1 -and -not $state.temporaries.complete) 'Inventario divergente.'
 $state.result='recovery-installation-diagnostics-passed-ui-pending';Save-State
 $gate=Join-Path $PSScriptRoot 'ui-inicial-observada.txt';$until=[DateTime]::UtcNow.AddMinutes(30)
 while([DateTime]::UtcNow -lt $until -and -not(Test-Path $gate)){Start-Sleep -Milliseconds 500}
 Require ((Test-Path $gate) -and (Get-Content $gate -Raw).Trim() -eq 'OBSERVADO') 'Conferencia inicial da UI nao recebida.'
 & (Join-Path $PSScriptRoot 'Reiniciar-Validar-0110.ps1')
}catch{$state.result='failed';$state.error=$_.Exception.Message}
finally{$state.finishedAtUtc=[DateTime]::UtcNow.ToString('o');Save-State}

