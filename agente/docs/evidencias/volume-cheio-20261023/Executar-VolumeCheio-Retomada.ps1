#Requires -Version 5.1
$ErrorActionPreference='Stop'
function Require([bool]$Condition,[string]$Message){if(-not $Condition){throw $Message}}
Require ((Get-CimInstance Win32_ComputerSystemProduct).UUID -eq '3a9992db-4644-405c-b642-9766edd10650') 'Clone inesperado.'
Require ($PSScriptRoot -eq 'C:\Users\safeuploadlab\Desktop\Homologacao-SafeUpload-016\disk-full') 'Laboratorio inesperado.'
Require (([Security.Principal.WindowsPrincipal]::new([Security.Principal.WindowsIdentity]::GetCurrent())).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) 'Elevacao necessaria.'
Require (-not(Test-Path 'C:\Program Files\SafeUpload\Agent') -and -not(Get-Service SafeUploadAgent -ErrorAction SilentlyContinue) -and @(Get-CimInstance Win32_Process -Filter "Name='SafeUpload.Agent.App.exe'").Count -eq 0) 'Estado sem agente inesperado.'
$previous=Get-Content 'C:\Users\safeuploadlab\Desktop\Homologacao-SafeUpload-016\0111\encerramento-0111\result.json' -Raw|ConvertFrom-Json
Require ($previous.result -eq 'boot-diagnostics-and-uninstall-passed' -and @($previous.eventIds).Count -eq 17 -and @($previous.preservedFiles).Count -eq 8) 'Aceite anterior divergente.'
Require ((Get-FileHash 'C:\ProgramData\SafeUpload\queue.jsonl').Hash -eq '64A3D85FD9B5091B11D88D6D32614D7EB2F7898686F01D9AC1F5B28947C8BA6A') 'Fila anterior modificada.'
foreach($entry in $previous.preservedFiles){Require ((Get-FileHash -LiteralPath $entry.path).Hash -eq $entry.sha256) 'Dado anterior divergente.'}
$receipt=Join-Path $PSScriptRoot 'clone-result-retry.json';Require (-not(Test-Path $receipt)) 'Recibo anterior; nao sobrescrever.'
$manifest=Get-Content (Join-Path $PSScriptRoot 'tool-retry\probe-manifest.json') -Raw|ConvertFrom-Json
$state=[ordered]@{result='running';startedAtUtc=[DateTime]::UtcNow.ToString('o');probeSource=$manifest.commit;probeSha256=$manifest.sha256;preservedFiles=$previous.preservedFiles;baselineEventIds=$previous.eventIds;systemDriveFreeBytesBefore=([IO.DriveInfo]::new('C:\')).AvailableFreeSpace}
function Save-State{$state|ConvertTo-Json -Depth 14|Set-Content -LiteralPath $receipt -Encoding UTF8}
function Confirm-Baseline{
 foreach($entry in $previous.preservedFiles){Require ((Get-FileHash -LiteralPath $entry.path).Hash -eq $entry.sha256) 'Dados anteriores alterados.'}
 $junction=Get-Item -Force -LiteralPath 'C:\ProgramData\SafeUpload\queue.jsonl.3b02cd4738904c24b71970010537bb42.tmp'
 Require (($junction.Attributes -band [IO.FileAttributes]::ReparsePoint) -and @($junction.Target).Count -eq 1 -and $junction.Target[0] -eq 'C:\Users\safeuploadlab\Desktop\Homologacao-SafeUpload-016\019\alvo-junction-sintetico') 'Junction anterior divergente.'
 $state.baselinePreserved=$true;$state.junctionPreserved=$true
}
Save-State
try{
 Confirm-Baseline
 $beforeVolumes=@(Get-ChildItem -LiteralPath $PSScriptRoot -Directory -Filter 'volume-*'|Select-Object -ExpandProperty FullName)
 & (Join-Path $PSScriptRoot 'Test-QueueFullVolume-Retomada.ps1') -Context Clone -OutputParent $PSScriptRoot -ProbePath (Join-Path $PSScriptRoot 'tool-retry\publish\QueueFullVolumeProbe.exe') -ManifestPath (Join-Path $PSScriptRoot 'tool-retry\probe-manifest.json') *> (Join-Path $PSScriptRoot 'clone-test-retry.log')
 $wrappers=@(Get-ChildItem -LiteralPath $PSScriptRoot -Directory -Filter 'volume-*'|Where-Object {$_.FullName -notin $beforeVolumes}|ForEach-Object{Join-Path $_.FullName 'wrapper-result.json'})
 Require ($wrappers.Count -eq 1) 'Quantidade de ensaios inesperada.'
 $wrapper=Get-Content -LiteralPath $wrappers[0] -Raw|ConvertFrom-Json
 Require ($wrapper.result -eq 'passed' -and $wrapper.detached) 'Ensaio/desmontagem incompleto.'
 $state.wrapperPath=$wrappers[0];$state.wrapper=$wrapper
 foreach($entry in $state.preservedFiles){Require ((Get-FileHash -LiteralPath $entry.path).Hash -eq $entry.sha256) 'Ensaio alterou dados homologados.'}
 $state.systemDriveFreeBytesAfter=([IO.DriveInfo]::new('C:\')).AvailableFreeSpace
 Require ($state.systemDriveFreeBytesAfter -gt 2GB) 'Espaco livre de apoio abaixo da guarda.'
 $state.result='full-volume-probe-and-baseline-preservation-passed'
}catch{$state.result='failed';$state.error=$_.Exception.Message}
finally{
 try{
  Confirm-Baseline
  $state.images=@(Get-ChildItem -LiteralPath $PSScriptRoot -Directory -Filter 'volume-*'|ForEach-Object{$v=Join-Path $_.FullName 'owned-64mb.vhd';if(Test-Path $v){$i=Get-DiskImage -ImagePath $v;[ordered]@{path=$v;attached=$i.Attached}}})
  Require (@($state.images|Where-Object attached).Count -eq 0) 'Imagem ainda montada.'
  $state.agentRootPresent=Test-Path 'C:\Program Files\SafeUpload\Agent'
  $state.agentServicePresent=[bool](Get-Service SafeUploadAgent -ErrorAction SilentlyContinue)
  $state.agentUiCount=@(Get-CimInstance Win32_Process -Filter "Name='SafeUpload.Agent.App.exe'").Count
  Require (-not $state.agentRootPresent -and -not $state.agentServicePresent -and $state.agentUiCount -eq 0) 'Estado final do agente divergente.'
 }catch{$state.result='failed';$state.finalCheckError=$_.Exception.Message}
 $state.finishedAtUtc=[DateTime]::UtcNow.ToString('o');Save-State
}
