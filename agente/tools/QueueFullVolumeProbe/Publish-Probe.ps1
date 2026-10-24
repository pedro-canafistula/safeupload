#Requires -Version 7.0
[CmdletBinding()]
param([Parameter(Mandatory)][string]$OutputDirectory)
$ErrorActionPreference='Stop'
$target=[IO.Path]::GetFullPath($OutputDirectory)
if(Test-Path $target){throw 'Use uma pasta nova para preservar artefatos anteriores.'}
$source=& git rev-parse HEAD
if($LASTEXITCODE -ne 0){throw 'Fonte Git indisponivel.'}
$dirty=[bool](& git status --porcelain)
$publish=Join-Path $target 'publish'
New-Item -ItemType Directory -Path $publish -Force|Out-Null
& dotnet publish (Join-Path $PSScriptRoot 'QueueFullVolumeProbe.csproj') -c Release -r win-x64 --self-contained true -p:PublishSingleFile=true -p:IncludeNativeLibrariesForSelfExtract=true -p:DebugType=None -o $publish *> (Join-Path $target 'publish.log')
if($LASTEXITCODE -ne 0){throw 'Publicacao falhou; preservar publish.log.'}
$exe=Get-Item -LiteralPath (Join-Path $publish 'QueueFullVolumeProbe.exe')
[ordered]@{tool='QueueFullVolumeProbe';commit=$source;sourceDirty=$dirty;sha256=(Get-FileHash -LiteralPath $exe.FullName).Hash;bytes=$exe.Length;selfContained=$true;runtime='win-x64';files=@(Get-ChildItem $publish -File|ForEach-Object{[ordered]@{name=$_.Name;bytes=$_.Length;sha256=(Get-FileHash $_.FullName).Hash}})}|ConvertTo-Json -Depth 6|Set-Content (Join-Path $target 'probe-manifest.json') -Encoding utf8NoBOM
Write-Output ('Ferramenta publicada: '+$exe.FullName)
