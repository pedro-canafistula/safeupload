#Requires -Version 7.0
[CmdletBinding()]
param(
    [ValidatePattern('^\d+\.\d+\.\d+$')][string]$Version = '0.1.15',
    [Parameter(Mandatory)][ValidateScript({Test-Path -LiteralPath $_ -PathType Leaf})][string]$CompilerPath,
    [string]$OutputDirectory = (Join-Path $PSScriptRoot '../../artifacts/installer')
)
$ErrorActionPreference = 'Stop'
$root = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../..'))
$OutputDirectory = [IO.Path]::GetFullPath($OutputDirectory)
$buildRoot = Join-Path $OutputDirectory ('build-' + [Guid]::NewGuid().ToString('N'))
$payload = Join-Path $buildRoot 'payload'
New-Item -ItemType Directory -Path $payload -Force | Out-Null
$commit = (& git -C $root rev-parse HEAD).Trim()
if ($LASTEXITCODE -ne 0) { throw 'Build from a Git checkout to record the exact source.' }
$sourceDirty = [bool](& git -C $root status --porcelain --untracked-files=normal -- agente .github/workflows/agent-installer.yml)
foreach ($project in @(@{name='Service'; folder='service'}, @{name='App'; folder='ui'})) {
    $destination = Join-Path $payload $project.folder
    $log = Join-Path $buildRoot ('publish-' + $project.folder + '.log')
    & dotnet publish (Join-Path $root "agente/SafeUpload.Agent.$($project.name)/SafeUpload.Agent.$($project.name).csproj") `
        -c Release -r win-x64 --self-contained true -p:PublishTrimmed=false -p:DebugType=None -p:DebugSymbols=false `
        "-p:Version=$Version" -o $destination --verbosity minimal *> $log
    if ($LASTEXITCODE -ne 0) { throw "Publishing $($project.name) failed. See $log" }
}
$setup = Join-Path $payload 'setup'
New-Item -ItemType Directory -Path $setup | Out-Null
Copy-Item -LiteralPath (Join-Path $PSScriptRoot 'support/Invoke-AgentSetup.ps1'),
    (Join-Path $PSScriptRoot 'support/SafeUpload.Setup.psm1'),
    (Join-Path $root 'agente/scripts/Install-SafeUploadAgent.ps1') -Destination $setup
Copy-Item -LiteralPath (Join-Path $root 'LICENSE') -Destination (Join-Path $payload 'LICENSE.txt')
Copy-Item -LiteralPath (Join-Path $PSScriptRoot 'INSTALLATION-NOTICE.txt') -Destination (Join-Path $payload 'LEIA-ME.txt')
$files = @(Get-ChildItem -LiteralPath $payload -File -Recurse | Sort-Object FullName | ForEach-Object {
    [ordered]@{path = [IO.Path]::GetRelativePath($payload, $_.FullName).Replace('\','/'); sha256=(Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash.ToLowerInvariant()}
})
$manifest = [ordered]@{schemaVersion=1;version=$Version;commit=$commit;sourceDirty=$sourceDirty;runtime='win-x64';selfContained=$true;files=$files}
$manifest | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath (Join-Path $payload 'payload-manifest.json') -Encoding utf8NoBOM
Import-Module (Join-Path $PSScriptRoot 'support/SafeUpload.Setup.psm1') -Force
$null = Test-SafeUploadPayload -Root $payload
$compilerLog = Join-Path $buildRoot 'compiler.log'
& $CompilerPath "/DPayloadRoot=$payload" "/DArtifactOutput=$OutputDirectory" "/DAgentVersion=$Version" `
    (Join-Path $PSScriptRoot 'SafeUpload.Agent.iss') *> $compilerLog
if ($LASTEXITCODE -ne 0) { throw "Installer compilation failed. See $compilerLog" }
$installer = Join-Path $OutputDirectory "SafeUploadAgent-$Version-win-x64-setup.exe"
if (-not (Test-Path -LiteralPath $installer -PathType Leaf)) { throw 'The compiler did not produce the installer.' }
[ordered]@{ installer=$installer; sha256=(Get-FileHash -LiteralPath $installer -Algorithm SHA256).Hash;
    version=$Version; commit=$commit; sourceDirty=$sourceDirty; buildRoot=$buildRoot; payloadFiles=$files.Count; signed=$false
} | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $OutputDirectory 'build-result.json') -Encoding utf8NoBOM
$hash = (Get-FileHash -LiteralPath $installer -Algorithm SHA256).Hash
"$hash  $([IO.Path]::GetFileName($installer))" | Set-Content -LiteralPath ($installer + '.sha256') -Encoding ascii
Get-Content -LiteralPath (Join-Path $OutputDirectory 'build-result.json')
