#Requires -Version 7.0
<#
.SYNOPSIS
Validates a built agent package without installing it or starting executables.
.DESCRIPTION
Checks build metadata, installer digest, payload manifest, runtime files and
published versions. A pass is static package verification, not installation,
runtime isolation, Authenticode approval or driver qualification.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$BuildResultPath,
    [string]$ResultsPath
)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

function Require([bool]$Condition, [string]$Message) {
    if (-not $Condition) { throw $Message }
}

$metadata = Get-Content -LiteralPath $BuildResultPath -Raw -Encoding UTF8 | ConvertFrom-Json
Require ($metadata.version -match '^\d+\.\d+\.\d+$') 'Invalid package version.'
Require ($metadata.commit -match '^[0-9a-fA-F]{40}$') 'Missing exact source commit.'
Require ($metadata.sourceDirty -is [bool] -and -not $metadata.sourceDirty) 'Package source must be clean.'
Require ($metadata.sha256 -match '^[0-9a-fA-F]{64}$') 'Invalid installer digest.'
$installer = Get-Item -LiteralPath $metadata.installer -Force
Require (-not $installer.PSIsContainer) 'Installer must be a file.'
$installerHash = (Get-FileHash -LiteralPath $installer.FullName -Algorithm SHA256).Hash
Require ($installerHash -eq $metadata.sha256) 'Installer hash differs from build metadata.'

$payloadRoot = Join-Path $metadata.buildRoot 'payload'
Import-Module (Join-Path $PSScriptRoot '../support/SafeUpload.Setup.psm1') -Force
$manifest = Test-SafeUploadPayload -Root $payloadRoot
Require ($manifest.commit -eq $metadata.commit -and $manifest.version -eq $metadata.version) 'Payload provenance differs from build metadata.'
Require ($manifest.sourceDirty -is [bool] -and -not $manifest.sourceDirty) 'Payload source must be clean.'
Require ($manifest.runtime -eq 'win-x64' -and $manifest.selfContained -is [bool] -and $manifest.selfContained) 'Expected self-contained win-x64 payload.'
Require (@($manifest.files).Count -eq $metadata.payloadFiles) 'Payload file count differs from build metadata.'

$listed = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
foreach ($entry in $manifest.files) {
    $null = $listed.Add(([string]$entry.path).Replace('\', '/'))
    Require ([IO.Path]::GetExtension($entry.path) -notin @('.sys', '.inf', '.cat')) 'Kernel driver files are outside this package scope.'
}
$null = $listed.Add('payload-manifest.json')
$actualFiles = @(Get-ChildItem -LiteralPath $payloadRoot -Force -File -Recurse)
foreach ($file in $actualFiles) {
    $relative = [IO.Path]::GetRelativePath($payloadRoot, $file.FullName).Replace('\', '/')
    Require ($listed.Contains($relative)) "Unlisted payload file: $relative"
}
Require ($actualFiles.Count -eq $listed.Count) 'Unexpected payload file inventory.'

$projects = @(
    @{folder='service';name='SafeUpload.Agent.Service';desktop=$false},
    @{folder='ui';name='SafeUpload.Agent.App';desktop=$true}
)
$runtimeResults = foreach ($project in $projects) {
    $folder = Join-Path $payloadRoot $project.folder
    foreach ($required in @('coreclr.dll','hostfxr.dll','hostpolicy.dll','System.Private.CoreLib.dll',
        ($project.name + '.exe'),($project.name + '.dll'),
        ($project.name + '.deps.json'),($project.name + '.runtimeconfig.json'))) {
        Require (Test-Path -LiteralPath (Join-Path $folder $required) -PathType Leaf) "Required runtime/application file is absent: $($project.folder)/$required"
    }
    $config = Get-Content -LiteralPath (Join-Path $folder ($project.name + '.runtimeconfig.json')) -Raw | ConvertFrom-Json
    $options = $config.runtimeOptions
    Require (-not $options.PSObject.Properties['framework'] -and -not $options.PSObject.Properties['frameworks']) 'Package references a globally installed framework.'
    Require ([bool]$options.PSObject.Properties['includedFrameworks']) 'Self-contained framework declaration is absent.'
    $frameworks = @($options.includedFrameworks)
    Require ('Microsoft.NETCore.App' -in @($frameworks.name)) 'Bundled .NET runtime declaration is absent.'
    if ($project.desktop) {
        Require ('Microsoft.WindowsDesktop.App' -in @($frameworks.name)) 'Bundled Windows Desktop runtime declaration is absent.'
        Require (Test-Path -LiteralPath (Join-Path $folder 'PresentationFramework.dll') -PathType Leaf) 'WPF runtime is absent.'
    }
    $version = [Diagnostics.FileVersionInfo]::GetVersionInfo((Join-Path $folder ($project.name + '.dll'))).ProductVersion
    Require ($version -eq $metadata.version -or $version.StartsWith($metadata.version + '+', [StringComparison]::Ordinal)) 'Published application version differs from package version.'
    Require ($version.Contains($metadata.commit, [StringComparison]::OrdinalIgnoreCase)) 'Published application does not identify the exact source commit.'
    [pscustomobject]@{component=$project.folder;version=$version;frameworks=@($frameworks | Select-Object name,version)}
}
foreach ($required in @('setup/Invoke-AgentSetup.ps1','setup/SafeUpload.Setup.psm1',
    'setup/Install-SafeUploadAgent.ps1','LICENSE.txt','LEIA-ME.txt')) {
    Require (Test-Path -LiteralPath (Join-Path $payloadRoot $required) -PathType Leaf) "Required package support file is absent: $required"
}

$signature = Get-AuthenticodeSignature -LiteralPath $installer.FullName
$result = [ordered]@{
    status='passed';scope='static-package-only';version=$metadata.version;commit=$metadata.commit
    sourceDirty=$metadata.sourceDirty;installer=$installer.FullName;installerSha256=$installerHash
    installerBytes=$installer.Length;payloadFiles=@($manifest.files).Count
    checkedFilesIncludingManifest=$actualFiles.Count;selfContained=$true
    signatureStatus=$signature.Status.ToString();runtime=@($runtimeResults)
    installationTested=$false;systemAccountTested=$false;driverTested=$false
}
$json = $result | ConvertTo-Json -Depth 8
if ($ResultsPath) { $json | Set-Content -LiteralPath $ResultsPath -Encoding utf8NoBOM }
Write-Output $json
