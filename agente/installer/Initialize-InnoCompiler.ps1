#Requires -Version 7.0
[CmdletBinding()]
param([string]$OutputDirectory = (Join-Path $PSScriptRoot '../../artifacts/installer-tools/inno-6.7.3'))
$ErrorActionPreference = 'Stop'
$OutputDirectory = [IO.Path]::GetFullPath($OutputDirectory)
New-Item -ItemType Directory -Path $OutputDirectory -Force | Out-Null
$download = Join-Path $OutputDirectory 'innosetup-6.7.3.exe'
$expectedHash = '9C73C3BAE7ED48D44112A0F48E66742C00090BDB5BEF71D9D3C056C66E97B732'
$url = 'https://github.com/jrsoftware/issrc/releases/download/is-6_7_3/innosetup-6.7.3.exe'
if (-not (Test-Path -LiteralPath $download)) { Invoke-WebRequest -Uri $url -OutFile $download }
if ((Get-FileHash -LiteralPath $download -Algorithm SHA256).Hash -ne $expectedHash) { throw 'Official compiler download hash mismatch.' }
$signature = Get-AuthenticodeSignature -LiteralPath $download
if ($signature.Status -ne 'Valid' -or $signature.SignerCertificate.Subject -notlike '*Pyrsys*') { throw 'Official compiler publisher verification failed.' }
$compilerDirectory = Join-Path $OutputDirectory 'compiler'
$process = Start-Process $download -WindowStyle Hidden -PassThru -Wait -ArgumentList @(
    '/VERYSILENT', '/SUPPRESSMSGBOXES', '/NORESTART', '/SP-', '/CURRENTUSER', '/PORTABLE=1',
    ('/DIR="' + $compilerDirectory + '"'), ('/LOG="' + (Join-Path $OutputDirectory 'extraction.log') + '"'))
if ($process.ExitCode -ne 0) { throw "Compiler extraction failed: $($process.ExitCode)" }
$compiler = Join-Path $compilerDirectory 'ISCC.exe'
if (-not (Test-Path -LiteralPath $compiler)) { throw 'The portable compiler is absent.' }
return $compiler
