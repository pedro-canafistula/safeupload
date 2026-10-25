#Requires -Version 5.1
#Requires -RunAsAdministrator
<#
.SYNOPSIS
Collects explicit M2 diagnostics over the existing administrator pipe.
.DESCRIPTION
Read-only: never loads/installs a driver, connects a filter port, stops a service,
changes a policy or qualifies protection. Requires the service already connected
to the agreed driver. Names may contain path tails. TimeoutSeconds is the existing
client's connection timeout, not a hard deadline for synchronous native queries.
.EXAMPLE
.\Test-SafeUploadM2Diagnostics.ps1 -OutputPath C:\Homologacao\m2-receipt.json
#>
[CmdletBinding()]
param(
    [string]$OutputPath,
    [ValidateRange(1,120)][int]$TimeoutSeconds = 10
)
$ErrorActionPreference = 'Stop'
if ($OutputPath -and (Test-Path -LiteralPath $OutputPath)) { throw 'Receipt output already exists.' }
Import-Module (Join-Path $PSScriptRoot 'support/SafeUpload.M2Diagnostics.psm1') -Force
$client = Join-Path $PSScriptRoot 'Get-SafeUploadDiagnostics.ps1'
$receipt = Invoke-SafeUploadM2DiagnosticCapture -Query {
    param($query)
    & $client -Query $query -TimeoutSeconds $TimeoutSeconds
}
$files = @($PSCommandPath, (Join-Path $PSScriptRoot 'support/SafeUpload.M2Diagnostics.psm1'), $client)
$hashes = @(foreach ($file in $files) {
    [pscustomobject]@{name=[IO.Path]::GetFileName($file);sha256=(Get-FileHash -LiteralPath $file -Algorithm SHA256).Hash}
})
$receipt | Add-Member -NotePropertyName collectorFiles -NotePropertyValue $hashes
$json = $receipt | ConvertTo-Json -Depth 20
if ($OutputPath) {
    # CreateNew also prevents overwriting a file created after the initial check.
    $stream = [IO.File]::Open($OutputPath, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
    try {
        $bytes = [Text.UTF8Encoding]::new($false).GetBytes($json)
        $stream.Write($bytes, 0, $bytes.Length)
    } finally { $stream.Dispose() }
}
$json
