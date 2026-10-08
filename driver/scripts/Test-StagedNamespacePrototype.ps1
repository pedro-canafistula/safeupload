# The current namespace probe uses service-owned allocations and a disposable
# second volume. Keep the original entry point for callers of this script.
$ErrorActionPreference = 'Stop'
& (Join-Path $PSScriptRoot 'Test-StagedCrossVolumePrototype.ps1')
