#requires -Version 5.1
$ErrorActionPreference = 'Stop'
& (Join-Path $PSScriptRoot 't5/security-roundtrip-native-control.ps1') -SelfCheckOnly
