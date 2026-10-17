#requires -Version 5.1
[CmdletBinding()]
param([switch]$SelfCheckOnly, [int]$CallerPid, [long]$CallerStarted, [string]$CallerSid)
$ErrorActionPreference = 'Stop'
Add-Type -Path (Join-Path $PSScriptRoot 'metadata-construction-native-control.cs')
[T8MetadataConstructionControl]::SelfCheck()
Write-Output 'T8ConstructionSignatureSelfCheck=PASS NativeCalls=False'
if ($SelfCheckOnly) { return }
if ($CallerPid -le 0 -or $CallerStarted -le 0 -or $CallerSid -notmatch '^S-1-5-21-[0-9-]+$') { throw 'Exact live non-SYSTEM caller identity is required.' }
$root = Join-Path ([IO.Path]::GetTempPath()) ('safeupload-t8-construction-' + [Guid]::NewGuid().ToString('N'))
Write-Output ('Scope=UnprotectedBuilderMechanismEvidence Root=' + $root + ' OS=' + [Environment]::OSVersion.Version)
$progressFile = Join-Path $PSScriptRoot 'metadata-construction-native-progress.txt'
$rows = @([T8MetadataConstructionControl]::Run($CallerPid, $CallerStarted, $CallerSid, $root, $progressFile))
Write-Output 'FixtureRemoved=True ProcessPrivilegesUnchanged=True'
foreach ($row in $rows) { $row | ConvertTo-Json -Depth 5 -Compress }
$failed = @($rows | Where-Object { -not $_.Passed })
Write-Output ('T8ConstructionRows=' + $rows.Count + ' Failed=' + $failed.Count)
if ($rows.Count -ne 24 -or $failed.Count -ne 0) { throw 'Native construction feasibility assertions failed; retain this receipt.' }
Write-Output 'T8ConstructionFeasibility=PASS TargetQualification=False ProductImplementation=False'
