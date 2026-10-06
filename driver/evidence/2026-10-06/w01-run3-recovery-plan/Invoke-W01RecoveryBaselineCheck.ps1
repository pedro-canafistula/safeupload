<#
Read-only guest-side verification for the W01 run3 recovery branch.

This script does not repair guest state. It reads a caller-supplied copy of
the retained W01 state.clixml, runs the pinned independent baseline helper,
and checks the original driver/policy/service/Verifier state and W01 actors.
The state file must be made readable at OriginalStatePath outside this script;
the script never copies or writes that file. Pass DomainUUID only after the
host independently reads `virsh domuuid win10-debug` and confirms the
recovery disk is the planned child. The baseline helper is already present in
the clean pre-W01 parent because the wrapper copied it before its checkpoint.

Output is to the PowerShell pipeline only. Any failed or ambiguous check throws
before the success sentinels are emitted.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)][string]$OriginalStatePath,
    [Parameter(Mandatory=$true)][string]$DomainUUID,
    [string]$BaselinePath = 'C:\Users\vika\Documents\Get-StagedBaseline.ps1'
)

$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

$ExpectedStateSha256 = '501E79475838293A134C81A2588C937C5EF98D0F2C55BA66FB79602AC721A1BC'
$ExpectedBaselineSha256 = 'E009A6975525DA254567CA570607BC180DF05A85D47610CA0444F77476342884'
$ExpectedDomainUUID = '9D44EEE8-81CF-4CC1-9FBA-7670F11DEF4D'
$ExpectedGuestUUID = '9D44EEE8-81CF-4CC1-9FBA-7670F11DEF4D'
$ExpectedFailedBootId = '2026-10-06T14:50:37.5000000Z'
$ExpectedRunGuid = 'ff67c01b990e41ff9af89b5a9959757c'
$ExpectedRunName = 'boot-start-w01-w01-b38b36-20261006c-ff67c01b990e41ff9af89b5a9959757c'
$OriginalDriverPath = 'C:\Windows\System32\drivers\SafeUpload.sys'
$OriginalPolicyPath = 'C:\ProgramData\SafeUpload\policy.json'
$OriginalUpperKey = 'HKLM:\SYSTEM\CurrentControlSet\Services\SafeUpload'
$OriginalAgentKey = 'HKLM:\SYSTEM\CurrentControlSet\Services\SafeUploadAgent'
$LowerKey = 'HKLM:\SYSTEM\CurrentControlSet\Services\SafeUploadSectionFault'
$LowerBinaryPath = 'C:\Windows\System32\drivers\SafeUploadSectionFault.sys'
$MemoryManagerKey = 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management'

function Require([bool]$Condition, [string]$Message) {
    if(-not $Condition) { throw $Message }
}

function Get-FileSha256([string]$Path) {
    $sha = [Security.Cryptography.SHA256]::Create()
    try {
        return ([BitConverter]::ToString($sha.ComputeHash([IO.File]::ReadAllBytes($Path)))).Replace('-', '')
    } finally { $sha.Dispose() }
}

function Get-BytesSha256([byte[]]$Bytes) {
    $sha = [Security.Cryptography.SHA256]::Create()
    try { return ([BitConverter]::ToString($sha.ComputeHash($Bytes))).Replace('-', '') }
    finally { $sha.Dispose() }
}

function Get-Field($Object, [string]$Name) {
    if($null -eq $Object) { throw ('Missing object while reading field: ' + $Name) }
    if($Object -is [System.Collections.IDictionary]) {
        if(-not $Object.Contains($Name)) { throw ('Missing field: ' + $Name) }
        return $Object[$Name]
    }
    $property = $Object.PSObject.Properties[$Name]
    if($null -eq $property) { throw ('Missing field: ' + $Name) }
    return $property.Value
}

function Get-MapNames($Map) {
    if($null -eq $Map) { throw 'Missing map' }
    if($Map -is [System.Collections.IDictionary]) { return @($Map.Keys | ForEach-Object { [string]$_ }) }
    return @($Map.PSObject.Properties | ForEach-Object { [string]$_.Name })
}

function Get-SecuritySddl([string]$Path) {
    $acl = Get-Acl -LiteralPath $Path -ErrorAction Stop
    $sections = [Security.AccessControl.AccessControlSections]::Owner -bor
        [Security.AccessControl.AccessControlSections]::Group -bor
        [Security.AccessControl.AccessControlSections]::Access
    return $acl.GetSecurityDescriptorSddlForm($sections)
}

function Read-MemoryVerifierSnapshot {
    $key = Get-Item -LiteralPath $MemoryManagerKey -ErrorAction Stop
    $snapshot = @{}
    foreach($name in $key.GetValueNames()) {
        if($name -match '^Verif') {
            $snapshot[$name] = @{
                Kind = $key.GetValueKind($name).ToString()
                Value = $key.GetValue($name, $null, [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)
            }
        }
    }
    return $snapshot
}

function Read-BaselineFields([string]$Text) {
    $fields = @{}
    foreach($line in ($Text -split '[\r\n]+')) {
        if($line -match '^([^=]+)=(.*)$') {
            $key = $matches[1]
            if($fields.ContainsKey($key)) { throw ('Duplicate baseline field: ' + $key) }
            $fields[$key] = $matches[2]
        }
    }
    return $fields
}

Require (Test-Path -LiteralPath $OriginalStatePath -PathType Leaf) 'Retained run3 state.clixml is not readable at OriginalStatePath'
Require ((Get-FileSha256 $OriginalStatePath) -ceq $ExpectedStateSha256) 'Retained run3 state.clixml SHA-256 mismatch'
Require (Test-Path -LiteralPath $BaselinePath -PathType Leaf) 'Pinned independent baseline helper is missing'
Require ((Get-FileSha256 $BaselinePath) -ceq $ExpectedBaselineSha256) 'Independent baseline helper SHA-256 mismatch'
Require ($DomainUUID.Trim('{}').ToUpperInvariant() -ceq $ExpectedDomainUUID) 'Host supplied domain UUID does not match the pinned debuggee domain'

$state = [Management.Automation.PSSerializer]::Deserialize([IO.File]::ReadAllText($OriginalStatePath))
Require (([string](Get-Field $state 'RunGuid')) -ceq $ExpectedRunGuid) 'Retained state RunGuid mismatch'
Require (([string](Get-Field $state 'RunName')) -ceq $ExpectedRunName) 'Retained state RunName mismatch'
Require ((Get-Field $state 'RecoveryRequired') -eq $true) 'Retained state does not record the expected recovery condition'
Require ((Get-Field $state 'ChildStarted') -eq $false) 'Retained state says the W01 child started'
Require ((Get-Field $state 'AgentTouched') -eq $false) 'Retained state says the agent was touched'
Require ((Get-Field $state 'Frozen') -eq $false) 'Retained state unexpectedly says artifacts were frozen'
Require ((Get-Field $state 'Restored') -eq $false) 'Retained state unexpectedly says restoration completed'

$inputs = Get-Field $state 'Inputs'
$expectedDriverHash = ([string](Get-Field $inputs 'ExpectedOriginalDriverSha256')).ToUpperInvariant()
$expectedPolicyHash = ([string](Get-Field $inputs 'ExpectedOriginalPolicySha256')).ToUpperInvariant()
Require ($expectedDriverHash -ceq 'ADA9D05AB6AECDD2B6C521B0CE529FC06C732154ACB3EE85439FBDC8AA80DFCE') 'Retained original driver pin mismatch'
Require ($expectedPolicyHash -ceq '29DC8A341BD7C549996596D2477A0CCCAF19602C362A2167FB4FDD5C66663731') 'Retained original policy pin mismatch'

$baselineOutput = (& $BaselinePath -ExpectedOriginal $expectedDriverHash -ExpectedPolicy $expectedPolicyHash 2>&1 | Out-String)
$baseline = Read-BaselineFields $baselineOutput
Require (@([regex]::Matches($baselineOutput, '(?m)^BaselineClean=True\s*$')).Count -eq 1) 'Independent baseline did not emit exactly one BaselineClean=True'
Require (@([regex]::Matches($baselineOutput, '(?m)^BaselineClean=False\s*$')).Count -eq 0) 'Independent baseline emitted BaselineClean=False'
Require ($baseline['Host'] -ceq 'WIN10-DEBUGGED') 'Independent guest host name mismatch'
Require ($baseline['UUID'].ToUpperInvariant() -ceq $ExpectedGuestUUID) 'Independent guest UUID mismatch'
Require ($baseline['OriginalDriverHash'] -ceq 'True') 'Independent original driver hash check failed'
Require ($baseline['OriginalPolicyHash'] -ceq 'True') 'Independent original policy hash check failed'
Require ($baseline['ServiceManualStopped'] -ceq 'True') 'Independent upper service baseline failed'
Require ($baseline['FilterUnloaded'] -ceq 'True') 'Independent upper filter absence check failed'
Require ($baseline['SectionFaultFilterAbsent'] -ceq 'True') 'Independent lower filter absence check failed'
Require ($baseline['SectionFaultBinaryAbsent'] -ceq 'True') 'Independent lower binary absence check failed'
Require ($baseline['SectionFaultRegistryAbsent'] -ceq 'True') 'Independent lower registry absence check failed'
Require ($baseline['SectionFaultServiceAbsent'] -ceq 'True') 'Independent lower service absence check failed'
Require ($baseline['VerifierOff'] -ceq 'True') 'Independent Verifier-off check failed'
Require ($baseline['VerifierNotConfigured'] -ceq 'True') 'Independent persisted Verifier check failed'
Require ($baseline['ZeroAgentProcesses'] -ceq 'True') 'Independent agent-process absence check failed'
Require ($baseline['ZeroTestTasks'] -ceq 'True') 'Independent test-task absence check failed'
Require ($baseline['NoGuidFixtureDirectories'] -ceq 'True') 'Independent fixture-directory absence check failed'
Require ($baseline['CanaryRootsEnumerated'] -ceq 'True') 'Independent canary-volume enumeration failed'
Require ($baseline['NoVolumeCanaryFiles'] -ceq 'True') 'Independent canary-file absence check failed'
Require ($baseline['VolumeTopologyRecorded'] -ceq 'True') 'Independent volume-topology read failed'
Require ($baseline['BaselineClean'] -ceq 'True') 'Independent baseline field map is not clean'
Require ($baseline['ProcessCreationAuditFlags'] -ceq '0') 'Process-creation audit flags differ from the captured clean original baseline'
Require ($baseline['ProcessCreationAuditPerUserCount'] -ceq '0') 'Per-user process-creation audit count differs from the captured clean original baseline'

$currentBoot = (Get-CimInstance Win32_OperatingSystem -ErrorAction Stop).LastBootUpTime.ToUniversalTime()
try { $failedBoot = [DateTime]::Parse($ExpectedFailedBootId, [Globalization.CultureInfo]::InvariantCulture).ToUniversalTime() }
catch { throw 'Pinned failed-boot identity is not a valid timestamp' }
Require ($currentBoot -ne $failedBoot) 'Guest boot identity did not change after the failed W01 boot'

$guestProduct = Get-CimInstance Win32_ComputerSystemProduct -ErrorAction Stop
Require ($guestProduct.UUID.ToUpperInvariant() -ceq $ExpectedGuestUUID) 'Guest hardware UUID differs from the pinned original debuggee'

# The baseline helper predates W01 and therefore does not count W01 transport
# phase tasks. Check all such tasks explicitly, plus any task bearing this run
# GUID. This is safe after restoration because the host runs this check directly,
# outside the W01 phase-task wrapper.
$tasks = @(Get-ScheduledTask -ErrorAction Stop)
$runGuidPattern = [regex]::Escape($ExpectedRunGuid)
$w01Tasks = @($tasks | Where-Object {
    $_.TaskName -like 'SafeUpload-W01Phase-*' -or $_.TaskName -match $runGuidPattern
})
Require ($w01Tasks.Count -eq 0) ('W01 scheduled task remains: ' + (($w01Tasks | ForEach-Object TaskName) -join ';'))

$processes = @(Get-CimInstance Win32_Process -ErrorAction Stop)
$w01Processes = @($processes | Where-Object {
    $_.ProcessId -ne $PID -and (
        $_.Name -ieq 'SafeUpload.Agent.Service.exe' -or
        $_.Name -ieq 'StagedW01Stimulus.exe' -or
        ($_.Name -match '^(powershell|pwsh)\.exe$' -and [string]::IsNullOrEmpty($_.CommandLine)) -or
        ($_.CommandLine -and ($_.CommandLine.IndexOf($ExpectedRunGuid, [StringComparison]::OrdinalIgnoreCase) -ge 0 -or
                              $_.CommandLine -match '(?i)(Test-StagedW01Diagnostic|StagedSectionFaultClient|StagedW01Stimulus|SafeUpload-W01Phase)'))
    )
})
Require ($w01Processes.Count -eq 0) ('W01 actor process remains or command line is unreadable: ' + (($w01Processes | ForEach-Object { $_.Name + ':' + $_.ProcessId }) -join ';'))

$documents = 'C:\Users\vika\Documents'
$fixturePaths = @(
    (Join-Path $documents ('SafeUpload-w01-state-' + $ExpectedRunGuid)),
    (Join-Path $documents ($ExpectedRunName + '-artifacts')),
    ('C:\SafeUpload-rv4-w01-files-' + $ExpectedRunGuid),
    ('C:\SafeUpload-rv4-w01-control-' + $ExpectedRunGuid),
    ('C:\SafeUpload-rv4-w01-protected-' + $ExpectedRunGuid)
)
foreach($path in $fixturePaths) {
    Require (-not (Test-Path -LiteralPath $path)) ('W01-owned fixture/state path remains: ' + $path)
}
$documentEntries = @(Get-ChildItem -LiteralPath $documents -Force -ErrorAction Stop)
$documentGuidFixtures = @($documentEntries | Where-Object {
    $_.Name -match '^SafeUpload-.*[0-9a-f]{32}$'
})
Require ($documentGuidFixtures.Count -eq 0) ('GUID-scoped SafeUpload fixture/state remains in Documents: ' + (($documentGuidFixtures | ForEach-Object Name) -join ';'))
$documentW01Artifacts = @($documentEntries | Where-Object {
    $_.Name -match '^boot-start-w01-.*-artifacts$'
})
Require ($documentW01Artifacts.Count -eq 0) ('W01 run artifacts remain in Documents: ' + (($documentW01Artifacts | ForEach-Object Name) -join ';'))
$systemDriveEntries = @(Get-ChildItem -LiteralPath 'C:\' -Force -ErrorAction Stop)
$allW01FixtureRoots = @($systemDriveEntries | Where-Object {
    $_.Name -match '^SafeUpload-rv4-w01-(files|control|protected)-[0-9a-f]{32}$'
})
Require ($allW01FixtureRoots.Count -eq 0) ('W01 fixture root remains on C: or root enumeration was incomplete: ' + (($allW01FixtureRoots | ForEach-Object Name) -join ';'))
Require (-not (Test-Path -LiteralPath $LowerKey)) 'Lower service registry key remains'
Require (-not (Test-Path -LiteralPath $LowerBinaryPath)) 'Lower driver binary remains'
Require (-not (Test-Path -LiteralPath ($OriginalUpperKey + '\Parameters'))) 'Upper Parameters/BootPolicy residue remains'

$savedUpper = Get-Field $state 'OriginalUpper'
$liveUpper = Get-ItemProperty -LiteralPath $OriginalUpperKey -ErrorAction Stop
foreach($name in @('Start','ErrorControl','Group','Type','ImagePath')) {
    Require ($liveUpper.$name -ceq (Get-Field $savedUpper $name)) ('Original upper service value differs: ' + $name)
}
$liveDependencies = @($liveUpper.DependOnService | ForEach-Object { [string]$_ }) -join [char]0
$savedDependencies = @((Get-Field $savedUpper 'DependOnService') | ForEach-Object { [string]$_ }) -join [char]0
Require ($liveDependencies -ceq $savedDependencies) 'Original upper service dependencies differ'

$savedAgent = Get-Field $state 'OriginalAgent'
$agentExists = [bool](Get-Field $savedAgent 'Exists')
Require (-not $agentExists) 'Pinned original state unexpectedly records an existing agent service'
Require (-not (Test-Path -LiteralPath $OriginalAgentKey)) 'W01-created agent service key remains'
Require (@(Get-CimInstance Win32_Service -Filter "Name='SafeUploadAgent'" -ErrorAction Stop).Count -eq 0) 'W01-created agent service remains registered'

$actualDriverHash = Get-FileSha256 $OriginalDriverPath
$actualPolicyHash = Get-FileSha256 $OriginalPolicyPath
Require ($actualDriverHash -ceq $expectedDriverHash) 'Original installed driver hash differs from retained state'
Require ($actualPolicyHash -ceq $expectedPolicyHash) 'Original policy hash differs from retained state'
$savedPolicyBytes = [Convert]::FromBase64String([string](Get-Field $state 'OriginalPolicyBase64'))
$actualPolicyBytes = [IO.File]::ReadAllBytes($OriginalPolicyPath)
Require ((Get-BytesSha256 $savedPolicyBytes) -ceq (Get-BytesSha256 $actualPolicyBytes)) 'Policy bytes differ from the captured original bytes'
Require ((Get-SecuritySddl $OriginalDriverPath) -ceq (Get-Field $state 'OriginalDriverSddl')) 'Original driver ACL differs from saved state'
Require ((Get-SecuritySddl $OriginalPolicyPath) -ceq (Get-Field $state 'OriginalPolicyFileSddl')) 'Original policy-file ACL differs from saved state'
Require ((Get-SecuritySddl (Split-Path -Parent $OriginalPolicyPath)) -ceq (Get-Field $state 'OriginalPolicyDirectorySddl')) 'Original policy-directory ACL differs from saved state'

$savedMemoryVerifier = Get-Field $state 'OriginalMemoryVerifier'
$actualMemoryVerifier = Read-MemoryVerifierSnapshot
$savedNames = @(Get-MapNames $savedMemoryVerifier | Sort-Object -CaseSensitive)
$actualNames = @(Get-MapNames $actualMemoryVerifier | Sort-Object -CaseSensitive)
Require (($savedNames -join [char]0) -ceq ($actualNames -join [char]0)) 'Persisted Verifier value inventory differs from saved original state'
foreach($name in $savedNames) {
    $savedValue = Get-Field $savedMemoryVerifier $name
    $actualValue = $actualMemoryVerifier[$name]
    Require ((Get-Field $actualValue 'Kind') -ceq (Get-Field $savedValue 'Kind')) ('Persisted Verifier registry type differs: ' + $name)
    $savedData = Get-Field $savedValue 'Value'
    $actualData = Get-Field $actualValue 'Value'
    Require ((ConvertTo-Json -InputObject $actualData -Compress -Depth 8) -ceq (ConvertTo-Json -InputObject $savedData -Compress -Depth 8)) ('Persisted Verifier registry value differs: ' + $name)
}

'RecoveryDomainUUID=' + $DomainUUID.Trim('{}').ToUpperInvariant()
'RecoveryGuestUUID=' + $guestProduct.UUID.ToUpperInvariant()
'RecoveryBootId=' + $currentBoot.ToString('o')
'FailedBootId=' + $failedBoot.ToString('o')
'BaselineSha256=' + $ExpectedBaselineSha256
'OriginalStateSha256=' + $ExpectedStateSha256
'IndependentBaselineClean=True'
'OriginalDriverAndPolicyBytesAclVerified=True'
'OriginalUpperAgentAndVerifierStateVerified=True'
'W01TasksActorsFixturesAndParametersAbsent=True'
'W01_RECOVERY_BASELINE_VERIFIED=True'
