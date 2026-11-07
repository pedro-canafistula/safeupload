#Requires -Version 5.1
[CmdletBinding()]
param([string]$ResultsPath)
$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot '../support/SafeUpload.Setup.psm1') -Force
$results = [Collections.Generic.List[object]]::new()
$fixture = Join-Path ([IO.Path]::GetTempPath()) ('safeupload-installer-tests-' + [Guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $fixture | Out-Null

function Assert-True([bool]$Condition) { if (-not $Condition) { throw 'Assertion failed.' } }
function Assert-Rejected([scriptblock]$Operation) {
    $rejected = $false
    try { & $Operation | Out-Null } catch { $rejected = $true }
    Assert-True $rejected
}
function Test-Case([string]$Name, [scriptblock]$Operation) {
    try { & $Operation | Out-Null; $results.Add([pscustomobject]@{name=$Name;passed=$true;error=$null}) }
    catch { $results.Add([pscustomobject]@{name=$Name;passed=$false;error=$_.Exception.Message}) }
}
function Write-Manifest($Entries) {
    @{schemaVersion=1;files=@($Entries)} | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath (Join-Path $fixture 'payload-manifest.json') -Encoding UTF8
}
try {
    $installRoot = Join-Path $fixture 'Program Files\SafeUpload\Agent'
    Test-Case 'A path containing spaces remains one quoted service executable' {
        $plan = New-SafeUploadInstallPlan -InstallRoot $installRoot -Mode Drive
        $expected = '"' + (Join-Path $installRoot 'service\SafeUpload.Agent.Service.exe') + '" --Interception:Mode=Drive --InspecaoTls:Habilitada=false'
        Assert-True ($plan.CommandLine -eq $expected)
        Assert-True (-not $plan.RestartRequired -and -not $plan.CommandLine.Contains('StagingPrototype'))
    }
    Test-Case 'Drive is the default mode' { Assert-True ((New-SafeUploadInstallPlan -InstallRoot $installRoot).Mode -eq 'Drive') }
    Test-Case 'Test mode is explicit and has no staged-driver flag' {
        $plan = New-SafeUploadInstallPlan -InstallRoot $installRoot -Mode FileSystemWatcher
        Assert-True ($plan.CommandLine.EndsWith('--Interception:Mode=FileSystemWatcher --InspecaoTls:Habilitada=false') -and
            -not $plan.CommandLine.Contains('--CentroAdministracao:BaseUrl=') -and
            -not $plan.CommandLine.Contains('StagingPrototype') -and -not $plan.RestartRequired)
    }
    Test-Case 'Different target directory is refused' { Assert-Rejected { Assert-SafeUploadDirectory -Path $fixture -ExpectedPath $installRoot } }
    Test-Case 'Expected ordinary target directory is accepted' { Assert-True ((Assert-SafeUploadDirectory -Path $installRoot -ExpectedPath $installRoot) -eq $installRoot) }
    $acl = [Security.AccessControl.DirectorySecurity]::new()
    $systemSid = [Security.Principal.SecurityIdentifier]::new('S-1-5-18')
    $usersSid = [Security.Principal.SecurityIdentifier]::new('S-1-5-32-545')
    $acl.SetOwner($systemSid)
    $acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new($systemSid, 'FullControl', 'Allow'))
    $acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new($usersSid, 'ReadAndExecute', 'Allow'))
    Test-Case 'Users may read and execute installed programs' { Assert-SafeUploadInstallAcl $acl }
    $acl.SetOwner($usersSid)
    Test-Case 'Untrusted owner is refused even when the current DACL is read-only' { Assert-Rejected { Assert-SafeUploadInstallAcl $acl } }
    $acl.SetOwner($systemSid)
    $writableAcl = [Security.AccessControl.DirectorySecurity]::new()
    $writableAcl.SetSecurityDescriptorSddlForm($acl.GetSecurityDescriptorSddlForm('All'))
    $writableAcl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new($usersSid, 'Write', 'Allow'))
    Test-Case 'A users-writable binary directory is refused' { Assert-Rejected { Assert-SafeUploadInstallAcl $writableAcl } }
    $creatorSid = [Security.Principal.SecurityIdentifier]::new('S-1-3-0')
    $acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new($creatorSid, 'FullControl',
        'ContainerInherit, ObjectInherit', 'InheritOnly', 'Allow'))
    Test-Case 'Inherited-only CREATOR OWNER ACE is allowed on a trusted-owned parent' { Assert-SafeUploadInstallAcl $acl }
    $state = [pscustomobject]@{AgentInstalled=$false;DriverInstalled=$false;DriverStart=-1;DriverState='Absent'}
    Test-Case 'Fresh test mode needs no driver' { Assert-SafeUploadMachineState $state FileSystemWatcher Install }
    Test-Case 'Drive mode installs when WinFsp is available' { Assert-SafeUploadMachineState $state Drive Install }
    Test-Case 'Drive mode without WinFsp is refused' { Assert-Rejected { Assert-SafeUploadMachineState $state Drive Install -WinFspAvailable $false } }
    $state.DriverInstalled=$true; $state.DriverStart=3; $state.DriverState='Running'
    Test-Case 'Registered driver blocks driver-free mode' { Assert-Rejected { Assert-SafeUploadMachineState $state FileSystemWatcher Install } }
    Test-Case 'A loaded gate driver does not block removal (uninstall removes it)' { Assert-SafeUploadMachineState $state Drive Uninstall }
    $state.AgentInstalled=$true
    Test-Case 'Existing service is never overwritten by the initial installer' { Assert-Rejected { Assert-SafeUploadMachineState $state Drive Install } }
    $payloadFile = Join-Path $fixture 'sample.dll'
    [IO.File]::WriteAllText($payloadFile, 'synthetic payload')
    $hash=(Get-FileHash -LiteralPath $payloadFile -Algorithm SHA256).Hash
    Write-Manifest @(@{path='sample.dll';sha256=$hash})
    Test-Case 'Payload hashes are verified on real isolated files' { $null = Test-SafeUploadPayload $fixture }
    [IO.File]::WriteAllText($payloadFile, 'tampered payload')
    Test-Case 'Tampered payload is refused' { Assert-Rejected { Test-SafeUploadPayload $fixture } }
    [IO.File]::WriteAllText($payloadFile, 'synthetic payload')
    Write-Manifest @(@{path='missing.dll';sha256=$hash})
    Test-Case 'Missing payload file is refused' { Assert-Rejected { Test-SafeUploadPayload $fixture } }
    Write-Manifest @()
    Test-Case 'Empty payload manifest is refused' { Assert-Rejected { Test-SafeUploadPayload $fixture } }
    foreach ($badPath in @('../outside.dll', 'C:\outside.dll', 'sample.dll:stream')) {
        Write-Manifest @(@{path=$badPath;sha256=$hash})
        Test-Case "Unsafe manifest path is refused: $badPath" { Assert-Rejected { Test-SafeUploadPayload $fixture } }
    }
    Write-Manifest @(@{path='sample.dll';sha256=$hash}, @{path='SAMPLE.DLL';sha256=$hash})
    Test-Case 'Duplicate Windows path is refused' { Assert-Rejected { Test-SafeUploadPayload $fixture } }
    Write-Manifest @(@{path='sample.dll';sha256='not-a-hash'})
    Test-Case 'Malformed digest is refused' { Assert-Rejected { Test-SafeUploadPayload $fixture } }
    $target = Join-Path $fixture 'target'; $junction = Join-Path $fixture 'junction'
    New-Item -ItemType Directory -Path $target | Out-Null
    New-Item -ItemType Junction -Path $junction -Target $target | Out-Null
    Test-Case 'Junction ancestors are refused before privileged file operations' { Assert-Rejected { Assert-SafeUploadDirectory -Path $junction -ExpectedPath $junction } }
    Remove-Item -LiteralPath $junction -Force
    Test-Case 'UI termination refuses relative or different executable names' {
        Assert-Rejected { Stop-SafeUploadInstalledUi 'SafeUpload.Agent.App.exe' }
        Assert-Rejected { Stop-SafeUploadInstalledUi (Join-Path $fixture 'other.exe') }
    }
    Test-Case 'UI termination stops only the exact executable and leaves the same name elsewhere running' {
        $ownedRoot = Join-Path $fixture 'owned'; $foreignRoot = Join-Path $fixture 'foreign'
        New-Item -ItemType Directory -Path $ownedRoot,$foreignRoot | Out-Null
        $ownedExe = Join-Path $ownedRoot 'SafeUpload.Agent.App.exe'
        $foreignExe = Join-Path $foreignRoot 'SafeUpload.Agent.App.exe'
        $escapedOutput = $ownedExe.Replace("'", "''")
        $compile = "Add-Type -TypeDefinition 'public class UiProcessFixture { public static void Main() { System.Threading.Thread.Sleep(-1); } }' -OutputAssembly '$escapedOutput' -OutputType ConsoleApplication"
        & "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -NonInteractive -EncodedCommand ([Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($compile)))
        if ($LASTEXITCODE -ne 0) { throw 'Synthetic .NET Framework process did not compile.' }
        Copy-Item -LiteralPath $ownedExe -Destination $foreignExe
        $owned = $null; $foreign = $null
        try {
            $owned = Start-Process $ownedExe -WindowStyle Hidden -PassThru
            $foreign = Start-Process $foreignExe -WindowStyle Hidden -PassThru
            Start-Sleep -Milliseconds 400
            Assert-True (-not $owned.HasExited -and -not $foreign.HasExited)
            Assert-True ((Stop-SafeUploadInstalledUi $ownedExe) -eq 1)
            Assert-True ($owned.WaitForExit(5000) -and -not $foreign.HasExited)
            Assert-True ((Stop-SafeUploadInstalledUi $ownedExe) -eq 0 -and -not $foreign.HasExited)
        } finally {
            # Only the two process objects created by this test may be cleaned up.
            foreach ($created in @($owned,$foreign)) {
                if ($created) { try { if (-not $created.HasExited) { $created.Kill(); $null=$created.WaitForExit(5000) } } finally { $created.Dispose() } }
            }
        }
    }
    $failed=@($results | Where-Object { -not $_.passed })
    $summary=[ordered]@{powershell=$PSVersionTable.PSVersion.ToString();total=$results.Count;passed=$results.Count-$failed.Count;failed=$failed.Count;tests=@($results)}
    if ($ResultsPath) { $summary | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $ResultsPath -Encoding UTF8 }
    $failed | Format-List | Out-Host
    Write-Output "InstallerContracts: $($summary.passed)/$($summary.total) passed (PowerShell $($summary.powershell))"
    if ($failed.Count -ne 0) { exit 1 }
} finally {
    $fullFixture=[IO.Path]::GetFullPath($fixture)
    $temporaryRoot=[IO.Path]::GetFullPath([IO.Path]::GetTempPath()).TrimEnd('\') + '\'
    if (-not $fullFixture.StartsWith($temporaryRoot,[StringComparison]::OrdinalIgnoreCase) -or
        (Split-Path -Leaf $fullFixture) -notmatch '^safeupload-installer-tests-[a-f0-9]{32}$') { throw 'Unsafe test cleanup target.' }
    Remove-Item -LiteralPath $fullFixture -Recurse -Force
}
