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
    Test-Case 'Empty URL explicitly selects local operation' { Assert-True ((ConvertTo-SafeUploadAdminUrl '') -eq '') }
    Test-Case 'HTTPS URL is normalized' { Assert-True ((ConvertTo-SafeUploadAdminUrl 'https://central.example.test/agent') -eq 'https://central.example.test/agent/') }
    Test-Case 'Local HTTP can be used by the contract runner' { Assert-True ((ConvertTo-SafeUploadAdminUrl 'http://127.0.0.1:18080/agent/') -eq 'http://127.0.0.1:18080/agent/') }
    foreach ($bad in @('http://central.example.test/agent/', 'https://user:secret@central.example.test/agent/',
        'https://central.example.test/agent/?token=secret', 'https://central.example.test/agent/#secret',
        'file:///C:/agent/', 'https://central.example.test/agent/api/', 'https://central.example.test/agent/ --bad',
        'https://central.example.test/agent/"', "https://central.example.test/agent/`n")) {
        $candidate = $bad
        Test-Case "Reject unsafe URL: $($results.Count)" { Assert-Rejected { ConvertTo-SafeUploadAdminUrl $candidate } }
    }
    $installRoot = Join-Path $fixture 'Program Files\SafeUpload\Agent'
    Test-Case 'A path containing spaces remains one quoted service executable' {
        $plan = New-SafeUploadInstallPlan -InstallRoot $installRoot -Mode Minifilter -AdminBaseUrl 'https://central.example.test/agent/'
        Assert-True $plan.CommandLine.StartsWith(('"' + (Join-Path $installRoot 'service\SafeUpload.Agent.Service.exe') + '" '))
        Assert-True $plan.CommandLine.Contains('--CentroAdministracao:BaseUrl=https://central.example.test/agent/ --InspecaoTls:Habilitada=false')
        Assert-True ($plan.RestartRequired -and $plan.CommandLine.Contains('--Interception:StagingPrototype=true'))
    }
    Test-Case 'Test mode is explicit and has no staged-driver flag' {
        $plan = New-SafeUploadInstallPlan -InstallRoot $installRoot -Mode FileSystemWatcher
        Assert-True ($plan.CommandLine.Contains('--CentroAdministracao:BaseUrl= --InspecaoTls:Habilitada=false') -and
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
    Test-Case 'Missing driver blocks minifilter installation' { Assert-Rejected { Assert-SafeUploadMachineState $state Minifilter Install } }
    $state.DriverInstalled=$true; $state.DriverStart=3; $state.DriverState='Stopped'
    Test-Case 'Stopped preinstalled driver permits the existing seeding procedure' { Assert-SafeUploadMachineState $state Minifilter Install }
    Test-Case 'Registered driver blocks driver-free mode' { Assert-Rejected { Assert-SafeUploadMachineState $state FileSystemWatcher Install } }
    Test-Case 'Demand-start driver blocks removal of the agent' { Assert-Rejected { Assert-SafeUploadMachineState $state Minifilter Uninstall } }
    $state.DriverState='Running'; $state.DriverStart=4
    Test-Case 'Loaded driver blocks removal even when disabled for the next boot' { Assert-Rejected { Assert-SafeUploadMachineState $state Minifilter Uninstall } }
    Test-Case 'Loaded driver blocks policy seeding at install' { Assert-Rejected { Assert-SafeUploadMachineState $state Minifilter Install } }
    $state.DriverState='Stopped'
    Test-Case 'Disabled and stopped driver permits removal of the agent' { Assert-SafeUploadMachineState $state Minifilter Uninstall }
    $state.AgentInstalled=$true
    Test-Case 'Existing service is never overwritten by the initial installer' { Assert-Rejected { Assert-SafeUploadMachineState $state Minifilter Install } }
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
    Test-Case 'Retention preview client requires explicit UTC and rejects culture-dependent or missing cutoffs' {
        $client = Join-Path $PSScriptRoot '../../scripts/Get-SafeUploadDiagnostics.ps1'
        $tokens = $null; $parseErrors = $null
        $ast = [Management.Automation.Language.Parser]::ParseFile((Resolve-Path $client), [ref]$tokens, [ref]$parseErrors)
        Assert-True ($parseErrors.Count -eq 0)
        $validation = @($ast.FindAll({param($node)
            $node -is [Management.Automation.Language.IfStatementAst] -and
                $node.Extent.Text.StartsWith("if (`$Query -eq 'audit-retention-preview')")
        }, $true))
        Assert-True ($validation.Count -eq 1)
        # Execute the client's real validation, without elevation or opening its pipe.
        $block = [scriptblock]::Create($validation[0].Extent.Text)
        foreach ($value in @('2020-01-01T00:00:00Z','2020-01-01T00:00:00.1234567Z','2020-01-01T00:00:00.0000000+00:00')) {
            & { param($text,$validationBlock)
                $Query = 'audit-retention-preview'; $OccurredBeforeUtc = $text; $cutoff = [DateTimeOffset]::MinValue
                . $validationBlock
                Assert-True ($cutoff.Offset -eq [TimeSpan]::Zero -and $cutoff.Year -eq 2020)
            } $value $block
        }
        foreach ($value in @('', 'SENSIVEL', '01/02/2020', '2020-01-01T00:00:00', '2020-01-01T00:00:00-03:00', '0001-01-01T00:00:00Z')) {
            Assert-Rejected {
                $Query = 'audit-retention-preview'; $OccurredBeforeUtc = $value; $cutoff = [DateTimeOffset]::MinValue
                . $block
            }
        }
    }
    Test-Case 'M2 diagnostics queries are explicit and dispatch unchanged in PowerShell' {
        $client = Join-Path $PSScriptRoot '../../scripts/Get-SafeUploadDiagnostics.ps1'
        $tokens = $null; $parseErrors = $null
        $ast = [Management.Automation.Language.Parser]::ParseFile((Resolve-Path $client), [ref]$tokens, [ref]$parseErrors)
        Assert-True ($parseErrors.Count -eq 0)
        $dispatch = @($ast.FindAll({param($node)
            $node -is [Management.Automation.Language.SwitchStatementAst] -and $node.Condition.Extent.Text -eq '$Query'
        }, $true))
        Assert-True ($dispatch.Count -eq 1)
        $parameters = [scriptblock]::Create($ast.ParamBlock.Extent.Text + "`n`$Query")
        $block = [scriptblock]::Create($dispatch[0].Extent.Text)
        foreach ($query in @('m2-counters','m2-stage-streams')) {
            Assert-True ((& $parameters -Query $query) -eq $query)
            $request = & { param($selected,$dispatchBlock)
                function Invoke-DiagnosticsQuery($Request) { return $Request }
                $Query = $selected
                . $dispatchBlock
            } $query $block
            Assert-True ($request.Count -eq 1 -and $request.query -eq $query)
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
