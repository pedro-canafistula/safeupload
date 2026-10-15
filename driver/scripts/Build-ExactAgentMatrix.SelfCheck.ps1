param([string] $BuildScript = (Join-Path $PSScriptRoot 'Build-ExactAgentMatrix.ps1'))
$ErrorActionPreference = 'Stop'
$tokens = $null; $errors = $null
$ast = [Management.Automation.Language.Parser]::ParseFile($BuildScript, [ref]$tokens, [ref]$errors)
if ($errors.Count) { throw 'Matrix script does not parse.' }
$names = @('Get-MatrixProfiles', 'Get-MatrixCompletionRows', 'Invoke-MatrixDiagnosticStep', 'Invoke-DiagnosticProfile', 'Invoke-DotnetGate')
$definitions = @($ast.FindAll({ param($node) $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -in $names }, $true))
if ($definitions.Count -ne $names.Count) { throw 'Matrix self-check functions missing.' }
$source = ($definitions | ForEach-Object { $_.Extent.Text }) -join "`n"
. ([scriptblock]::Create($source))
function Assert-Control([bool] $Condition, [string] $Message) { if (-not $Condition) { throw $Message } }
$work = Join-Path ([IO.Path]::GetTempPath()) ('matrix-selfcheck-' + [guid]::NewGuid().ToString('N'))
[void][IO.Directory]::CreateDirectory($work)
$script:out = $work
$script:Utf8ConsoleEncoding = New-Object Text.UTF8Encoding($false)
$script:dotnetExe = Join-Path $work 'fake-dotnet.ps1'
@'
param([Parameter(ValueFromRemainingArguments=$true)] $Rest)
$global:LASTEXITCODE = $global:fixtureNativeExit
'fixture failure'
'@ | Set-Content -LiteralPath $script:dotnetExe -Encoding UTF8
$script:builder = [pscustomobject]@{ ssh_user = 'vika' }
function Get-MatrixUserIdentity {
    [pscustomobject]@{ Name = 'FIXTURE\vika'; User = [pscustomobject]@{ Value = 'S-1-5-21-1-2-3-1001' } }
}
function Assert-TrxLeg { param($Path, $Name) return 1 }
function Invoke-SystemProcess {
    param($FilePath, $ArgumentLine, $WorkingDirectory, $StdoutPath, $Environment)
    ++$script:systemCalls
    [IO.File]::WriteAllText($StdoutPath, "SYSTEM_TEST_TASK_SID=S-1-5-18`n")
    return 0
}
function Test-MatrixControls {
    $global:fixtureNativeExit = 1
    $script:summary = @(); $script:diagnosticFailed = $false
    $script:DiagnosticCompileOnly = $false
    # The production fail-fast command must prevent the next command.
    $reached = $false; $failed = $false
    try { Invoke-DotnetGate 'first' @('build'); $reached = $true; Invoke-DotnetGate 'second' @('build') }
    catch { $failed = $true }
    Assert-Control ($failed -and -not $reached -and $script:summary.Count -eq 1) 'Default mode did not stop at its first failed command.'
    $script:summary = @(); $script:diagnosticFailed = $false
    $script:diagnosticTestLegsAttempted = 0
    $profiles = @(Get-MatrixProfiles)
    Assert-Control ($profiles.Count -eq 4) 'Missing build profiles.'
    foreach ($profile in $profiles) {
        $name = $profile.Mode + '-' + $profile.Configuration.ToLowerInvariant()
        # No assembly: every build fails and BOTH test legs must record a
        # separate failure; no native tests, tasks or builds run in this check.
        Invoke-DiagnosticProfile $name $profile.Configuration @('-warnaserror') service app tests (Join-Path $work 'missing-source')
    }
    Assert-Control $script:diagnosticFailed 'Diagnostic failures disappeared.'
    foreach ($name in @('normal-debug', 'normal-release', 'feature-debug', 'feature-release')) {
        $actions = @('build', 'app-build', 'test-build', 'tests-discovery-list', 'tests-discovery-fqns', 'tests-user', 'tests-system')
        if ($name.EndsWith('-release')) { $actions += 'publish' }
        foreach ($action in $actions) {
            Assert-Control (@($script:summary | Where-Object { $_ -like ($name + '-' + $action + ': DiagnosticFailure=*') }).Count -eq 1) ('Missing continued action: ' + $name + '/' + $action)
        }
    }
    Assert-Control ($script:diagnosticTestLegsAttempted -eq 8) 'Not all eight legs were attempted.'
    # With an assembly available, execute both mocked accounts even when user
    # tests fail; then prove the all-pass diagnostic still cannot be a gate.
    foreach ($nativeExit in @(1, 0)) {
        $global:fixtureNativeExit = $nativeExit
        $script:systemCalls = 0
        $script:summary = @(); $script:diagnosticFailed = $false
        foreach ($profile in $profiles) {
            $name = $profile.Mode + '-' + $profile.Configuration.ToLowerInvariant()
            $profileSource = Join-Path $work ('source-' + $name)
            $bin = Join-Path $profileSource ('agente/SafeUpload.Agent.Tests/bin/' + $profile.Configuration)
            [void][IO.Directory]::CreateDirectory($bin)
            [IO.File]::WriteAllText((Join-Path $bin 'SafeUpload.Agent.Tests.dll'), 'nonexecutable fixture')
            Invoke-DiagnosticProfile $name $profile.Configuration @('-warnaserror') service app tests $profileSource
        }
        Assert-Control ($script:systemCalls -eq 4) 'A user failure prevented a SYSTEM leg.'
        foreach ($name in @('normal-debug', 'normal-release', 'feature-debug', 'feature-release')) {
            Assert-Control (@($script:summary | Where-Object { $_ -like ($name + '-tests-user: exit=*') }).Count -eq 1) 'User tests did not execute.'
        }
        Assert-Control ($script:diagnosticFailed -eq ($nativeExit -ne 0)) 'Diagnostic failure state is wrong.'
    }
    foreach ($passed in @($true, $false)) {
        $rows = @(Get-MatrixCompletionRows $passed $true $false $false)
        Assert-Control (($rows -ccontains 'AgentMatrixGate=False') -and ($rows -ccontains 'DiagnosticContinue=True') -and
            ($rows -ccontains 'DiagnosticContinue: not a gate') -and ($rows -cnotcontains 'AgentMatrixGate=True')) 'Diagnostic completion became a gate.'
        $rows = @(Get-MatrixCompletionRows $passed $false $false $true)
        Assert-Control (($rows -ccontains 'AgentMatrixGate=False') -and ($rows -ccontains 'ParityCheck: not a gate')) 'Parity completion became a gate.'
    }
    $rows = @(Get-MatrixCompletionRows $true $false $false $false)
    Assert-Control ($rows.Count -eq 1 -and $rows[0] -ceq 'AgentMatrixGate=True') 'Ordinary gate completion changed.'
    $stopped = $false
    try { Invoke-MatrixDiagnosticStep cleanup { throw 'SYSTEM task cleanup could not be confirmed: fixture' } }
    catch { $stopped = $true }
    Assert-Control $stopped 'Uncertain SYSTEM lifetime was swallowed.'
}
try {
    Test-MatrixControls
    $mutations = @(
        @('($Name + ''-publish'')', '($Name + ''-omitted-publish'')'),
        @('param([string] $StepName, [scriptblock] $Action)', 'param([string] $Name, [scriptblock] $Action)'),
        @("@('normal', 'feature')", "@('normal')"),
        @('try { & $Action }', '& $Action; try { }'),
        @('else { throw (''Build gate failed: '' + $Name) }', 'else { $script:diagnosticFailed = $true }'),
        @('if ($ContinueMode -or $CompileOnly -or $Parity)', 'if ($CompileOnly -or $Parity)'),
        @('if ($ContinueMode -or $CompileOnly -or $Parity)', 'if ($ContinueMode -or $CompileOnly)'),
        @('''DiagnosticContinue=True''', '''DiagnosticContinue=False'''),
        @('''DiagnosticContinue: not a gate''', '''DiagnosticContinue: gate'''),
        @('($Name + ''-tests-user'')', '($Name + ''-omitted-user'')'),
        @('($Name + ''-tests-system'')', '($Name + ''-omitted-system'')'),
        @('if ($_.Exception.Message -like ''SYSTEM task cleanup could not be confirmed:*'')', 'if ($false)')
    )
    foreach ($mutation in $mutations) {
        $changed = $source.Replace($mutation[0], $mutation[1])
        Assert-Control ($changed -cne $source) 'Mutation did not change source.'
        . ([scriptblock]::Create($changed))
        $caught = $false
        try { Test-MatrixControls } catch { $caught = $true }
        Assert-Control $caught ('Matrix guard mutation escaped: ' + $mutation[0])
        . ([scriptblock]::Create($source))
    }
} finally { Remove-Item -LiteralPath $work -Recurse -Force }
'BuildExactAgentMatrixSelfCheck=PASS; controls=fail-fast,all-eight-legs,non-gates,lifetime-stop; mutations=12'
