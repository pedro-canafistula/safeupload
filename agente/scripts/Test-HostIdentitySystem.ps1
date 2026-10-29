param([Parameter(Mandatory)][string]$ResultsDirectory)
$ErrorActionPreference = 'Stop'
if ($env:GITHUB_ACTIONS -ne 'true' -or -not $env:RUNNER_TEMP) {
    throw 'This SYSTEM fixture is restricted to the disposable GitHub Actions runner.'
}
$project = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '../SafeUpload.Agent.Tests/SafeUpload.Agent.Tests.csproj')).Path
$assembly = (Resolve-Path -LiteralPath (Join-Path (Split-Path $project) 'bin/Release/net10.0-windows/SafeUpload.Agent.Tests.dll')).Path
$nugetRoot = (& dotnet msbuild $project -nologo -getProperty:NuGetPackageRoot).Trim()
if ($LASTEXITCODE -ne 0 -or -not (Test-Path -LiteralPath $nugetRoot -PathType Container)) { throw 'Package cache unavailable.' }
$results = [IO.Path]::GetFullPath($ResultsDirectory)
New-Item -ItemType Directory -Path $results -Force | Out-Null
$root = Join-Path $env:RUNNER_TEMP ('safeupload-host-identity-' + [guid]::NewGuid().ToString('N'))
$taskName = 'SafeUpload-Identity-Test-' + [guid]::NewGuid().ToString('N')
$worker = Join-Path $env:RUNNER_TEMP ($taskName + '.ps1')
$body = @'
param([string]$Assembly, [string]$Results, [string]$IdentityRoot, [string]$RunnerTemp, [string]$Dotnet, [string]$NugetRoot)
$ErrorActionPreference = 'Stop'
$env:RUNNER_TEMP = $RunnerTemp
$env:DOTNET_SKIP_FIRST_TIME_EXPERIENCE = '1'
$env:DOTNET_NOLOGO = '1'
$env:NUGET_PACKAGES = $NugetRoot
$env:SAFEUPLOAD_IDENTITY_TEST_ROOT = $IdentityRoot
foreach ($phase in @('provision', 'restore')) {
    $env:SAFEUPLOAD_IDENTITY_PHASE = $phase
    & $Dotnet vstest $Assembly '/TestCaseFilter:FullyQualifiedName~RegisteredHostIdentitySystemTests' ("/Logger:trx;LogFileName=identity-system-$phase.trx") ("/ResultsDirectory:$Results") *> (Join-Path $Results "identity-system-$phase.log")
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
}
exit 0
'@
Set-Content -LiteralPath $worker -Value $body -Encoding ascii
function Quote-Argument([string]$Value) {
    if ($Value.Contains('"') -or $Value.Contains("`r") -or $Value.Contains("`n")) { throw 'Unexpected argument.' }
    return '"' + $Value.TrimEnd('\') + '"'
}
$arguments = '-NoProfile -NonInteractive -File ' + ((@($worker, $assembly, $results, $root, $env:RUNNER_TEMP, (Get-Command dotnet).Source, $nugetRoot) |
    ForEach-Object { Quote-Argument $_ }) -join ' ')
try {
    $action = New-ScheduledTaskAction -Execute (Join-Path $env:SystemRoot 'System32/WindowsPowerShell/v1.0/powershell.exe') -Argument $arguments
    $principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
    Register-ScheduledTask -TaskName $taskName -Action $action -Principal $principal | Out-Null
    $started = (Get-Date).AddSeconds(-1)
    Start-ScheduledTask -TaskName $taskName
    $deadline = (Get-Date).AddSeconds(120)
    do {
        Start-Sleep -Seconds 2
        $info = Get-ScheduledTaskInfo -TaskName $taskName
        $task = Get-ScheduledTask -TaskName $taskName
    } while (($info.LastRunTime -lt $started -or $task.State -eq 'Running') -and (Get-Date) -lt $deadline)
    if ($info.LastRunTime -lt $started -or $task.State -eq 'Running' -or $info.LastTaskResult -ne 0) {
        throw 'SYSTEM identity fixture did not complete successfully; inspect its logs.'
    }
    foreach ($phase in @('provision', 'restore')) {
        [xml]$trx = Get-Content -LiteralPath (Join-Path $results "identity-system-$phase.trx") -Raw
        $cases = @($trx.SelectNodes("//*[local-name()='UnitTestResult']"))
        if ($cases.Count -ne 1 -or $cases[0].GetAttribute('outcome') -ne 'Passed') {
            throw "SYSTEM phase $phase is absent, skipped or failed."
        }
    }
    Write-Output 'SYSTEM identity provision and recovery passed in two separate processes.'
} finally {
    $ownedTask = Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
    if ($ownedTask) {
        if ($ownedTask.State -eq 'Running') { Stop-ScheduledTask -TaskName $taskName }
        Unregister-ScheduledTask -TaskName $taskName -Confirm:$false
    }
    Remove-Item -LiteralPath $worker -ErrorAction SilentlyContinue
}
