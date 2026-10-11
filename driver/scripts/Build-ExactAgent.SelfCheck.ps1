param([string[]] $BuildScripts = @(
    (Join-Path $PSScriptRoot 'Build-ExactAgent.ps1'),
    (Join-Path $PSScriptRoot 'Build-ExactAgentMatrix.ps1')))
$ErrorActionPreference = 'Stop'
foreach ($buildScript in $BuildScripts) {
    $tokens = $null
    $errors = $null
    [void][Management.Automation.Language.Parser]::ParseFile($buildScript, [ref]$tokens, [ref]$errors)
    if ($errors.Count -ne 0) { throw ('Build script does not parse: ' + $buildScript) }
    $command = Get-Command -Name $buildScript
    if (-not $command.Parameters.ContainsKey('SourceCommit') -or $command.Parameters.ContainsKey('ManifestSha256') -or
        -not @($command.ParameterSets[0].Parameters | Where-Object { $_.Name -eq 'SourceCommit' -and $_.IsMandatory }).Count) {
        throw 'Agent builds require a Git commit and accept no source manifest.'
    }
    $arguments = @{ Label = 'parameter-control'; ArchiveSha256 = ('a' * 64) }
    $rejected = $false
    try { & $buildScript @arguments -SourceCommit 'invalid' }
    catch [Management.Automation.ParameterBindingException] { $rejected = $true }
    if (-not $rejected) { throw 'Malformed source commit was accepted.' }
    $rejected = $false
    try { & $buildScript @arguments -SourceCommit ('b' * 40) -ManifestSha256 ('c' * 64) }
    catch [Management.Automation.ParameterBindingException] { $rejected = $true }
    if (-not $rejected) { throw 'An obsolete source manifest was accepted.' }
}
'BuildExactAgentSelfCheck=PASS; controls=required-commit,invalid-commit,no-source-manifest'
