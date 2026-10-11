param([string] $BuildScript = (Join-Path $PSScriptRoot 'Build-ExactSource.ps1'))
$ErrorActionPreference = 'Stop'
$tokens = $null
$errors = $null
[void][Management.Automation.Language.Parser]::ParseFile($BuildScript, [ref]$tokens, [ref]$errors)
if ($errors.Count -ne 0) { throw 'Build script does not parse.' }
$command = Get-Command -Name $BuildScript
$commitSet = @($command.ParameterSets | Where-Object { $_.Name -eq 'Commit' })
$worktreeSet = @($command.ParameterSets | Where-Object { $_.Name -eq 'Worktree' })
if ($commitSet.Count -ne 1 -or $worktreeSet.Count -ne 1) { throw 'Source parameter sets are missing.' }
if (-not @($commitSet[0].Parameters | Where-Object { $_.Name -eq 'SourceCommit' -and $_.IsMandatory }).Count -or
    @($commitSet[0].Parameters | Where-Object { $_.Name -eq 'ManifestSha256' }).Count) {
    throw 'Committed builds must require a commit and accept no manifest.'
}
$arguments = @{ Label = 'parameter-control'; ArchiveSha256 = ('a' * 64); CertificateThumbprint = ('b' * 40) }
$rejected = $false
try { & $BuildScript @arguments -SourceCommit 'invalid' } catch [Management.Automation.ParameterBindingException] { $rejected = $true }
if (-not $rejected) { throw 'Malformed commit was accepted.' }
$rejected = $false
try { & $BuildScript @arguments -SourceCommit ('c' * 40) -ManifestSha256 ('d' * 64) }
catch [Management.Automation.ParameterBindingException] { $rejected = $true }
if (-not $rejected) { throw 'Mixed source parameter sets were accepted.' }
'BuildExactSourceSelfCheck=PASS; controls=parameter-sets,invalid-commit,mixed-source'
