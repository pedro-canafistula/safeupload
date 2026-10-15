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
$source = [IO.File]::ReadAllText($BuildScript)
$ast = [Management.Automation.Language.Parser]::ParseFile($BuildScript, [ref]$tokens, [ref]$errors)
$buildTry = @($ast.FindAll({ param($node)
    $node -is [Management.Automation.Language.TryStatementAst] -and
    $node.Body.Extent.Text.Contains('SafeUpload.Minifilter.vcxproj')
}, $true))
if ($buildTry.Count -ne 1) { throw 'Build body missing or ambiguous.' }
$body = $buildTry[0].Body.Extent.Text
$body = $body.Substring(1, $body.Length - 2)
$work = Join-Path ([IO.Path]::GetTempPath()) ('kernel-profiles-' + [guid]::NewGuid().ToString('N'))
[void][IO.Directory]::CreateDirectory($work)
function Test-BuildProfiles([string] $Body) {
    # Execute the real build loop with inert native tools; no WDK, signing or network.
    function Invoke-NativeToLog([string] $Executable, [string[]] $Arguments, [string] $Log) {
        [void]$script:fixtureBuildCalls.Add([pscustomobject]@{ Arguments = $Arguments; Log = $Log })
        [IO.File]::WriteAllText($Log, "Build succeeded`n0 Warning(s)`n0 Error(s)`nApiValidator DriverRecommendedRules")
        return 0
    }
    function Test-Path { param($LiteralPath) return $true }
    function Copy-Item { param($LiteralPath, $Destination, [switch] $Force) }
    function Get-FileHash { param($LiteralPath, $Algorithm) return [pscustomobject]@{ Hash = ('A' * 64) } }
    $out = $work; $src = $work; $msbuild = 'inert-msbuild'; $rules = 'DriverRecommendedRules.ruleset'
    foreach ($OwnerWinFspPrototype in @('false', 'true')) {
        $summary = New-Object Collections.ArrayList
        $script:fixtureBuildCalls = New-Object Collections.ArrayList
        & ([scriptblock]::Create($Body))
        if ($script:fixtureBuildCalls.Count -ne 4) { throw 'Expected two driver builds, one feature Inspector and one writer fixture.' }
        $drivers = @($script:fixtureBuildCalls | Where-Object { $_.Arguments[0] -like '*SafeUpload.Minifilter.vcxproj' })
        if ($drivers.Count -ne 2) { throw 'Both feature driver builds are required.' }
        foreach ($configuration in @('Debug', 'Release')) {
            $calls = @($drivers | Where-Object { $_.Arguments -ccontains ('/p:Configuration=' + $configuration) })
            if ($calls.Count -ne 1) { throw 'Missing or duplicate configuration.' }
            foreach ($argument in @('/warnaserror', '/p:SafeUploadStagingPrototype=true', '/p:RunCodeAnalysis=true',
                    '/p:EnablePREfast=true', ('/p:CodeAnalysisRuleSet=' + $rules),
                    ('/p:SafeUploadOwnedWinFspPrototype=' + $OwnerWinFspPrototype))) {
                if ($calls[0].Arguments -cnotcontains $argument) { throw ('Build guard missing: ' + $argument) }
            }
        }
        $inspectors = @($script:fixtureBuildCalls | Where-Object { $_.Arguments[0] -like '*SafeUpload.Inspector.vcxproj' })
        if ($inspectors.Count -ne 1 -or $inspectors[0].Arguments -cnotcontains '/p:SafeUploadStagingPrototype=true') {
            throw 'Feature Inspector is required.'
        }
        foreach ($name in @('owned-feature', 'owned-feature-release')) {
            $rows = @($summary | Where-Object { $_.StartsWith('driver:' + $name + ' :') })
            if ($rows.Count -ne 1 -or $rows[0] -notlike '*feature=true*warnings=0 errors=0 apivalidator=True prefast=True*') {
                throw 'Feature summary missing or invalid.'
            }
        }
        if (@($summary | Where-Object { $_ -like '*normal*' }).Count) { throw 'Normal profile appeared in delivery.' }
    }
}
try {
    if (-not $source.Contains("[void]`$summary.Add('KernelBuildProfiles=owned-feature,owned-feature-release')")) {
        throw 'Profile receipt missing.'
    }
    Test-BuildProfiles $body
    $mutations = @(
        @("@('Debug', 'Release')", "@('Debug')"),
        @("@('Debug', 'Release')", "@('Release')"),
        @('SafeUploadStagingPrototype=true', 'SafeUploadStagingPrototype=false'),
        @("'/warnaserror'", "'/warn:4'"),
        @('/p:RunCodeAnalysis=true', '/p:RunCodeAnalysis=false'),
        @('/p:EnablePREfast=true', '/p:EnablePREfast=false'),
        @('/p:CodeAnalysisRuleSet=$rules', '/p:CodeAnalysisRuleSet=wrong'),
        @("`$name = 'owned-feature'", "`$name = 'normal'")
    )
    foreach ($mutation in $mutations) {
        $changed = $body.Replace($mutation[0], $mutation[1])
        if ($changed -ceq $body) { throw 'Mutation did not change source.' }
        $caught = $false
        try { Test-BuildProfiles $changed } catch { $caught = $true }
        if (-not $caught) { throw ('Build guard mutation escaped: ' + $mutation[0]) }
    }
} finally { Remove-Item -LiteralPath $work -Recurse -Force }
'BuildExactSourceSelfCheck=PASS; controls=parameter-sets,two-feature-builds,analysis,Inspector,profile-receipt; mutations=8'
