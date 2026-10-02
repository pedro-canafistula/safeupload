<#
Run on the WDK builder. Proves the NORMAL (staging compiled out) driver is unchanged by a
feature-only change: builds the committed HEAD minifilter in a directory whose full path
has the same length as the working mirror, then compares every PE section of the HEAD
normal SYS with the working-tree normal SYS built by Build-StagedOwnedStreams.ps1.
Only debug metadata in .rdata (PDB path/GUID/timestamp) may differ.
Prerequisite: a tar of `git archive HEAD driver/SafeUpload.Minifilter` on the builder.
#>
param(
    [Parameter(Mandatory)] [string] $HeadTar,
    [Parameter(Mandatory)] [string] $MilestoneDirectory,
    [string] $HeadRoot = 'C:\Users\vika\Documents\safeupload-staging-head',
    [int] $MaxRdataDifferingBytes = 32
)
$ErrorActionPreference = 'Stop'
$mirror = 'C:\Users\vika\Documents\safeupload-staging-test'
if ($HeadRoot.Length -ne $mirror.Length) { throw "HeadRoot length $($HeadRoot.Length) must equal mirror length $($mirror.Length)." }
$msbuild = 'C:\Program Files\Microsoft Visual Studio\18\Community\MSBuild\Current\Bin\amd64\MSBuild.exe'
$rules = 'C:\Program Files (x86)\Windows Kits\10\CodeAnalysis\DriverRecommendedRules.ruleset'
if (Test-Path -LiteralPath $HeadRoot) { Remove-Item -LiteralPath $HeadRoot -Recurse -Force }
New-Item -ItemType Directory -Path $HeadRoot | Out-Null
tar -xf $HeadTar -C $HeadRoot
function Get-PeSections([string] $Path) {
    $b = [IO.File]::ReadAllBytes($Path); $pe = [BitConverter]::ToInt32($b, 0x3C)
    $n = [BitConverter]::ToUInt16($b, $pe + 6); $opt = [BitConverter]::ToUInt16($b, $pe + 20); $sec = $pe + 24 + $opt
    $result = [ordered]@{}
    for ($i = 0; $i -lt $n; $i++) {
        $o = $sec + 40 * $i
        $name = [Text.Encoding]::ASCII.GetString($b, $o, 8).TrimEnd([char]0)
        $sz = [BitConverter]::ToUInt32($b, $o + 16); $ptr = [BitConverter]::ToUInt32($b, $o + 20)
        $result[$name] = $b[$ptr..($ptr + $sz - 1)]
    }
    $result
}
$failed = $false
Push-Location $HeadRoot
try {
    foreach ($case in @(@('Debug', 'normal.sys'), @('Release', 'normal-release.sys'))) {
        $cfg = $case[0]
        & $msbuild driver\SafeUpload.Minifilter\SafeUpload.Minifilter.vcxproj /t:Rebuild "/p:Configuration=$cfg" /p:Platform=x64 `
            /warnaserror /p:SafeUploadStagingPrototype=false /p:RunCodeAnalysis=true /p:EnablePREfast=true "/p:CodeAnalysisRuleSet=$rules" *> $null
        if ($LASTEXITCODE -ne 0) { throw "HEAD normal $cfg build failed." }
        $head = Get-PeSections (Join-Path $HeadRoot "driver\SafeUpload.Minifilter\x64\$cfg\SafeUpload.sys")
        $work = Get-PeSections (Join-Path $MilestoneDirectory $case[1])
        if (($head.Keys -join ',') -ne ($work.Keys -join ',')) { "Identity_$cfg=FAIL section list differs"; $failed = $true; continue }
        foreach ($name in $head.Keys) {
            $diff = 0
            for ($i = 0; $i -lt $head[$name].Length; $i++) { if ($head[$name][$i] -ne $work[$name][$i]) { $diff++ } }
            $limit = if ($name -eq '.rdata') { $MaxRdataDifferingBytes } else { 0 }
            $ok = $diff -le $limit
            if (-not $ok) { $failed = $true }
            "Identity_${cfg}_$name len=$($head[$name].Length) differingBytes=$diff allowed<=$limit $(if ($ok) { 'ok' } else { 'FAIL' })"
        }
    }
}
finally { Pop-Location }
'NormalBuildIdentity=' + $(if ($failed) { 'FAIL' } else { 'PASS' })
