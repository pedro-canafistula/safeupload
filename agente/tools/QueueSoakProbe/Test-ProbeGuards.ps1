[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$ProbeDll,
    [Parameter(Mandatory)][string]$OutputParent
)
$ErrorActionPreference='Stop'
$dll=(Resolve-Path -LiteralPath $ProbeDll).Path
$parent=[IO.Path]::GetFullPath($OutputParent)
$cases=Join-Path $parent ('probe-guards-'+[guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $cases | Out-Null
$pilot=Get-Content -LiteralPath (Join-Path $PSScriptRoot 'pilot.json') -Raw
$results=@()
foreach($name in @('event-budget','invalid-profile','installed-path')) {
    $profile=$pilot | ConvertFrom-Json
    $output=Join-Path $cases $name
    if($name -eq 'event-budget'){$profile.maxEvents=1}
    if($name -eq 'invalid-profile'){$profile.phaseSeconds=0}
    if($name -eq 'installed-path'){$output=Join-Path $env:ProgramData 'SafeUpload'}
    $profileFile=Join-Path $cases ($name+'.json')
    $profile | ConvertTo-Json | Set-Content -LiteralPath $profileFile -Encoding utf8
    $log=Join-Path $cases ($name+'.log')
    & dotnet $dll $output $profileFile *> $log
    $exit=$LASTEXITCODE
    if($exit -eq 0){throw ('Unexpected success: '+$name)}
    if($name -eq 'event-budget'){
        $receipts=@(Get-ChildItem -LiteralPath $output -Filter result.json -Recurse -File)
        if($receipts.Count -ne 1){throw 'Missing incomplete receipt'}
        $receipt=Get-Content -LiteralPath $receipts[0].FullName -Raw | ConvertFrom-Json
        if($receipt.status -ne 'incomplete' -or $receipt.events -ne 1 -or $receipt.error -notlike '*Event budget reached*'){
            throw 'Budget guard did not preserve incomplete state'
        }
        $queue=Join-Path $receipts[0].DirectoryName 'queue.jsonl'
        if(@(Get-Content -LiteralPath $queue).Count -ne 1){throw 'Budget queue changed'}
    } else {
        $expected=if($name -eq 'invalid-profile'){'Invalid bounded synthetic profile'}else{'Installed data refused'}
        if((Get-Content -LiteralPath $log -Raw) -notlike ('*'+$expected+'*')){throw ('Unexpected failure: '+$name)}
        if($name -eq 'invalid-profile' -and (Test-Path -LiteralPath $output)){throw 'Invalid profile created output'}
    }
    $results += [ordered]@{case=$name;passed=$true;exitCode=$exit;log=[IO.Path]::GetFileName($log)}
}
$results | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath (Join-Path $cases 'guards.json') -Encoding utf8
Write-Output ('PASS: 3 guards; '+$cases)
