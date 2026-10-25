#requires -Version 7.5
[CmdletBinding()]
param([Parameter(Mandatory)][string]$OutputParent)
$ErrorActionPreference='Stop'
$root=Join-Path ([IO.Path]::GetFullPath($OutputParent)) ('profile-cases-'+[guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $root -Force | Out-Null
$source=Join-Path $PSScriptRoot 'proposed-72h.json'
$before=(Get-FileHash -LiteralPath $source).Hash
$results=@()
foreach($case in @('proposed','short-event-budget','short-output-budget','analyzer-limit','recovery-capacity','invalid-duration','unknown-field')){
    $p=Get-Content -LiteralPath $source -Raw | ConvertFrom-Json -DateKind String
    $expectedReason=$null
    switch($case){
        'short-event-budget'{$p.maxEvents=200;$expectedReason='event-budget-below-modeled-demand'}
        'short-output-budget'{$p.maxOutputBytes=8388608;$expectedReason='output-budget-below-modeled-demand'}
        'analyzer-limit'{$p.writeIntervalMs=500;$p.maxEvents=400000;$p.maxOutputBytes=2147483648;$expectedReason='analysis-file-limit-exceeded'}
        'recovery-capacity'{$p.batchSize=1;$expectedReason='nominal-recovery-capacity-insufficient'}
        'invalid-duration'{$p.phaseSeconds=0;$expectedReason='invalid-field:phaseSeconds'}
        'unknown-field'{$p|Add-Member -NotePropertyName accidentalSetting -NotePropertyValue 1;$expectedReason='unknown-profile-field'}
    }
    $profileFile=Join-Path $root ($case+'-profile.json')
    $p|ConvertTo-Json|Set-Content -LiteralPath $profileFile -Encoding utf8NoBOM
    $out=Join-Path $root ($case+'-result.json')
    $threw=$false
    try{& (Join-Path $PSScriptRoot 'Test-SoakProfile.ps1') -ProfilePath $profileFile -OutputPath $out | Out-Null}catch{$threw=$true}
    $r=Get-Content -LiteralPath $out -Raw | ConvertFrom-Json
    if($case -eq 'proposed'){
        if($threw -or $r.status -cne 'compatible-under-model-assumptions' -or $r.model.requestedActiveHours -ne 72 -or $r.model.totalEventsUpper -ne 17282){throw 'Unexpected proposed-profile model'}
    }elseif(-not $threw -or $r.status -cne 'profile-rejected' -or $expectedReason -cnotin $r.reasons){throw ('Unexpected rejection: '+$case)}
    if($r.executionAuthorized -ne $false -or $r.environmentQualified -ne $false -or $r.qualificationGranted -ne $false){throw 'Static check granted authorization/qualification'}
    $results+=[ordered]@{case=$case;passed=$true;status=$r.status;reasons=$r.reasons;report=[IO.Path]::GetFileName($out)}
}
$out=Join-Path $root 'proposed-result.json'
$hash=(Get-FileHash -LiteralPath $out).Hash
$threw=$false
try{& (Join-Path $PSScriptRoot 'Test-SoakProfile.ps1') -ProfilePath $source -OutputPath $out | Out-Null}catch{$threw=$true}
if(-not $threw -or (Get-FileHash -LiteralPath $out).Hash -cne $hash){throw 'Existing report overwritten'}
$results+=[ordered]@{case='output-preserved';passed=$true;status='existing-output-refused'}
if((Get-FileHash -LiteralPath $source).Hash -cne $before){throw 'Proposed source profile changed'}
$results|ConvertTo-Json -Depth 8|Set-Content -LiteralPath (Join-Path $root 'cases.json') -Encoding utf8NoBOM
Write-Output ('PASS: 8 profile controls; no workload started; '+$root)
