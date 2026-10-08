#requires -Version 5.1
# Synthetic controls only; never qualifies a workload or actual taint state.
$ErrorActionPreference='Stop'
$tokens=$null;$errors=$null
$ast=[Management.Automation.Language.Parser]::ParseFile((Join-Path $PSScriptRoot 'Test-StagedInvariantSuite.ps1'),[ref]$tokens,[ref]$errors)
if($errors.Count){throw 'Suite parse failed'}
$definitions=@($ast.FindAll({param($node)$node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -ceq 'Test-InvariantLiveTaintWindow'},$false))
if($definitions.Count -ne 1){throw 'Missing/ambiguous live taint function'}
Invoke-Expression $definitions[0].Extent.Text
$checks=0
function CheckVerdict($Before,$After,$Counters,[string]$Expected,[string]$Label){
    $result=Test-InvariantLiveTaintWindow $Before $After $Counters
    if($result.Verdict -cne $Expected){throw ($Label+': '+($result|ConvertTo-Json -Compress -Depth 8))}
    $script:checks++
}
function Receipt([long]$Start,[long]$End){return @{BootId='boot';StartQpc=$Start;EndQpc=$End;Coverage=@{policyFlags='0x00000030';flags='0x00000042';policyGeneration=1;policyGenerationEnd=1}}}
$before=Receipt 10 20;$after=Receipt 80 90
$counters=@{Before=@{BootId='boot';StartQpc=30;EndQpc=40};After=@{BootId='boot';StartQpc=60;EndQpc=70};NoCounterChanges=$true}
CheckVerdict $before $after $counters 'PASS' 'Live bit and unchanged actual window'
CheckVerdict $null $after $counters 'INCONCLUSIVE' 'Missing boundary'
CheckVerdict $before $after $null 'INCONCLUSIVE' 'Missing counters'
$before.Coverage.policyFlags='0x00000010'
CheckVerdict $before $after $counters 'FAIL' 'Current policy bit off'
$before.Coverage.policyFlags='0x00000030';$after.Coverage.policyFlags='0x00000010'
CheckVerdict $before $after $counters 'FAIL' 'Ending policy bit off'
$after.Coverage.policyFlags='0x00000030';$after.Coverage.flags='0x00000002'
CheckVerdict $before $after $counters 'FAIL' 'Old driver echoing an unsupported policy bit'
$after.Coverage.flags='0x00000040'
CheckVerdict $before $after $counters 'INCONCLUSIVE' 'Unstable native receipt'
$after.Coverage.flags='0x00000042';$after.Coverage.policyGenerationEnd=2
CheckVerdict $before $after $counters 'INCONCLUSIVE' 'Native generation changed'
$after.Coverage.policyGenerationEnd=1;$after.Coverage.policyFlags='registry value'
CheckVerdict $before $after $counters 'INCONCLUSIVE' 'Malformed policy flags'
$after.Coverage.policyFlags='0x00000030';$after.BootId='other'
CheckVerdict $before $after $counters 'FAIL' 'Cross-boot receipts'
$after.BootId='boot';$before.EndQpc=31
CheckVerdict $before $after $counters 'FAIL' 'Starting receipt ordering'
$before.EndQpc=20;$after.StartQpc=69
CheckVerdict $before $after $counters 'FAIL' 'Ending receipt ordering'
$after.StartQpc=80;$counters.NoCounterChanges=$false
CheckVerdict $before $after $counters 'FAIL' 'Any taint counter activity'
$jsonDefinition=@($ast.FindAll({param($node)$node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -ceq 'Get-ActivationInspectorJson'},$false))
if($jsonDefinition.Count -ne 1){throw 'Missing/ambiguous JSON capture helper'}
Invoke-Expression $jsonDefinition[0].Extent.Text
$evidenceDirectory=Join-Path ([IO.Path]::GetTempPath()) ('live-taint-port-control-'+[guid]::NewGuid().ToString('N'))
$null=New-Item -ItemType Directory -Path $evidenceDirectory
$script:portAttempts=0;$script:portMode='transient'
function Invoke-ActivationInspector([string]$Argument,[string]$Prefix,[int]$Timeout){
    $script:portAttempts++
    if($script:portMode -ceq 'malformed'){return 'malformed'}
    if($script:portMode -ceq 'transient' -and $script:portAttempts -gt 1){return '{"policyFlags":"0x00000020"}'}
    [IO.File]::WriteAllText($Prefix+'.out',$(if($script:portMode -ceq 'wrong'){ 'hr = 0x80070005' }else{'hr = 0x800704D6'}))
    [IO.File]::WriteAllText($Prefix+'.err','')
    throw 'Synthetic Inspector failure'
}
try{
    $capture=Get-ActivationInspectorJson '--admission-coverage' 'control' -RetryTransientConnection
    if($portAttempts -ne 2 -or $capture.FailedConnectionAttempts.Count -ne 1 -or -not(Test-Path -LiteralPath $capture.FailedConnectionAttempts[0].StdOutPath)){throw 'Bounded retry must retain actual failed transport artifacts'};$checks++
    foreach($kind in @('default','persistent','wrong','malformed')){
        $script:portAttempts=0;$script:portMode=if($kind -ceq 'default'){'transient'}else{$kind}
        $refused=$false;try{if($kind -ceq 'default'){$null=Get-ActivationInspectorJson '--admission-coverage' 'control'}else{$null=Get-ActivationInspectorJson '--admission-coverage' 'control' -RetryTransientConnection}}catch{$refused=$true}
        $want=if($kind -ceq 'persistent'){4}else{1}
        if(-not $refused -or $portAttempts -ne $want){throw ('Invalid native/parser/default retry for '+$kind)};$checks++
    }
}finally{Remove-Item -LiteralPath $evidenceDirectory -Recurse -Force}
'LiveTaintSelfCheck=PASS;Checks='+$checks
