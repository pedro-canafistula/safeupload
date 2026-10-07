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
'LiveTaintSelfCheck=PASS;Checks='+$checks
