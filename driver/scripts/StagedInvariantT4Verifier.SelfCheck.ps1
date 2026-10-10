#requires -Version 5.1
# Test the actual coordinator parser against observed Windows 19045 tuple
# labels and refusal controls. This is parser qualification, never pool evidence.
$ErrorActionPreference='Stop'
$tokens=$null;$errors=$null
$ast=[Management.Automation.Language.Parser]::ParseFile((Join-Path $PSScriptRoot 't4\cycles-coordinator.ps1'),[ref]$tokens,[ref]$errors)
if($errors.Count){throw 'Coordinator does not parse'}
$functions=@($ast.FindAll({param($node)$node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -ceq 'ConvertFrom-T4VerifierPool'},$false))
if($functions.Count -ne 1){throw 'Actual Verifier pool parser unavailable'}
Invoke-Expression $functions[0].Extent.Text
$count=0
function Assert-Control([bool]$Good,[string]$Label){if(-not $Good){throw ('T4 Verifier control failed: '+$Label)};$script:count++}
# Numbers and labels from m2t4long2's retained /query output, with competing
# modules added to prove selection never borrows their pool or global totals.
$text=@'
Verifier Flags: 0x0000013b
Pool Allocations Failed: 0
MODULE: Other.sys (load: 1 / unload: 0)
Current Pool Allocations: ( 9999 / 88 )
Current Pool Bytes: ( 99999999 / 88888 )
Peak Pool Bytes: ( 999999999 / 888888 )
MODULE: SafeUpload.sys (load: 1 / unload: 0)
Pool Allocation Statistics: ( NonPaged / Paged )
Current Pool Allocations: ( 4963 / 0 )
Current Pool Bytes: ( 11875360 / 0 )
Peak Pool Bytes: ( 11959680 / 418240 )
MODULE: Trailing.sys (load: 1 / unload: 0)
Current Pool Allocations: ( 777 / 66 )
Current Pool Bytes: ( 777777 / 66666 )
Peak Pool Bytes: ( 7777777 / 666666 )
'@
$pool=ConvertFrom-T4VerifierPool $text
Assert-Control ($pool.Verified -and $pool.Flags -ceq '0x0000013b') 'exact target module and flags'
Assert-Control ($pool.NonPagedBytes -eq 11875360 -and $pool.NonPagedAllocations -eq 4963) 'actual NonPaged values from the target tuple'
Assert-Control ($pool.PagedBytes -eq 0 -and $pool.PeakNonPagedBytes -eq 11959680) 'tuple order and peak remain exact'
Assert-Control ($null -eq $pool.AllocationFailures) 'global allocation failures are not reported as driver-owned failures'
$large=ConvertFrom-T4VerifierPool ($text.Replace('11875360','4294967296'))
Assert-Control ($large.NonPagedBytes -eq 4294967296) 'pool bytes use 64-bit arithmetic'
$legacy=@'
Verifier Flags: 0x0000013b
MODULE: SafeUpload.sys
Current Non-Paged Pool Usage (bytes): 4096
Current Non-Paged Pool Allocations: 2
Current Paged Pool Usage (bytes): 0
Peak Non-Paged Pool Usage (bytes): 8192
Pool Allocation Failures: 0
'@
$pool=ConvertFrom-T4VerifierPool $legacy
Assert-Control ($pool.Verified -and $pool.NonPagedBytes -eq 4096 -and $pool.PeakNonPagedBytes -eq 8192 -and $pool.AllocationFailures -eq 0) 'separate-label format remains supported'
$none=ConvertFrom-T4VerifierPool ($text.Replace('MODULE: SafeUpload.sys','MODULE: SafeUpload.sysx'))
Assert-Control (-not $none.Verified -and $null -eq $none.NonPagedBytes) 'similarly named module cannot become SafeUpload evidence'
foreach($bad in @(
    $text.Replace('Current Pool Bytes: ( 11875360 / 0 )','Current Pool Bytes: unavailable'),
    $text.Replace('Current Pool Allocations: ( 4963 / 0 )','Current Pool Allocations: unavailable'),
    $text.Replace('Peak Pool Bytes: ( 11959680 / 418240 )','Peak Pool Bytes: unavailable'),
    ($text+"`r`nMODULE: SafeUpload.sys`r`nCurrent Pool Bytes: ( 1 / 0 )")
)){
    $refused=$false;try{$null=ConvertFrom-T4VerifierPool $bad}catch{$refused=$true}
    Assert-Control $refused 'missing or ambiguous target evidence is refused'
}
'T4VerifierSelfCheck=PASS;Controls='+$count+';Qualification=False'
