#requires -Version 5.1
# Portable managed-only controls. The full -SelfCheckOnly entry point also checks the existing Windows helpers.
$ErrorActionPreference = 'Stop'
if (-not ('SecurityDescriptorNativeControl' -as [type])) {
    & (Join-Path $PSScriptRoot 'security-descriptor-native-control.ps1')
} else { [SecurityDescriptorNativeControl]::SelfCheck() }
$tokens = $null; $errors = $null
$control = [Management.Automation.Language.Parser]::ParseFile((Join-Path $PSScriptRoot 'security-roundtrip-native-control.ps1'),[ref]$tokens,[ref]$errors)
if ($errors.Count -ne 0) { throw 'Native control parse failed.' }
# Load only the three pure byte comparison functions, never the Windows fixture code.
foreach ($name in @('Get-Hex','Get-DescriptorField','Get-DescriptorDifference')) {
    $definition = $control.Find({param($node) $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq $name},$false)
    if ($null -eq $definition) { throw ('Missing comparator: ' + $name) }
    . ([scriptblock]::Create($definition.Extent.Text))
}
# A complete self-relative layout: owner, group, SACL, DACL, plus outer padding.
$bytes = New-Object byte[] 64
$bytes[0]=1; $bytes[2]=0x14; $bytes[3]=0x80
foreach ($component in @(@(4,20),@(8,32),@(12,44),@(16,52))) {
    [BitConverter]::GetBytes([uint32]$component[1]).CopyTo($bytes,$component[0])
}
foreach ($offset in @(20,32)) { $bytes[$offset]=1; $bytes[$offset+1]=1 }
foreach ($offset in @(44,52)) { $bytes[$offset]=2; $bytes[$offset+2]=8 }
for ($offset=0; $offset -lt $bytes.Length; $offset++) {
    $changed=[byte[]]$bytes.Clone(); $changed[$offset]=$changed[$offset] -bxor 1
    $delta=@(Get-DescriptorDifference $bytes $changed)
    if ($delta.Count -ne 1 -or $delta[0].Offset -ne $offset -or $delta[0].Expected -eq $delta[0].Actual) {
        throw ('Descriptor byte mutation missed: ' + $offset)
    }
}
foreach ($test in @(@(0,'Revision'),@(1,'ResourceManagerControl'),@(3,'Control'),@(4,'OwnerOffset'),
    @(8,'GroupOffset'),@(12,'SaclOffset'),@(16,'DaclOffset'),@(20,'Owner+0'),@(32,'Group+0'),@(44,'Sacl+0'),@(52,'Dacl+0'),@(60,'Padding'))) {
    if ((Get-DescriptorField $bytes $test[0]) -ne $test[1]) { throw ('Incorrect field diagnostic: ' + $test[0]) }
}
$changed=[byte[]]$bytes.Clone(); $changed[3]=$changed[3] -bor 4
$delta=@(Get-DescriptorDifference $bytes $changed)
if ($delta.Count -ne 1 -or $delta[0].Offset -ne 3 -or $delta[0].ExpectedField -ne 'Control') { throw 'Auto-inherited bit was masked.' }
if (@(Get-DescriptorDifference $bytes $bytes).Count -ne 0 -or
    @(Get-DescriptorDifference $bytes (New-Object byte[] 65)).Count -eq 0) { throw 'Descriptor equality/length control failed.' }
$wrapper=[Management.Automation.Language.Parser]::ParseFile((Join-Path $PSScriptRoot 'Invoke-SecurityRoundTripNativeControl.ps1'),[ref]$tokens,[ref]$errors)
if ($errors.Count -ne 0) { throw 'SYSTEM wrapper parse failed.' }
$names=@('CompareAutoInheritanceRequests','CompareNativeInheritance','CompareAutoInheritConversion','CompareMarkerBehavior')
foreach ($ast in @($control,$wrapper)) {
    foreach ($name in $names) {
        $parameter=@($ast.ParamBlock.Parameters | Where-Object {$_.Name.VariablePath.UserPath -eq $name})
        if ($parameter.Count -ne 1 -or $parameter[0].StaticType -ne [Management.Automation.SwitchParameter]) { throw ('Missing switch: ' + $name) }
    }
}
# Evaluate the actual forwarding/selection statements for every combination, without scheduling a task or calling CREATE.
$forward=@($wrapper.EndBlock.Statements | Where-Object {$_.Extent.Text -match '^\$controlArguments\s*=' -or $_.Extent.Text -match '^if .*\$controlArguments \+='})
$select=@($control.EndBlock.Statements | Where-Object {$_.Extent.Text -match '^\$constructions\s*=' -or $_.Extent.Text -match '^if .*\$constructions \+='})
if ($forward.Count -ne 4 -or $select.Count -ne 4) { throw 'Unexpected forwarding/construction statements.' }
for ($mask=0; $mask -lt 16; $mask++) {
    for ($bit=0; $bit -lt $names.Count; $bit++) { Set-Variable -Name $names[$bit] -Value (($mask -band (1 -shl $bit)) -ne 0) }
    foreach ($statement in @($forward + $select)) { . ([scriptblock]::Create($statement.Extent.Text)) }
    $expected=@('stored'); $argumentText=''
    $constructionNames=@('dacl-auto-inherit-request','native-inheritance','auto-inherit-conversion','marker-behavior')
    for ($bit=0; $bit -lt $names.Count; $bit++) {
        if (($mask -band (1 -shl $bit)) -ne 0) {
            $argumentText+=' -'+$names[$bit]
            if ($bit -lt 3) { $expected+=$constructionNames[$bit] }
        }
    }
    if ($controlArguments -ne $argumentText -or ($constructions -join ',') -ne ($expected -join ',')) { throw ('Switch forwarding changed: ' + $mask) }
}
Write-Output 'FullDescriptorComparatorSelfCheck=PASS Bytes=64 MarkerUnmasked=True NativeCalls=False'
Write-Output 'DescriptorSwitchForwardingSelfCheck=PASS Combinations=16 Candidate1NeverImplicit=True NativeCalls=False'
