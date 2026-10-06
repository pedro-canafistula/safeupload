$ErrorActionPreference='Stop'
$ProgressPreference='SilentlyContinue'
if($env:COMPUTERNAME -ne 'DESKTOP-O1LP5DG' -or (Get-CimInstance Win32_ComputerSystemProduct).UUID -ne 'C6440689-D11C-4C63-A463-F3722B7DDB69'){throw 'Wrong builder'}
$path='C:\Users\vika\Documents\w01r2-recovery-check-20261006a.ps1'
if((Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash -ne '25453548C14102F5FB2344BB542033A9CD606598B4821C067AEDF67C10DA0394'){throw 'Checker source hash mismatch'}
$tokens=$null;$errors=$null
$ast=[Management.Automation.Language.Parser]::ParseFile($path,[ref]$tokens,[ref]$errors)
if($errors.Count){$errors|Format-List *|Out-String|Write-Output;throw 'Recovery checker parser failed'}
'PARSE_PASS SHA256=25453548C14102F5FB2344BB542033A9CD606598B4821C067AEDF67C10DA0394'
# Define only these pure helpers from the parsed AST; never invoke the checker.
foreach($name in @('Require','Get-Field','Get-MapNames','Read-BaselineFields')){
 $nodes=@($ast.FindAll({param($node) $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -ceq $name},$true))
 if($nodes.Count -ne 1){throw ('Unexpected helper definition inventory: '+$name)}
 . ([ScriptBlock]::Create($nodes[0].Extent.Text))
}
function MustThrow([ScriptBlock]$Action,[string]$Name){
 $threw=$false
 try{& $Action|Out-Null}catch{$threw=$true}
 if(-not $threw){throw ('Negative control accepted: '+$Name)}
 'NEGATIVE_CONTROL_PASS '+$Name
}
$clean=Read-BaselineFields "Host=WIN10-DEBUGGED`nBaselineClean=True`n"
Require ($clean['Host'] -ceq 'WIN10-DEBUGGED' -and $clean['BaselineClean'] -ceq 'True') 'Baseline positive control failed'
MustThrow {Read-BaselineFields "BaselineClean=True`nBaselineClean=False`n"} 'conflicting baseline fields'
MustThrow {Read-BaselineFields "Host=one`nHost=one`n"} 'repeated baseline fields'
Require ((Get-Field @{Known=$false} 'Known') -eq $false) 'False field lost'
MustThrow {Get-Field @{} 'Missing'} 'missing map field'
MustThrow {Get-Field $null 'Missing'} 'missing object'
MustThrow {Get-Field ([pscustomobject]@{Known=1}) 'Missing'} 'missing object property'
$roundtrip=[Management.Automation.PSSerializer]::Deserialize([Management.Automation.PSSerializer]::Serialize(@{OriginalMemoryVerifier=@{VerifyDriverLevel=@{Kind='DWord';Value=[int]0}};OriginalAgent=@{Exists=$false}},32))
Require ((Get-Field (Get-Field $roundtrip 'OriginalAgent') 'Exists') -eq $false) 'Deserialized false value lost'
$mv=Get-Field $roundtrip 'OriginalMemoryVerifier'
Require (@(Get-MapNames $mv).Count -eq 1 -and (Get-MapNames $mv) -ceq 'VerifyDriverLevel') 'Deserialized registry inventory failed'
Require ((Get-Field (Get-Field $mv 'VerifyDriverLevel') 'Kind') -ceq 'DWord') 'Deserialized registry kind failed'
MustThrow {Require $false 'intentional control'} 'failed condition'
'PURE_HELPER_CONTROLS_PASS; checker and baseline never invoked; no guest repair operation'
'AUTHORING_VALIDATION_PASS PowerShell='+$PSVersionTable.PSVersion.ToString()+' UTC='+[DateTime]::UtcNow.ToString('o')
