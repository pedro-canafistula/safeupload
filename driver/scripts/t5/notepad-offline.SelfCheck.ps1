# Pure local diagnostics: no native calls, VM, or network.
$ErrorActionPreference='Stop'
if($PSVersionTable.PSVersion.Major -lt 7){throw 'Use the standalone self-checks directly on Windows PowerShell 5.1'}
# Offline PS7 compatibility: preserve JSON date strings exactly as Windows PS5.1 does.
function Restore-DateStrings($Object) {
    if($Object -is [string]) {return $Object.Replace('T5_DATE_LITERAL:','')}
    if($Object -is [array]) {return ,@($Object | ForEach-Object {Restore-DateStrings $_})}
    if($Object -is [pscustomobject]) {foreach($p in $Object.PSObject.Properties){$p.Value=Restore-DateStrings $p.Value}}
    return $Object
}
function global:ConvertFrom-Json {
    [CmdletBinding()]param([Parameter(ValueFromPipeline=$true)][string]$InputObject)
    process {
        $masked=[regex]::Replace($InputObject,'"(\d{4}-\d{2}-\d{2}T[^"\\]+)"','"T5_DATE_LITERAL:$1"')
        Restore-DateStrings (Microsoft.PowerShell.Utility\ConvertFrom-Json -InputObject $masked)
    }
}
foreach($name in @('notepad-actor.ps1','notepad-coordinator.ps1','notepad-coordinator.SelfCheck.ps1','notepad-journal.SelfCheck.ps1')){
    $path=Join-Path $PSScriptRoot $name;$tokens=$null;$errors=$null
    $ast=[Management.Automation.Language.Parser]::ParseFile($path,[ref]$tokens,[ref]$errors)
    if($errors.Count){throw ($errors | Out-String)}
    $name+':ParseErrors=0'
    if($name -eq 'notepad-actor.ps1'){
        foreach($type in $ast.FindAll({param($n)$n -is [Management.Automation.Language.StringConstantExpressionAst] -and $n.Value.StartsWith('using System;')},$true)){Add-Type -TypeDefinition $type.Value}
        'T5ActorNativeCompile=PASS;NativeCallsExecuted=False'
    }
}
& (Join-Path $PSScriptRoot 'notepad-coordinator.SelfCheck.ps1')
& (Join-Path $PSScriptRoot 'notepad-journal.SelfCheck.ps1')
'T5OfflinePowerShellSelfCheck=PASS;JsonDateMode=PS5StringEmulation;WindowsGate=False;ProductQualified=False'
