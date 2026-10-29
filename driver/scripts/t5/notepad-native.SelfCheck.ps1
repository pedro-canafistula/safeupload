#requires -Version 5.1
# Compile the actual embedded native declarations; never invoke Windows APIs.
$ErrorActionPreference='Stop'
$tokens=$null;$errors=$null
$ast=[Management.Automation.Language.Parser]::ParseFile((Join-Path $PSScriptRoot 'notepad-actor.ps1'),[ref]$tokens,[ref]$errors)
if($errors.Count){throw 'Actor source parse errors'}
$types=@($ast.FindAll({param($n)$n -is [Management.Automation.Language.StringConstantExpressionAst] -and $n.Value.StartsWith('using System;')},$true))
if($types.Count -ne 1 -or -not $types[0].Value.Contains('class T5Native') -or -not $types[0].Value.Contains('class T5Shell')){throw 'Expected the actual combined native/Shell declaration block'}
foreach($type in $types){Add-Type -TypeDefinition $type.Value -ErrorAction Stop}
$read=[T5Native].GetMethod('Read')
if($null -eq $read -or $read.ReturnType -ne [T5ReadResult] -or $read.GetParameters().Count -ne 1 -or $read.GetParameters()[0].ParameterType -ne [string]){throw 'Native read signature mismatch'}
$transfer=[T5Shell].GetMethod('Transfer')
if($null -eq $transfer -or $transfer.ReturnType -ne [string] -or $transfer.GetParameters().Count -ne 3 -or
    $transfer.GetParameters()[0].ParameterType -ne [string] -or $transfer.GetParameters()[1].ParameterType -ne [string] -or
    $transfer.GetParameters()[2].ParameterType -ne [bool]){throw 'Shell transfer signature mismatch'}
if($null -eq [T5Native].GetMethod('ReplaceText')){throw 'Notepad notified edit method missing'}
'T5NativeDeclarationSelfCheck=PASS;Blocks=1;NativeCallsExecuted=False;ProductQualified=False'
