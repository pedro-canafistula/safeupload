#requires -Version 5.1
# Compile the actual embedded native declarations; never invoke Windows APIs.
$ErrorActionPreference='Stop'
$tokens=$null;$errors=$null
$ast=[Management.Automation.Language.Parser]::ParseFile((Join-Path $PSScriptRoot 'notepad-actor.ps1'),[ref]$tokens,[ref]$errors)
if($errors.Count){throw 'Actor source parse errors'}
$types=@($ast.FindAll({param($n)$n -is [Management.Automation.Language.StringConstantExpressionAst] -and $n.Value.StartsWith('using System;')},$true))
if($types.Count -ne 1 -or -not $types[0].Value.Contains('class T5Native') -or -not $types[0].Value.Contains('class T5Shell')){throw 'Expected the actual combined native/Shell declaration block'}
foreach($type in $types){Add-Type -TypeDefinition $type.Value -ErrorAction Stop}
'T5NativeDeclarationSelfCheck=PASS;Blocks=1;NativeCallsExecuted=False;ProductQualified=False'
