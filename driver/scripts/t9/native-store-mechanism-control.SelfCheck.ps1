#requires -Version 5.1
[CmdletBinding()]
param([switch]$SelfCheck)
# Both entry points are managed-only. -SelfCheck is accepted for explicit offline use.
$ErrorActionPreference = 'Stop'
[Console]::OutputEncoding = New-Object System.Text.UTF8Encoding($false)
try {
    $path = Join-Path $PSScriptRoot 'native-store-mechanism-control.ps1'
    foreach ($file in @($path,$PSCommandPath)) {
        $tokens = $null; $parseErrors = $null
        $ast = [Management.Automation.Language.Parser]::ParseFile($file,[ref]$tokens,[ref]$parseErrors)
        if ($parseErrors.Count -ne 0) { throw ('Parse failed: '+$file+': '+($parseErrors.Message -join '; ')) }
        # PS7 parses on Linux too; reject syntax known to require a newer language.
        # The Windows gate must still run this with the actual 5.1 parser/compiler.
        $newSyntax = @($ast.FindAll({param($node) $node.GetType().Name -in @('TernaryExpressionAst','PipelineChainAst')},$true))
        if ($newSyntax.Count -ne 0 -or @($tokens | Where-Object { $_.Kind.ToString() -in @('QuestionQuestion','QuestionQuestionEquals','QuestionDot','QuestionLBracket') }).Count -ne 0) {
            throw 'Post-5.1 language syntax found.'
        }
    }
    # Calls the very same embedded layout/signature/comparison tests used before
    # runtime, without OS/token/volume/file-native entry points. Add-Type uses
    # Windows' built-in compiler when this gate runs on Windows PowerShell 5.1.
    $result = @(& $path -SelfCheck)
    if ($result -notcontains 'NativeStoreMechanismSelfCheck=PASS') { throw 'Managed control did not pass.' }
    $managed = @($result | Where-Object { $_ -like '{*' } | ForEach-Object { $_ | ConvertFrom-Json } | Where-Object { $_.Kind -eq 'SelfCheck' })
    if ($managed.Count -ne 1 -or $managed[0].FaultRetentionReleaseMutations -ne 'PASS' -or $managed[0].NativeCalls -ne $false) {
        throw 'Missing extended fault/retention/release mutation receipt.'
    }
    # Exercise the actual PowerShell -> CLR argument boundary used for verdicts.
    $control = New-Object T9NativeStoreControl
    if ([T9NativeStoreControl]::Verdict($control.FirstDifference,$true) -ne 'PASS' -or
        [T9NativeStoreControl]::Verdict($control.FirstDifference,$false) -ne 'RECORDED') { throw 'PowerShell null-string verdict binding failed.' }
    $control.FirstDifference = 'Flipped NTSTATUS'
    if ([T9NativeStoreControl]::Verdict($control.FirstDifference,$true) -ne 'DIFFERS') { throw 'PowerShell difference verdict binding failed.' }
    foreach ($line in $result) { Write-Output $line }
    [pscustomobject]@{Kind='ParserSelfCheck'; ParserVersion=$PSVersionTable.PSVersion.ToString(); ParseErrors=0; NativeCalls=$false; ActualPS51=($PSVersionTable.PSVersion.Major -eq 5 -and $PSVersionTable.PSVersion.Minor -eq 1)} | ConvertTo-Json -Compress
    Write-Output 'NativeStoreMechanismHarnessSelfCheck=PASS'
} catch {
    [pscustomobject]@{Kind='SelfCheckError'; Message=$_.Exception.Message; NativeCalls=$false} | ConvertTo-Json -Compress
    Write-Output 'NativeStoreMechanismHarnessSelfCheck=FAIL'
    exit 1
}
