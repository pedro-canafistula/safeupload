<# Local Windows PowerShell 5.1 builder check of exact observer-corpus source bytes.
   This script never invokes the corpus body, an observer capture, or stimulus methods.
   Usage: powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\observer-corpus-builder-check.ps1
          -Corpus .\Test-StagedInvariantObserverCorpus.ps1 -Observer .\StagedInvariantObserver.psm1
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)][string]$Corpus,
    [Parameter(Mandatory=$true)][string]$Observer
)
$ErrorActionPreference='Stop'
Set-StrictMode -Version 2.0
if($PSVersionTable.PSVersion.Major -ne 5 -or $PSVersionTable.PSVersion.Minor -ne 1){throw 'Windows PowerShell 5.1 required'}

$expectedCorpus='D5AD73C40B57DB02087BDEA4F0B2FE5B693C191FE2129751875AA3C993B74784'
$expectedObserver='4411CC06C522D62B6078F52689C0D2C681401795D8CB50603E8FFBD5ED5AE46E'
$corpusBytes=[IO.File]::ReadAllBytes((Resolve-Path -LiteralPath $Corpus).ProviderPath)
$observerPath=(Resolve-Path -LiteralPath $Observer).ProviderPath
$sha=[Security.Cryptography.SHA256]::Create()
try {
    $corpusHash=([BitConverter]::ToString($sha.ComputeHash($corpusBytes))).Replace('-','')
    $observerHash=([BitConverter]::ToString($sha.ComputeHash([IO.File]::ReadAllBytes($observerPath)))).Replace('-','')
} finally {$sha.Dispose()}
if($corpusHash -cne $expectedCorpus -or $observerHash -cne $expectedObserver){
    throw ('Exact source hash mismatch; corpus='+$corpusHash+' observer='+$observerHash)
}
Write-Output ('CorpusSha256='+$corpusHash)
Write-Output ('ObserverSha256='+$observerHash)

$utf8=New-Object System.Text.UTF8Encoding($false,$true)
$source=$utf8.GetString($corpusBytes)
$tokens=$null;$parseErrors=$null
$ast=[System.Management.Automation.Language.Parser]::ParseInput($source,[ref]$tokens,[ref]$parseErrors)
Write-Output ('CorpusParseErrors='+@($parseErrors).Count)
if(@($parseErrors).Count -ne 0){
    foreach($errorRecord in $parseErrors){Write-Output ('ParseError='+$errorRecord.Extent.StartLineNumber+':'+$errorRecord.Message)}
    throw 'Corpus parse failed'
}
if($ast -isnot [System.Management.Automation.Language.ScriptBlockAst]){throw 'Corpus AST is not a script block'}

# The import defines StagedInvariant.Native and SameIdentity. No exported observer command is invoked.
Import-Module $observerPath -Force -DisableNameChecking -ErrorAction Stop
if(-not ('StagedInvariant.Native' -as [type])){throw 'Canonical observer Native type unavailable'}

$wanted=@('Fail','Inconclusive','Assert-ReaderResult','Assert-Readers')
foreach($name in $wanted){
    $matches=@($ast.EndBlock.Statements | Where-Object {
        $_ -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $_.Name -ceq $name
    })
    if($matches.Count -ne 1){throw ('Missing/duplicate top-level actual corpus function: '+$name)}
    . ([scriptblock]::Create($matches[0].Extent.Text))
    Write-Output ('ActualFunction='+$name+';Line='+$matches[0].Extent.StartLineNumber)
}

$stimuli=@($ast.FindAll({param($node)
    $node -is [System.Management.Automation.Language.StringConstantExpressionAst] -and
    $node.Extent.Text.StartsWith("@'") -and $node.Value.Contains('class ObserverCorpusStimulus')
},$true))
if($stimuli.Count -ne 1){throw 'Embedded fixture-only C# stimulus missing/ambiguous'}
if($stimuli[0].Value -notmatch 'public static class ObserverCorpusStimulus' -or
   $stimuli[0].Value -notmatch 'extern bool MoveFileEx' -or
   $stimuli[0].Value -notmatch 'extern bool SetFileInformationByHandle'){
    throw 'Embedded stimulus surface changed'
}
if('ObserverCorpusStimulus' -as [type]){throw 'Builder check requires a fresh PowerShell process'}
Add-Type -TypeDefinition $stimuli[0].Value -ErrorAction Stop
if(-not ('ObserverCorpusStimulus' -as [type])){throw 'Embedded stimulus C# did not compile'}
Write-Output ('EmbeddedStimulusCompiled=True;Line='+$stimuli[0].Extent.StartLineNumber)

function New-SyntheticIdentity([string]$FileId='A1') {
    $identity=[StagedInvariant.Identity]::new()
    $identity.VolumeSerial=[uint64]42;$identity.FileId=$FileId
    $identity.Reference=[uint64]281474976710657
    $identity.Eof=4;$identity.Allocation=4096;$identity.Attributes=128
    $identity.Links=1;$identity.Modified=7;$identity.Changed=8
    return $identity
}
function New-SyntheticReader([string]$Path,[bool]$Unbuffered,[string]$Role,[string]$FileId) {
    $result=[StagedInvariant.Reader]::new()
    $result.Status='OK';$result.Before=New-SyntheticIdentity $FileId
    $result.After=New-SyntheticIdentity $FileId
    $result.Length=4;$result.Digest='ABCD'
    return [pscustomobject]@{Path=$Path;Unbuffered=$Unbuffered;Role=$Role;FileId=$FileId;Status='OK';Result=$result}
}
function New-SyntheticCapture {
    $path='C:\synthetic-current.bin';$old='C:\synthetic-retained.bin'
    $current=[pscustomobject]@{Role='Current';Path=$path;Absent=$false;Identity=(New-SyntheticIdentity 'A1');Length=4;Sha256='ABCD'}
    $retained=[pscustomobject]@{Role='Retained:old';Path=$old;Absent=$false;Identity=(New-SyntheticIdentity 'B2');Length=4;Sha256='ABCD'}
    return [pscustomobject]@{
        Images=@($current,$retained)
        Readers=@((New-SyntheticReader $path $false 'Current' 'A1'),
                  (New-SyntheticReader $path $true 'Current' 'A1'),
                  (New-SyntheticReader $null $false 'Retained' 'B2'))
    }
}
function Check-Synthetic([string]$Name,[string]$Expected,[scriptblock]$Change) {
    $capture=New-SyntheticCapture
    if($null -ne $Change){& $Change $capture}
    $actual='OK';$message=''
    try {Assert-Readers $capture}
    catch {
        $message=$_.Exception.Message
        if($message.StartsWith('FAIL:')){$actual='FAIL'}
        elseif($message.StartsWith('INCONCLUSIVE:')){$actual='INCONCLUSIVE'}
        else {throw ('Unexpected assertion exception in '+$Name+': '+$message)}
    }
    if($actual -cne $Expected){throw ($Name+' expected '+$Expected+' got '+$actual+' '+$message)}
    Write-Output ('Synthetic_'+$Name+'='+$actual)
}

Check-Synthetic 'CurrentAndRetainedPairs' 'OK' $null
Check-Synthetic 'MissingUncachedCurrent' 'INCONCLUSIVE' {
    param($c) $c.Readers=@($c.Readers | Where-Object {$_.Unbuffered -eq $false})
}
Check-Synthetic 'MissingHeldRetained' 'INCONCLUSIVE' {
    param($c) $c.Readers=@($c.Readers | Where-Object {$_.Role -ne 'Retained'})
}
Check-Synthetic 'ReaderError' 'INCONCLUSIVE' {param($c) $c.Readers[0].Status='ERROR'}
Check-Synthetic 'NativeError' 'INCONCLUSIVE' {param($c) $c.Readers[0].Result.Status='ERROR'}
Check-Synthetic 'MissingNativeResult' 'INCONCLUSIVE' {param($c) $c.Readers[0].Result=$null}
Check-Synthetic 'DigestMismatch' 'FAIL' {param($c) $c.Readers[0].Result.Digest='BAD'}
Check-Synthetic 'LengthMismatch' 'FAIL' {param($c) $c.Readers[0].Result.Length=3}
Check-Synthetic 'UnstableIdentity' 'INCONCLUSIVE' {param($c) $c.Readers[0].Result.After=New-SyntheticIdentity 'OTHER'}
Write-Output 'BuilderSyntheticCheck=PASS;NotVmQualification=True'
