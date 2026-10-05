param(
    [Parameter(Mandatory=$true)][string]$SuitePath,
    [Parameter(Mandatory=$true)][string]$ExpectedSha256
)
$ErrorActionPreference='Stop'
$ProgressPreference='SilentlyContinue'
$actualHash=(Get-FileHash -Algorithm SHA256 -LiteralPath $SuitePath).Hash
if($actualHash -cne $ExpectedSha256){throw "Suite SHA mismatch: $actualHash"}
$tokens=$null;$errors=$null
$suiteAst=[Management.Automation.Language.Parser]::ParseFile($SuitePath,[ref]$tokens,[ref]$errors)
if(@($errors).Count -ne 0){throw "Suite parse errors: $($errors | Out-String)"}
$functions=@($suiteAst.FindAll({param($node) $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -ceq 'Get-WriterBody'},$true))
if($functions.Count -ne 1){throw "Expected one actual Get-WriterBody; got $($functions.Count)"}
Invoke-Expression $functions[0].Extent.Text
$ownedRoot=Join-Path ([IO.Path]::GetTempPath()) ('SafeUpload-S01-WriterTemp-' + [guid]::NewGuid().ToString('N'))
[IO.Directory]::CreateDirectory($ownedRoot) | Out-Null
$priorTemp=$env:TEMP;$priorTmp=$env:TMP
try {
    $literal=$ownedRoot.Replace("'","''")
    $body=(Get-WriterBody).Replace('__CONFIG__','mock-config').Replace('__IDENTITY__','mock-identity').Replace('__GO__','mock-go').Replace('__TEMP__',$literal)
    if($body.Contains('__TEMP__')){throw 'Unresolved TEMP placeholder'}
    $bodyTokens=$null;$bodyErrors=$null
    $bodyAst=[Management.Automation.Language.Parser]::ParseInput($body,[ref]$bodyTokens,[ref]$bodyErrors)
    if(@($bodyErrors).Count -ne 0){throw "Generated writer parse errors: $($bodyErrors | Out-String)"}
    $statements=@($bodyAst.EndBlock.Statements)
    if($statements.Count -lt 3 -or $statements[2] -isnot [Management.Automation.Language.PipelineAst] -or
        $statements[2].PipelineElements.Count -ne 1 -or
        $statements[2].PipelineElements[0].GetCommandName() -cne 'Add-Type') {throw 'Expected TEMP, TMP, then actual Add-Type statements'}
    $first=$statements[0].Extent.Text;$second=$statements[1].Extent.Text;$third=$statements[2].Extent.Text
    if($first -cne ('$env:TEMP=' + "'" + $literal + "'") -or $second -cne '$env:TMP=$env:TEMP'){throw 'Unexpected writer temp assignment order'}
    Invoke-Expression ($first + "`n" + $second + "`n" + $third)
    if($env:TEMP -cne $ownedRoot -or $env:TMP -cne $ownedRoot){throw 'Writer temp redirection failed'}
    if(-not ('SUWriter' -as [type]) -or -not ('SUCall' -as [type])){throw 'Actual writer Add-Type did not load'}
    [pscustomobject]@{NotVmQualification=$true;SuiteSha256=$actualHash;SuiteParseErrors=0;WriterBodyParseErrors=0;ExtractedGetWriterBody=$true;ActualAddTypeCompiled=$true;TempAndTmp=$ownedRoot;RunIdentity=[Security.Principal.WindowsIdentity]::GetCurrent().Name;LimitedActorTask=$false} | ConvertTo-Json -Compress
} finally {
    $env:TEMP=$priorTemp;$env:TMP=$priorTmp
    if([IO.Directory]::Exists($ownedRoot)){[IO.Directory]::Delete($ownedRoot,$true)}
}
