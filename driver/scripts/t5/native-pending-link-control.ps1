#requires -Version 5.1
param([Parameter(Mandatory=$true)][string]$NativeLibraryPath)
$ErrorActionPreference='Stop'
$tokens=$null;$errors=$null
$ast=[Management.Automation.Language.Parser]::ParseFile($NativeLibraryPath,[ref]$tokens,[ref]$errors)
if(@($errors).Count -ne 0){throw 'Native library parse failed'}
$sources=@($ast.FindAll({param($node)
    $node -is [Management.Automation.Language.StringConstantExpressionAst] -and
    $node.Value -match 'public static class NativeDeletePublicationControl'
},$true))
if($sources.Count -ne 1){throw 'One actual native helper source is required'}
Add-Type -TypeDefinition $sources[0].Value
$script:Assertions=0
function Assert-Link([bool]$Condition,[string]$Message){
    $script:Assertions++
    if(-not $Condition){throw $Message}
}
function Read-LinkPair([string]$Parent,[string]$Leaf){
    $a=[NativeDeletePublicationControl]::DirectoryEntry($Parent,$Leaf)
    $b=[NativeDeletePublicationControl]::DirectoryEntry($Parent,$Leaf)
    Assert-Link ($a.Length -eq 4 -and $b.Length -eq 4 -and $a[3] -eq 'Complete' -and $b[3] -eq 'Complete') 'Incomplete parent enumeration'
    Assert-Link ($a[0] -eq $b[0] -and $a[0].Length -eq 48 -and $a[1] -eq $b[1]) 'Unstable parent or leaf identity'
    return ,$a
}
'Machine='+$env:COMPUTERNAME
'PSVersion='+$PSVersionTable.PSVersion
'WindowsBuild='+[Environment]::OSVersion.Version
$root=Join-Path ([IO.Path]::GetTempPath()) ('safeupload-native-pending-link-'+[guid]::NewGuid().ToString('N'))
$volume=Get-Volume -DriveLetter ([IO.Path]::GetPathRoot($root).Substring(0,1))
Assert-Link ($volume.FileSystem -eq 'NTFS') 'NTFS is required'
$null=New-Item -ItemType Directory -Path $root
$reader=$null;$creator=$null
try {
    $leaf='pending-original.txt';$path=Join-Path $root $leaf
    $initial=Read-LinkPair $root $leaf
    Assert-Link ($initial[1] -eq '') 'New parent unexpectedly contains target'
    'NativePendingLinkSelfCheck=PASS;FreshParentAbsence=True'
    [IO.File]::WriteAllText($path,'original-pre-open')
    $reader=[NativeDeletePublicationControl]::Open($path,$false,$false)
    $original=[NativeDeletePublicationControl]::Identity($reader)
    $creator=[NativeDeletePublicationControl]::Open($path,$true,$false)
    Assert-Link ([NativeDeletePublicationControl]::Identity($creator) -eq $original) 'Native creator identity differs'
    $before=Read-LinkPair $root $leaf
    Assert-Link ($before[1] -eq $original -and $before[0] -eq $initial[0]) 'Initial parent mapping differs from original'
    $creator.Dispose();$creator=$null
    $probe=[NativeDeletePublicationControl]::Probe($path)
    $pending=[NativeDeletePublicationControl]::DeletePending($reader)
    Assert-Link ($probe -eq 5 -and $pending) 'Expected native child-open refusal/delete-pending state missing'
    $after=Read-LinkPair $root $leaf
    Assert-Link ($after[1] -eq $original -and $after[0] -eq $initial[0]) 'Read-only parent enumeration lost the pending original'
    'Case=after-creator-cleanup;ChildOpenWin32='+$probe+';NativeDeletePending='+$pending+';ParentIdentity='+$after[0]+';OriginalIdentity='+$original+';EnumeratedIdentity='+$after[1]+';TwoCompleteQueries=True;ChildOpenedForEnumeration=False;Verdict=PASS'
    $reader.Dispose();$reader=$null
    $absent=Read-LinkPair $root $leaf
    Assert-Link ($absent[1] -eq '' -and $absent[0] -eq $initial[0]) 'Last native reader close did not remove the exact parent entry'
    'Case=after-last-reader-cleanup;ParentIdentity='+$absent[0]+';ExactLeafAbsent=True;TwoCompleteQueries=True;Verdict=PASS'
    'NativePendingLinkControl=PASS;Assertions='+$script:Assertions+';ProductQualified=False;RecoveryNotImplemented=True'
}finally{
    if($null -ne $creator){$creator.Dispose()}
    if($null -ne $reader){$reader.Dispose()}
    Remove-Item -LiteralPath $root -Recurse -Force
}
