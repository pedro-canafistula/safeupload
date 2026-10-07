$ErrorActionPreference='Stop'
Import-Module 'C:\Users\vika\Documents\sol-harness-20261007a\StagedInvariantObserver.psm1' -Force
$root='E:\sol-retained-capture-check'
if(Test-Path $root){throw 'Fixture collision'}
New-Item -ItemType Directory -Path $root | Out-Null
$fixtures=Join-Path $root 'fixture';New-Item -ItemType Directory -Path $fixtures | Out-Null
$bytes=[Text.Encoding]::ASCII.GetBytes(('Independent retained whole-image control').PadRight(12288,'R'))
[IO.File]::WriteAllBytes((Join-Path $fixtures 'known.txt'),$bytes)
Get-Volume -DriveLetter E | Write-VolumeCache
$guid=[StagedInvariant.Native]::ResolveGuid($fixtures)
$c=$null
try{
 $c=Open-InvariantObserver -VolumeGuid $guid -ScopePath $fixtures -EvidenceDirectory (Join-Path $root 'evidence') -CaseId 'RetainedCaptureControl'
 if($c.Status -cne 'OK'){throw ($c.Error | Out-String)}
 $b=Capture-InvariantBaseline -Context $c -DestinationNames @('known.txt') -ExpectedImages @{'known.txt'=$bytes}
 if($b.Status -cne 'OK'){throw ($b.Error | Out-String)}
 $s=Capture-InvariantSample -Context $c -Baseline $b -Phase 'Retained' -OperationSequence 0
 if($s.Status -cne 'OK'){throw ($s.Error | Out-String)}
 $historical=@($s.Captures.Images | Where-Object Role -ceq 'Historical')
 $retained=@($s.Captures.Images | Where-Object {$_.Role -like 'Retained:*'})
 if($historical.Count -lt 1 -or $retained.Count -ne 1 -or $retained[0].Length -ne $bytes.Length -or $retained[0].Sha256 -cne [StagedInvariant.Native]::Hash($bytes)){throw 'Real retained/historical whole-image evidence missing'}
 if(@($historical | Where-Object Offset -lt 0).Count){throw 'Cached diagnostic was read as physical'}
 'RetainedCaptureBuilderControl=PASS;HistoricalCount='+$historical.Count+';Length='+$retained[0].Length+';SHA256='+$retained[0].Sha256
}finally{
 if($null -ne $c -and $c.Status -ceq 'OK'){$disposal=Close-InvariantObserver -Context $c;if($disposal.Status -cne 'OK'){throw 'Observer disposal failed'}}
}
