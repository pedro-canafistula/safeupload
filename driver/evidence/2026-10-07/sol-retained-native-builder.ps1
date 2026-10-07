$ErrorActionPreference='Stop'
Import-Module 'C:\Users\vika\Documents\sol-harness-20261007a\StagedInvariantObserver.psm1' -Force -DisableNameChecking
$root='E:\sol-retained-capture-check\fixture'
$p=Join-Path $root 'known.txt'
$expected=[IO.File]::ReadAllBytes($p)
$volume=$null;$handle=$null
try{
 $volume=[StagedInvariant.Native]::OpenVolume([StagedInvariant.Native]::ResolveGuid($root),$root)
 $handle=[StagedInvariant.Native]::Open($p,$false,$false)
 $first=[StagedInvariant.Native]::Capture($volume,$handle)
 $second=[StagedInvariant.Native]::Capture($volume,$handle)
 $digest=[StagedInvariant.Native]::Hash($expected)
 if($first.Digest -cne $digest -or $second.Digest -cne $digest -or $first.Logical.Length -ne 12288 -or $second.Logical.Length -ne 12288){throw 'Retained whole-image mismatch'}
 if($first.Containers.Count -lt 1){throw 'Missing physical containers'}
 $count=0
 foreach($c in $first.Containers){
  if($c.Offset -lt 0){throw 'Successful raw capture contains cached response'}
  $read=[StagedInvariant.Native]::ReadAligned($volume.Raw,$c.Offset,$c.Bytes.Length,$volume.Geometry.Alignment,$false,0)
  if([StagedInvariant.Native]::Hash($read) -cne $c.Sha256){throw 'Historical physical range changed'};$count++
 }
 'BuilderBuild='+(Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion').UBR
 'Qualification=False;Reason=Builder19045.6466;NativeRegressionControlOnly'
 'RetainedNativeBuilderControl=PASS;HistoricalCount='+$count+';Length='+$second.Logical.Length+';SHA256='+$digest
}finally{
 if($null -ne $handle){$handle.Dispose()};if($null -ne $volume){$volume.Raw.Dispose()}
}
