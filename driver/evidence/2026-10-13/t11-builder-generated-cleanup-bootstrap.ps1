$ErrorActionPreference='Stop'
if($env:COMPUTERNAME -ne 'DESKTOP-O1LP5DG' -or (Get-CimInstance Win32_ComputerSystemProduct).UUID -ne 'C6440689-D11C-4C63-A463-F3722B7DDB69'){throw 'Wrong builder'}
$r='C:\Users\vika\Documents\exact-agent-matrix-t5-security-storage2'
$o=Join-Path $r 'out';$p=Join-Path $o 'normal-release-publish'
$z=Join-Path $o 'normal-release-service-publish.zip';$m=Join-Path $o 'normal-release-package-manifest.txt'
$zh='60AB0570C90F99F606C18E34E3A3E7A58D97413EA98F5DEB08BF8BAC7A6E641A';$mh='7DF61D340A119B1340C995EE21F239BEE0A584D5478F94FB9B5FD75FE763622D'
foreach($v in @('C:\Users\vika\Documents',$r,$o,$p,$z,$m)){if((Get-Item -LiteralPath $v).Attributes -band [IO.FileAttributes]::ReparsePoint){throw 'Reparse'}}
if((Get-FileHash $z).Hash -ne $zh -or (Get-FileHash $m).Hash -ne $mh){throw 'Retained package mismatch'}
$a=@(Get-ChildItem -LiteralPath $p -Recurse -Force);if(@($a|Where-Object {$_.Attributes -band [IO.FileAttributes]::ReparsePoint}).Count){throw 'Reparse child'}
$f=@($a|Where-Object {-not $_.PSIsContainer});$x=@{}
foreach($line in Get-Content -LiteralPath $m){if($line -notmatch '^([A-F0-9]{64})  ([A-Za-z0-9_.-]+)$' -or $Matches[2] -in @('.','..') -or $x.ContainsKey($Matches[2])){throw 'Invalid manifest'};$x.Add($Matches[2],$Matches[1])}
if($f.Count -ne $x.Count){throw 'File inventory mismatch'}
foreach($v in $f){$n=$v.FullName.Substring($p.Length+1);if(-not $x.ContainsKey($n) -or (Get-FileHash -LiteralPath $v.FullName).Hash -ne $x[$n]){throw 'Unpacked mismatch'}}
if(@(Get-CimInstance Win32_Process|Where-Object {$_.CommandLine -and $_.CommandLine.IndexOf($r,[StringComparison]::OrdinalIgnoreCase) -ge 0}).Count){throw 'Active build'}
Remove-Item -LiteralPath $p -Recurse -Force
if((Test-Path $p) -or (Get-FileHash $z).Hash -ne $zh -or (Get-FileHash $m).Hash -ne $mh){throw 'Restoration mismatch'}
'BOOTSTRAP_DUPLICATE_CLEANUP=PASS source_packages_evidence_retained=True'
(Get-CimInstance Win32_LogicalDisk -Filter "DeviceID='C:'").FreeSpace
