$ErrorActionPreference='Stop'
$ProgressPreference='SilentlyContinue'
if($env:COMPUTERNAME-cne 'DESKTOP-O1LP5DG'){throw 'Wrong builder'}
$sid=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value
if($sid-cne 'S-1-5-21-316478115-1595729549-2803163825-1001'){throw 'Wrong user'}
$d='C:\Users\vika\Documents\harness-gate-r24-1011-a1'
$i=Get-Item -LiteralPath $d -Force
if(-not $i.PSIsContainer-or($i.Attributes-band[IO.FileAttributes]::ReparsePoint)-ne 0){throw 'Directory is not plain'}
$m=Join-Path $d 'HarnessWindowsGate.manifest.json'
if((Get-FileHash -LiteralPath $m -Algorithm SHA256).Hash.ToLowerInvariant()-cne '1a10aa3cf34348386febb3b9de7fe0dda78e8a8ba7650bd8e221574b5f2e4aca'){throw 'Manifest changed'}
$doc=Get-Content -LiteralPath $m -Raw|ConvertFrom-Json
$rows=@($doc.sourceFiles)+@($doc.gateRunner,$doc.gateWorker,$doc.gateControl,$doc.gateProtocol,$doc.gateKeeper,$doc.gateFixture)
$hashes=@{}
foreach($row in $rows){$p=Join-Path $d $row.path;$item=Get-Item -LiteralPath $p -Force;if($item.PSIsContainer-or($item.Attributes-band[IO.FileAttributes]::ReparsePoint)-ne 0){throw 'Source is not plain'};$h=(Get-FileHash -LiteralPath $p -Algorithm SHA256).Hash.ToLowerInvariant();if($h-cne $row.sha256){throw 'Source changed'};$hashes[$row.path]=$h}
$hashes['HarnessWindowsGate.manifest.json']=(Get-FileHash -LiteralPath $m -Algorithm SHA256).Hash.ToLowerInvariant()
$app=Get-Item -LiteralPath 'C:\Users\vika\AppData' -Force
$result=@{ComputerName=$env:COMPUTERNAME;UserSID=$sid;RemoteFiles=$hashes;AppDataAttributes=[string]$app.Attributes;AppDataIsDirectory=[bool]$app.PSIsContainer;AppDataIsReparse=(($app.Attributes-band[IO.FileAttributes]::ReparsePoint)-ne 0);ReadOnlyQuery=$true;FixtureRerun=$false;ProductInvoked=$false;OriginalRemoteProcessTerminalProof=$false;RemoteCustodyQualified=$false}
[Console]::Out.WriteLine(($result|ConvertTo-Json -Depth 5 -Compress))
