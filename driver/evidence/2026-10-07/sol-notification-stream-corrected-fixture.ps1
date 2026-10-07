$ErrorActionPreference='Stop'
$tokens=$null;$errors=$null
$ast=[Management.Automation.Language.Parser]::ParseFile('C:\Users\vika\Documents\sol-harness-20261007a\Test-StagedInvariantSuite.ps1',[ref]$tokens,[ref]$errors)
if($errors.Count){throw 'Suite parse error'}
foreach($name in @('Get-ActivationProductStatus','Close-ActivationNotificationCapture')){
 $f=@($ast.FindAll({param($n)$n -is [Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -ceq $name},$false))
 if($f.Count -ne 1){throw 'Missing function'};Invoke-Expression $f[0].Extent.Text
}
function Get-BootId {'synthetic-builder-fixture'}
$script:ActivationNotificationHistory=@();$script:ActivationObservedPrematureReady=@();$script:ActivationHolderLive=$true;$script:ActivationCandidateGeneration=[uint32]42
$name='SolNotificationFixture-'+[guid]::NewGuid().ToString('N')
$server=[IO.Pipes.NamedPipeServerStream]::new($name,[IO.Pipes.PipeDirection]::Out,1,[IO.Pipes.PipeTransmissionMode]::Byte,[IO.Pipes.PipeOptions]::Asynchronous)
$client=[IO.Pipes.NamedPipeClientStream]::new('.',$name,[IO.Pipes.PipeDirection]::In,[IO.Pipes.PipeOptions]::Asynchronous)
$ready=[Threading.ManualResetEventSlim]::new($false);$stop=[Threading.ManualResetEventSlim]::new($false);$runspace=[PowerShell]::Create()
try{
 $null=$runspace.AddScript('param($server,$ready,$stop) $server.WaitForConnection();$w=[IO.StreamWriter]::new($server);$w.AutoFlush=$true;try{$w.WriteLine(''{"type":"status","admissionCoverage":"Pending","nativePolicyGeneration":42,"protectionActive":true}'');$ready.Wait();$w.WriteLine(''{"type":"status","admissionCoverage":"Ready","nativePolicyGeneration":42,"protectionActive":true}'');$w.WriteLine(''{"type":"status","admissionCoverage":"Pending","nativePolicyGeneration":42,"protectionActive":true}'');$stop.Wait()}finally{$w.Dispose();$server.Dispose()}').AddArgument($server).AddArgument($ready).AddArgument($stop)
 $operation=$runspace.BeginInvoke();$client.Connect(2000)
 # Fixture supplies an already connected reader to test I/O/lifetime only; it
 # does not claim or bypass production endpoint authentication.
 $script:ActivationNotificationCapture=@{Pipe=$client;Reader=[IO.StreamReader]::new($client,[Text.Encoding]::UTF8,$false,4096,$true);ReadTask=$null;Last=$null;LastQpc=$null;Sequence=0;ServerPid=0;ServerSid='SYNTHETIC'}
 $first=Get-ActivationProductStatus 'first' 2000 -FirstSnapshotOnly
 if($first.Status -ne 'OK' -or $first.Value.admissionCoverage -ne 'Pending' -or $first.RetainedStreamState -or -not $first.FirstConnectionSnapshot){throw ('Initial async status failed: '+($first|ConvertTo-Json -Compress))}
 $q=[Diagnostics.Stopwatch]::StartNew();$retained=Get-ActivationProductStatus 'no-update' 30
 if($retained.Status -ne 'INCONCLUSIVE' -or -not $retained.RetainedStreamState -or $retained.StatusReceiptQpc -ne $first.StatusReceiptQpc -or $q.Elapsed.TotalSeconds -gt 1){throw 'Retained status/deadline invalid'}
 $ready.Set();$changed=Get-ActivationProductStatus 'changed' 2000
 if($changed.Status -ne 'OK' -or $changed.StatusSequence -lt 2 -or $changed.RetainedStreamState){throw 'Status update not consumed'}
 $latest=Get-ActivationProductStatus 'pending-after-ready' 1000
 if($latest.Status -notin @('OK','INCONCLUSIVE') -or $latest.Value.admissionCoverage -ne 'Pending' -or $script:ActivationObservedPrematureReady.Count -ne 1 -or $script:ActivationNotificationHistory.Count -ne 3){throw 'Ready observation was erased by subsequent Pending'}
 $stop.Set();$lost=Get-ActivationProductStatus 'disconnected' 2000
 if($lost.Status -ne 'INCONCLUSIVE' -or $null -ne $script:ActivationNotificationCapture){throw 'Disconnected stream reused status or leaked capture'}
 $null=$runspace.EndInvoke($operation);if($runspace.HadErrors){throw ($runspace.Streams.Error|Out-String)}
 Write-Output 'NotificationStreamFixture=PASS;AsyncRead,BoundedIdle,ReceiptRetention,StatusChange,PrematureReadyLatchedDespitePending,DisconnectInvalidation,CheckedClose'
}finally{$ready.Set();$stop.Set();Close-ActivationNotificationCapture;$client.Dispose();$server.Dispose();$runspace.Dispose();$ready.Dispose();$stop.Dispose()}
