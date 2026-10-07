$ErrorActionPreference='Stop'
$tokens=$null;$errors=$null
$ast=[Management.Automation.Language.Parser]::ParseFile('C:\Users\vika\Documents\sol-harness-20261007a\Test-StagedInvariantSuite.ps1',[ref]$tokens,[ref]$errors)
if($errors.Count){throw 'Suite parse error'}
foreach($name in @('Receive-ActivationStatusFrame','Get-ActivationProductStatus','Close-ActivationNotificationCapture')){
 $f=@($ast.FindAll({param($n)$n -is [Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -ceq $name},$false))
 if($f.Count -ne 1){throw 'Missing function'};Invoke-Expression $f[0].Extent.Text
}
function Get-BootId {'synthetic-builder-fixture'}
foreach($mode in @('normal','completed-unread-close')){
 $script:ActivationNotificationHistory=@();$script:ActivationObservedPrematureReady=@();$script:ActivationHolderLive=$true;$script:ActivationCandidateGeneration=[uint32]42
 $name='SolNotificationFixture-'+[guid]::NewGuid().ToString('N')
 $server=[IO.Pipes.NamedPipeServerStream]::new($name,[IO.Pipes.PipeDirection]::Out,1,[IO.Pipes.PipeTransmissionMode]::Byte,[IO.Pipes.PipeOptions]::Asynchronous)
 $client=[IO.Pipes.NamedPipeClientStream]::new('.',$name,[IO.Pipes.PipeDirection]::In,[IO.Pipes.PipeOptions]::Asynchronous)
 $ready=[Threading.ManualResetEventSlim]::new($false);$stop=[Threading.ManualResetEventSlim]::new($false);$runspace=[PowerShell]::Create()
 try{
  $null=$runspace.AddScript('param($server,$ready,$stop) $server.WaitForConnection();$w=[IO.StreamWriter]::new($server);$w.AutoFlush=$true;try{$w.WriteLine(''{"type":"status","admissionCoverage":"Pending","nativePolicyGeneration":42,"protectionActive":true}'');$ready.Wait();$w.WriteLine(''{"type":"status","admissionCoverage":"Ready","nativePolicyGeneration":42,"protectionActive":true}'');$w.WriteLine(''{"type":"status","admissionCoverage":"Ready","nativePolicyGeneration":43,"protectionActive":true}'');$w.WriteLine(''{"type":"status","admissionCoverage":"Ready","nativePolicyGeneration":42,"protectionActive":false}'');$w.WriteLine(''{"type":"status","admissionCoverage":"Pending","nativePolicyGeneration":42,"protectionActive":true}'');$stop.Wait()}finally{$w.Dispose();$server.Dispose()}').AddArgument($server).AddArgument($ready).AddArgument($stop)
  $operation=$runspace.BeginInvoke();$client.Connect(2000)
  # Seeded SYNTHETIC connection tests I/O/lifetime, not production authentication.
  $script:ActivationNotificationCapture=@{Pipe=$client;Reader=[IO.StreamReader]::new($client,[Text.Encoding]::UTF8,$false,4096,$true);ReadTask=$null;Last=$null;LastQpc=$null;Sequence=0;ConnectionId=$name;ServerPid=0;ServerSid='SYNTHETIC'}
  $first=Get-ActivationProductStatus 'first' 2000 -FirstSnapshotOnly
  if($first.Status -ne 'OK' -or $first.Value.admissionCoverage -ne 'Pending' -or -not $first.FirstConnectionSnapshot){throw 'Initial snapshot failed'}
  $q=[Diagnostics.Stopwatch]::StartNew();$retained=Get-ActivationProductStatus 'no-update' 30
  if($retained.Status -ne 'INCONCLUSIVE' -or -not $retained.RetainedStreamState -or $retained.StatusReceiptQpc -ne $first.StatusReceiptQpc -or $q.Elapsed.TotalSeconds -gt 1){throw 'Retained state/deadline invalid'}
  $ready.Set()
  if($mode -eq 'completed-unread-close'){
   if(-not $script:ActivationNotificationCapture.ReadTask.Wait(2000)){throw 'Fixture Ready read did not complete'}
   # Leave its result unread. Replacement must consume it through the same latch.
   Close-ActivationNotificationCapture
   if($null -ne $script:ActivationNotificationCapture){throw 'Capture leaked after close'}
  }else{
   for($n=0;$n -lt 6 -and $script:ActivationNotificationHistory.Count -lt 5;$n++){$null=Get-ActivationProductStatus 'update' 1000}
   if($script:ActivationNotificationCapture.Last.admissionCoverage -ne 'Pending'){throw 'Final Pending not consumed'}
   $stop.Set();$lost=Get-ActivationProductStatus 'disconnected' 2000
   if($lost.Status -ne 'INCONCLUSIVE' -or -not $lost.TransportInvalidated -or $null -ne $script:ActivationNotificationCapture){throw 'Disconnect reused status or leaked capture'}
  }
  if($script:ActivationObservedPrematureReady.Count -ne 1 -or $script:ActivationNotificationHistory.Count -ne 5){throw ('Read history/latch wrong: '+$script:ActivationObservedPrematureReady.Count+'/'+$script:ActivationNotificationHistory.Count)}
  $stop.Set();$null=$runspace.EndInvoke($operation);if($runspace.HadErrors){throw ($runspace.Streams.Error|Out-String)}
  Write-Output ('NotificationCloseFixture=PASS;Mode='+$mode+';History=5;PrematureReady=1;WrongGenerationAndInactiveReadyIgnored')
 }finally{$ready.Set();$stop.Set();Close-ActivationNotificationCapture;$client.Dispose();$server.Dispose();$runspace.Dispose();$ready.Dispose();$stop.Dispose()}
}
Write-Output 'NotificationCloseFixtureGate=PASS'
