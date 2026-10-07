$ErrorActionPreference='Stop'
$p='C:\Users\vika\Documents\sol-harness-20261007a\StagedInvariantLatency.SelfCheck.ps1'
$tokens=$null;$errors=$null;$null=[Management.Automation.Language.Parser]::ParseFile($p,[ref]$tokens,[ref]$errors)
Write-Output ('LatencyControlParseErrors='+$errors.Count)
if($errors.Count){throw ($errors|Out-String)}
& $p
if(-not $?){throw 'Native latency control failed'}
