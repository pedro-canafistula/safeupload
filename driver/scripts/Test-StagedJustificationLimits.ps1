<# Bound untrusted input and concurrent idle pipe requests; original restored. #>
param([switch] $ReproduceKnownGap)
$ErrorActionPreference='Stop'
. (Join-Path $PSScriptRoot 'StagedTestAgent.ps1')
Add-Type -Path (Join-Path $PSScriptRoot 'StagedApprovalPipeProbe.cs')
$installed='C:\Windows\System32\drivers\SafeUpload.sys'
$expected='ADA9D05AB6AECDD2B6C521B0CE529FC06C732154ACB3EE85439FBDC8AA80DFCE'
$backup='C:\Users\vika\Documents\SafeUpload-original-before-pipe-limits.sys'
$loaded=$false; $replaced=$false; $agent=$null; $clients=$null
if($env:COMPUTERNAME -ne 'WIN10-DEBUGGED' -or
    (Get-CimInstance Win32_ComputerSystemProduct).UUID -ne '9D44EEE8-81CF-4CC1-9FBA-7670F11DEF4D'){throw 'Wrong debuggee.'}
if((Get-FileHash $installed).Hash -ne $expected){throw 'Original hash mismatch.'}
if((& fltmc.exe filters) -match '^SafeUpload\s'){throw 'Expected unloaded baseline.'}
try {
    Copy-Item $installed $backup -Force
    Copy-Item 'C:\Users\vika\Documents\SafeUpload-stage-prototype.sys' $installed -Force; $replaced=$true
    & fltmc.exe load SafeUpload | Out-Host
    if($LASTEXITCODE -ne 0){throw 'Load failed.'}; $loaded=$true
    $agent=Start-StagedTestAgent 'C:\Users\vika\Documents\stage-service-publish' 'C:\Users\vika\Documents\stage-pipe-limits-service'
    for($attempt=0;$attempt -lt 40;$attempt++){
        Start-Sleep -Milliseconds 250
        if((Get-Content 'C:\Users\vika\Documents\stage-pipe-limits-service-out.log' -Raw) -match 'Minifiltro conectado.'){break}
    }
    $clients=[StagedApprovalPipeProbe+IdleClients]::new(16)
    if($ReproduceKnownGap){
        if(-not $agent.Process.WaitForExit(10000)){throw 'Old service did not reproduce the instance-cap failure.'}
        'SixteenIdleClientsTerminateOldService=True'
    }
    else {
        Start-Sleep -Milliseconds 500
        if($agent.Process.HasExited){throw 'Idle clients terminated the service.'}
        $watch=[Diagnostics.Stopwatch]::StartNew()
        $seventeenth=[StagedApprovalPipeProbe+IdleClients]::new(1)
        $watch.Stop(); $seventeenth.Dispose()
        if($watch.ElapsedMilliseconds -lt 3000 -or $watch.ElapsedMilliseconds -gt 8000){throw "Idle slots did not drain at the read deadline: $($watch.ElapsedMilliseconds)"}
        if($agent.Process.HasExited){throw 'Service exited while draining idle clients.'}
        "IdleSixteenClientsBoundedAndSeventeenthAdmittedAfterDeadline=True; Milliseconds=$($watch.ElapsedMilliseconds)"
        $clients.Dispose(); $clients=$null
        # No newline: reject as soon as the bounded input limit is crossed.
        if([StagedApprovalPipeProbe]::Raw(('x'*4097)) -ne 'rejected'){throw 'Oversized unterminated request not rejected.'}
        if([StagedApprovalPipeProbe]::Raw("{malformed}`n") -ne 'rejected'){throw 'Malformed JSON not rejected.'}
        if([StagedApprovalPipeProbe]::Justify([guid]::NewGuid().ToString(),'unknown fixture') -ne 'rejected'){throw 'Unknown justification accepted.'}
        if($agent.Process.HasExited){throw 'Invalid requests terminated service.'}
        'OversizedUnterminatedMalformedAndUnknownRequestsRejectedServiceAlive=True'
    }
}
finally {
    if($null -ne $clients){$clients.Dispose()}
    Stop-StagedTestAgent $agent
    if($replaced){Restore-StagedTestDriver $backup $loaded}
}
