<# Actual WPF notification -> justification -> authenticated exact-version save.
   Run only on the recorded disposable debuggee. Session is recorded, not inferred. #>
param([switch] $Verifier,[switch] $PipeOnly)
$ErrorActionPreference='Stop'
$OutputEncoding=[Console]::OutputEncoding=[Text.UTF8Encoding]::new($false)
. (Join-Path $PSScriptRoot 'StagedTestAgent.ps1')
Add-Type -Path (Join-Path $PSScriptRoot 'StagedIdentityProbe.cs')
Add-Type -Path (Join-Path $PSScriptRoot 'StagedApprovalPipeProbe.cs')
Add-Type -AssemblyName UIAutomationClient,UIAutomationTypes
$installed='C:\Windows\System32\drivers\SafeUpload.sys'
$expected='ADA9D05AB6AECDD2B6C521B0CE529FC06C732154ACB3EE85439FBDC8AA80DFCE'
$backup='C:\Users\vika\Documents\SafeUpload-original-before-approval.sys'
$id=[guid]::NewGuid().ToString('N')
$target='C:\SafeUpload\Escopo Monitorado\approval-'+$id+'.txt'
$policy='C:\ProgramData\SafeUpload\policy.json'
$journal='C:\ProgramData\SafeUpload\staging-journal'
$agent=$null; $app=$null; $file=$null; $observer=$null; $notifications=$null
$loaded=$false; $replaced=$false; $verified=$false; $policyBytes=$null; $cleanup=@(); $approved=$false

function Wait-Transfer([string] $phase,[string] $differentId='') {
    $watch=[Diagnostics.Stopwatch]::StartNew()
    while($watch.ElapsedMilliseconds -lt 20000){
        $line=$notifications.Next(500)
        if($null -eq $line){continue}
        $message=$line | ConvertFrom-Json
        if($message.type -eq 'transfer' -and $message.fileName -eq [IO.Path]::GetFileName($target)){
            Write-Output "Notification=$line" | Out-Host
            if($message.phase -eq $phase -and $message.transferId -ne $differentId){return $message}
        }
    }
    throw "Missing $phase notification."
}
function Wait-Control($root,[string] $automationId) {
    $condition=[Windows.Automation.PropertyCondition]::new(
        [Windows.Automation.AutomationElement]::AutomationIdProperty,$automationId)
    for($attempt=0;$attempt -lt 80;$attempt++){
        $control=$root.FindFirst([Windows.Automation.TreeScope]::Descendants,$condition)
        if($null -ne $control){return $control}
        Start-Sleep -Milliseconds 250
    }
    throw "Missing WPF control: $automationId"
}
function Check-PhysicalOriginal {
    $observer.Position=0
    $bytes=New-Object byte[] 100; $count=$observer.Read($bytes,0,$bytes.Length)
    if([Text.Encoding]::UTF8.GetString($bytes,0,$count) -ne 'PUBLIC ORIGINAL'){throw 'Unapproved bytes changed held physical destination.'}
}

if($env:COMPUTERNAME -ne 'WIN10-DEBUGGED' -or
    (Get-CimInstance Win32_ComputerSystemProduct).UUID -ne '9D44EEE8-81CF-4CC1-9FBA-7670F11DEF4D'){throw 'Wrong debuggee.'}
if((Get-FileHash $installed).Hash -ne $expected){throw 'Original hash mismatch.'}
if((& fltmc.exe filters) -match '^SafeUpload\s'){throw 'Expected unloaded baseline.'}
if(@(Get-Process SafeUpload.Agent.App -ErrorAction SilentlyContinue).Count){throw 'Existing app must not be disturbed.'}
try {
    $appZip='C:\Users\vika\Documents\staged-ui-app.zip'
    if((Get-FileHash $appZip).Hash -ne '7C5A73EBFEB122BE48671A6E27F007E4CD92F7E2CB474F5B4CB789922CAF2E50'){throw 'App package mismatch.'}
    Expand-Archive -LiteralPath $appZip -DestinationPath 'C:\Users\vika\Documents\staged-ui-app' -Force
    $policyBytes=[IO.File]::ReadAllBytes($policy)
    $testPolicy=[Text.Encoding]::UTF8.GetString($policyBytes) | ConvertFrom-Json
    $testPolicy.overrideAllowed=$true
    [IO.File]::WriteAllText($policy,($testPolicy | ConvertTo-Json -Depth 10),[Text.UTF8Encoding]::new($false))
    [IO.File]::WriteAllText($target,'PUBLIC ORIGINAL')
    $observer=[IO.FileStream]::new($target,[IO.FileMode]::Open,[IO.FileAccess]::Read,
        [IO.FileShare]::ReadWrite -bor [IO.FileShare]::Delete)
    Backup-StagedTestDriver $backup
    Copy-Item 'C:\Users\vika\Documents\SafeUpload-stage-prototype.sys' $installed -Force; $replaced=$true
    if($Verifier){
        & verifier.exe /volatile /flags 0x13B /adddriver SafeUpload.sys | Out-Host
        if($LASTEXITCODE -ne 0){throw 'Verifier setup failed.'}; $verified=$true
    }
    & fltmc.exe load SafeUpload | Out-Host
    if($LASTEXITCODE -ne 0){throw 'Load failed.'}; $loaded=$true
    $agent=Start-StagedTestAgent 'C:\Users\vika\Documents\stage-service-publish' 'C:\Users\vika\Documents\stage-approval-service'
    $notifications=[StagedApprovalPipeProbe]::new()
    $app=Start-Process 'C:\Users\vika\Documents\staged-ui-app\SafeUpload.Agent.App.exe' -PassThru
    "ApprovalWriterSession=$([Diagnostics.Process]::GetCurrentProcess().SessionId); AppSession=$($app.SessionId)"
    for($attempt=0;$attempt -lt 40 -and $null -eq $file;$attempt++){
        Start-Sleep -Milliseconds 250
        try{$file=[StagedIdentityProbe]::Open($target,$true,$true)}catch{}
    }
    if($null -eq $file){throw 'Writer did not open.'}
    if([StagedApprovalPipeProbe]::Justify([guid]::NewGuid().ToString(),'unknown fixture') -ne 'rejected'){throw 'Unknown version accepted.'}
    [StagedIdentityProbe]::Write($file,'CPF: 529.982.247-25 old private version')
    $file.Dispose(); $file=$null
    $older=Wait-Transfer 'Blocked'
    if(-not $older.overrideAllowed){throw 'Policy did not offer exact-version justification.'}
    Check-PhysicalOriginal
    $file=[StagedIdentityProbe]::Open($target,$true,$true)
    $content='CPF: 529.982.247-25 current exact version'
    [StagedIdentityProbe]::Write($file,$content)
    $file.Dispose(); $file=$null
    $current=Wait-Transfer 'Blocked' $older.transferId
    if(-not $current.overrideAllowed){throw 'New version has no justification.'}
    $stale=[StagedApprovalPipeProbe]::Justify($older.transferId,'stale version fixture')
    if($stale -ne 'rejected'){throw "Superseded version did not return a rejection: $stale"}
    Check-PhysicalOriginal
    "UnknownAndSupersededJustificationsDenied=True; StaleReply=$stale"

    if($PipeOnly){
        & C:\Users\vika\Documents\staged-approval-client\StagedApprovalClient.exe $current.transferId 'Disposable VM exact-version approval regression' | Out-Host
        if($LASTEXITCODE -ne 0){throw 'Actual application client did not approve current version.'}
    }
    else {
    $windowCondition=[Windows.Automation.AndCondition]::new(
        [Windows.Automation.PropertyCondition]::new([Windows.Automation.AutomationElement]::ProcessIdProperty,$app.Id),
        [Windows.Automation.PropertyCondition]::new([Windows.Automation.AutomationElement]::NameProperty,'Envio bloqueado pelo SafeUpload'))
    $window=$null
    for($attempt=0;$attempt -lt 80 -and $null -eq $window;$attempt++){
        $window=[Windows.Automation.AutomationElement]::RootElement.FindFirst([Windows.Automation.TreeScope]::Children,$windowCondition)
        if($null -eq $window){Start-Sleep -Milliseconds 250}
    }
    if($null -eq $window){throw 'Actual WPF notification window not found.'}
    $targetText=Wait-Control $window 'JustificationTargetText'
    if($targetText.Current.Name -ne ('Justificar: '+[IO.Path]::GetFileName($target))){throw 'UI names the wrong destination.'}
    $input=Wait-Control $window 'JustificationInput'
    $button=Wait-Control $window 'SubmitJustificationButton'
    $status=Wait-Control $window 'JustificationStatusText'
    $reason='Disposable VM exact-version approval regression'
    ([Windows.Automation.ValuePattern]$input.GetCurrentPattern([Windows.Automation.ValuePattern]::Pattern)).SetValue($reason)
    ([Windows.Automation.InvokePattern]$button.GetCurrentPattern([Windows.Automation.InvokePattern]::Pattern)).Invoke()
    }
    $released=Wait-Transfer 'Released'
    if($released.transferId -ne $current.transferId){throw 'UI approved a different version.'}
    if(-not $PipeOnly){
        for($attempt=0;$attempt -lt 40 -and $input.Current.IsEnabled;$attempt++){Start-Sleep -Milliseconds 250}
        if($input.Current.IsEnabled -or $status.Current.Name -notlike 'Justificativa aceita.*'){throw 'UI did not acknowledge exact-version save.'}
        "ActualWpfNotificationAndJustificationAccepted=True; Transfer=$($current.transferId); Status=$($status.Current.Name)"
    }
    else {'ActualApplicationPipeIntegration=True; InteractiveWpfUiAcceptance=False'}
    if([StagedApprovalPipeProbe]::Justify($current.transferId,'replay fixture') -eq 'accepted'){throw 'Consumed justification accepted again.'}
    $entry=Get-Content (Join-Path $journal ($current.transferId.Replace('-','')+'.json')) -Raw | ConvertFrom-Json
    if($entry.State -ne 5){throw 'Approval is not durably Released.'} # TransferJournalState.Released
    $digest=[Security.Cryptography.SHA256]::Create()
    try{$expectedDigest=[BitConverter]::ToString($digest.ComputeHash([Text.Encoding]::UTF8.GetBytes($content))).Replace('-','')}
    finally{$digest.Dispose()}
    if($entry.Sha256Hex -ne $expectedDigest){throw 'Released digest differs from current version.'}
    $records=@(Get-Content 'C:\ProgramData\SafeUpload\queue.jsonl' | ForEach-Object {$_ | ConvertFrom-Json})
    $overrideIndex=-1; $approvedIndex=-1
    for($index=0;$index -lt $records.Count;$index++){
        $record=$records[$index]
        if($record.eventId -ne $current.transferId){continue}
        if($record.type -eq 'override' -and $record.justification -eq 'Disposable VM exact-version approval regression'){$overrideIndex=$index}
        if($record.verdict -eq 'Approved' -and $record.notInspectedReason -eq 'justified_version'){$approvedIndex=$index}
    }
    if($overrideIndex -lt 0 -or $approvedIndex -le $overrideIndex){throw 'Exact-version justification audit does not precede its Approved outcome.'}
    'ExactVersionOverrideAuditedBeforeApprovedOutcome=True'
    Check-PhysicalOriginal # POSIX replacement preserves the held old object.
    $approved=$true
    'ReplayDeniedAndExactDigestDurable=True'
}
finally {
    if($null -ne $file){$file.Dispose()}
    if($null -ne $app -and -not $app.HasExited){Stop-Process -Id $app.Id -Force; [void]$app.WaitForExit(5000)}
    if($null -ne $notifications){$notifications.Dispose()}
    if($null -ne $observer){$observer.Dispose()}
    Stop-StagedTestAgent $agent
    if($null -ne $policyBytes){[IO.File]::WriteAllBytes($policy,$policyBytes); 'OriginalPolicyRestored=True'}
    Save-StagedVerifierEvidence
    if($replaced){Restore-StagedTestDriver $backup $loaded $verified}
    if($approved){
        if([IO.File]::ReadAllText($target) -ne $content){throw 'Independent unfiltered destination bytes differ.'}
        'IndependentUnfilteredApprovedDestinationBytesExact=True'
    }
    foreach($path in (Get-ChildItem $journal -Filter '*.json')){
        $entry=Get-Content $path.FullName -Raw | ConvertFrom-Json
        if($entry.Transfer.DestinationPath.Contains($id)){$cleanup+=@($entry.Transfer.StagePath,$path.FullName)}
    }
    Remove-StagedTestFiles ($cleanup+@($target))
}
