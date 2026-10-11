#requires -Version 5.1
# Run the actual T4 actor on unprotected NTFS with a held exclusive handle.
# Exercise the real failure guard/export helpers; never qualify product code.
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 't4\failure-evidence.ps1')
$tokens = $null; $errors = $null
$ast = [Management.Automation.Language.Parser]::ParseFile((Join-Path $PSScriptRoot 't4\cycles-coordinator.ps1'), [ref]$tokens, [ref]$errors)
if ($errors.Count) { throw 'Coordinator does not parse.' }
foreach ($name in 'Read-T4ControlText', 'Write-T4ResultLine') {
    $functions = @($ast.FindAll({ param($node) $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -ceq $name }, $false))
    if ($functions.Count -ne 1) { throw ('Actual coordinator helper unavailable: ' + $name) }
    Invoke-Expression $functions[0].Extent.Text
}
$count = 0
function Assert-Control([bool]$Good, [string]$Label) {
    if (-not $Good) { throw ('T4 failure control failed: ' + $Label) }
    $script:count++
}
function Outcome([int]$Cycle, [string]$Pattern, [string]$Why, [string]$Target = 'C:\fixture\same.txt') {
    [pscustomobject]@{ I = $Cycle; Pattern = $Pattern; Target = $Target; Ok = [string]::IsNullOrEmpty($Why); Why = $Why }
}
$counts = @{}
Assert-Control ($null -eq (Get-T4FailureDecision $counts (Outcome 1 'new' $null))) 'success never enters the failure counts'
Assert-Control ($counts.Count -eq 0) 'success does not invent a failure key'
Assert-Control ($null -eq (Get-T4FailureDecision $counts (Outcome 2 'resave' 'native Win32=5'))) 'first ordinary failure alone does not stop'
Assert-Control ($null -eq (Get-T4FailureDecision $counts (Outcome 3 'resave' $null))) 'intervening success remains successful'
$decision = Get-T4FailureDecision $counts (Outcome 4 'resave' 'native Win32=5')
Assert-Control ($decision.Reason -ceq 'repeated-identical-failure' -and $decision.FirstCycle -eq 2 -and $decision.Count -eq 2) 'second occurrence stops even with successful cycles between'
Assert-Control ($null -eq (Get-T4FailureDecision $counts (Outcome 5 'resave' 'native Win32=32'))) 'distinct native error is not the same failure'
Assert-Control ($null -eq (Get-T4FailureDecision $counts (Outcome 6 'replace' 'native Win32=5'))) 'distinct operation is not the same failure'
$counts = @{}
$null = Get-T4FailureDecision $counts (Outcome 1 'new' 'denied C:\fixture\new-1.txt' 'C:\fixture\new-1.txt')
$decision = Get-T4FailureDecision $counts (Outcome 2 'new' 'denied C:\fixture\new-2.txt' 'C:\fixture\new-2.txt')
Assert-Control ($decision.Reason -ceq 'repeated-identical-failure') 'only the exact cycle-specific destination is normalized'
Assert-Control ((Get-T4FailureDecision @{} (Outcome 1 'new' 'BLOCKED BYTES PUBLISHED')).Reason -ceq 'blocked-bytes-published') 'byte exposure stops at its first occurrence'
Assert-Control ((Get-T4FailureDecision @{} (Outcome 1 'new' 'actor: timeout')).Reason -ceq 'actor-command-timeout') 'actor timeout stops before another command'

$scratch = Join-Path ([IO.Path]::GetTempPath()) ('safeupload-t4-failure-' + [guid]::NewGuid().ToString('N'))
$control = Join-Path $scratch 'control'; $public = Join-Path $scratch 'public'
$journal = Join-Path $scratch 'journal'; $stage = Join-Path $scratch 'stage'
$process = $null; $held = $null
foreach ($path in $scratch, $control, $public, $journal, $stage) { [void][IO.Directory]::CreateDirectory($path) }
try {
    $target = Join-Path $public 'held.txt'
    [IO.File]::WriteAllText($target, 'original control bytes')
    $held = [IO.FileStream]::new($target, [IO.FileMode]::Open, [IO.FileAccess]::ReadWrite, [IO.FileShare]::None)
    $actor = Join-Path $PSScriptRoot 't4\cycles-actor.ps1'
    $arguments = '-NoProfile -NonInteractive -ExecutionPolicy Bypass -File "' + $actor + '" -Control "' + $control + '" -Root "' + $public + '"'
    $process = Start-Process powershell.exe -ArgumentList $arguments -PassThru -WindowStyle Hidden
    $deadline = [Diagnostics.Stopwatch]::GetTimestamp() + 30 * [Diagnostics.Stopwatch]::Frequency
    while (-not (Test-Path -LiteralPath (Join-Path $control 'actor-started.txt'))) {
        if ($process.HasExited -or [Diagnostics.Stopwatch]::GetTimestamp() -ge $deadline) { throw 'Native control actor did not start.' }
        Start-Sleep -Milliseconds 20
    }
    Assert-Control $true 'actual actor starts against the unprotected control directory'
    $counts = @{}; $attempts = 0; $stopped = $false
    for ($i = 1; $i -le 3; $i++) {
        $payload = Join-Path $control ('payload-' + $i + '.bin')
        [IO.File]::WriteAllText($payload, 'clean control bytes ' + $i)
        $part = Join-Path $control ('next-' + $i + '.part')
        [IO.File]::WriteAllText($part, "$i resave held.txt $payload")
        [IO.File]::Move($part, (Join-Path $control ('cmd-' + $i + '.txt')))
        $ack = Join-Path $control ('ack-' + $i + '.txt')
        $deadline = [Diagnostics.Stopwatch]::GetTimestamp() + 30 * [Diagnostics.Stopwatch]::Frequency
        while (-not (Test-Path -LiteralPath $ack)) {
            if ($process.HasExited -or [Diagnostics.Stopwatch]::GetTimestamp() -ge $deadline) { throw 'Native control actor did not acknowledge.' }
            Start-Sleep -Milliseconds 20
        }
        $ackText = (Read-T4ControlText $ack).Trim()
        Assert-Control ($ackText.StartsWith('error ') -and $ackText -match '(another process|being used)') 'real Windows exclusive handle produces the actor failure'
        $row = Outcome $i 'resave' ('actor: ' + $ackText) $target
        Write-T4ResultLine (Join-Path $scratch 'cycles.jsonl') ($row | ConvertTo-Json -Compress)
        $attempts++
        $decision = Get-T4FailureDecision $counts $row
        if ($decision) {
            $stopped = Stop-T4Actor $control
            break
        }
    }
    Assert-Control ($attempts -eq 2 -and $decision.Reason -ceq 'repeated-identical-failure') 'two real native failures end the command stream'
    Assert-Control ($stopped -and (Test-Path -LiteralPath (Join-Path $control 'actor-stopped.txt'))) 'actual actor acknowledges orderly stop'
    Assert-Control (-not (Test-Path -LiteralPath (Join-Path $control 'payload-3.bin'))) 'no third command or payload is queued'
    Assert-Control ($process.WaitForExit(10000) -and $process.ExitCode -eq 0) 'actual actor exits successfully after stop'
    $held.Dispose(); $held = $null
    Assert-Control ([IO.File]::ReadAllText($target) -ceq 'original control bytes') 'failed native writes preserve the original bytes'
    $raw = '{"State":5,"Transfer":{"DestinationPath":"control-only"}}'
    [IO.File]::WriteAllText((Join-Path $journal 'fixture.json'), $raw, [Text.UTF8Encoding]::new($false))
    [IO.File]::WriteAllText((Join-Path $stage 'fixture.stage'), 'private control fixture: never copied')
    $saved = Save-T4FailureEvidence (Join-Path $scratch 'failure-evidence') $journal $stage 2 $target
    $receipt = Get-Content -LiteralPath (Join-Path $saved 'receipt.json') -Raw | ConvertFrom-Json
    $inventory = @(Get-Content -LiteralPath (Join-Path $saved 'inventory.jsonl') | ForEach-Object { $_ | ConvertFrom-Json })
    Assert-Control ($receipt.JournalCopied -eq 1 -and $receipt.StageObserved -eq 1 -and $receipt.Errors.Count -eq 0) 'real NTFS journal copy and stage metadata capture complete'
    Assert-Control ($receipt.PointInTimeOnly -and -not $receipt.AtomicSnapshot -and -not $receipt.ProductAuthority) 'receipt cannot become product approval or cleanup evidence'
    Assert-Control ([IO.File]::ReadAllText((Join-Path $saved 'journal\fixture.json')) -ceq $raw) 'journal bytes are copied exactly'
    Assert-Control (@(Get-ChildItem -LiteralPath $saved -Recurse -File | Where-Object { $_.Name -eq 'fixture.stage' }).Count -eq 0) 'private stage bytes are never exported'
    foreach ($row in $inventory) {
        Assert-Control ($row.Before.VolumeSerial.Length -eq 16 -and $row.Before.FileId128.Length -eq 32 -and $row.UnchangedDuringRead) 'same open handle supplies full volume/file identity and stable metadata'
    }
    $acl = (Get-Item -LiteralPath $saved).GetAccessControl()
    $identities = @($acl.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier]) | ForEach-Object { $_.IdentityReference.Value })
    Assert-Control ($acl.AreAccessRulesProtected -and -not @($identities | Where-Object { $_ -in 'S-1-1-0', 'S-1-5-11', 'S-1-5-32-545' }).Count) 'diagnostic journal copies have no standard-user read grant'
    $refused = $false
    try { $null = Save-T4FailureEvidence (Join-Path $scratch 'failure-evidence') $journal $stage 2 $target } catch { $refused = $true }
    Assert-Control $refused 'existing evidence is never overwritten'
    $locked = [IO.FileStream]::new((Join-Path $journal 'fixture.json'), [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::None)
    try { $savedError = Save-T4FailureEvidence (Join-Path $scratch 'failure-evidence') $journal $stage 3 $target }
    finally { $locked.Dispose() }
    $errorReceipt = Get-Content -LiteralPath (Join-Path $savedError 'receipt.json') -Raw | ConvertFrom-Json
    Assert-Control ($errorReceipt.JournalCopied -eq 0 -and $errorReceipt.Errors.Count -eq 1) 'real sharing refusal is retained as a capture error'
    'T4FailureControlStopReason=' + $decision.Reason + ';Attempts=' + $attempts + ';ActorStopped=' + $stopped
    'T4FailureControlReceipt=' + ($receipt | ConvertTo-Json -Depth 5 -Compress)
    foreach ($row in $inventory) { 'T4FailureControlInventory=' + ($row | ConvertTo-Json -Depth 5 -Compress) }
    'T4FailureControlErrorReceipt=' + ($errorReceipt | ConvertTo-Json -Depth 5 -Compress)
    'T4FailureSelfCheck=PASS;Controls=' + $count + ';NativeActor=True;ProductQualified=False'
} finally {
    if ($held) { $held.Dispose() }
    if ($process) {
        if (-not $process.HasExited) { $process.Kill(); [void]$process.WaitForExit(10000) }
        $process.Dispose()
    }
    Remove-Item -LiteralPath $scratch -Recurse -Force
}
