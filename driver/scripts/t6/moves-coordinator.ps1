<#
T6 move coordinator (SYSTEM). Drives moves-actor.ps1 (a standard user) through moves from an ordinary folder (C:\T6src) into the
protected folder (C:\Protected\t6) and checks every outcome from outside the actor's private namespace:
  copy-fallback patterns (movefileex, moveitem, cmdmove, shell), clean content -> the caller succeeds, the public file holds exactly
      the moved bytes (inspected, approved, published) and the source is gone;
  the same with CPF content -> the caller succeeds, a hand-back with exactly those bytes appears in the actor's profile, the public
      name never holds them (it stays absent) and the source is gone;
  rawrename / hardlink -> Win32 17 (ERROR_NOT_SAME_DEVICE), the source keeps its bytes, the target stays absent.
A directory moved with the Explorer copy engine is recorded for information only (staging does not create directories inside a
protected folder). Results: C:\T6\moves.jsonl (one line per move), C:\T6\result.json.
#>
param(
    [int]$Rounds = 3,
    [string]$ActorUser = 't6actor',
    [string]$ActorTask = 't6-actor',
    [string]$Diagnostics = 'C:\Users\vika\Documents\Get-SafeUploadDiagnostics.ps1'
)
$ErrorActionPreference = 'Stop'
function Write-T6ResultLine([string]$Path, [string]$Line) {
    $bytes = [Text.UTF8Encoding]::new($false).GetBytes($Line + "`r`n")
    $stream = [IO.FileStream]::new($Path, [IO.FileMode]::Append, [IO.FileAccess]::Write, [IO.FileShare]'ReadWrite, Delete')
    try { $stream.Write($bytes, 0, $bytes.Length); $stream.Flush() } finally { $stream.Dispose() }
}
function Read-ControlText([string]$Path) {
    # The actor publishes an ack by rename; for a moment its handle can still deny sharing. Retry only sharing violations.
    $deadline = [Diagnostics.Stopwatch]::GetTimestamp() + 5 * [Diagnostics.Stopwatch]::Frequency
    for (;;) {
        try {
            $stream = [IO.FileStream]::new($Path, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]'ReadWrite, Delete')
            try { $reader = [IO.StreamReader]::new($stream); try { return $reader.ReadToEnd() } finally { $reader.Dispose() } }
            finally { $stream.Dispose() }
        } catch [IO.IOException] {
            $ioFailure = $_.Exception
            while ($ioFailure.InnerException) { $ioFailure = $ioFailure.InnerException }
            if (($ioFailure.HResult -band 0xffff) -notin @(32,33) -or [Diagnostics.Stopwatch]::GetTimestamp() -ge $deadline) { throw }
            Start-Sleep -Milliseconds 2
        }
    }
}
function Read-Public([string]$Path) {
    try {
        $stream = New-Object IO.FileStream($Path, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]'ReadWrite, Delete')
        try { $buffer = New-Object byte[] $stream.Length; $read = 0; while ($read -lt $buffer.Length) { $n = $stream.Read($buffer, $read, $buffer.Length - $read); if ($n -le 0) { break }; $read += $n }; , $buffer } finally { $stream.Dispose() }
    } catch [IO.FileNotFoundException] { $null } catch [IO.DirectoryNotFoundException] { $null } catch [IO.IOException] { , @() }
}
function Same([byte[]]$A, [byte[]]$B) { if ($null -eq $A -or $null -eq $B -or $A.Length -ne $B.Length) { return $false }; for ($i = 0; $i -lt $A.Length; ++$i) { if ($A[$i] -ne $B[$i]) { return $false } }; $true }
function New-Payload([int]$N, [bool]$Sensitive) {
    # Hex digits of a GUID can form a valid CPF: encode them as letters so a clean fixture never matches the detector.
    $nonce = [guid]::NewGuid().ToString('N')
    for ($digit = 0; $digit -lt 10; ++$digit) { $nonce = $nonce.Replace([string]$digit, [string][char](103 + $digit)) }
    $text = if ($Sensitive) { "T6 move $N CPF: 529.982.247-25`r`n" } else { "T6 move $N clean " + $nonce + "`r`n" }
    , [Text.Encoding]::ASCII.GetBytes($text)
}
$out = 'C:\T6'; $control = Join-Path $out 'control'; $root = 'C:\Protected\t6'; $sourceRoot = 'C:\T6src'
$frequency = [Diagnostics.Stopwatch]::Frequency
$script:n = 0
function Invoke-ActorCommand([string]$Pattern, [string]$Source, [string]$Target, [byte[]]$Bytes) {
    $script:n++
    $payload = Join-Path $control ('payload-' + $script:n + '.bin'); [IO.File]::WriteAllBytes($payload, $Bytes)
    $command = Join-Path $control ('cmd-' + $script:n + '.txt'); $staging = Join-Path $control ('next-' + $script:n + '.part')
    Set-Content -LiteralPath $staging -Value ("$($script:n) $Pattern $Source $Target $payload"); [IO.File]::Move($staging, $command)
    $ack = Join-Path $control ('ack-' + $script:n + '.txt')
    $started = [Diagnostics.Stopwatch]::GetTimestamp(); $deadline = $started + 120 * $frequency
    while (-not (Test-Path $ack)) { if ([Diagnostics.Stopwatch]::GetTimestamp() -gt $deadline) { break }; Start-Sleep -Milliseconds 5 }
    $text = if (Test-Path $ack) { (Read-ControlText $ack).Trim() } else { 'timeout' }
    Remove-Item -LiteralPath $payload, $ack -Force -ErrorAction SilentlyContinue
    if ($text -eq 'timeout') { throw ('actor command ' + $script:n + ' (' + $Pattern + ') timed out; task state ' + (Get-ScheduledTask -TaskName $ActorTask).State) }
    [pscustomobject]@{ N = $script:n; Ack = $text; AckMs = [math]::Round(([Diagnostics.Stopwatch]::GetTimestamp() - $started) * 1000.0 / $frequency, 1) }
}

New-Item -ItemType Directory -Force -Path $out, $control | Out-Null
Remove-Item -LiteralPath (Join-Path $out 'moves.jsonl'), (Join-Path $out 'result.json') -ErrorAction SilentlyContinue
$result = [ordered]@{ Rounds = $Rounds; Started = [DateTime]::UtcNow.ToString('o'); Expected = 0; Completed = 0; Failures = @(); Outcomes = [ordered]@{} }
function Add-Outcome([string]$Key, [bool]$Ok, [string]$Why, $Ack, [hashtable]$Extra) {
    $result.Expected++
    if (-not $result.Outcomes.Contains($Key)) { $result.Outcomes[$Key] = [ordered]@{ Ok = 0; Failed = 0 } }
    if ($Ok) { $result.Completed++; $result.Outcomes[$Key].Ok++ } else { $result.Outcomes[$Key].Failed++; if ($result.Failures.Count -lt 50) { $result.Failures += ("$($Ack.N) $Key $Why") } }
    $line = [ordered]@{ N = $Ack.N; Key = $Key; Ok = $Ok; Why = $Why; Ack = $Ack.Ack; AckMs = $Ack.AckMs }
    if ($Extra) { foreach ($k in $Extra.Keys) { $line[$k] = $Extra[$k] } }
    Write-T6ResultLine (Join-Path $out 'moves.jsonl') ($line | ConvertTo-Json -Compress)
}
try {
    Start-ScheduledTask -TaskName $ActorTask
    $deadline = [Diagnostics.Stopwatch]::GetTimestamp() + 120 * $frequency
    while (-not (Test-Path (Join-Path $control 'actor-started.txt'))) {
        if ([Diagnostics.Stopwatch]::GetTimestamp() -gt $deadline) {
            $info = Get-ScheduledTaskInfo -TaskName $ActorTask -ErrorAction SilentlyContinue
            throw ('the actor did not start: task result 0x' + ([uint32]$info.LastTaskResult).ToString('X8') + ', last run ' + $info.LastRunTime)
        }
        Start-Sleep -Milliseconds 200
    }
    $result.Actor = (Read-ControlText (Join-Path $control 'actor-started.txt')).Trim()
    $sid = (New-Object Security.Principal.NTAccount($env:COMPUTERNAME, $ActorUser)).Translate([Security.Principal.SecurityIdentifier]).Value
    $profile = (Get-CimInstance Win32_UserProfile | Where-Object { $_.SID -eq $sid }).LocalPath
    if (-not $profile) { throw "no profile for $ActorUser ($sid)" }
    $handback = Join-Path $profile 'SafeUpload\_bloqueados'
    $result.Handback = $handback

    for ($round = 1; $round -le $Rounds; ++$round) {
        foreach ($pattern in 'movefileex', 'moveitem', 'cmdmove', 'shell') {
            foreach ($sensitive in $false, $true) {
                $leaf = 'mv-' + ($script:n + 1) + '-' + $pattern + '.txt'
                $source = Join-Path (Join-Path $sourceRoot ([string]($script:n + 1))) $leaf
                $target = Join-Path $root $leaf
                $bytes = New-Payload ($script:n + 1) $sensitive
                $before = @(Get-ChildItem -LiteralPath $handback -Filter '*.txt' -File -Force -ErrorAction SilentlyContinue).Count
                $ack = Invoke-ActorCommand $pattern $source $target $bytes
                $acked = [Diagnostics.Stopwatch]::GetTimestamp()
                $ok = $false; $why = $null; $published = $false
                if ($ack.Ack -ne 'ok') { $why = 'caller: ' + $ack.Ack }
                else {
                    $deadline = $acked + 120 * $frequency
                    do {
                        $public = Read-Public $target
                        if ($sensitive) {
                            if (Same $public $bytes) { $published = $true; break }
                            $files = @(Get-ChildItem -LiteralPath $handback -Filter '*.txt' -File -Force -ErrorAction SilentlyContinue | Sort-Object LastWriteTimeUtc)
                            if ($files.Count -gt $before -and (Same (Read-Public $files[-1].FullName) $bytes)) { $ok = $true }
                        } elseif (Same $public $bytes) { $ok = $true }
                        if (-not $ok) { Start-Sleep -Milliseconds 20 }
                    } while (-not $ok -and [Diagnostics.Stopwatch]::GetTimestamp() -lt $deadline)
                    if ($published) { $ok = $false; $why = 'BLOCKED BYTES PUBLISHED' }
                    elseif (-not $ok) { $why = if ($sensitive) { 'no hand-back of the blocked bytes' } else { 'the public file never held the moved bytes' } }
                    elseif (Test-Path -LiteralPath $source) { $ok = $false; $why = 'the source was not removed' }
                    elseif ($sensitive -and $null -ne (Read-Public $target)) { $ok = $false; $why = 'the blocked move left a public file' }
                }
                $outcomeMs = [math]::Round(([Diagnostics.Stopwatch]::GetTimestamp() - $acked) * 1000.0 / $frequency, 1)
                Add-Outcome ($pattern + '-' + $(if ($sensitive) { 'block' } else { 'approve' })) $ok $why $ack @{ Round = $round; OutcomeMs = $outcomeMs }
                if ($why -eq 'BLOCKED BYTES PUBLISHED') { throw 'BLOCKED BYTES PUBLISHED' }
            }
        }
    }
    foreach ($pattern in 'rawrename', 'hardlink') {
        foreach ($sensitive in $false, $true) {
            $leaf = 'mv-' + ($script:n + 1) + '-' + $pattern + '.txt'
            $source = Join-Path (Join-Path $sourceRoot ([string]($script:n + 1))) $leaf
            $target = Join-Path $root $leaf
            $bytes = New-Payload ($script:n + 1) $sensitive
            $ack = Invoke-ActorCommand $pattern $source $target $bytes
            Start-Sleep -Seconds 2
            $ok = $ack.Ack -eq 'win32 17'; $why = $null
            if (-not $ok) { $why = 'expected win32 17 (ERROR_NOT_SAME_DEVICE), caller saw ' + $ack.Ack }
            elseif (-not (Same (Read-Public $source) $bytes)) { $ok = $false; $why = 'the source lost its bytes' }
            elseif ($null -ne (Read-Public $target)) { $ok = $false; $why = 'the refused move left a public file' }
            Add-Outcome ($pattern + '-' + $(if ($sensitive) { 'block' } else { 'approve' })) $ok $why $ack $null
        }
    }
    # Information only: a whole folder moved by the Explorer copy engine.
    try {
        $dirLeaf = 'dir-' + ($script:n + 1)
        $dirSource = Join-Path (Join-Path $sourceRoot $dirLeaf) 'a.txt'; $dirTarget = Join-Path (Join-Path $root $dirLeaf) 'a.txt'
        $bytes = New-Payload ($script:n + 1) $false
        $ack = Invoke-ActorCommand 'shelldir' $dirSource $dirTarget $bytes
        $deadline = [Diagnostics.Stopwatch]::GetTimestamp() + 60 * $frequency
        while (-not (Same (Read-Public $dirTarget) $bytes) -and [Diagnostics.Stopwatch]::GetTimestamp() -lt $deadline) { Start-Sleep -Milliseconds 50 }
        $result.FolderMove = [ordered]@{ Ack = $ack.Ack; TargetFolderExists = (Test-Path -LiteralPath (Split-Path -Parent $dirTarget));
            TargetPublished = (Same (Read-Public $dirTarget) $bytes); SourceRemains = (Test-Path -LiteralPath $dirSource) }
    } catch { $result.FolderMoveError = $_.Exception.Message }
    Start-Sleep -Seconds 10
    try {
        $ring = @(& $Diagnostics -Query deny-ring)
        $result.RingNotSameDevice = @($ring | Where-Object { $_.status -eq '0xC00000D4' -and $_.major -eq 'SET_INFORMATION' }).Count
        $result.RingTotal = $ring.Count
    } catch { $result.RingError = $_.Exception.Message }
    $stopPart = Join-Path $control 'stop.part'
    [IO.File]::WriteAllText($stopPart, 'stop')
    [IO.File]::Move($stopPart, (Join-Path $control 'cmd-stop.txt'))
    $deadline = [Diagnostics.Stopwatch]::GetTimestamp() + 60 * $frequency
    while (-not (Test-Path (Join-Path $control 'actor-stopped.txt'))) { if ([Diagnostics.Stopwatch]::GetTimestamp() -gt $deadline) { break }; Start-Sleep -Milliseconds 200 }
    $result.ActorStopped = Test-Path (Join-Path $control 'actor-stopped.txt')
} catch {
    $result.Error = $_.Exception.Message
    $result.ErrorDetail = $_.Exception.ToString()
    $result.ErrorScriptStackTrace = $_.ScriptStackTrace
} finally {
    $result.Finished = [DateTime]::UtcNow.ToString('o')
    $resultPart = Join-Path $out 'result.part'
    [IO.File]::WriteAllText($resultPart, ($result | ConvertTo-Json -Depth 8), [Text.UTF8Encoding]::new($false))
    [IO.File]::Move($resultPart, (Join-Path $out 'result.json'))
}
