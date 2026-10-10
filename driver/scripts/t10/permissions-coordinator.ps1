<#
T10 permissions coordinator (SYSTEM, an administrator-equivalent). With permissions-actor.ps1 (a standard user) it checks that
permission and owner changes reach the real file or folder while the private backing never changes, and that a permission change
gives a standard user no way to put unapproved bytes into the protected folder:
  1. the actor holds a version of existing.txt in progress (CPF bytes in its private stage);
  2. the administrator grants Users full control on the real existing.txt and read on the folder: both succeed and the real ACLs
     change, while the private stage file stays closed to them (its security can be neither read nor changed) and the private
     stage directory keeps its exact security descriptor;
  3. the held version is blocked and handed back; the public file keeps its approved bytes;
  4. the actor, now with full control of existing.txt, grants Everyone full control on it (Windows allows it), then writes CPF:
     blocked and handed back, never public;
  5. the actor tries to grant itself full control of the folder: Windows refuses (the actor lacks WRITE_DAC there);
  6. the actor writes clean bytes: approved and published (whether the earlier ACEs survive publication is recorded for T8).
Results: C:\T10\result.json with one entry per check.
#>
param([string]$ActorUser = 't10actor', [string]$ActorTask = 't10-actor')
$ErrorActionPreference = 'Stop'
$out = 'C:\T10'; $control = Join-Path $out 'control'; $root = 'C:\Protected\t10'; $file = Join-Path $root 'existing.txt'
$stageDir = 'C:\ProgramData\SafeUpload\staging'
$frequency = [Diagnostics.Stopwatch]::Frequency
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
    } catch [IO.FileNotFoundException] { $null } catch [IO.IOException] { , @() }
}
function Same([byte[]]$A, [byte[]]$B) { if ($null -eq $A -or $null -eq $B -or $A.Length -ne $B.Length) { return $false }; for ($i = 0; $i -lt $A.Length; ++$i) { if ($A[$i] -ne $B[$i]) { return $false } }; $true }
function Get-Sddl([string]$Path) { (Get-Acl -LiteralPath $Path).Sddl }
# The driver refuses every non-service open inside the private staging folder, SYSTEM's included, so a stage file's security can
# be neither read nor changed from here: that refusal is what is checked. The folder itself (opened without a trailing component)
# stays readable, and its descriptor must not change.
function Get-StageFiles { @(Get-ChildItem -LiteralPath $stageDir -File -Force -ErrorAction SilentlyContinue | ForEach-Object { $_.FullName }) }
function Test-StageAclClosed([string]$Path) {
    $read = try { $null = Get-Acl -LiteralPath $Path; 'readable' } catch { 'refused' }
    $out = (& icacls.exe $Path /grant '*S-1-1-0:(F)' 2>&1 | Out-String)
    [ordered]@{ Path = $Path; Read = $read; GrantExit = $LASTEXITCODE; Grant = ($out -replace '\s+', ' ') }
}
$script:n = 0
function Invoke-Actor([string]$Op, [string]$Path, [byte[]]$Bytes, [string[]]$Arguments) {
    $script:n++
    $payload = $null
    if ($null -ne $Bytes) { $payload = Join-Path $control ('payload-' + $script:n + '.bin'); [IO.File]::WriteAllBytes($payload, $Bytes) }
    $json = [ordered]@{ N = $script:n; Op = $Op; Path = $Path; Payload = $payload; Args = @($Arguments) } | ConvertTo-Json -Compress
    $part = Join-Path $control ('next-' + $script:n + '.part'); [IO.File]::WriteAllText($part, $json)
    [IO.File]::Move($part, (Join-Path $control ('cmd-' + $script:n + '.json')))
    $ack = Join-Path $control ('ack-' + $script:n + '.txt')
    $deadline = [Diagnostics.Stopwatch]::GetTimestamp() + 120 * $frequency
    while (-not (Test-Path $ack)) { if ([Diagnostics.Stopwatch]::GetTimestamp() -gt $deadline) { throw ("actor $Op timed out") }; Start-Sleep -Milliseconds 5 }
    $text = (Read-ControlText $ack).Trim(); Remove-Item -LiteralPath $ack -Force
    $text
}
function Wait-HandBack([string]$Dir, [int]$Before, [byte[]]$Bytes) {
    $deadline = [Diagnostics.Stopwatch]::GetTimestamp() + 120 * $frequency
    do {
        $files = @(Get-ChildItem -LiteralPath $Dir -Filter '*.txt' -File -Force -ErrorAction SilentlyContinue | Sort-Object LastWriteTimeUtc)
        if ($files.Count -gt $Before -and (Same (Read-Public $files[-1].FullName) $Bytes)) { return $true }
        Start-Sleep -Milliseconds 50
    } while ([Diagnostics.Stopwatch]::GetTimestamp() -lt $deadline)
    $false
}
function Wait-Public([string]$Path, [byte[]]$Bytes) {
    $deadline = [Diagnostics.Stopwatch]::GetTimestamp() + 120 * $frequency
    do { if (Same (Read-Public $Path) $Bytes) { return $true }; Start-Sleep -Milliseconds 50 } while ([Diagnostics.Stopwatch]::GetTimestamp() -lt $deadline)
    $false
}
$result = [ordered]@{ Started = [DateTime]::UtcNow.ToString('o'); Checks = @() }
function Check([string]$Name, [bool]$Ok, [string]$Detail) { $script:result.Checks += [ordered]@{ Name = $Name; Ok = $Ok; Detail = $Detail } }
New-Item -ItemType Directory -Force -Path $out, $control | Out-Null
try {
    Start-ScheduledTask -TaskName $ActorTask
    $deadline = [Diagnostics.Stopwatch]::GetTimestamp() + 120 * $frequency
    while (-not (Test-Path (Join-Path $control 'actor-started.txt'))) { if ([Diagnostics.Stopwatch]::GetTimestamp() -gt $deadline) { throw 'the actor did not start' }; Start-Sleep -Milliseconds 200 }
    $sid = (New-Object Security.Principal.NTAccount($env:COMPUTERNAME, $ActorUser)).Translate([Security.Principal.SecurityIdentifier]).Value
    $profile = (Get-CimInstance Win32_UserProfile | Where-Object { $_.SID -eq $sid }).LocalPath
    $handback = Join-Path $profile 'SafeUpload\_bloqueados'
    $original = Read-Public $file
    Check 'T10ExistingPublished' ($null -ne $original -and $original.Length -gt 0) 'the pre-existing protected file is readable'
    $cpf1 = [Text.Encoding]::ASCII.GetBytes("T10 held CPF: 529.982.247-25`r`n")
    $cpf2 = [Text.Encoding]::ASCII.GetBytes("T10 after grant CPF: 529.982.247-25`r`n")
    $clean = [Text.Encoding]::ASCII.GetBytes("T10 clean final " + [guid]::NewGuid().ToString('N').Replace('0','g').Replace('1','h').Replace('2','i').Replace('3','j').Replace('4','k').Replace('5','l').Replace('6','m').Replace('7','n').Replace('8','o').Replace('9','p') + "`r`n")

    # 1-2: a version in progress, then the administrator changes the real file's and the folder's permissions.
    $dirBefore = Get-Sddl $stageDir
    $filesBefore = Get-StageFiles
    $before = @(Get-ChildItem -LiteralPath $handback -Filter '*.txt' -File -Force -ErrorAction SilentlyContinue).Count
    $ack = Invoke-Actor 'hold' $file $cpf1 $null
    Check 'T10VersionHeld' ($ack -eq 'ok') ('actor holds a staged version: ' + $ack)
    $newStages = @(Get-StageFiles | Where-Object { $filesBefore -notcontains $_ })
    Check 'T10StageFilePresent' ($newStages.Count -ge 1) ("new stage files: " + ($newStages -join ', '))
    $fileOut = (& icacls.exe $file /grant '*S-1-5-32-545:(F)' 2>&1 | Out-String); $fileExit = $LASTEXITCODE
    $dirOut = (& icacls.exe $root /grant '*S-1-5-32-545:(OI)(CI)(RX)' 2>&1 | Out-String); $dirExit = $LASTEXITCODE
    Check 'T10AdminFileAclChanged' ($fileExit -eq 0 -and (Get-Sddl $file) -match '\(A;[^)]*;FA;;;BU\)') ("icacls exit $fileExit; " + ($fileOut -replace '\s+', ' '))
    Check 'T10AdminFolderAclChanged' ($dirExit -eq 0) ("icacls exit $dirExit; " + ($dirOut -replace '\s+', ' '))
    $probes = @($newStages | ForEach-Object { Test-StageAclClosed $_ })
    $result.StageProbes = $probes
    Check 'T10PrivateBackingClosedToSecurityChanges' ($probes.Count -ge 1 -and @($probes | Where-Object { $_.Read -ne 'refused' -or $_.GrantExit -eq 0 }).Count -eq 0) ('an administrator-equivalent can neither read nor change a stage file''s security: ' + (($probes | ForEach-Object { $_.Read + '/' + $_.GrantExit }) -join ', '))

    # 3: the held CPF version is blocked; the public file keeps its approved bytes.
    $ack = Invoke-Actor 'release' $file $null $null
    Check 'T10HeldBlocked' ($ack -eq 'ok' -and (Wait-HandBack $handback $before $cpf1) -and (Same (Read-Public $file) $original)) ('release: ' + $ack)

    # 4: with full control the actor may change the file's ACL, but CPF it writes is still blocked.
    $ack = Invoke-Actor 'icacls' $file $null @('/grant', '*S-1-1-0:(F)')
    Check 'T10ActorFileAclAllowed' ($ack -eq 'ok' -and (Get-Sddl $file) -match '\(A;[^)]*;FA;;;WD\)') ('actor icacls on the file: ' + $ack)
    $before = @(Get-ChildItem -LiteralPath $handback -Filter '*.txt' -File -Force -ErrorAction SilentlyContinue).Count
    $ack = Invoke-Actor 'write' $file $cpf2 $null
    $blocked = ($ack -eq 'ok') -and (Wait-HandBack $handback $before $cpf2)
    $public = Read-Public $file
    Check 'T10CpfAfterGrantBlocked' ($blocked -and (Same $public $original)) ('write: ' + $ack)
    Check 'T10NoBlockedBytesPublished' (-not (Same $public $cpf1) -and -not (Same $public $cpf2)) 'the public file never holds the blocked bytes'

    # 5: the actor lacks WRITE_DAC on the folder: Windows refuses.
    $folderBefore = Get-Sddl $root
    $ack = Invoke-Actor 'icacls' $root $null @('/grant', '*S-1-1-0:(OI)(CI)(F)')
    Check 'T10ActorFolderAclRefusedByWindows' ($ack -like 'exit *' -and (Get-Sddl $root) -eq $folderBefore) ('actor icacls on the folder: ' + $ack)

    # 6: clean bytes are approved and published.
    $ack = Invoke-Actor 'write' $file $clean $null
    Check 'T10CleanPublished' ($ack -eq 'ok' -and (Wait-Public $file $clean)) ('write: ' + $ack)
    $result.AclAfterPublication = Get-Sddl $file
    $result.AdminAceSurvivedPublication = $result.AclAfterPublication -match '\(A;[^)]*;FA;;;BU\)'
    Start-Sleep -Seconds 5
    Check 'T10PrivateDirectoryAclUnchanged' ((Get-Sddl $stageDir) -eq $dirBefore) 'the private stage directory keeps its security descriptor'
    $stop = Join-Path $control 'stop.part'; [IO.File]::WriteAllText($stop, '{"Op":"stop"}'); [IO.File]::Move($stop, (Join-Path $control 'cmd-stop.json'))
} catch {
    $result.Error = $_.Exception.Message
    $result.ErrorScriptStackTrace = $_.ScriptStackTrace
} finally {
    $result.Finished = [DateTime]::UtcNow.ToString('o')
    $part = Join-Path $out 'result.part'
    [IO.File]::WriteAllText($part, ($result | ConvertTo-Json -Depth 6), [Text.UTF8Encoding]::new($false))
    [IO.File]::Move($part, (Join-Path $out 'result.json'))
}
