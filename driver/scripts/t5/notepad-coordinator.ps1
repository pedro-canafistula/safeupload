<#
T5 coordinator (SYSTEM). Drives notepad-actor.ps1 (a standard user in its interactive session) through Save As patterns into the
protected folder and records, for each, what reached the public name (bytes, owner), the journal entries for that name and, at the
end, the driver's deny ring. Expected after T5: clean text is published exactly; CPF text is handed back and never public; no
empty test-create version stays published; Notepad shows no error window.
Results: C:\T5\result.json.
#>
param([string]$ActorUser = 't5actor', [string]$ActorTask = 't5-actor',
    [string]$Diagnostics = 'C:\Users\vika\Documents\Get-SafeUploadDiagnostics.ps1')
$ErrorActionPreference = 'Stop'
$out = 'C:\T5'; $control = Join-Path $out 'control'; $root = 'C:\Protected\t5'
$journalDir = 'C:\ProgramData\SafeUpload\staging-journal'
$frequency = [Diagnostics.Stopwatch]::Frequency
function Read-ControlText([string]$Path) {
    $deadline = [Diagnostics.Stopwatch]::GetTimestamp() + 5 * $frequency
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
function Sha([byte[]]$B) { if ($null -eq $B) { return $null }; $h = [Security.Cryptography.SHA256]::Create(); try { [BitConverter]::ToString($h.ComputeHash($B)).Replace('-', '') } finally { $h.Dispose() } }
$script:n = 0
function Invoke-Actor([string]$Op, [string]$Path, [string]$Text) {
    $script:n++
    $json = [ordered]@{ N = $script:n; Op = $Op; Path = $Path; Text = $Text } | ConvertTo-Json -Compress
    $part = Join-Path $control ('next-' + $script:n + '.part'); [IO.File]::WriteAllText($part, $json)
    [IO.File]::Move($part, (Join-Path $control ('cmd-' + $script:n + '.json')))
    $ack = Join-Path $control ('ack-' + $script:n + '.json')
    $deadline = [Diagnostics.Stopwatch]::GetTimestamp() + 180 * $frequency
    while (-not (Test-Path $ack)) { if ([Diagnostics.Stopwatch]::GetTimestamp() -gt $deadline) { throw "actor $Op timed out" }; Start-Sleep -Milliseconds 20 }
    $value = (Read-ControlText $ack) | ConvertFrom-Json; Remove-Item -LiteralPath $ack -Force
    $value
}
function Get-JournalFor([string]$Leaf) {
    @(Get-ChildItem -LiteralPath $journalDir -Filter '*.json' -File -Force -ErrorAction SilentlyContinue | ForEach-Object {
        $text = try { [IO.File]::ReadAllText($_.FullName) } catch { '' }
        if ($text -like "*$Leaf*") { $_.Name + ' ' + (($text -replace '\s+', ' ').Substring(0, [Math]::Min(1500, ($text -replace '\s+', ' ').Length))) }
    })
}
$result = [ordered]@{ Started = [DateTime]::UtcNow.ToString('o'); Cases = @() }
New-Item -ItemType Directory -Force -Path $out, $control | Out-Null
try {
    Start-ScheduledTask -TaskName $ActorTask
    $deadline = [Diagnostics.Stopwatch]::GetTimestamp() + 120 * $frequency
    while (-not (Test-Path (Join-Path $control 'actor-started.txt'))) { if ([Diagnostics.Stopwatch]::GetTimestamp() -gt $deadline) { throw 'the actor did not start' }; Start-Sleep -Milliseconds 200 }
    $result.Actor = (Read-ControlText (Join-Path $control 'actor-started.txt')).Trim()
    $sid = (New-Object Security.Principal.NTAccount($env:COMPUTERNAME, $ActorUser)).Translate([Security.Principal.SecurityIdentifier]).Value
    $handback = Join-Path ((Get-CimInstance Win32_UserProfile | Where-Object { $_.SID -eq $sid }).LocalPath) 'SafeUpload\_bloqueados'
    $cases = @(
        @{ Op = 'probe-delete'; Leaf = 'probe-delete.txt'; Sensitive = $false },
        @{ Op = 'probe-doc'; Leaf = 'probe-doc.txt'; Sensitive = $false },
        @{ Op = 'notepad'; Leaf = 'ok.txt'; Sensitive = $false },
        @{ Op = 'notepad'; Leaf = 'cpf.txt'; Sensitive = $true }
    )
    foreach ($case in $cases) {
        $path = Join-Path $root $case.Leaf
        $text = if ($case.Sensitive) { 'T5 notepad CPF: 529.982.247-25' } else { 'T5 ' + $case.Op + ' clean text' }
        $bytes = [Text.Encoding]::ASCII.GetBytes($text)
        $before = @(Get-ChildItem -LiteralPath $handback -Filter '*.txt' -File -Force -ErrorAction SilentlyContinue).Count
        $ack = Invoke-Actor $case.Op $path $text
        $deadline = [Diagnostics.Stopwatch]::GetTimestamp() + 60 * $frequency
        $published = $false; $handedBack = $false; $leaked = $false
        do {
            $public = Read-Public $path
            if (Same $public $bytes) { if ($case.Sensitive) { $leaked = $true } else { $published = $true } }
            if ($case.Sensitive) {
                $files = @(Get-ChildItem -LiteralPath $handback -Filter '*.txt' -File -Force -ErrorAction SilentlyContinue | Sort-Object LastWriteTimeUtc)
                if ($files.Count -gt $before -and (Same (Read-Public $files[-1].FullName) $bytes)) { $handedBack = $true }
            }
            if ($published -or $handedBack -or $leaked) { break }
            Start-Sleep -Milliseconds 100
        } while ([Diagnostics.Stopwatch]::GetTimestamp() -lt $deadline)
        Start-Sleep -Seconds 3
        $final = Read-Public $path
        $owner = try { (Get-Acl -LiteralPath $path).Owner } catch { $null }
        $result.Cases += [ordered]@{ Op = $case.Op; Leaf = $case.Leaf; Sensitive = $case.Sensitive; Ack = $ack; Published = $published;
            HandedBack = $handedBack; Leaked = ($leaked -or ($case.Sensitive -and (Same $final $bytes))); FinalLength = $(if ($null -eq $final) { -1 } else { $final.Length });
            FinalSha256 = (Sha $final); ExpectedSha256 = (Sha $bytes); Owner = $owner; Journal = @(Get-JournalFor $case.Leaf) }
    }
    try {
        $ring = @(& $Diagnostics -Query deny-ring)
        $result.Ring = @($ring | Select-Object -Last 60 | ForEach-Object { $_ | ConvertTo-Json -Compress })
    } catch { $result.RingError = $_.Exception.Message }
    $stop = Join-Path $control 'stop.part'; [IO.File]::WriteAllText($stop, '{"Op":"stop"}'); [IO.File]::Move($stop, (Join-Path $control 'cmd-stop.json'))
} catch {
    $result.Error = $_.Exception.Message
    $result.ErrorScriptStackTrace = $_.ScriptStackTrace
} finally {
    $result.Finished = [DateTime]::UtcNow.ToString('o')
    $part = Join-Path $out 'result.part'
    [IO.File]::WriteAllText($part, ($result | ConvertTo-Json -Depth 8), [Text.UTF8Encoding]::new($false))
    [IO.File]::Move($part, (Join-Path $out 'result.json'))
}
