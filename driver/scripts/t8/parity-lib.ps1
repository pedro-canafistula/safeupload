#requires -Version 5.1
# T8 native-parity helpers. Dot-sourced by parity-case.ps1 and parity-cases.ps1; runs as the interactive standard user.
# A case body runs twice, once in an unprotected control folder and once in the protected folder, through the same
# Invoke-Step wrapper. Every step records its outcome as an error code (not a message), so the two sides compare exactly.
Set-StrictMode -Version 2.0

$script:RunTag = (Get-Date).ToString('HHmmss')   # folders that cannot be deleted from a protected tree get a fresh name per run
$script:Steps = $null
$script:StepLog = $null
$script:Roots = @()

function P([string]$Dir, [string]$Name) { return [string][IO.Path]::Combine($Dir, $Name) }   # never pass Join-Path output to COM: it is a PSObject

function Get-ErrorCode($Exception) {
    $e = $Exception
    while ($null -ne $e.InnerException -and ($e -is [Management.Automation.RuntimeException] -or $e -is [Reflection.TargetInvocationException] -or $e -is [Management.Automation.MethodInvocationException])) { $e = $e.InnerException }
    if ($e -is [ComponentModel.Win32Exception]) { return 'win32:' + $e.NativeErrorCode }
    $hr = [int]$e.HResult
    if (($hr -band 0xFFFF0000) -eq 0x80070000) { return 'win32:' + ($hr -band 0xFFFF) }
    return 'hr:0x{0:X8}' -f $hr
}

function ConvertTo-StepText([string]$Text) {
    if ($null -eq $Text) { return '' }
    $t = $Text
    foreach ($r in $script:Roots) { if ($r) { $t = $t.Replace($r, '<D>') } }
    $t = ($t -replace '\s+', ' ').Trim()
    if ($t.Length -gt 300) { $t = $t.Substring(0, 300) }
    return $t
}

# Body returns the value the application or API reported (compared); -Info values are recorded but never compared.
function Invoke-Step([string]$Name, [scriptblock]$Body, [switch]$Info) {
    $sw = [Diagnostics.Stopwatch]::StartNew()
    $r = [ordered]@{ step = $Name; ok = $true; code = ''; error = ''; value = ''; ms = 0; info = [bool]$Info }
    try {
        $global:LASTEXITCODE = 0
        $v = @(& $Body)
        $r.value = if ($v.Count -eq 0) { '' } elseif ($v.Count -eq 1 -and $v[0] -is [string]) { $v[0] } else { ConvertTo-Json -InputObject $v -Compress -Depth 4 }
        $r.value = ConvertTo-StepText ([string]$r.value)
    } catch {
        $r.ok = $false
        $r.code = Get-ErrorCode $_.Exception
        $r.error = ConvertTo-StepText $_.Exception.Message
    }
    $r.ms = [int]$sw.ElapsedMilliseconds
    $o = [pscustomobject]$r
    [void]$script:Steps.Add($o)
    if ($script:StepLog) { Add-Content -LiteralPath $script:StepLog -Value (ConvertTo-Json -InputObject $o -Compress) -Encoding UTF8 }
    return $o
}

function Invoke-Native([string]$File, [string[]]$Arguments, [int[]]$Allowed = @(0)) {
    $out = & $File @Arguments 2>&1 | Out-String
    $code = $LASTEXITCODE
    if ($Allowed -notcontains $code) { throw (New-Object ComponentModel.Win32Exception($code, ($File + ' exit ' + $code + ': ' + ($out -replace '\s+', ' ')))) }
    return $code
}

# cmd.exe needs its command line verbatim; PowerShell's native-argument quoting mangles embedded quotes.
function Invoke-Cmd([string]$CommandLine, [int[]]$Allowed = @(0)) {
    $psi = New-Object Diagnostics.ProcessStartInfo
    $psi.FileName = $env:ComSpec; $psi.Arguments = '/c "' + $CommandLine + '"'
    $psi.UseShellExecute = $false; $psi.RedirectStandardOutput = $true; $psi.RedirectStandardError = $true; $psi.CreateNoWindow = $true
    $p = [Diagnostics.Process]::Start($psi)
    $out = $p.StandardOutput.ReadToEnd() + $p.StandardError.ReadToEnd()
    [void]$p.WaitForExit(60000)
    if ($Allowed -notcontains $p.ExitCode) { throw (New-Object ComponentModel.Win32Exception($p.ExitCode, ('cmd exit ' + $p.ExitCode + ': ' + ($out -replace '\s+', ' ')))) }
    return $out.Trim()
}

# The unprotected source/scratch folders are shared by both sides: start each side from an empty one.
# Diagnostic only: forces the memory manager to trim cached sections, which retires versions whose upper FILE_OBJECT it still references.
function Invoke-MemoryPressure([int]$Megabytes = 2800) {
    $list = New-Object Collections.ArrayList
    try { for ($i = 0; $i -lt [int]($Megabytes / 100); $i++) { $b = New-Object byte[] (100MB); for ($j = 0; $j -lt $b.Length; $j += 4096) { $b[$j] = 1 }; [void]$list.Add($b) } } catch { }
    $list.Clear(); [GC]::Collect()
    return ('allocated ' + ($list.Count * 100))
}

function Reset-Dir([string]$Path) {
    if (Test-Path -LiteralPath $Path) { Remove-Item -LiteralPath $Path -Recurse -Force -ErrorAction Stop }
    [void](New-Item -ItemType Directory -Path $Path)
    return [string]$Path
}

function Get-TopNames([string]$Dir) {
    return @(Get-ChildItem -LiteralPath $Dir -Force -ErrorAction SilentlyContinue | ForEach-Object { $_.Name })
}

function Get-ZipParts([string]$Path) {
    try {
        Add-Type -AssemblyName System.IO.Compression.FileSystem -ErrorAction Stop
        $z = [IO.Compression.ZipFile]::OpenRead($Path)
        try { return @($z.Entries | Where-Object { $_.FullName -notmatch '^docProps/' } | Sort-Object FullName | ForEach-Object { $_.FullName + ':' + $_.Length }) } finally { $z.Dispose() }
    } catch { return @('unreadable:' + $_.Exception.Message) }
}

function Get-EntryRecord([string]$Root, [IO.FileSystemInfo]$Item) {
    $rel = $Item.FullName.Substring($Root.Length).TrimStart('\')
    $rec = [ordered]@{ rel = $rel; kind = $(if ($Item.PSIsContainer) { 'dir' } else { 'file' }); attr = [string]$Item.Attributes; len = -1; sha = ''; owner = ''; sddl = ''; streams = ''; parts = ''; created = ''; written = '' }
    try { $acl = Get-Acl -LiteralPath $Item.FullName; $rec.owner = [string]$acl.Owner; $rec.sddl = [string]$acl.Sddl } catch { $rec.owner = 'ERR:' + (Get-ErrorCode $_.Exception) }
    $rec.created = $Item.CreationTimeUtc.ToString('o'); $rec.written = $Item.LastWriteTimeUtc.ToString('o')
    if (-not $Item.PSIsContainer) {
        $rec.len = [int64]$Item.Length
        try {
            $rec.streams = (@(Get-Item -LiteralPath $Item.FullName -Stream * -ErrorAction Stop | ForEach-Object { $_.Stream }) -join ',')
            if ($Item.Length -le 32MB) { $rec.sha = (Get-FileHash -LiteralPath $Item.FullName -Algorithm SHA256 -ErrorAction Stop).Hash }
            if ($Item.Extension -in '.docx', '.xlsx', '.pptx', '.zip') { $rec.parts = (Get-ZipParts $Item.FullName) -join ';' }
        } catch { $rec.sha = 'ERR:' + (Get-ErrorCode $_.Exception) }
    }
    return [pscustomobject]$rec
}

# Entries under $Dir that were not there before the case; directories are walked.
function Get-NewEntries([string]$Dir, [string[]]$Before) {
    $set = @{}; foreach ($b in $Before) { $set[$b.ToLowerInvariant()] = $true }
    $out = New-Object Collections.ArrayList
    foreach ($top in @(Get-ChildItem -LiteralPath $Dir -Force -ErrorAction SilentlyContinue)) {
        if ($set.ContainsKey($top.Name.ToLowerInvariant())) { continue }
        [void]$out.Add((Get-EntryRecord $Dir $top))
        if ($top.PSIsContainer) { foreach ($sub in @(Get-ChildItem -LiteralPath $top.FullName -Force -Recurse -ErrorAction SilentlyContinue)) { [void]$out.Add((Get-EntryRecord $Dir $sub)) } }
    }
    return @($out | Sort-Object rel)
}

function Get-QuickKey([string]$Dir, [string[]]$Before) {
    return ((Get-NewEntries $Dir $Before | ForEach-Object { $_.rel + '|' + $_.len + '|' + $_.written }) -join ';')
}

# Wait until the set of new entries stops changing (publication, owner-file removal and recovery are all asynchronous).
function Wait-Settled([string]$Dir, [string[]]$Before, [int]$MaxSeconds = 60) {
    $sw = [Diagnostics.Stopwatch]::StartNew(); $last = $null; $stable = 0
    while ($sw.Elapsed.TotalSeconds -lt $MaxSeconds) {
        $k = Get-QuickKey $Dir $Before
        if ($k -ceq $last) { $stable++ } else { $stable = 0; $last = $k }
        if ($stable -ge 4) { return [pscustomobject]@{ settled = $true; seconds = [math]::Round($sw.Elapsed.TotalSeconds - 2.8, 1) } }
        Start-Sleep -Milliseconds 700
    }
    return [pscustomobject]@{ settled = $false; seconds = [math]::Round($sw.Elapsed.TotalSeconds, 1) }
}

function Remove-NewEntries([string]$Dir, [string[]]$Before) {
    $failed = @()
    for ($try = 0; $try -lt 6; $try++) {
        $failed = @()
        foreach ($top in @(Get-ChildItem -LiteralPath $Dir -Force -ErrorAction SilentlyContinue)) {
            if ($Before -contains $top.Name) { continue }
            try { if ($top.PSIsContainer) { Remove-Item -LiteralPath $top.FullName -Recurse -Force -ErrorAction Stop } else { (Get-Item -LiteralPath $top.FullName -Force).Attributes = 'Normal'; Remove-Item -LiteralPath $top.FullName -Force -ErrorAction Stop } }
            catch { $failed += ($top.Name + ' ' + (Get-ErrorCode $_.Exception)) }
        }
        if ($failed.Count -eq 0) { break }
        Start-Sleep -Seconds 2
    }
    return $failed
}

function Stop-OfficeProcesses {
    foreach ($n in 'WINWORD', 'EXCEL', 'POWERPNT') { Get-Process -Name $n -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue }
    Start-Sleep -Milliseconds 500
}

# What the user sees: every top-level window of the application (document windows carry "[Read-Only]" / "Protected View"
# in the title; a dialog is another window). Compared between control and protected like any other value.
function Get-OfficeUiState([string]$ProcessName) {
    Add-Type -AssemblyName UIAutomationClient, UIAutomationTypes
    $ids = @(Get-Process -Name $ProcessName -ErrorAction SilentlyContinue | ForEach-Object { $_.Id })
    $cond = New-Object Windows.Automation.PropertyCondition ([Windows.Automation.AutomationElement]::ControlTypeProperty), ([Windows.Automation.ControlType]::Window)
    $found = @()
    foreach ($w in [Windows.Automation.AutomationElement]::RootElement.FindAll([Windows.Automation.TreeScope]::Children, $cond)) {
        $c = $w.Current
        if ($ids -contains $c.ProcessId) { $found += ($c.ClassName + '=' + $c.Name) }
    }
    return ($found | Sort-Object) -join ' || '
}

function Release-Com($Object) { if ($null -ne $Object) { try { [void][Runtime.InteropServices.Marshal]::FinalReleaseComObject($Object) } catch {} } }

# Runs one case function against one directory and returns the side's record.
function Invoke-Side([string]$Side, [string]$Dir, [string]$Fn, [string]$StepLogPath, [string]$SourceDir, [int]$SettleSeconds) {
    $script:Steps = New-Object Collections.ArrayList
    $script:StepLog = $StepLogPath
    $before = Get-TopNames $Dir
    $start = [DateTime]::UtcNow
    $fatal = ''
    try { & $Fn $Dir $SourceDir } catch { $fatal = ConvertTo-StepText $_.Exception.Message }
    Stop-OfficeProcesses
    $end = [DateTime]::UtcNow
    $settle = Wait-Settled $Dir $before $SettleSeconds
    $entries = @(Get-NewEntries $Dir $before)
    $cleanup = @(Remove-NewEntries $Dir $before)
    return [pscustomobject]@{ side = $Side; dir = $Dir; startUtc = $start.ToString('o'); endUtc = $end.ToString('o'); settle = $settle; steps = @($script:Steps); entries = $entries; fatal = $fatal; cleanupFailures = $cleanup }
}

function Compare-Sides($Control, $Protected, [hashtable]$Options) {
    $d = New-Object Collections.ArrayList
    $cs = @($Control.steps); $ps = @($Protected.steps)
    if ($Control.fatal) { [void]$d.Add('control fatal: ' + $Control.fatal) }
    if ($Protected.fatal) { [void]$d.Add('protected fatal: ' + $Protected.fatal) }
    if ($cs.Count -ne $ps.Count) { [void]$d.Add(('step count control=' + $cs.Count + ' protected=' + $ps.Count)) }
    for ($i = 0; $i -lt [Math]::Min($cs.Count, $ps.Count); $i++) {
        $a = $cs[$i]; $b = $ps[$i]
        if ($a.step -cne $b.step) { [void]$d.Add(('step ' + $i + ' name ' + $a.step + ' vs ' + $b.step)); continue }
        if ($a.info) { continue }
        if ($a.ok -ne $b.ok) { [void]$d.Add(('STEP ' + $a.step + ': control ' + $(if ($a.ok) { 'ok' } else { 'FAIL ' + $a.code }) + ', protected ' + $(if ($b.ok) { 'ok' } else { 'FAIL ' + $b.code + ' ' + $b.error }))) }
        elseif (-not $a.ok -and $a.code -cne $b.code) { [void]$d.Add(('STEP ' + $a.step + ': error code control ' + $a.code + ' protected ' + $b.code)) }
        elseif ($a.ok -and $a.value -cne $b.value) { [void]$d.Add(('STEP ' + $a.step + ': value control [' + $a.value + '] protected [' + $b.value + ']')) }
    }
    $ce = @{}; foreach ($e in @($Control.entries)) { $ce[$e.rel.ToLowerInvariant()] = $e }
    $pe = @{}; foreach ($e in @($Protected.entries)) { $pe[$e.rel.ToLowerInvariant()] = $e }
    foreach ($k in $ce.Keys) { if (-not $pe.ContainsKey($k)) { [void]$d.Add('ENTRY only in control: ' + $ce[$k].rel) } }
    foreach ($k in $pe.Keys) { if (-not $ce.ContainsKey($k)) { [void]$d.Add('ENTRY only in protected: ' + $pe[$k].rel) } }
    foreach ($k in $ce.Keys) {
        if (-not $pe.ContainsKey($k)) { continue }
        $a = $ce[$k]; $b = $pe[$k]; $n = $a.rel
        if ($a.kind -ne $b.kind) { [void]$d.Add('ENTRY ' + $n + ' kind ' + $a.kind + ' vs ' + $b.kind); continue }
        if ($a.attr -cne $b.attr) { [void]$d.Add(('META ' + $n + ' attributes control [' + $a.attr + '] protected [' + $b.attr + ']')) }
        if ($a.owner -cne $b.owner) { [void]$d.Add(('META ' + $n + ' owner control ' + $a.owner + ' protected ' + $b.owner)) }
        if ($a.sddl -cne $b.sddl) { [void]$d.Add(('META ' + $n + ' sddl control ' + $a.sddl + ' protected ' + $b.sddl)) }
        if ($a.kind -eq 'file') {
            if ($a.streams -cne $b.streams) { [void]$d.Add(('META ' + $n + ' streams control [' + $a.streams + '] protected [' + $b.streams + ']')) }
            if ($a.parts -and $b.parts) { if ($a.parts -cne $b.parts) { [void]$d.Add(('BYTES ' + $n + ' package parts differ')) } }
            elseif ($Options.Deterministic) { if ($a.sha -cne $b.sha) { [void]$d.Add(('BYTES ' + $n + ' sha control ' + $a.sha.Substring(0, [Math]::Min(8, $a.sha.Length)) + ' protected ' + $b.sha.Substring(0, [Math]::Min(8, $b.sha.Length)))) } }
            elseif ($a.len -ne $b.len) { [void]$d.Add(('BYTES ' + $n + ' length control ' + $a.len + ' protected ' + $b.len)) }
        }
        if ($Options.CompareTimes -and $a.kind -eq 'file' -and $a.written -cne $b.written) { [void]$d.Add(('META ' + $n + ' last write control ' + $a.written + ' protected ' + $b.written)) }
    }
    if ($Protected.cleanupFailures.Count -gt 0 -and $Control.cleanupFailures.Count -eq 0) { [void]$d.Add('CLEANUP protected could not remove: ' + ($Protected.cleanupFailures -join ', ')) }
    if (-not $Protected.settle.settled) { [void]$d.Add('SETTLE protected did not settle in ' + $Protected.settle.seconds + ' s') }
    return @($d)
}
