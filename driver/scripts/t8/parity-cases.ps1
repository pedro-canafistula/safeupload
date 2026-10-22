#requires -Version 5.1
# T8 native-parity case catalog (see driver/docs/design/T8-CLOSURE-PLAN.md section 3). Each function runs against ONE
# directory ($d: the unprotected control folder or the protected folder) and must behave identically in both.
# Every file name is fixed per case, so the two sides can be compared name by name. $src is an unprotected source folder.
# Registry: Name, Function, Deterministic (compare SHA-256, not just length), CompareTimes (final last-write must match).
Set-StrictMode -Version 2.0

$Cases = @(
    @{ Name = 'txt-lifecycle';      Fn = 'Case-TxtLifecycle';      Deterministic = $true }
    @{ Name = 'txt-cmd-ops';        Fn = 'Case-TxtCmdOps';         Deterministic = $true }
    @{ Name = 'txt-attributes';     Fn = 'Case-TxtAttributes';     Deterministic = $true }
    @{ Name = 'txt-times';          Fn = 'Case-TxtTimes';          Deterministic = $true; CompareTimes = $true }
    @{ Name = 'txt-acl';            Fn = 'Case-TxtAcl';            Deterministic = $true }
    @{ Name = 'shell-copy-in-out';  Fn = 'Case-ShellCopy';         Deterministic = $true }
    @{ Name = 'shell-move-in-out';  Fn = 'Case-ShellMove';         Deterministic = $true }
    @{ Name = 'shell-recycle';      Fn = 'Case-ShellRecycle';      Deterministic = $true }
    @{ Name = 'folder-create';      Fn = 'Case-FolderCreate';      Deterministic = $true }
    @{ Name = 'folder-rename';      Fn = 'Case-FolderRename';      Deterministic = $true }
    @{ Name = 'folder-delete';      Fn = 'Case-FolderDelete';      Deterministic = $true }
    @{ Name = 'folder-copy-move';   Fn = 'Case-FolderCopyMove';    Deterministic = $true }
    @{ Name = 'robocopy';           Fn = 'Case-Robocopy';          Deterministic = $true }
    @{ Name = 'zip-roundtrip';      Fn = 'Case-Zip';               Deterministic = $false }
    @{ Name = 'large-file';         Fn = 'Case-LargeFile';         Deterministic = $true }
    @{ Name = 'word-saveas-edit';   Fn = 'Case-WordSaveAsEdit';    Deterministic = $false }
    @{ Name = 'word-inplace';       Fn = 'Case-WordInPlace';       Deterministic = $false }
    @{ Name = 'word-overwrite';     Fn = 'Case-WordOverwrite';     Deterministic = $false }
    @{ Name = 'word-reopen-loop';   Fn = 'Case-WordReopenLoop';    Deterministic = $false }
    @{ Name = 'word-locked-open';   Fn = 'Case-WordLockedOpen';    Deterministic = $false }
    @{ Name = 'word-pdf';           Fn = 'Case-WordPdf';           Deterministic = $false }
    @{ Name = 'excel-saveas-edit';  Fn = 'Case-ExcelSaveAsEdit';   Deterministic = $false }
    @{ Name = 'excel-inplace';      Fn = 'Case-ExcelInPlace';      Deterministic = $false }
    @{ Name = 'ppt-saveas-reopen';  Fn = 'Case-PptSaveAsReopen';   Deterministic = $false }
)

function Case-TxtLifecycle([string]$d, [string]$src) {
    $p = P $d 'lc.txt'
    Invoke-Step 'create' { Set-Content -LiteralPath $p -Value 'one' -Encoding ASCII } | Out-Null
    Invoke-Step 'read-immediately' { (Get-Content -LiteralPath $p -Raw).Trim() } | Out-Null
    Invoke-Step 'append' { Add-Content -LiteralPath $p -Value 'two' -Encoding ASCII } | Out-Null
    Invoke-Step 'read-after-append' { (Get-Content -LiteralPath $p) -join '|' } | Out-Null
    Invoke-Step 'stream-write-share-read' { $f = [IO.File]::Open($p, 'Open', 'Write', 'Read'); try { $b = [Text.Encoding]::ASCII.GetBytes('three'); $f.Seek(0, 'End') | Out-Null; $f.Write($b, 0, $b.Length) } finally { $f.Dispose() } } | Out-Null
    Invoke-Step 'rename' { Rename-Item -LiteralPath $p -NewName 'lc2.txt' } | Out-Null
    $p2 = P $d 'lc2.txt'
    Invoke-Step 'copy-within' { Copy-Item -LiteralPath $p2 -Destination (P $d 'lc3.txt') } | Out-Null
    Invoke-Step 'delete-original' { Remove-Item -LiteralPath $p2 -ErrorAction Stop } | Out-Null
    Invoke-Step 'delete-missing' { Remove-Item -LiteralPath $p2 -ErrorAction Stop } | Out-Null
    Invoke-Step 'overwrite-existing' { Set-Content -LiteralPath (P $d 'lc3.txt') -Value 'replaced' -Encoding ASCII } | Out-Null
    Invoke-Step 'truncate' { $f = [IO.File]::Open((P $d 'lc3.txt'), 'Open', 'Write', 'None'); try { $f.SetLength(3) } finally { $f.Dispose() } } | Out-Null
}

function Case-TxtCmdOps([string]$d, [string]$src) {
    $c1 = P $d 'c1.txt'; $c2 = P $d 'c2.txt'; $c3 = P $d 'c3.txt'; $c4 = P $d 'c4.txt'
    Invoke-Step 'cmd-echo-create' { Invoke-Cmd ('echo alpha> "' + $c1 + '"') } | Out-Null
    Invoke-Step 'cmd-echo-append' { Invoke-Cmd ('echo beta>> "' + $c1 + '"') } | Out-Null
    Invoke-Step 'cmd-type' { (Invoke-Cmd ('type "' + $c1 + '"')) -replace '\s+', '|' } | Out-Null
    Invoke-Step 'cmd-copy' { Invoke-Cmd ('copy /y "' + $c1 + '" "' + $c2 + '" >nul') } | Out-Null
    Invoke-Step 'cmd-ren' { Invoke-Cmd ('ren "' + $c2 + '" c3.txt') } | Out-Null
    Invoke-Step 'cmd-move' { Invoke-Cmd ('move /y "' + $c3 + '" "' + $c4 + '" >nul') } | Out-Null
    Invoke-Step 'cmd-xcopy-in' { Set-Content -LiteralPath (P $src 'xc.txt') -Value 'xcopy' -Encoding ASCII; Invoke-Cmd ('xcopy /y /q "' + (P $src 'xc.txt') + '" "' + $d + '\" >nul') } | Out-Null
    Invoke-Step 'cmd-del' { Invoke-Cmd ('del /q "' + $c1 + '"') } | Out-Null
}

function Case-TxtAttributes([string]$d, [string]$src) {
    $p = P $d 'at.txt'
    Invoke-Step 'create' { Set-Content -LiteralPath $p -Value 'attr' -Encoding ASCII } | Out-Null
    Invoke-Step 'set-readonly' { Invoke-Native 'attrib.exe' @('+R', $p) } | Out-Null
    Invoke-Step 'write-readonly' { Add-Content -LiteralPath $p -Value 'x' -ErrorAction Stop } | Out-Null
    Invoke-Step 'delete-readonly' { Remove-Item -LiteralPath $p -ErrorAction Stop } | Out-Null
    Invoke-Step 'set-hidden' { Invoke-Native 'attrib.exe' @('+H', $p) } | Out-Null
    Invoke-Step 'clear-readonly' { Invoke-Native 'attrib.exe' @('-R', $p) } | Out-Null
    Invoke-Step 'delete-after-clear' { Remove-Item -LiteralPath $p -Force -ErrorAction Stop } | Out-Null
    Invoke-Step 'create-final-readonly' { Set-Content -LiteralPath (P $d 'at2.txt') -Value 'final' -Encoding ASCII; Invoke-Native 'attrib.exe' @('+R', (P $d 'at2.txt')) } | Out-Null
}

function Case-TxtTimes([string]$d, [string]$src) {
    $p = P $d 'tm.txt'
    $t = [DateTime]::SpecifyKind([DateTime]'2020-03-04T05:06:07', 'Utc')
    Invoke-Step 'create' { Set-Content -LiteralPath $p -Value 'times' -Encoding ASCII } | Out-Null
    Invoke-Step 'set-lastwrite' { (Get-Item -LiteralPath $p).LastWriteTimeUtc = $t } | Out-Null
    Invoke-Step 'set-creation' { (Get-Item -LiteralPath $p).CreationTimeUtc = $t.AddDays(-2) } | Out-Null
    Invoke-Step 'readback-lastwrite' { (Get-Item -LiteralPath $p).LastWriteTimeUtc.ToString('o') } | Out-Null
    Invoke-Step 'copy-preserves-mtime' { Copy-Item -LiteralPath $p -Destination (P $d 'tm2.txt'); (Get-Item -LiteralPath (P $d 'tm2.txt')).LastWriteTimeUtc.ToString('o') } | Out-Null
    Invoke-Step 'src-mtime-in' { $s = P $src 'tm-src.txt'; Set-Content -LiteralPath $s -Value 'src' -Encoding ASCII; (Get-Item -LiteralPath $s).LastWriteTimeUtc = $t.AddYears(1); Copy-Item -LiteralPath $s -Destination (P $d 'tm3.txt'); (Get-Item -LiteralPath (P $d 'tm3.txt')).LastWriteTimeUtc.ToString('o') } | Out-Null
}

function Case-TxtAcl([string]$d, [string]$src) {
    $p = P $d 'ac.txt'
    Invoke-Step 'create' { Set-Content -LiteralPath $p -Value 'acl' -Encoding ASCII } | Out-Null
    Invoke-Step 'icacls-grant-read-everyone' { Invoke-Native 'icacls.exe' @($p, '/grant', '*S-1-1-0:(R)') } | Out-Null
    Invoke-Step 'icacls-deny-write-guests' { Invoke-Native 'icacls.exe' @($p, '/deny', '*S-1-5-32-546:(W)') } | Out-Null
    Invoke-Step 'read-after-acl' { (Get-Content -LiteralPath $p -Raw).Trim() } | Out-Null
    Invoke-Step 'owner-readback' { (Get-Acl -LiteralPath $p).Owner } -Info | Out-Null
    Invoke-Step 'append-after-acl' { Add-Content -LiteralPath $p -Value 'more' -Encoding ASCII } | Out-Null
}

function Wait-ShellDone([scriptblock]$Done, [int]$Seconds = 20) {
    $sw = [Diagnostics.Stopwatch]::StartNew()
    while ($sw.Elapsed.TotalSeconds -lt $Seconds) { if (& $Done) { return $true }; Start-Sleep -Milliseconds 250 }
    return $false
}

function Case-ShellCopy([string]$d, [string]$src) {
    $shell = New-Object -ComObject Shell.Application
    $a = P $src 'sc-in.txt'; Set-Content -LiteralPath $a -Value 'copy in via the shell' -Encoding ASCII
    Invoke-Step 'shell-copy-in' { $shell.NameSpace($d).CopyHere($a, 4 + 16 + 1024); if (-not (Wait-ShellDone { Test-Path -LiteralPath (P $d 'sc-in.txt') })) { throw 'copy did not appear' }; (Get-Content -LiteralPath (P $d 'sc-in.txt') -Raw).Trim() } | Out-Null
    Invoke-Step 'shell-copy-over-existing' { Set-Content -LiteralPath $a -Value 'second copy over the first' -Encoding ASCII; $shell.NameSpace($d).CopyHere($a, 4 + 16 + 1024); Start-Sleep -Seconds 2; (Get-Content -LiteralPath (P $d 'sc-in.txt') -Raw).Trim() } | Out-Null
    $out = Reset-Dir (P $src 'sc-out')
    Invoke-Step 'shell-copy-out' { Remove-Item -LiteralPath (P $out 'sc-in.txt') -ErrorAction SilentlyContinue; $shell.NameSpace($out).CopyHere((P $d 'sc-in.txt'), 4 + 16 + 1024); if (-not (Wait-ShellDone { Test-Path -LiteralPath (P $out 'sc-in.txt') })) { throw 'copy out did not appear' }; (Get-Content -LiteralPath (P $out 'sc-in.txt') -Raw).Trim() } | Out-Null
    Release-Com $shell
}

function Case-ShellMove([string]$d, [string]$src) {
    $shell = New-Object -ComObject Shell.Application
    $a = P $src 'sm-in.txt'; Set-Content -LiteralPath $a -Value 'moved in via the shell' -Encoding ASCII
    Invoke-Step 'shell-move-in' { $shell.NameSpace($d).MoveHere($a, 4 + 16 + 1024); if (-not (Wait-ShellDone { Test-Path -LiteralPath (P $d 'sm-in.txt') })) { throw 'moved file did not appear' }; (Get-Content -LiteralPath (P $d 'sm-in.txt') -Raw).Trim() } | Out-Null
    Invoke-Step 'source-gone-after-move' { Wait-ShellDone { -not (Test-Path -LiteralPath $a) } | Out-Null; Test-Path -LiteralPath $a } | Out-Null
    Invoke-Step 'rename-in-place' { Rename-Item -LiteralPath (P $d 'sm-in.txt') -NewName 'sm-renamed.txt' } | Out-Null
    $out = Reset-Dir (P $src 'sm-out')
    Invoke-Step 'shell-move-out' { Remove-Item -LiteralPath (P $out 'sm-renamed.txt') -ErrorAction SilentlyContinue; $shell.NameSpace($out).MoveHere((P $d 'sm-renamed.txt'), 4 + 16 + 1024); if (-not (Wait-ShellDone { Test-Path -LiteralPath (P $out 'sm-renamed.txt') })) { throw 'moved-out file did not appear' }; (Get-Content -LiteralPath (P $out 'sm-renamed.txt') -Raw).Trim() } | Out-Null
    Invoke-Step 'protected-copy-gone' { Wait-ShellDone { -not (Test-Path -LiteralPath (P $d 'sm-renamed.txt')) } | Out-Null; Test-Path -LiteralPath (P $d 'sm-renamed.txt') } | Out-Null
    Release-Com $shell
}

function Case-ShellRecycle([string]$d, [string]$src) {
    Add-Type -AssemblyName Microsoft.VisualBasic
    $p = P $d 'rc.txt'
    Invoke-Step 'create' { Set-Content -LiteralPath $p -Value 'recycle me' -Encoding ASCII } | Out-Null
    Invoke-Step 'delete-to-recycle-bin' { [Microsoft.VisualBasic.FileIO.FileSystem]::DeleteFile($p, 'OnlyErrorDialogs', 'SendToRecycleBin'); Wait-ShellDone { -not (Test-Path -LiteralPath $p) } | Out-Null; Test-Path -LiteralPath $p } | Out-Null
    Invoke-Step 'restore-from-recycle-bin' {
        $shell = New-Object -ComObject Shell.Application
        try {
            $bin = $shell.NameSpace(10)
            $item = @($bin.Items() | Where-Object { $_.Name -eq 'rc.txt' -or $_.Name -eq 'rc' } | Sort-Object { $_.ModifyDate } | Select-Object -Last 1)
            if ($item.Count -eq 0) { throw 'item not found in the recycle bin' }
            $item[0].InvokeVerb('undelete')
            if (-not (Wait-ShellDone { Test-Path -LiteralPath $p })) { throw 'restored file did not appear' }
            (Get-Content -LiteralPath $p -Raw).Trim()
        } finally { Release-Com $shell }
    } | Out-Null
    Invoke-Step 'delete-permanently' { [Microsoft.VisualBasic.FileIO.FileSystem]::DeleteFile($p, 'OnlyErrorDialogs', 'DeletePermanently'); Wait-ShellDone { -not (Test-Path -LiteralPath $p) } | Out-Null; Test-Path -LiteralPath $p } | Out-Null
}

function New-FolderFixture([string]$d, [string]$name) {
    $f = P $d $name
    Invoke-Step ('setup-' + $name) { New-Item -ItemType Directory -Path $f | Out-Null; Set-Content -LiteralPath (P $f 'a.txt') -Value 'in folder' -Encoding ASCII; Set-Content -LiteralPath (P $f 'b.docx') -Value 'not a real docx' -Encoding ASCII; New-Item -ItemType Directory -Path (P $f 'sub') | Out-Null; Set-Content -LiteralPath (P (P $f 'sub') 'c.txt') -Value 'nested' -Encoding ASCII } | Out-Null
    Start-Sleep -Seconds 4
    return $f
}

function Case-FolderCreate([string]$d, [string]$src) {
    $f = P $d ('fc-dir-' + $script:RunTag)
    Invoke-Step 'mkdir' { New-Item -ItemType Directory -Path $f | Out-Null } | Out-Null
    Invoke-Step 'file-in-new-folder' { Set-Content -LiteralPath (P $f 'a.txt') -Value 'in folder' -Encoding ASCII } | Out-Null
    Invoke-Step 'read-in-new-folder' { (Get-Content -LiteralPath (P $f 'a.txt') -Raw).Trim() } | Out-Null
    Invoke-Step 'nested-mkdir-and-file' { New-Item -ItemType Directory -Path (P $f 'sub') | Out-Null; Set-Content -LiteralPath (P (P $f 'sub') 'c.txt') -Value 'nested' -Encoding ASCII } | Out-Null
    Invoke-Step 'delete-empty-folder' { New-Item -ItemType Directory -Path (P $d ('fc-empty-' + $script:RunTag)) | Out-Null; Remove-Item -LiteralPath (P $d ('fc-empty-' + $script:RunTag)) -ErrorAction Stop } | Out-Null
}

function Case-FolderRename([string]$d, [string]$src) {
    $f = New-FolderFixture $d ('fr-dir-' + $script:RunTag)
    Invoke-Step 'rename-folder' { Rename-Item -LiteralPath $f -NewName ('fr-dir2-' + $script:RunTag) } | Out-Null
    Invoke-Step 'children-after-rename' { (Get-ChildItem -LiteralPath (P $d ('fr-dir2-' + $script:RunTag)) -Recurse | ForEach-Object { $_.Name } | Sort-Object) -join ',' } | Out-Null
}

function Case-FolderDelete([string]$d, [string]$src) {
    $f = New-FolderFixture $d ('fd-dir-' + $script:RunTag)
    Invoke-Step 'delete-folder-recursive' { Remove-Item -LiteralPath $f -Recurse -Force -ErrorAction Stop } | Out-Null
    Invoke-Step 'gone-after-delete' { Test-Path -LiteralPath $f } | Out-Null
    $g = New-FolderFixture $d ('fd-dir2-' + $script:RunTag)
    Invoke-Step 'cmd-rd-s' { Invoke-Cmd ('rd /s /q "' + $g + '"') } | Out-Null
}

function Case-FolderCopyMove([string]$d, [string]$src) {
    $f = New-FolderFixture $d ('fm-dir-' + $script:RunTag)
    Invoke-Step 'copy-folder-within' { Copy-Item -LiteralPath $f -Destination (P $d ('fm-copy-' + $script:RunTag)) -Recurse } | Out-Null
    Invoke-Step 'copy-folder-out' { Reset-Dir (P $src 'fm-out') | Out-Null; Remove-Item -LiteralPath (P $src 'fm-out') -Recurse -Force; Copy-Item -LiteralPath $f -Destination (P $src 'fm-out') -Recurse -Force } | Out-Null
    Invoke-Step 'copy-folder-in' { Copy-Item -LiteralPath (P $src 'fm-out') -Destination (P $d ('fm-in-' + $script:RunTag)) -Recurse } | Out-Null
    Invoke-Step 'move-folder-in-from-outside' { $o = Reset-Dir (P $src 'fm-move'); Set-Content -LiteralPath (P $o 'm.txt') -Value 'move me' -Encoding ASCII; Move-Item -LiteralPath $o -Destination (P $d ('fm-moved-' + $script:RunTag)) } | Out-Null
}

function Case-Robocopy([string]$d, [string]$src) {
    $s = Reset-Dir (P $src 'rb-src')
    Set-Content -LiteralPath (P $s 'r1.txt') -Value 'robocopy one' -Encoding ASCII
    Set-Content -LiteralPath (P $s 'r2.txt') -Value 'robocopy two' -Encoding ASCII
    New-Item -ItemType Directory -Path (P $s 'sub') | Out-Null
    Set-Content -LiteralPath (P (P $s 'sub') 'r3.txt') -Value 'robocopy three' -Encoding ASCII
    $t = P $d ('rb-dst-' + $script:RunTag)
    Invoke-Step 'mkdir-target' { New-Item -ItemType Directory -Path $t | Out-Null } | Out-Null
    Invoke-Step 'robocopy-E' { Invoke-Native 'robocopy.exe' @($s, $t, '/E', '/R:1', '/W:1', '/NFL', '/NDL', '/NJH', '/NJS', '/NP') @(0, 1, 2, 3) } | Out-Null
    Invoke-Step 'robocopy-rerun-nothing-to-do' { Invoke-Native 'robocopy.exe' @($s, $t, '/E', '/R:1', '/W:1', '/NFL', '/NDL', '/NJH', '/NJS', '/NP') @(0, 1, 2, 3) } | Out-Null
    Invoke-Step 'robocopy-mirror-after-source-delete' { Remove-Item -LiteralPath (P $s 'r2.txt'); Invoke-Native 'robocopy.exe' @($s, $t, '/MIR', '/R:1', '/W:1', '/NFL', '/NDL', '/NJH', '/NJS', '/NP') @(0, 1, 2, 3) } | Out-Null
    Invoke-Step 'robocopy-copy2-dat' { Set-Content -LiteralPath (P $s 'r4.txt') -Value 'dat' -Encoding ASCII; Invoke-Native 'robocopy.exe' @($s, $t, 'r4.txt', '/COPY:DAT', '/R:1', '/W:1', '/NFL', '/NDL', '/NJH', '/NJS', '/NP') @(0, 1, 2, 3) } | Out-Null
    Invoke-Step 'robocopy-out-to-source' { $o = Reset-Dir (P $src 'rb-out'); Invoke-Native 'robocopy.exe' @($t, $o, '/E', '/R:1', '/W:1', '/NFL', '/NDL', '/NJH', '/NJS', '/NP') @(0, 1, 2, 3); (Get-ChildItem -LiteralPath $o -Recurse -File | ForEach-Object { $_.Name } | Sort-Object) -join ',' } | Out-Null
}

function Case-Zip([string]$d, [string]$src) {
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    $s = Reset-Dir (P $src 'zp-src')
    Set-Content -LiteralPath (P $s 'z1.txt') -Value 'zip one' -Encoding ASCII
    Set-Content -LiteralPath (P $s 'z2.txt') -Value 'zip two' -Encoding ASCII
    $z = P $d 'zp.zip'
    Invoke-Step 'compress-archive' { Compress-Archive -Path (P $s '*') -DestinationPath $z -Force } | Out-Null
    Invoke-Step 'zip-entries' { [IO.Compression.ZipFile]::OpenRead($z).Entries | ForEach-Object { $_.FullName } | Sort-Object } | Out-Null
    Invoke-Step 'expand-archive' { Start-Sleep -Seconds 2; Expand-Archive -LiteralPath $z -DestinationPath (P $d ('zp-ex-' + $script:RunTag)) } | Out-Null
    Invoke-Step 'read-extracted' { (Get-Content -LiteralPath (P (P $d ('zp-ex-' + $script:RunTag)) 'z1.txt') -Raw).Trim() } | Out-Null
    Invoke-Step 'shell-extract-all' { $shell = New-Object -ComObject Shell.Application; try { $out = P $d ('zp-ex2-' + $script:RunTag); New-Item -ItemType Directory -Path $out | Out-Null; $shell.NameSpace($out).CopyHere($shell.NameSpace($z).Items(), 4 + 16 + 1024); [void](Wait-ShellDone { (Get-ChildItem -LiteralPath $out -ErrorAction SilentlyContinue | Measure-Object).Count -ge 2 }); (Get-ChildItem -LiteralPath $out | ForEach-Object { $_.Name } | Sort-Object) -join ',' } finally { Release-Com $shell } } | Out-Null
}

function Case-LargeFile([string]$d, [string]$src) {
    $p = P $d 'big.bin'
    Invoke-Step 'write-64MiB' { $rng = New-Object Random 42; $buf = New-Object byte[] (1MB); $f = [IO.File]::Open($p, 'Create', 'Write', 'None'); try { for ($i = 0; $i -lt 64; $i++) { $rng.NextBytes($buf); $f.Write($buf, 0, $buf.Length) } } finally { $f.Dispose() } } | Out-Null
    Invoke-Step 'length-after-close' { (Get-Item -LiteralPath $p).Length } -Info | Out-Null
    Invoke-Step 'read-back-hash' { (Get-FileHash -LiteralPath $p -Algorithm SHA256).Hash } | Out-Null
    Invoke-Step 'copy-large-out' { Copy-Item -LiteralPath $p -Destination (P $src 'big-out.bin') -Force } | Out-Null
}

# ---- Microsoft 365 Apps -----------------------------------------------------------------------------------------------
function New-WordApp { $w = New-Object -ComObject Word.Application; $w.Visible = $true; $w.DisplayAlerts = 0; return $w }
function Close-WordApp($w) { if ($null -ne $w) { try { $w.Quit(0) } catch {}; Release-Com $w } }
function Get-WordState($doc) { return ('saved=' + [bool]$doc.Saved + ' readOnly=' + [bool]$doc.ReadOnly + ' name=' + $doc.Name) }

function Case-WordSaveAsEdit([string]$d, [string]$src) {
    $p = P $d 'w1.docx'; $w = $null; $doc = $null
    try {
        Invoke-Step 'start-word' { $script:w = New-WordApp; $true } | Out-Null; $w = $script:w
        Invoke-Step 'new-document' { $script:doc = $w.Documents.Add(); $script:doc.Content.Text = 'T8 parity hello. Nothing sensitive here.'; '' } | Out-Null; $doc = $script:doc
        Invoke-Step 'saveas2' { $doc.SaveAs2($p); Get-WordState $doc } | Out-Null
        Invoke-Step 'ui-after-saveas' { Start-Sleep -Milliseconds 800; Get-OfficeUiState 'WINWORD' } | Out-Null
        Invoke-Step 'owner-file-while-open' { (Get-TopNames $d | Where-Object { $_ -like '~$*' } | ForEach-Object { 'owner-file' }) -join ',' } | Out-Null
        Invoke-Step 'edit-and-save' { $doc.Content.InsertAfter(' Second edit.'); $doc.Save(); Get-WordState $doc } | Out-Null
        Invoke-Step 'close' { $doc.Close(0); $script:doc = $null; $true } | Out-Null; $doc = $null
        Invoke-Step 'reopen' { $d2 = $w.Documents.Open($p); try { Start-Sleep -Milliseconds 800; (Get-WordState $d2) + ' text=' + $d2.Content.Text.Trim() + ' ui=' + (Get-OfficeUiState 'WINWORD') } finally { $d2.Close(0) } } | Out-Null
        Invoke-Step 'reopen-readonly-true-explicit' { $d3 = $w.Documents.Open($p, $false, $true); try { Get-WordState $d3 } finally { $d3.Close(0) } } | Out-Null
    } finally { if ($doc) { try { $doc.Close(0) } catch {} }; Close-WordApp $w }
}

function Case-WordInPlace([string]$d, [string]$src) {
    $p = P $d 'w2.docx'; $w = $null
    try {
        $script:w = New-WordApp; $w = $script:w
        Invoke-Step 'seed-document' { $doc = $w.Documents.Add(); $doc.Content.Text = 'Seed text.'; $doc.SaveAs2($p); $doc.Close(0); $true } | Out-Null
        Start-Sleep -Seconds 4
        for ($i = 1; $i -le 3; $i++) {
            Invoke-Step ('open-edit-save-' + $i) { $doc = $w.Documents.Open($p); try { $doc.Content.InsertAfter(' Edit ' + $i + '.'); $doc.Save(); Get-WordState $doc } finally { $doc.Close(0) } } | Out-Null
        }
        Invoke-Step 'final-text' { $doc = $w.Documents.Open($p, $false, $true); try { $doc.Content.Text.Trim() } finally { $doc.Close(0) } } | Out-Null
    } finally { Close-WordApp $w }
}

function Case-WordOverwrite([string]$d, [string]$src) {
    $p = P $d 'w3.docx'; $w = $null
    try {
        $w = New-WordApp
        Invoke-Step 'first-save' { $doc = $w.Documents.Add(); $doc.Content.Text = 'First.'; $doc.SaveAs2($p); $doc.Close(0); $true } | Out-Null
        Start-Sleep -Seconds 3
        Invoke-Step 'saveas-over-existing' { $doc = $w.Documents.Add(); $doc.Content.Text = 'Second, replaces the first.'; $doc.SaveAs2($p); $r = Get-WordState $doc; $doc.Close(0); $r } | Out-Null
        Invoke-Step 'reopen-text' { $doc = $w.Documents.Open($p, $false, $true); try { $doc.Content.Text.Trim() } finally { $doc.Close(0) } } | Out-Null
    } finally { Close-WordApp $w }
}

function Case-WordReopenLoop([string]$d, [string]$src) {
    $p = P $d 'w4.docx'; $w = $null
    try {
        $w = New-WordApp
        Invoke-Step 'save-then-close' { $doc = $w.Documents.Add(); $doc.Content.Text = 'Reopen loop.'; $doc.SaveAs2($p); $doc.Close(0); $true } | Out-Null
        for ($i = 1; $i -le 5; $i++) {
            Invoke-Step ('immediate-reopen-' + $i) { $doc = $w.Documents.Open($p); try { (Get-WordState $doc) + ' ui=' + (Get-OfficeUiState 'WINWORD') } finally { $doc.Close(0) } } | Out-Null
        }
    } finally { Close-WordApp $w }
}

function Case-WordLockedOpen([string]$d, [string]$src) {
    $p = P $d 'w5.docx'; $w = $null
    try {
        $w = New-WordApp
        Invoke-Step 'seed' { $doc = $w.Documents.Add(); $doc.Content.Text = 'Locked while open.'; $doc.SaveAs2($p); $doc.Close(0); $true } | Out-Null
        Start-Sleep -Seconds 4
        Invoke-Step 'open-document' { $script:held = $w.Documents.Open($p); Get-WordState $script:held } | Out-Null
        Invoke-Step 'other-process-write-open' { $f = [IO.File]::Open($p, 'Open', 'ReadWrite', 'ReadWrite'); $f.Dispose() } | Out-Null
        Invoke-Step 'other-process-read-open' { $f = [IO.File]::Open($p, 'Open', 'Read', 'ReadWrite'); $f.Dispose(); 'read ok' } | Out-Null
        Invoke-Step 'rename-while-open' { Rename-Item -LiteralPath $p -NewName 'w5-renamed.docx' -ErrorAction Stop } | Out-Null
        Invoke-Step 'delete-while-open' { Remove-Item -LiteralPath $p -ErrorAction Stop } | Out-Null
        Invoke-Step 'close-document' { $script:held.Close(0); $true } | Out-Null
        Start-Sleep -Seconds 2
        Invoke-Step 'delete-after-close' { Remove-Item -LiteralPath $p -ErrorAction Stop } | Out-Null
    } finally { Close-WordApp $w }
}

function Case-WordPdf([string]$d, [string]$src) {
    $p = P $d 'w6.pdf'; $w = $null
    try {
        $w = New-WordApp
        Invoke-Step 'export-pdf' { $doc = $w.Documents.Add(); $doc.Content.Text = 'PDF export.'; try { $doc.ExportAsFixedFormat($p, 17) } finally { $doc.Close(0) }; $true } | Out-Null
        Start-Sleep -Seconds 4
        Invoke-Step 'pdf-header' { $b = [IO.File]::ReadAllBytes($p); [Text.Encoding]::ASCII.GetString($b, 0, 4) } | Out-Null
    } finally { Close-WordApp $w }
}

function New-ExcelApp { $x = New-Object -ComObject Excel.Application; $x.Visible = $true; $x.DisplayAlerts = $false; return $x }
function Close-ExcelApp($x) { if ($null -ne $x) { try { $x.Quit() } catch {}; Release-Com $x } }

function Case-ExcelSaveAsEdit([string]$d, [string]$src) {
    $p = P $d 'x1.xlsx'; $x = $null
    try {
        $x = New-ExcelApp
        Invoke-Step 'saveas' { $wb = $x.Workbooks.Add(); $wb.Worksheets.Item(1).Range('A1').Value2 = 'T8'; $wb.Worksheets.Item(1).Range('B1').Formula = '=1+2'; $wb.SaveAs($p, 51); $r = 'saved=' + $wb.Saved + ' readOnly=' + $wb.ReadOnly; $wb.Close($false); $r } | Out-Null
        Invoke-Step 'reopen-edit-save' { $wb = $x.Workbooks.Open($p); try { $wb.Worksheets.Item(1).Range('C1').Value2 = 'edit'; $wb.Save(); 'saved=' + $wb.Saved + ' readOnly=' + $wb.ReadOnly + ' b1=' + $wb.Worksheets.Item(1).Range('B1').Value2 } finally { $wb.Close($false) } } | Out-Null
        Invoke-Step 'reopen-values' { $wb = $x.Workbooks.Open($p); try { 'a1=' + $wb.Worksheets.Item(1).Range('A1').Value2 + ' c1=' + $wb.Worksheets.Item(1).Range('C1').Value2 + ' readOnly=' + $wb.ReadOnly + ' ui=' + (Get-OfficeUiState 'EXCEL') } finally { $wb.Close($false) } } | Out-Null
    } finally { Close-ExcelApp $x }
}

function Case-ExcelInPlace([string]$d, [string]$src) {
    $p = P $d 'x2.xlsx'; $x = $null
    try {
        $x = New-ExcelApp
        Invoke-Step 'seed' { $wb = $x.Workbooks.Add(); $wb.Worksheets.Item(1).Range('A1').Value2 = 1; $wb.SaveAs($p, 51); $wb.Close($false); $true } | Out-Null
        Start-Sleep -Seconds 4
        for ($i = 1; $i -le 3; $i++) {
            Invoke-Step ('open-edit-save-' + $i) { $wb = $x.Workbooks.Open($p); try { $wb.Worksheets.Item(1).Range('A1').Value2 = $wb.Worksheets.Item(1).Range('A1').Value2 + 1; $wb.Save(); 'a1=' + $wb.Worksheets.Item(1).Range('A1').Value2 + ' readOnly=' + $wb.ReadOnly } finally { $wb.Close($false) } } | Out-Null
        }
    } finally { Close-ExcelApp $x }
}

function Case-PptSaveAsReopen([string]$d, [string]$src) {
    $p = P $d 'p1.pptx'; $a = $null
    try {
        $a = New-Object -ComObject PowerPoint.Application
        Invoke-Step 'saveas' { $pres = $a.Presentations.Add(-1); $s = $pres.Slides.Add(1, 12); $pres.SaveAs($p); $r = 'saved=' + $pres.Saved + ' slides=' + $pres.Slides.Count; $pres.Close(); $r } | Out-Null
        Invoke-Step 'reopen' { $pres = $a.Presentations.Open($p, 0, 0, -1); try { 'readOnly=' + $pres.ReadOnly + ' slides=' + $pres.Slides.Count } finally { $pres.Close() } } | Out-Null
        Invoke-Step 'reopen-edit-save' { $pres = $a.Presentations.Open($p, 0, 0, -1); try { [void]$pres.Slides.Add(2, 12); $pres.Save(); 'slides=' + $pres.Slides.Count } finally { $pres.Close() } } | Out-Null
    } finally { if ($a) { try { $a.Quit() } catch {}; Release-Com $a } }
}
