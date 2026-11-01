# Runs as t5actor in the interactive session (vm-as-actor.sh adds Out and the DONE line).
$B = 'C:\SafeUpload\Envios'
$CPF = '529.982.247-25'
Add-Type -AssemblyName System.IO.Compression.FileSystem

function WaitFor([scriptblock]$cond, [int]$seconds) {
    $sw = [Diagnostics.Stopwatch]::StartNew()
    while ($sw.Elapsed.TotalSeconds -lt $seconds) {
        $ok = $false
        try { $ok = [bool](& $cond) } catch { $ok = $false }
        if ($ok) { return [int]$sw.Elapsed.TotalMilliseconds }
        Start-Sleep -Milliseconds 250
    }
    return -1
}
function Check([string]$name, [bool]$ok, [string]$detail) {
    $word = 'FAIL'; if ($ok) { $word = 'PASS' }
    Out ($word + ' ' + $name + ' ' + $detail)
}
function DocText([string]$path) {
    $tmp = [IO.Path]::Combine($env:TEMP, [guid]::NewGuid().ToString() + '.zip')
    Copy-Item -LiteralPath $path -Destination $tmp
    $zip = [IO.Compression.ZipFile]::OpenRead($tmp)
    $sb = New-Object Text.StringBuilder
    foreach ($e in $zip.Entries) {
        if ($e.FullName -like '*.xml') { $r = New-Object IO.StreamReader($e.Open()); [void]$sb.Append($r.ReadToEnd()); $r.Close() }
    }
    $zip.Dispose(); Remove-Item -LiteralPath $tmp
    return $sb.ToString()
}
function Step([string]$name, [scriptblock]$body) {
    try { & $body } catch { Out ('FAIL ' + $name + ' exception: ' + $_.Exception.Message) }
}

$wait = [Diagnostics.Stopwatch]::StartNew()
while (-not (Test-Path 'S:\') -and $wait.Elapsed.TotalSeconds -lt 120) { Start-Sleep -Seconds 2 }
Out ('drive present: ' + (Test-Path 'S:\') + ' user=' + $env:USERNAME)

Step 'T1' {
    Set-Content -LiteralPath 'S:\limpo.txt' -Value 'Relatorio sem dados pessoais' -Encoding UTF8
    $ms = WaitFor { Test-Path -LiteralPath "$B\limpo.txt" } 15
    Check 'T1 clean text reaches the destination' ($ms -ge 0) "($ms ms)"
}
Step 'T2' {
    Set-Content -LiteralPath 'S:\cpf.txt' -Value "Cliente Maria, CPF $CPF" -Encoding UTF8
    Start-Sleep -Seconds 6
    Check 'T2 sensitive text never reaches the destination' (-not (Test-Path -LiteralPath "$B\cpf.txt")) ''
    Check 'T2 sensitive text stays visible on S:' (Test-Path -LiteralPath 'S:\cpf.txt') ''
}
Step 'T3' {
    try { Set-Content -LiteralPath "$B\direto.txt" -Value 'x' -ErrorAction Stop; Check 'T3 direct write to the destination refused' $false 'write succeeded' }
    catch { Check 'T3 direct write to the destination refused' $true $_.Exception.GetType().Name }
}
Step 'T4' {
    [IO.File]::WriteAllText('S:\limpo.txt', "Agora com CPF $CPF")
    Start-Sleep -Seconds 6
    $dest = (Get-Content -Raw -LiteralPath "$B\limpo.txt").Trim()
    Check 'T4a blocked in-place edit keeps the previous version at the destination' ($dest -like '*sem dados*') "dest='$dest'"
    [IO.File]::WriteAllText('S:\limpo.txt', 'Versao corrigida')
    $ms = WaitFor { (Get-Content -Raw -LiteralPath "$B\limpo.txt") -like '*corrigida*' } 15
    Check 'T4b corrected edit published' ($ms -ge 0) "($ms ms)"
}
Step 'T5' {
    $w = New-Object -ComObject Word.Application
    $w.Visible = $false; $w.DisplayAlerts = 0
    $d = $w.Documents.Add(); $d.Content.Text = 'Relatorio trimestral sem dados pessoais'
    $d.SaveAs2([string]'S:\relatorio.docx')
    $ms = WaitFor { Test-Path -LiteralPath "$B\relatorio.docx" } 20
    Check 'T5a Word SaveAs reaches the destination while the document stays open' ($ms -ge 0) "($ms ms)"
    $d.Content.InsertAfter(" CPF $CPF"); $d.Save()
    Start-Sleep -Seconds 8
    $t = DocText "$B\relatorio.docx"
    Check 'T5b Word save with a CPF is held; the destination keeps the clean version' (($t -notlike "*$CPF*") -and ($t -like '*trimestral*')) ''
    $d.Content.Text = 'Relatorio corrigido'; $d.Save()
    $ms = WaitFor { (DocText "$B\relatorio.docx") -like '*corrigido*' } 20
    Check 'T5c Word corrected save published' ($ms -ge 0) "($ms ms)"
    $d.Close()
    $d2 = $w.Documents.Add(); $d2.Content.Text = 'Documento novo sobrescrevendo'
    $d2.SaveAs2([string]'S:\relatorio.docx')
    $ms = WaitFor { (DocText "$B\relatorio.docx") -like '*sobrescrevendo*' } 20
    Check 'T5d Word SaveAs over an existing document published' ($ms -ge 0) "($ms ms)"
    $d2.Close(); $w.Quit()
    [void][Runtime.InteropServices.Marshal]::ReleaseComObject($w)
    Start-Sleep -Seconds 4
    $left = @(Get-ChildItem -LiteralPath $B -Force | Where-Object { $_.Name -like '~*' } | ForEach-Object { $_.Name })
    Check 'T5e no Word temporary files left at the destination' ($left.Count -eq 0) ($left -join ',')
}
Step 'T6' {
    $x = New-Object -ComObject Excel.Application
    $x.Visible = $false; $x.DisplayAlerts = $false
    $wb = $x.Workbooks.Add(); $ws = $wb.Worksheets.Item(1)
    $ws.Cells.Item(1, 1).Value2 = 'Nome'; $ws.Cells.Item(2, 1).Value2 = 'Joao'
    $wb.SaveAs([string]'S:\planilha.xlsx', 51)
    $ms = WaitFor { Test-Path -LiteralPath "$B\planilha.xlsx" } 20
    Check 'T6a Excel SaveAs reaches the destination' ($ms -ge 0) "($ms ms)"
    $ws.Cells.Item(2, 2).Value2 = $CPF; $wb.Save()
    Start-Sleep -Seconds 8
    $t = DocText "$B\planilha.xlsx"
    Check 'T6b Excel save with a CPF is held; the destination keeps the clean version' (($t -notlike "*$CPF*") -and ($t -like '*Joao*')) ''
    $ws.Cells.Item(2, 2).Value2 = 'removido'; $wb.Save()
    $ms = WaitFor { (DocText "$B\planilha.xlsx") -like '*removido*' } 20
    Check 'T6c Excel corrected save published' ($ms -ge 0) "($ms ms)"
    $wb.Close($false); $x.Quit()
    [void][Runtime.InteropServices.Marshal]::ReleaseComObject($x)
}
Step 'T7' {
    $src = [IO.Path]::Combine($env:TEMP, 'origem')
    New-Item -ItemType Directory -Force -Path $src | Out-Null
    Set-Content -LiteralPath ([IO.Path]::Combine($src, 'a-limpo.txt')) -Value 'arquivo limpo'
    Set-Content -LiteralPath ([IO.Path]::Combine($src, 'b-cartao.txt')) -Value 'Cartao 4111 1111 1111 1111'
    New-Item -ItemType Directory -Path 'S:\copias' | Out-Null
    $sh = New-Object -ComObject Shell.Application
    $ns = $sh.NameSpace('S:\copias')
    $ns.CopyHere([string]([IO.Path]::Combine($src, 'a-limpo.txt')), 20)
    $ns.CopyHere([string]([IO.Path]::Combine($src, 'b-cartao.txt')), 20)
    $ms = WaitFor { Test-Path -LiteralPath "$B\copias\a-limpo.txt" } 20
    Check 'T7a Explorer copy of a clean file reaches the destination' ($ms -ge 0) "($ms ms)"
    Start-Sleep -Seconds 6
    Check 'T7b Explorer copy of a card number never reaches the destination' (-not (Test-Path -LiteralPath "$B\copias\b-cartao.txt")) ''
    Check 'T7c both copies are visible on S:' ((Test-Path -LiteralPath 'S:\copias\a-limpo.txt') -and (Test-Path -LiteralPath 'S:\copias\b-cartao.txt')) ''
}
Step 'T8' {
    Rename-Item -LiteralPath 'S:\limpo.txt' -NewName 'limpo2.txt'
    $ms = WaitFor { (Test-Path -LiteralPath "$B\limpo2.txt") -and -not (Test-Path -LiteralPath "$B\limpo.txt") } 15
    Check 'T8a rename reaches the destination' ($ms -ge 0) "($ms ms)"
    Remove-Item -LiteralPath 'S:\limpo2.txt'
    $ms = WaitFor { -not (Test-Path -LiteralPath "$B\limpo2.txt") } 15
    Check 'T8b delete reaches the destination' ($ms -ge 0) "($ms ms)"
    New-Item -ItemType Directory -Path 'S:\pasta' | Out-Null
    Rename-Item -LiteralPath 'S:\pasta' -NewName 'pasta2'
    Check 'T8c folder create + rename' ((Test-Path -LiteralPath "$B\pasta2") -and -not (Test-Path -LiteralPath "$B\pasta")) ''
    Remove-Item -LiteralPath 'S:\pasta2'
    Check 'T8d folder delete' (-not (Test-Path -LiteralPath "$B\pasta2")) ''
}

Step 'T9' {
    # Listen like the tray app, save a blocked file, then justify it through the justification pipe.
    $utf8 = New-Object Text.UTF8Encoding($false)
    $notices = New-Object IO.Pipes.NamedPipeClientStream('.', 'SafeUpload.Agent', [IO.Pipes.PipeDirection]::In)
    $notices.Connect(5000)
    $reader = New-Object IO.StreamReader($notices, $utf8)
    Set-Content -LiteralPath 'S:\justificar.txt' -Value "Cliente Joana, CPF $CPF" -Encoding UTF8
    $eventId = $null
    $sw = [Diagnostics.Stopwatch]::StartNew()
    $pending = $reader.ReadLineAsync()
    while ($eventId -eq $null -and $sw.Elapsed.TotalSeconds -lt 20) {
        if ($pending.Wait(1000)) {
            $line = $pending.Result
            if ($line -ne $null -and $line -match '"type":"transfer"' -and $line -match 'justificar' -and $line -match '"phase":"Blocked"') {
                if ($line -match '"transferId":"([0-9a-fA-F-]{36})"') { $eventId = $Matches[1] }
                Out ('  notice: ' + $line.Substring(0, [Math]::Min(220, $line.Length)))
            }
            if ($eventId -eq $null) { $pending = $reader.ReadLineAsync() }
        }
    }
    $notices.Dispose()
    Check 'T9a block notice reaches the user session with a justification id' ($eventId -ne $null) "id=$eventId"
    if ($eventId -ne $null) {
        $pipe = New-Object IO.Pipes.NamedPipeClientStream('.', 'SafeUpload.Agent.Justification', [IO.Pipes.PipeDirection]::InOut)
        $pipe.Connect(5000)
        $writer = New-Object IO.StreamWriter($pipe, $utf8)
        $writer.WriteLine('{"eventId":"' + $eventId + '","justification":"Envio autorizado pelo cliente (teste)"}')
        $writer.Flush()
        $answer = (New-Object IO.StreamReader($pipe, $utf8)).ReadLine()
        $pipe.Dispose()
        Check 'T9b justification accepted' ($answer -eq 'accepted') "answer=$answer"
        $ms = WaitFor { Test-Path -LiteralPath "$B\justificar.txt" } 15
        Check 'T9c the justified version reaches the destination' ($ms -ge 0) "($ms ms)"
    }
}

Out '--- destination'
Get-ChildItem -LiteralPath $B -Recurse -Force | ForEach-Object { Out ('  ' + $_.FullName.Substring($B.Length) + ' ' + $_.Length) }
Out '--- S:'
Get-ChildItem -LiteralPath 'S:\' -Recurse -Force | ForEach-Object { Out ('  ' + $_.FullName + ' ' + $_.Length) }
