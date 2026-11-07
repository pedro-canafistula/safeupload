# Runs as t5actor in the interactive session, with the tray app running (run.sh adds Out and the DONE line).
# Policy clipboard.mode Block: a copy with sensitive data pastes normally into a local app and as the warning into an
# egress app. The destination is the process that owns the foreground window, so each paste is a small window in a
# copy of powershell.exe named like the app it stands for (chrome is on the agent's egress list, editorlocal is not).
function Check([string]$name, [bool]$ok, [string]$detail) {
    $word = 'FAIL'; if ($ok) { $word = 'PASS' }
    Out ($word + ' ' + $name + ' ' + $detail)
}

$reader = @'
param([string]$OutPath)
Add-Type -AssemblyName System.Windows.Forms
Add-Type -Namespace W -Name U -MemberDefinition @"
[DllImport("user32.dll")] public static extern bool SetForegroundWindow(IntPtr h);
[DllImport("user32.dll")] public static extern IntPtr GetForegroundWindow();
[DllImport("user32.dll")] public static extern void keybd_event(byte k, byte s, int f, int e);
"@
$form = New-Object Windows.Forms.Form
$form.Text = 'SafeUpload smoke paste'
$form.TopMost = $true
$timer = New-Object Windows.Forms.Timer
$timer.Interval = 1500
$form.Add_Shown({
    # A tap of Alt lets a process started by the task scheduler take the foreground.
    [W.U]::keybd_event(0x12, 0, 0, 0); [W.U]::keybd_event(0x12, 0, 2, 0)
    [void][W.U]::SetForegroundWindow($form.Handle); $form.Activate(); $timer.Start() })
$timer.Add_Tick({
    $timer.Stop()
    $foreground = [W.U]::GetForegroundWindow() -eq $form.Handle
    $text = [Windows.Forms.Clipboard]::GetText()
    [IO.File]::WriteAllText($OutPath, "foreground=$foreground`n$text")
    $form.Close() })
[Windows.Forms.Application]::Run($form)
'@
[IO.File]::WriteAllText('C:\T5\paste-read.ps1', $reader)
Copy-Item "$PSHOME\powershell.exe" 'C:\T5\chrome.exe' -Force
Copy-Item "$PSHOME\powershell.exe" 'C:\T5\editorlocal.exe' -Force

$copied = 'Projeto Atlas: aditivos CT-2041/26 e CT-2042/26. Cliente CPF 529.982.247-25'
Set-Clipboard -Value $copied
Start-Sleep -Seconds 3
foreach ($app in 'editorlocal', 'chrome') {
    Remove-Item "C:\T5\paste-$app.txt" -ErrorAction SilentlyContinue
    $p = Start-Process "C:\T5\$app.exe" -ArgumentList '-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', 'C:\T5\paste-read.ps1',
        '-OutPath', "C:\T5\paste-$app.txt" -PassThru
    [void]$p.WaitForExit(30000)
    Start-Sleep -Seconds 2
}
# The pasted text ends with the NUL terminator of CF_UNICODETEXT when read this way; it is not part of the text.
$local = ([string](Get-Content 'C:\T5\paste-editorlocal.txt' -Raw -ErrorAction SilentlyContinue)) -replace "`0", ''
$egress = ([string](Get-Content 'C:\T5\paste-chrome.txt' -Raw -ErrorAction SilentlyContinue)) -replace "`0", ''
Check C1 ([string]$local).Contains($copied) ('local app got the copied text (' + ([string]$local).Split("`n")[0] + ')')
Check C2 (([string]$egress).Contains('[SafeUpload]') -and -not ([string]$egress).Contains('529.982.247-25')) `
    ('egress app got the warning instead of the text: ' + (([string]$egress) -replace "`r?`n", ' | '))
