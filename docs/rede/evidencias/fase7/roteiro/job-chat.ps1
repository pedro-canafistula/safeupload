# Sessao interativa: digita num ChatGPT de verdade (sem login) e captura a tela.
$Q = 'C:\src\q'; $edge = 'C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe'
$shots = "$Q\shots-chat"; New-Item -ItemType Directory -Force $shots | Out-Null
Add-Type -AssemblyName System.Windows.Forms, System.Drawing
function Shot([string]$name) {
    $b = [System.Windows.Forms.Screen]::PrimaryScreen.Bounds
    $bmp = New-Object System.Drawing.Bitmap $b.Width, $b.Height
    $g = [System.Drawing.Graphics]::FromImage($bmp); $g.CopyFromScreen($b.Location, [System.Drawing.Point]::Empty, $b.Size)
    $bmp.Save("$shots\$name.png"); $g.Dispose(); $bmp.Dispose()
}
Get-Process msedge -ErrorAction SilentlyContinue | Stop-Process -Force; Start-Sleep 1
Start-Process 'C:\src\agente\SafeUpload.Agent.App\bin\Release\net10.0-windows\SafeUpload.Agent.App.exe'
$p = Start-Process $edge -ArgumentList '--no-first-run', '--start-maximized', '--hide-crash-restore-bubble', "--user-data-dir=$Q\profile-real", 'https://chatgpt.com/' -PassThru
Start-Sleep 25
$shell = New-Object -ComObject WScript.Shell
[void]$shell.AppActivate('ChatGPT')
Start-Sleep 1
[System.Windows.Forms.SendKeys]::SendWait('qual a capital da Franca?{ENTER}')
Start-Sleep 25
Shot '1-prompt-limpo'
[void]$shell.AppActivate('ChatGPT')
[System.Windows.Forms.SendKeys]::SendWait('confira o cadastro do cliente de cpf 529.982.247-25{ENTER}')
Start-Sleep 25
Shot '2-prompt-com-cpf'
Get-Process msedge -ErrorAction SilentlyContinue | Stop-Process -Force
"feito"
