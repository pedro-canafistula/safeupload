# Sessao interativa: Edge com janela de verdade (nao headless), captura da tela.
$Q = 'C:\src\q'; $edge = 'C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe'
$shots = "$Q\shots-real"; New-Item -ItemType Directory -Force $shots | Out-Null
Add-Type -AssemblyName System.Windows.Forms, System.Drawing
function Shot([string]$name) {
    $b = [System.Windows.Forms.Screen]::PrimaryScreen.Bounds
    $bmp = New-Object System.Drawing.Bitmap $b.Width, $b.Height
    $g = [System.Drawing.Graphics]::FromImage($bmp); $g.CopyFromScreen($b.Location, [System.Drawing.Point]::Empty, $b.Size)
    $bmp.Save("$shots\$name.png"); $g.Dispose(); $bmp.Dispose()
}
Get-Process SafeUpload.Agent.App -ErrorAction SilentlyContinue | Stop-Process -Force
$sites = [ordered]@{ chatgpt = 'https://chatgpt.com/'; claude = 'https://claude.ai/'; drive = 'https://drive.google.com/'; outlook = 'https://outlook.live.com/'; policy = 'edge://policy' }
foreach ($name in $sites.Keys) {
    Get-Process msedge -ErrorAction SilentlyContinue | Stop-Process -Force; Start-Sleep 1
    Start-Process $edge -ArgumentList '--no-first-run', '--start-maximized', "--user-data-dir=$Q\profile-real", $sites[$name]
    Start-Sleep 25
    Shot $name
    "$name capturado"
}
Get-Process msedge -ErrorAction SilentlyContinue | Stop-Process -Force
