# Sessao interativa: Edge de verdade (headless), com as politicas e o filtro em vigor.
$Q = 'C:\src\q'
$edge = 'C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe'
$mode = (Get-Content "$Q\mode.txt" -ErrorAction SilentlyContinue | Select-Object -First 1)
$shots = if ($mode -eq 'baseline') { "$Q\shots-base" } else { "$Q\shots" }; New-Item -ItemType Directory -Force $shots | Out-Null
function Edge([string[]]$extra, [int]$timeout = 60) {
    $common = @('--headless=new', '--disable-gpu', '--no-first-run', '--hide-scrollbars', "--user-data-dir=$Q\profile", '--window-size=1280,900')
    $p = Start-Process $edge -ArgumentList ($common + $extra) -PassThru -RedirectStandardOutput "$Q\edge.out" -RedirectStandardError "$Q\edge.err"
    if (-not $p.WaitForExit($timeout * 1000)) { $p | Stop-Process -Force; return 'TIMEOUT' }
    return 'ok'
}
function Shot-Desktop([string]$name) {
    Add-Type -AssemblyName System.Windows.Forms, System.Drawing
    $b = [System.Windows.Forms.Screen]::PrimaryScreen.Bounds
    $bmp = New-Object System.Drawing.Bitmap $b.Width, $b.Height
    $g = [System.Drawing.Graphics]::FromImage($bmp)
    $g.CopyFromScreen($b.Location, [System.Drawing.Point]::Empty, $b.Size)
    $bmp.Save("$shots\$name.png"); $g.Dispose(); $bmp.Dispose()
}

if ($mode -ne 'baseline') {
"=== uploads pelo Edge (pagina local com fetch)"
Edge @('--virtual-time-budget=60000', '--dump-dom', "file:///C:/src/q/upload.html") 120 | Out-Null
(Get-Content "$Q\edge.out" -Raw) -replace '(?s).*<pre id="r">', '' -replace '(?s)</pre>.*', ''
Start-Sleep 3
Shot-Desktop 'desktop-apos-bloqueio'

"=== formulario HTML enviado por navegacao"
Edge @('--virtual-time-budget=20000', '--dump-dom', "file:///C:/src/q/form.html") 60 | Out-Null
$dom = Get-Content "$Q\edge.out" -Raw
if ($dom -match 'SafeUpload bloqueou[^<]*') { "pagina mostrada: " + $Matches[0] } else { "pagina mostrada (inicio): " + $dom.Substring(0, [Math]::Min(200, $dom.Length)) }

}
"=== matriz de sites"
$sites = [ordered]@{
    google = 'https://www.google.com/'; wikipedia = 'https://pt.wikipedia.org/wiki/Brasil'; github = 'https://github.com/dotnet/runtime'
    youtube = 'https://www.youtube.com/'; drive = 'https://drive.google.com/'; gmail = 'https://mail.google.com/'
    chatgpt = 'https://chatgpt.com/'; outlook = 'https://outlook.live.com/'; whatsapp = 'https://web.whatsapp.com/'
    dropbox = 'https://www.dropbox.com/'; wetransfer = 'https://wetransfer.com/'; onedrive = 'https://onedrive.live.com/'
    bb = 'https://www.bb.com.br/'; govbr = 'https://www.gov.br/pt-br'; claude = 'https://claude.ai/'; gemini = 'https://gemini.google.com/'
}
foreach ($name in $sites.Keys) {
    $sw = [Diagnostics.Stopwatch]::StartNew()
    $r = Edge @('--virtual-time-budget=12000', "--screenshot=$shots\$name.png", $sites[$name]) 90
    $size = if (Test-Path "$shots\$name.png") { (Get-Item "$shots\$name.png").Length } else { 0 }
    "{0,-10} {1,-8} {2,5} ms  png {3,7} bytes" -f $name, $r, $sw.ElapsedMilliseconds, $size
}
