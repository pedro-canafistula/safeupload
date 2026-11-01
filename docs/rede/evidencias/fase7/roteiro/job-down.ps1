$Q = 'C:\src\q'; $edge = 'C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe'
$p = Start-Process $edge -ArgumentList '--headless=new', '--disable-gpu', '--no-first-run', "--user-data-dir=$Q\profile", '--virtual-time-budget=8000', '--dump-dom', 'https://pt.wikipedia.org/wiki/Brasil' -PassThru -RedirectStandardOutput "$Q\down.out" -RedirectStandardError "$Q\down.err"
if (-not $p.WaitForExit(60000)) { $p | Stop-Process -Force }
$dom = Get-Content "$Q\down.out" -Raw
if ($dom -match '<title>([^<]*)</title>') { "titulo: " + $Matches[1] } else { "sem titulo; " + ([string]$dom).Length + " caracteres" }
if ($dom -match 'ERR_[A-Z_]+') { "erro do navegador: " + $Matches[0] }
