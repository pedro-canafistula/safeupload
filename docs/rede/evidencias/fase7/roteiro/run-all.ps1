. C:\src\q\lib.ps1
Get-Process SafeUpload.Agent.App -ErrorAction SilentlyContinue | Stop-Process -Force
Get-Process msedge -ErrorAction SilentlyContinue | Stop-Process -Force
Stop-Agent
& $Svc desvio remove | Out-Null
Remove-Item $Q\shots, $Q\shots-base, $Q\profile -Recurse -Force -ErrorAction SilentlyContinue

"##### SEM O PROXY (referencia)"
Set-Content $Q\mode.txt baseline
Invoke-Interactive "$Q\job-browser.ps1" 1500

"##### COM O PROXY"
Remove-Item C:\ProgramData\SafeUpload -Recurse -Force -ErrorAction SilentlyContinue
Remove-Item $Q\profile -Recurse -Force -ErrorAction SilentlyContinue
"servico no ar: " + (Start-Agent)
Invoke-Interactive "$Q\job-app.ps1" 60 | Out-Null
Set-Content $Q\mode.txt proxy
Invoke-Interactive "$Q\job-browser.ps1" 1500

"=== latencia com curl (mediana de 5, segundos): direto x pelo proxy"
foreach ($u in 'https://www.google.com/', 'https://pt.wikipedia.org/', 'https://github.com/', 'https://httpbin.org/get', 'https://www.gov.br/pt-br') {
    $d = 1..5 | ForEach-Object { [double](curl.exe -s -o NUL -w '%{time_total}' --max-time 30 $u) } | Sort-Object
    $p = 1..5 | ForEach-Object { [double](curl.exe -s -o NUL -w '%{time_total}' --max-time 30 -x http://127.0.0.1:8877 $u) } | Sort-Object
    "{0,-28} direto {1:N3}  proxy {2:N3}  diferenca {3:N0} ms" -f $u, $d[2], $p[2], (($p[2] - $d[2]) * 1000)
}
"=== log do servico"
Get-Content $Q\svc.log | Select-String 'Envio |recusou|Falha ao|Certificado do servidor|fail:|warn:' | ForEach-Object { $_.Line.Trim() } | Group-Object | ForEach-Object { "{0,3}x {1}" -f $_.Count, $_.Name } | Select-Object -First 40
"=== fila de auditoria"
Get-Content C:\ProgramData\SafeUpload\queue.jsonl -ErrorAction SilentlyContinue | ForEach-Object { $e = $_ | ConvertFrom-Json; "{0} {1} user={2} file='{3}' dest={4} cat={5}" -f $e.channel, $e.verdict, $e.userName, $e.fileName, $e.destinationPath, ($e.categories -join ',') }
