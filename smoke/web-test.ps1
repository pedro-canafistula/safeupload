# Runs as the VM administrator. The smoke policy turns web inspection on (web.inspect, one exception domain): the
# agent must divert the browsers, block an upload with a CPF through its proxy, let clean uploads and the exception
# domain through, and undo everything when the policy turns inspection off. The site is local: a self-signed HTTPS
# listener for smoke.safeupload.test and excecao.safeupload.test (both 127.0.0.1), trusted in LocalMachine\Root.
$ErrorActionPreference = 'Continue'
$queue = 'C:\ProgramData\SafeUpload\queue.jsonl'
function Check([string]$name, [bool]$ok, [string]$detail) {
    $word = 'FAIL'; if ($ok) { $word = 'PASS' }
    $word + ' ' + $name + ' ' + $detail
}
function Listening {
    try { $c = New-Object Net.Sockets.TcpClient; $c.Connect('127.0.0.1', 8877); $c.Close(); $true } catch { $false }
}
function WaitFor([scriptblock]$cond, [int]$seconds) {
    $sw = [Diagnostics.Stopwatch]::StartNew()
    while ($sw.Elapsed.TotalSeconds -lt $seconds) { if (& $cond) { return $true }; Start-Sleep -Seconds 2 }
    return [bool](& $cond)
}
function EdgeProxy { (Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Edge' -ErrorAction SilentlyContinue).ProxyServer }

# The clipboard test (as the user) ran before: its blocked paste is audited with the custom rule name.
$paste = Get-Content $queue -ErrorAction SilentlyContinue |
    Where-Object { $_ -match '"channel":"Clipboard"' -and $_ -match '"verdict":"Blocked"' } | Select-Object -Last 1
Check C3 ("$paste" -match '"customRules":\["Projeto Atlas"\]') ('blocked paste audited with the rule name: ' +
    ([regex]::Match("$paste", '"categories":\[[^\]]*\]').Value) + ' ' + ([regex]::Match("$paste", '"customRules":\[[^\]]*\]').Value))

Check W1 (WaitFor { Listening } 90) 'inspection proxy listening on 127.0.0.1:8877 (policy web.inspect)'
Check W2 ((EdgeProxy) -eq '127.0.0.1:8877') ('browsers diverted: Edge ProxyServer=' + (EdgeProxy))

# Local HTTPS site.
$names = 'smoke.safeupload.test', 'excecao.safeupload.test'
$cert = New-SelfSignedCertificate -DnsName $names -CertStoreLocation Cert:\LocalMachine\My -NotAfter (Get-Date).AddDays(1)
$root = New-Object Security.Cryptography.X509Certificates.X509Store('Root', 'LocalMachine')
$root.Open('ReadWrite'); $root.Add([Security.Cryptography.X509Certificates.X509Certificate2]::new($cert.RawData)); $root.Close()
Add-Content -LiteralPath "$env:SystemRoot\System32\drivers\etc\hosts" -Value "`r`n127.0.0.1 smoke.safeupload.test`r`n127.0.0.1 excecao.safeupload.test"
& netsh.exe http add sslcert ipport=0.0.0.0:9443 certhash=$($cert.Thumbprint) 'appid={5a3e0c47-6f1b-4a43-9a0e-2a5d6b7c9e11}' | Out-Null
Remove-Item C:\T5\site.log -ErrorAction SilentlyContinue
$site = Start-Job {
    $listener = New-Object Net.HttpListener; $listener.Prefixes.Add('https://+:9443/'); $listener.Start()
    while ($true) {
        $context = $listener.GetContext()
        $body = (New-Object IO.StreamReader($context.Request.InputStream)).ReadToEnd()
        Add-Content C:\T5\site.log ($context.Request.Url.Host + ' ' + $body.Length)
        $bytes = [Text.Encoding]::UTF8.GetBytes('ok'); $context.Response.OutputStream.Write($bytes, 0, 2); $context.Response.Close()
    }
}
# The job starts a new PowerShell; on a busy VM that takes more than a few seconds.
$siteUp = WaitFor { try { $c = New-Object Net.Sockets.TcpClient; $c.Connect('127.0.0.1', 9443); $c.Close(); $true } catch { $false } } 60
if (-not $siteUp) { 'FAIL W0 the local test site did not start: ' + (Receive-Job $site 2>&1 | Out-String) }
[IO.File]::WriteAllText('C:\T5\clientes-web.csv', "Cliente;CPF`r`nAna Souza;529.982.247-25`r`n")
[IO.File]::WriteAllText('C:\T5\limpo-web.csv', "Cliente;Cidade`r`nAna Souza;Recife`r`n")
# Prints the HTTP code and time, then curl's error if there was one (000 = no answer).
function Upload([string]$file, [string]$hostName) {
    $answer = & curl.exe -sS -o NUL -w '%{http_code} %{time_total}s' --max-time 60 --proxy http://127.0.0.1:8877 -F "arquivo=@$file" `
        "https://${hostName}:9443/upload" 2>&1
    (($answer | Out-String) -replace '\s+', ' ').Trim()
}
function Received([string]$hostName) { @(Get-Content C:\T5\site.log -ErrorAction SilentlyContinue | Where-Object { $_ -like "$hostName *" }).Count }

$code = Upload 'C:\T5\clientes-web.csv' 'smoke.safeupload.test'
Check W3 ($code -like '403 *' -and (Received 'smoke.safeupload.test') -eq 0) "upload with a CPF answered $code and the site received nothing"
$code = Upload 'C:\T5\limpo-web.csv' 'smoke.safeupload.test'
Check W4 ($code -like '200 *' -and (Received 'smoke.safeupload.test') -eq 1) "clean upload answered $code and reached the site"
$code = Upload 'C:\T5\clientes-web.csv' 'excecao.safeupload.test'
Check W5 ($code -like '200 *' -and (Received 'excecao.safeupload.test') -eq 1) "exception domain from the policy is not opened: answered $code"
$web = $null; $sw = [Diagnostics.Stopwatch]::StartNew()
while (-not $web -and $sw.Elapsed.TotalSeconds -lt 30) {
    $web = Get-Content $queue -ErrorAction SilentlyContinue |
        Where-Object { $_ -match '"channel":"Web"' -and $_ -match 'clientes-web\.csv' } | Select-Object -Last 1
    if (-not $web) { Start-Sleep -Seconds 2 }
}
Check W6 ("$web" -match '"verdict":"Blocked"' -and "$web" -match '"Cpf"') ('blocked upload audited: ' +
    ([regex]::Match("$web", '"verdict":"[A-Za-z]+"').Value) + ' ' + ([regex]::Match("$web", '"destinationPath":"[^"]*"').Value))

# What cannot be inspected does not leave, as on the drive: a broken document, and a body above the proxy's 64 MB limit
# when its start says it is a watched type. A large file of a type the policy does not watch goes through unrecorded.
function LastWebEvent([string]$name) {
    Get-Content $queue -ErrorAction SilentlyContinue | Where-Object { $_ -match '"channel":"Web"' -and $_ -match [regex]::Escape($name) } |
        Select-Object -Last 1
}
$broken = [byte[]](@(0x50, 0x4B, 0x03, 0x04) + (1..4000 | ForEach-Object { Get-Random -Maximum 256 }))
[IO.File]::WriteAllBytes('C:\T5\quebrado.docx', $broken)
& fsutil.exe file createnew C:\T5\base-grande.csv 73400320 | Out-Null
& fsutil.exe file createnew C:\T5\video-grande.mp4 73400320 | Out-Null
$before = Received 'smoke.safeupload.test'
$code = Upload 'C:\T5\quebrado.docx' 'smoke.safeupload.test'
Start-Sleep -Seconds 2
Check W8 ($code -like '403 *' -and (Received 'smoke.safeupload.test') -eq $before -and "$(LastWebEvent 'quebrado.docx')" -match '"verdict":"Blocked".*"notInspectedReason":"parse_error:') `
    "broken document blocked: answered $code, $([regex]::Match("$(LastWebEvent 'quebrado.docx')", '"notInspectedReason":"[^"]*"').Value)"
$code = Upload 'C:\T5\base-grande.csv' 'smoke.safeupload.test'
Start-Sleep -Seconds 2
Check W9 ($code -like '403 *' -and (Received 'smoke.safeupload.test') -eq $before -and "$(LastWebEvent 'base-grande.csv')" -match '"verdict":"Blocked".*"notInspectedReason":"file_too_large"') `
    "70 MB .csv blocked by its start: answered $code"
$code = Upload 'C:\T5\video-grande.mp4' 'smoke.safeupload.test'
Start-Sleep -Seconds 2
Check W10 ($code -like '200 *' -and (Received 'smoke.safeupload.test') -eq ($before + 1) -and -not (LastWebEvent 'video-grande.mp4')) `
    "70 MB .mp4 (not watched) went through unrecorded: answered $code"

# The policy turns web inspection off: the agent removes the diversion and stops the proxy within its 30 s check.
$path = 'C:\ProgramData\SafeUpload\policy.json'
$json = [IO.File]::ReadAllText($path) -replace '"version": 2', '"version": 3' -replace '"inspect": true', '"inspect": false'
[IO.File]::WriteAllText($path, $json, (New-Object Text.UTF8Encoding($false)))
& C:\Users\vika\Documents\su\scripts\Protect-SafeUploadPolicy.ps1 -PolicyPath $path | Out-Null
$off = WaitFor { -not (Listening) -and -not (EdgeProxy) } 90
Check W7 $off ('policy turned inspection off: proxy listening=' + (Listening) + ', Edge ProxyServer=' + (EdgeProxy))

Stop-Job $site; Remove-Job $site -Force
& netsh.exe http delete sslcert ipport=0.0.0.0:9443 | Out-Null
