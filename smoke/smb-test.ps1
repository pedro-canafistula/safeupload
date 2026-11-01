# Runs as t5actor: the share \\localhost\Compartilhado gets a SafeUpload drive and direct writes to it are refused.
$CPF = '529.982.247-25'
$share = '\\localhost\Compartilhado'
function Check([string]$name, [bool]$ok, [string]$detail) {
    $word = 'FAIL'; if ($ok) { $word = 'PASS' }
    Out ($word + ' ' + $name + ' ' + $detail)
}
function WaitFor([scriptblock]$cond, [int]$seconds) {
    $sw = [Diagnostics.Stopwatch]::StartNew()
    while ($sw.Elapsed.TotalSeconds -lt $seconds) {
        $ok = $false
        try { $ok = [bool](& $cond) } catch { $ok = $false }
        if ($ok) { return [int]$sw.Elapsed.TotalMilliseconds }
        Start-Sleep -Milliseconds 500
    }
    return -1
}

$drive = $null
$ms = WaitFor {
    $script:drive = (Get-CimInstance Win32_LogicalDisk | Where-Object { $_.VolumeName -eq 'SafeUpload-Compartilhado' } |
        Select-Object -First 1).DeviceID
    $script:drive
} 60
Check 'N0 the share gets a SafeUpload drive' ($ms -ge 0) "drive=$drive"
if ($ms -lt 0) { return }

Set-Content -LiteralPath "$drive\relatorio-rede.txt" -Value 'relatorio sem dados pessoais'
$ms = WaitFor { Test-Path -LiteralPath "$share\relatorio-rede.txt" } 20
Check 'N1 a clean file reaches the share' ($ms -ge 0) "($ms ms)"

Set-Content -LiteralPath "$drive\clientes-rede.txt" -Value "CPF $CPF"
Start-Sleep -Seconds 6
Check 'N2 a sensitive file never reaches the share' (-not (Test-Path -LiteralPath "$share\clientes-rede.txt")) ''

try { [IO.File]::WriteAllText("$share\direto.txt", 'x'); Check 'N3 direct write to the share refused' $false 'write succeeded' }
catch { Check 'N3 direct write to the share refused' $true '' }
Out ('share: ' + ((Get-ChildItem -LiteralPath $share -Force | ForEach-Object { $_.Name }) -join ', '))
