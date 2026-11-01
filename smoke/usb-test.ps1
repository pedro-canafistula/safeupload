# Runs as t5actor after a USB stick was attached: the stick gets its own SafeUpload drive and direct writes are refused.
$CPF = '529.982.247-25'
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

$stick = $null; $drive = $null
$ms = WaitFor {
    $script:stick = (Get-CimInstance Win32_LogicalDisk -Filter 'DriveType=2' | Select-Object -First 1).DeviceID
    $script:drive = (Get-CimInstance Win32_LogicalDisk | Where-Object { $_.VolumeName -like 'SafeUpload-USB-*' } |
        Select-Object -First 1).DeviceID
    $script:stick -and $script:drive
} 90
Check 'U0 the stick gets a SafeUpload drive' ($ms -ge 0) "stick=$stick drive=$drive ($ms ms)"
if ($ms -lt 0) { return }

Set-Content -LiteralPath "$drive\limpo-usb.txt" -Value 'arquivo limpo para o pendrive'
$ms = WaitFor { Test-Path -LiteralPath "$stick\limpo-usb.txt" } 20
Check 'U1 a clean file reaches the stick' ($ms -ge 0) "($ms ms)"

Set-Content -LiteralPath "$drive\cpf-usb.txt" -Value "CPF $CPF"
Start-Sleep -Seconds 6
Check 'U2 a sensitive file never reaches the stick' (-not (Test-Path -LiteralPath "$stick\cpf-usb.txt")) ''

try { [IO.File]::WriteAllText("$stick\direto.txt", 'x'); Check 'U3 direct write to the stick refused' $false 'write succeeded' }
catch { Check 'U3 direct write to the stick refused' $true '' }
Out ('stick: ' + ((Get-ChildItem -LiteralPath "$stick\" -Force | ForEach-Object { $_.Name }) -join ', '))
