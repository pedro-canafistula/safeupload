$ErrorActionPreference = 'Stop'
[Console]::OutputEncoding = New-Object System.Text.UTF8Encoding($false)
$OutputEncoding = New-Object System.Text.UTF8Encoding($false)
if ($env:COMPUTERNAME -ne 'DESKTOP-O1LP5DG' -or
    (Get-CimInstance Win32_ComputerSystemProduct).UUID -ne 'C6440689-D11C-4C63-A463-F3722B7DDB69' -or
    -not @(Get-NetAdapter | Where-Object { $_.MacAddress -eq '52-54-00-63-87-7A' }).Count) { throw 'Wrong builder.' }
if ($PSVersionTable.PSVersion.Major -ne 5 -or $PSVersionTable.PSVersion.Minor -ne 1 -or
    $PSVersionTable.PSEdition -ne 'Desktop' -or -not [Environment]::Is64BitProcess) { throw 'Windows PS 5.1 x64 required.' }
if ([Security.Principal.WindowsIdentity]::GetCurrent().User.Value -ne 'S-1-5-21-316478115-1595729549-2803163825-1001') { throw 'Ordinary Vika diagnostic user required.' }
$directory = 'C:\Users\vika\Documents\m2-t5-coordinator-r16-diag-1011-a1'
$expected = @{
    'notepad-coordinator.ps1' = 'C21757ED59ACD607138BE5EAAFBDBCD2192DD48DD840C80563CB5B21F22D291D'
    'notepad-coordinator.SelfCheck.ps1' = 'E64729A084D6D87DB93BFC99A41CC95537CBF3E5E2F2977BF53C49761758AFE8'
}
$current = [Diagnostics.Process]::GetCurrentProcess()
Write-Output ('CONTROL_PROCESS_ID=' + $current.Id + ';START_FILETIME=' + $current.StartTime.ToFileTimeUtc())
Write-Output ('PS_VERSION=' + $PSVersionTable.PSVersion + ';SID=' + [Security.Principal.WindowsIdentity]::GetCurrent().User.Value)
function Assert-ControlInputs {
    $items = @(Get-ChildItem -LiteralPath $directory -Force)
    if ($items.Count -ne 2) { throw 'Unexpected diagnostic directory membership.' }
    foreach ($item in $items) {
        if ($item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0 -or
            -not $expected.ContainsKey($item.Name) -or
            (Get-FileHash -LiteralPath $item.FullName -Algorithm SHA256).Hash -cne $expected[$item.Name]) { throw 'Source pin or file type differs.' }
    }
}
Assert-ControlInputs
foreach ($name in @($expected.Keys | Sort-Object)) {
    $tokens = $null; $parseErrors = $null
    [void][Management.Automation.Language.Parser]::ParseFile((Join-Path $directory $name), [ref]$tokens, [ref]$parseErrors)
    Write-Output ($name + ':ParseErrors=' + @($parseErrors).Count + ';SHA256=' + $expected[$name])
    if (@($parseErrors).Count -ne 0) { $parseErrors | ForEach-Object { Write-Output $_.Message }; throw 'Parser errors.' }
}
$output = @(& (Join-Path $directory 'notepad-coordinator.SelfCheck.ps1') -CoordinatorPath (Join-Path $directory 'notepad-coordinator.ps1'))
$output | ForEach-Object { Write-Output $_ }
$passes = @($output | Where-Object { [string]$_ -match '^T5 coordinator schema self-check PASS \([1-9][0-9]* assertions\)\.$' })
if ($passes.Count -ne 1) { throw 'Missing or ambiguous complete self-check PASS.' }
Assert-ControlInputs
Write-Output 'T5_COORDINATOR_STANDALONE_DIAGNOSTIC=PASS'
