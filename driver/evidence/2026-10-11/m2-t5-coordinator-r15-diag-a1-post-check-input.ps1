$ErrorActionPreference='Stop'
if ($env:COMPUTERNAME -ne 'DESKTOP-O1LP5DG' -or (Get-CimInstance Win32_ComputerSystemProduct).UUID -ne 'C6440689-D11C-4C63-A463-F3722B7DDB69') { throw 'Wrong builder' }
$p='C:\Users\vika\Documents\m2-t5-coordinator-r15-diag-1011-a1'
$expected=@{ 'notepad-coordinator.ps1'='C21757ED59ACD607138BE5EAAFBDBCD2192DD48DD840C80563CB5B21F22D291D';'notepad-coordinator.SelfCheck.ps1'='DBC00A84C456B97F6903CFCB4CCC0BA37C5FF763FC6B67E83AAB3E86E807245F' }
$items=@(Get-ChildItem -LiteralPath $p -Force)
if ($items.Count -ne 2) { throw 'Membership changed' }
foreach($item in $items) {
 if ($item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0 -or -not $expected.ContainsKey($item.Name) -or (Get-FileHash -LiteralPath $item.FullName -Algorithm SHA256).Hash -cne $expected[$item.Name]) { throw 'Source changed' }
 Write-Output ($item.Name+':POST_SHA256='+$expected[$item.Name])
}
$process=Get-Process -Id 2672 -ErrorAction SilentlyContinue
if ($null -ne $process -and $process.StartTime.ToFileTimeUtc() -eq 134361997802714102) { throw 'Original diagnostic process still live' }
Write-Output 'PINNED_SOURCES_UNCHANGED_AND_ORIGINAL_PROCESS_TERMINAL'
