$ErrorActionPreference='Stop'
if ($env:COMPUTERNAME -ne 'DESKTOP-O1LP5DG' -or (Get-CimInstance Win32_ComputerSystemProduct).UUID -ne 'C6440689-D11C-4C63-A463-F3722B7DDB69') { throw 'Wrong builder' }
$p='C:\Users\vika\Documents\m2-t5-coordinator-r17-diag-1011-a1'
$expected=@{ 'notepad-coordinator.ps1'='C21757ED59ACD607138BE5EAAFBDBCD2192DD48DD840C80563CB5B21F22D291D';'notepad-coordinator.SelfCheck.ps1'='BE52114A729E2861AFCCF6C73D900D5B03FC9F476E3664A64F10F959CB33AE47' }
$items=@(Get-ChildItem -LiteralPath $p -Force)
if ($items.Count -ne 2) { throw 'Membership changed' }
foreach($item in $items) {
 if ($item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0 -or -not $expected.ContainsKey($item.Name) -or (Get-FileHash -LiteralPath $item.FullName -Algorithm SHA256).Hash -cne $expected[$item.Name]) { throw 'Source changed' }
 Write-Output ($item.Name+':POST_SHA256='+$expected[$item.Name])
}
$process=Get-Process -Id 5328 -ErrorAction SilentlyContinue
if ($null -ne $process -and $process.StartTime.ToFileTimeUtc() -eq 134362013037965246) { throw 'Original diagnostic process still live' }
Write-Output 'PINNED_SOURCES_UNCHANGED_AND_ORIGINAL_PROCESS_TERMINAL'
