$ErrorActionPreference='Stop'
if ($env:COMPUTERNAME -ne 'DESKTOP-O1LP5DG' -or (Get-CimInstance Win32_ComputerSystemProduct).UUID -ne 'C6440689-D11C-4C63-A463-F3722B7DDB69') { throw 'Wrong builder' }
$p='C:\Users\vika\Documents\m2-t5-harness-r21-receipt-control-1011-a2'
$expected=@{ 'HarnessWindowsGateProtocol.psm1'='F9DBA8569C7BF2FAFEF648C5B6D49211EE299B6ADC4651733DFB5ACBBD6F251A';'Invoke-R21ReceiptWriterControl.ps1'='265B1BEF47B4B5CCD907CFC5F8427BBFEE5113F583AE8136D042E5D041F1B3C0' }
$items=@(Get-ChildItem -LiteralPath $p -Force)
if ($items.Count -ne 2) { throw 'Membership changed' }
foreach($item in $items) {
 if ($item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0 -or -not $expected.ContainsKey($item.Name) -or (Get-FileHash -LiteralPath $item.FullName -Algorithm SHA256).Hash -cne $expected[$item.Name]) { throw 'Source changed' }
 Write-Output ($item.Name+':POST_SHA256='+$expected[$item.Name])
}
$process=Get-Process -Id 2116 -ErrorAction SilentlyContinue
if ($null -ne $process -and $process.StartTime.ToFileTimeUtc() -eq 134362011021749534) { throw 'Original diagnostic process still live' }
Write-Output 'PINNED_SOURCES_UNCHANGED_AND_ORIGINAL_PROCESS_TERMINAL'

$fixture='C:\Users\vika\AppData\Local\Temp\SafeUpload-HarnessGate-ReceiptControl-96886a8fb3244ba7bb272d329cb74c05'
if (Test-Path -LiteralPath $fixture) { throw 'Success fixture still exists' }
Write-Output 'OWNED_FIXTURE_ABSENT_AFTER_SUCCESS'
