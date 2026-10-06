$ErrorActionPreference='Stop';$product=Get-CimInstance Win32_ComputerSystemProduct
if($env:COMPUTERNAME -cne 'DESKTOP-O1LP5DG' -or $product.UUID -cne 'C6440689-D11C-4C63-A463-F3722B7DDB69'){throw 'Builder identity mismatch.'}
$o=Join-Path $env:TEMP ('safeupload-csplist-'+[Guid]::NewGuid().ToString('N')+'.stdout.bin');$e=$o.Replace('.stdout.bin','.stderr.bin')
$p=Start-Process -FilePath (Join-Path $env:windir 'System32\certutil.exe') -ArgumentList '-csplist' -NoNewWindow -Wait -PassThru -RedirectStandardOutput $o -RedirectStandardError $e
$ob=[IO.File]::ReadAllBytes($o);$eb=[IO.File]::ReadAllBytes($e)
[ordered]@{Status='Completed';UTC=[DateTime]::UtcNow.ToString('o');ComputerName=$env:COMPUTERNAME;UUID=$product.UUID;Exit=$p.ExitCode;StdoutBase64=[Convert]::ToBase64String($ob);StderrBase64=[Convert]::ToBase64String($eb)}|ConvertTo-Json -Compress
