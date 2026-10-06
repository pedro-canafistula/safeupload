$ErrorActionPreference='Stop'
if($env:COMPUTERNAME -ne 'DESKTOP-O1LP5DG' -or (Get-CimInstance Win32_ComputerSystemProduct).UUID -ne 'C6440689-D11C-4C63-A463-F3722B7DDB69'){throw 'Wrong builder'}
try { $p=Split-Path -LiteralPath 'C:\Users\vika\Documents\SafeUploadDependencyReview-WinFsp-v2.2B4-20261006\winfsp-2.2.26215.msi' -Parent; @{Result=$p;ParameterBindingPassed=$true}|ConvertTo-Json -Compress } catch { @{ParameterBindingPassed=$false;Message=$_.Exception.Message;ErrorId=$_.FullyQualifiedErrorId}|ConvertTo-Json -Compress;exit 3 }
