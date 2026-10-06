$ErrorActionPreference='Stop'
if($env:COMPUTERNAME -ne 'DESKTOP-O1LP5DG' -or (Get-CimInstance Win32_ComputerSystemProduct).UUID -ne 'C6440689-D11C-4C63-A463-F3722B7DDB69' -or -not @(Get-NetAdapter|Where-Object {$_.MacAddress -eq '52-54-00-63-87-7A'}).Count){throw 'Wrong builder'}
if(@(Get-Process -Name msiexec,MSBuild,dotnet,csc,VBCSCompiler -ErrorAction SilentlyContinue).Count){throw 'Build actors present'}
if(Test-Path -LiteralPath ('C:\Users\vika\Documents\exact-driver-ownerdiag-20261006a')){throw 'Destination exists'}
if(Test-Path -LiteralPath ('C:\Users\vika\Documents\exact-driver-ownerdiag-20261006a.zip')){throw 'Destination exists'}
if(Test-Path -LiteralPath ('C:\Users\vika\Documents\exact-driver-ownerdiag-20261006a.manifest')){throw 'Destination exists'}
if(Test-Path -LiteralPath ('C:\Users\vika\Documents\Frozen-driver-ownerdiag-20261006a.ps1')){throw 'Destination exists'}
