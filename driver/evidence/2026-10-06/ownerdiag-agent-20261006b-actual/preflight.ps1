$ErrorActionPreference='Stop'
if($env:COMPUTERNAME -ne 'DESKTOP-O1LP5DG' -or (Get-CimInstance Win32_ComputerSystemProduct).UUID -ne 'C6440689-D11C-4C63-A463-F3722B7DDB69' -or -not @(Get-NetAdapter|Where-Object {$_.MacAddress -eq '52-54-00-63-87-7A'}).Count){throw 'Wrong builder'}
if(@(Get-Process -Name msiexec,MSBuild,dotnet,csc,VBCSCompiler -ErrorAction SilentlyContinue).Count){throw 'Build actors present'}
if(Test-Path -LiteralPath ('C:\Users\vika\Documents\exact-agent-matrix-agent-ownerdiag-20261006b')){throw 'Destination exists'}
if(Test-Path -LiteralPath ('C:\Users\vika\Documents\exact-agent-matrix-agent-ownerdiag-20261006b.zip')){throw 'Destination exists'}
if(Test-Path -LiteralPath ('C:\Users\vika\Documents\exact-agent-matrix-agent-ownerdiag-20261006b.manifest')){throw 'Destination exists'}
if(Test-Path -LiteralPath ('C:\Users\vika\Documents\Frozen-agent-ownerdiag-20261006b.ps1')){throw 'Destination exists'}
