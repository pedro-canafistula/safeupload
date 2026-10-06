$ErrorActionPreference='Stop'
if($env:COMPUTERNAME -cne 'DESKTOP-O1LP5DG' -or (Get-CimInstance Win32_ComputerSystemProduct).UUID -cne 'C6440689-D11C-4C63-A463-F3722B7DDB69'){throw 'Wrong builder'}
'StartPublicRead'
$p='C:\Users\vika\Documents\exact-mvp20261006admissioncap2\replacement-machine-key-v8-metadata.json'
$m=Get-Content -LiteralPath $p -Raw|ConvertFrom-Json
'MetadataLoaded'
(Get-FileHash -LiteralPath $p -Algorithm SHA256).Hash
(Get-FileHash -LiteralPath $m.PublicCerPath -Algorithm SHA256).Hash
'HashesRead'
(Get-Acl -LiteralPath $m.KeyFilePath).Sddl
'AclRead'
