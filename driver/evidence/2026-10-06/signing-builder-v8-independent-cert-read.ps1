$ErrorActionPreference='Stop'
if($env:COMPUTERNAME -cne 'DESKTOP-O1LP5DG' -or (Get-CimInstance Win32_ComputerSystemProduct).UUID -cne 'C6440689-D11C-4C63-A463-F3722B7DDB69'){throw 'Wrong builder'}
'BeforeMachineCertificate'
$c=Get-Item -LiteralPath 'Cert:\LocalMachine\My\A6D6CE1AA28835D509160A80ADB7894869AADF38'
'AfterMachineCertificate'
$c.Thumbprint
$c.HasPrivateKey
'BeforePublicCertificate'
$f=[Security.Cryptography.X509Certificates.X509Certificate2]::new('C:\safeupload-pkg\SafeUploadTest-Recovery-20261006-v8.cer')
'AfterPublicCertificate'
$f.Thumbprint
