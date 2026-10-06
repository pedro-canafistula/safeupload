$ErrorActionPreference='Stop'
$uuid=(Get-CimInstance Win32_ComputerSystemProduct).UUID
$identity=[Security.Principal.WindowsIdentity]::GetCurrent()
if($env:COMPUTERNAME -cne 'DESKTOP-O1LP5DG' -or $uuid -cne 'C6440689-D11C-4C63-A463-F3722B7DDB69' -or $identity.User.Value -cne 'S-1-5-21-316478115-1595729549-2803163825-1001'){throw 'Builder identity mismatch'}
$stores=[ordered]@{}
foreach($scope in @('CurrentUser','LocalMachine')){foreach($name in @('My','Root','TrustedPublisher')){$path='Cert:\'+$scope+'\'+$name;$stores[$scope+'\'+$name]=@((Get-ChildItem -LiteralPath $path -ErrorAction Stop).Thumbprint|Sort-Object)}}
$files=@();foreach($path in @('C:\safeupload-cert\SafeUploadTest.pfx','C:\safeupload-cert\SafeUploadTest.cer')){$item=Get-Item -LiteralPath $path;$files+=@([ordered]@{Path=$path;Length=$item.Length;SHA256=(Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash})}
$old=Get-Item -LiteralPath 'Cert:\CurrentUser\My\220DD82C37FCF36048D59E4F10113185D81D5DC7'
$bcd=& bcdedit.exe /enum '{current}' 2>&1|Out-String;if($LASTEXITCODE -ne 0){throw 'Boot configuration read failed'}
$actors=@(Get-Process -Name MSBuild,dotnet,csc,vbcsc,VBCSCompiler -ErrorAction SilentlyContinue|ForEach-Object{[ordered]@{Name=$_.ProcessName;Id=$_.Id;StartTimeUtc=$_.StartTime.ToUniversalTime().ToString('o')}})
[ordered]@{BootTimeUtc=(Get-CimInstance Win32_OperatingSystem -ErrorAction Stop).LastBootUpTime.ToUniversalTime().ToString('o');UTC=[DateTime]::UtcNow.ToString('o');ComputerName=$env:COMPUTERNAME;UUID=$uuid;SID=$identity.User.Value;Stores=$stores;OriginalFiles=$files;OriginalCertificate=[ordered]@{Thumbprint=$old.Thumbprint;Subject=$old.Subject;HasPrivateKey=$old.HasPrivateKey};TestSigningLine=([regex]::Match($bcd,'(?im)^testsigning\s+\S+').Value);BuildProcesses=$actors;StateMutated=$false}|ConvertTo-Json -Depth 6 -Compress
