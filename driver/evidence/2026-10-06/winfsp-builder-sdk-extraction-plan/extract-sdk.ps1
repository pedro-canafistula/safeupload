[CmdletBinding()]
param([Parameter(Mandatory)][string]$MsiPath,
      [Parameter(Mandatory)][string]$FreshTargetDirectory,
      [Parameter(Mandatory)][string]$FreshLogPath)
$ErrorActionPreference='Stop'
if($env:COMPUTERNAME -cne 'DESKTOP-O1LP5DG' -or
   (Get-CimInstance Win32_ComputerSystemProduct).UUID -cne 'C6440689-D11C-4C63-A463-F3722B7DDB69') { throw 'Wrong builder' }
if([Security.Principal.WindowsIdentity]::GetCurrent().User.Value -cne 'S-1-5-21-316478115-1595729549-2803163825-1001') { throw 'Wrong user' }
$root='C:\Users\vika\Documents\SafeUploadWinFspSdk-20261006-'
if(-not $FreshTargetDirectory.StartsWith($root,[StringComparison]::Ordinal) -or
   $FreshTargetDirectory.Substring($root.Length) -notmatch '^[0-9a-f]{32}$' -or
   $FreshLogPath -cne ($FreshTargetDirectory+'.log')) { throw 'Invalid extraction target' }
if((Test-Path -LiteralPath $FreshTargetDirectory) -or (Test-Path -LiteralPath $FreshLogPath)) { throw 'Target exists' }
$msi=Get-Item -LiteralPath $MsiPath
if($msi.PSIsContainer -or ($msi.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw 'Invalid MSI file' }
if((Get-FileHash -LiteralPath $MsiPath -Algorithm SHA256).Hash -cne '2ECB5C89405488A95BBD8A01875E02C48534FD37BBDFD84488F7590464D65944') { throw 'MSI hash mismatch' }
$s=Get-AuthenticodeSignature -LiteralPath $MsiPath
if($s.Status.ToString() -cne 'Valid' -or $s.SignerCertificate.Thumbprint -cne '75C6C88B0B6C4556F13FCE3B081FC9051EAE457E') { throw 'Publisher signature mismatch' }
if(@(Get-Process -Name msiexec,MSBuild,dotnet,csc,VBCSCompiler -ErrorAction SilentlyContinue).Count) { throw 'Unexpected installer/build actors' }
$installer=New-Object -ComObject WindowsInstaller.Installer
$db=$installer.GetType().InvokeMember('OpenDatabase','InvokeMethod',$null,$installer,@($MsiPath,0))
$view=$db.GetType().InvokeMember('OpenView','InvokeMethod',$null,$db,@('SELECT `Action`,`Condition`,`Sequence` FROM `AdminExecuteSequence` ORDER BY `Sequence`'))
$rows=@()
try {
    $view.GetType().InvokeMember('Execute','InvokeMethod',$null,$view,$null)|Out-Null
    for(;;) {
        $record=$view.GetType().InvokeMember('Fetch','InvokeMethod',$null,$view,$null)
        if($null -eq $record) { break }
        $values=@();foreach($n in 1..3) {$values+=([string]$record.GetType().InvokeMember('StringData','GetProperty',$null,$record,@($n)))}
        $rows+=($values -join '|')
    }
} finally { $view.GetType().InvokeMember('Close','InvokeMethod',$null,$view,$null)|Out-Null }
$expected=@('CostInitialize||800','FileCost||900','CostFinalize||1000','InstallValidate||1400','InstallInitialize||1500','InstallAdminPackage||3900','InstallFiles||4000','InstallFinalize||6600')
if(($rows -join ';') -cne ($expected -join ';')) { throw 'Unreviewed administrative actions' }
$beforePackages=@(Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*','HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*' -ErrorAction SilentlyContinue | Where-Object {$_.DisplayName -like '*WinFsp*'})
$beforeDrivers=@(Get-CimInstance Win32_SystemDriver | Where-Object {$_.Name -like '*WinFsp*'})
$beforeServices=@(Get-Service -Name '*WinFsp*' -ErrorAction SilentlyContinue)
if($beforePackages.Count -or $beforeDrivers.Count -or $beforeServices.Count) { throw 'Unexpected existing WinFsp installation' }
# Administrative image extraction only. The exact admin sequence above has no
# service, registration, driver, or custom action. Never invoke an extracted binary.
$arguments=@('/a',('"'+$MsiPath+'"'),'/qn','/norestart',('TARGETDIR="'+$FreshTargetDirectory+'"'),'/l*v',('"'+$FreshLogPath+'"'))
$p=Start-Process -FilePath "$env:SystemRoot\System32\msiexec.exe" -ArgumentList $arguments -Wait -PassThru
if($p.ExitCode -ne 0) { throw ('Administrative extraction failed: '+$p.ExitCode+'; retain output and log') }
$afterPackages=@(Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*','HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*' -ErrorAction SilentlyContinue | Where-Object {$_.DisplayName -like '*WinFsp*'})
$afterDrivers=@(Get-CimInstance Win32_SystemDriver | Where-Object {$_.Name -like '*WinFsp*'})
$afterServices=@(Get-Service -Name '*WinFsp*' -ErrorAction SilentlyContinue)
if($afterPackages.Count -or $afterDrivers.Count -or $afterServices.Count) { throw 'Unexpected WinFsp installation after extraction' }
$files=@(Get-ChildItem -LiteralPath $FreshTargetDirectory -Recurse -File | ForEach-Object {
    if(($_.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw 'Extracted reparse file' }
    [ordered]@{Path=$_.FullName;Bytes=$_.Length;SHA256=(Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash}
})
if(-not $files.Count) { throw 'No files extracted' }
[ordered]@{Status='WINFSP_BUILDER_ADMIN_IMAGE_EXTRACTED';Computer=$env:COMPUTERNAME;UUID=(Get-CimInstance Win32_ComputerSystemProduct).UUID;
 MsiSHA256='2ECB5C89405488A95BBD8A01875E02C48534FD37BBDFD84488F7590464D65944';NativeExitCode=$p.ExitCode;TargetDirectory=$FreshTargetDirectory;LogPath=$FreshLogPath;
 AdminActions=$rows;Files=$files;WinFspInstalled=$false;ExtractedBinaryExecuted=$false;RuntimeQualified=$false}|ConvertTo-Json -Depth 8 -Compress
