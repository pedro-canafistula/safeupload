$ErrorActionPreference='Stop'
if($env:COMPUTERNAME -cne 'DESKTOP-O1LP5DG' -or (Get-CimInstance Win32_ComputerSystemProduct).UUID -cne 'C6440689-D11C-4C63-A463-F3722B7DDB69'){throw 'Wrong builder'}
$p='C:\Users\vika\Documents\SafeUploadDependencyReview-WinFsp-v2.2B4-20261006\winfsp-2.2.26215.msi';if((Get-FileHash -LiteralPath $p -Algorithm SHA256).Hash -cne '2ECB5C89405488A95BBD8A01875E02C48534FD37BBDFD84488F7590464D65944'){throw 'MSI hash mismatch'}
$i=New-Object -ComObject WindowsInstaller.Installer
$db=$i.GetType().InvokeMember('OpenDatabase','InvokeMethod',$null,$i,@($p,0))
$result=[ordered]@{}
foreach($table in @('Feature','FeatureComponents','Component','ServiceInstall','ServiceControl','CustomAction','InstallExecuteSequence','Property')){
 $v=$db.GetType().InvokeMember('OpenView','InvokeMethod',$null,$db,@('SELECT * FROM `'+$table+'`'))
 try{$v.GetType().InvokeMember('Execute','InvokeMethod',$null,$v,$null)|Out-Null;$rows=@();for(;;){$record=$v.GetType().InvokeMember('Fetch','InvokeMethod',$null,$v,$null);if($null -eq $record){break};$count=$record.GetType().InvokeMember('FieldCount','GetProperty',$null,$record,$null);$fields=@();for($n=1;$n -le $count;$n++){$fields+=([string]$record.GetType().InvokeMember('StringData','GetProperty',$null,$record,@($n)))};$rows+=,@($fields)};$result[$table]=$rows}finally{$v.GetType().InvokeMember('Close','InvokeMethod',$null,$v,$null)|Out-Null}
}
[ordered]@{Status='WINFSP_MSI_READ_ONLY_TABLES';MSIPath=$p;InstallerExecuted=$false;DatabaseOpenMode=0;Tables=$result}|ConvertTo-Json -Depth 8 -Compress
