$ErrorActionPreference='Stop';$ProgressPreference='SilentlyContinue';
$sid=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value;
if($env:COMPUTERNAME -ne 'DESKTOP-O1LP5DG' -or $sid -ne 'S-1-5-21-316478115-1595729549-2803163825-1001' -or -not [Environment]::Is64BitProcess -or $PSVersionTable.PSVersion.Major -ne 5){throw 'Builder identity mismatch'};
$p='C:/Users/vika/AppData/Local/Temp/SafeUpload-lifecycle-r2-parse-1011-a1';if(Test-Path -LiteralPath $p){throw 'Diagnostic directory already exists'};[void][IO.Directory]::CreateDirectory($p);
[pscustomobject]@{Computer=$env:COMPUTERNAME;SID=$sid;PSVersion=$PSVersionTable.PSVersion.ToString();ParseOnly=$true;Directory=$p}|ConvertTo-Json -Compress
