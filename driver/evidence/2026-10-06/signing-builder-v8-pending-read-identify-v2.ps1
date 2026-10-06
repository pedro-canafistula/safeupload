$ErrorActionPreference='Stop'
if($env:COMPUTERNAME -cne 'DESKTOP-O1LP5DG' -or (Get-CimInstance Win32_ComputerSystemProduct).UUID -cne 'C6440689-D11C-4C63-A463-F3722B7DDB69'){throw 'Wrong builder'}
$probeRows=@()
foreach($process in @(Get-CimInstance Win32_Process -Filter "Name='powershell.exe'")){
 if($process.CommandLine -match '-File (C:\\Users\\vika\\AppData\\Local\\Temp\\remote_ps_[a-f0-9]{32}\.ps1)'){
  $file=$Matches[1]
  if((Test-Path -LiteralPath $file -PathType Leaf) -and (Get-FileHash -LiteralPath $file -Algorithm SHA256).Hash -ieq 'd525d8631daeb65777dff7e359bd575b0d9e3f29e068c8908bce64dd6f746c11'){$probeRows+=@([ordered]@{ProcessId=$process.ProcessId;ParentProcessId=$process.ParentProcessId;ExactReadProbeScript=$file;ScriptSHA256='d525d8631daeb65777dff7e359bd575b0d9e3f29e068c8908bce64dd6f746c11'})}
 }
}
$probeRows|ConvertTo-Json -Depth 3 -Compress
