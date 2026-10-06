$ErrorActionPreference='Stop'
if($env:COMPUTERNAME -cne 'DESKTOP-O1LP5DG' -or (Get-CimInstance Win32_ComputerSystemProduct).UUID -cne 'C6440689-D11C-4C63-A463-F3722B7DDB69'){throw 'Wrong builder'}
$sid=[Security.Principal.SecurityIdentifier]::new('S-1-5-21-316478115-1595729549-2803163825-1001')
$rule=[Security.AccessControl.FileSystemAccessRule]::new($sid,[Security.AccessControl.FileSystemRights]::Read,[Security.AccessControl.AccessControlType]::Allow)
[ordered]@{UTC=[DateTime]::UtcNow.ToString('o');PowerShellVersion=$PSVersionTable.PSVersion.ToString();RequestedMask=[int][Security.AccessControl.FileSystemRights]::Read;ConstructedMask=[int]$rule.FileSystemRights;ConstructedRights=$rule.FileSystemRights.ToString();StateMutated=$false;FileOrKeyOpened=$false}|ConvertTo-Json -Compress
