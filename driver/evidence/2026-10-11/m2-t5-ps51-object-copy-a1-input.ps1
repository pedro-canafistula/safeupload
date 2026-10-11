$ErrorActionPreference='Stop'
if ($env:COMPUTERNAME -ne 'DESKTOP-O1LP5DG' -or (Get-CimInstance Win32_ComputerSystemProduct).UUID -ne 'C6440689-D11C-4C63-A463-F3722B7DDB69' -or [Security.Principal.WindowsIdentity]::GetCurrent().User.Value -ne 'S-1-5-21-316478115-1595729549-2803163825-1001' -or $PSVersionTable.PSVersion.Major -ne 5 -or $PSVersionTable.PSVersion.Minor -ne 1 -or -not [Environment]::Is64BitProcess) { throw 'Wrong builder or PS5.1 ordinary-user environment' }
$original=[pscustomobject]@{ StageCleanupStarted=$false; CreateReservationId='original'; HandbackState='0' }
$copy=$original.PSObject.Copy()
$copy.StageCleanupStarted=$true
$copy.CreateReservationId='mutant'
[pscustomobject]@{ PSVersion=[string]$PSVersionTable.PSVersion; OriginalStageCleanupStarted=$original.StageCleanupStarted; OriginalCreateReservationId=$original.CreateReservationId; CopyStageCleanupStarted=$copy.StageCleanupStarted; CopyCreateReservationId=$copy.CreateReservationId; SourceMutatedByCopy=($original.StageCleanupStarted -or $original.CreateReservationId -cne 'original'); ControlsPassed=$true; ProjectSourceInvoked=$false; FileWrites=$false } | ConvertTo-Json -Compress
