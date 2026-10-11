$ErrorActionPreference='Stop'
if ($env:COMPUTERNAME -ne 'DESKTOP-O1LP5DG' -or (Get-CimInstance Win32_ComputerSystemProduct).UUID -ne 'C6440689-D11C-4C63-A463-F3722B7DDB69' -or [Security.Principal.WindowsIdentity]::GetCurrent().User.Value -ne 'S-1-5-21-316478115-1595729549-2803163825-1001' -or $PSVersionTable.PSVersion.Major -ne 5 -or $PSVersionTable.PSVersion.Minor -ne 1 -or -not [Environment]::Is64BitProcess) { throw 'Wrong builder or PS5.1 ordinary-user environment' }
function Get-EmptyFixtureErrors { return @() }
function Get-OneFixtureError { return @('error') }
$ambiguous=@((Get-EmptyFixtureErrors) + (Get-EmptyFixtureErrors))
$direct=@(Get-EmptyFixtureErrors; Get-EmptyFixtureErrors)
$one=@(Get-EmptyFixtureErrors; Get-OneFixtureError)
$two=@(Get-OneFixtureError; Get-OneFixtureError)
if ($ambiguous.Count -ne 1 -or $null -ne $ambiguous[0] -or $direct.Count -ne 0 -or $one.Count -ne 1 -or $one[0] -cne 'error' -or $two.Count -ne 2) { throw 'Unexpected empty-output cardinality' }
[pscustomobject]@{ PSVersion=[string]$PSVersionTable.PSVersion; ExistingEmptySumCount=$ambiguous.Count; ExistingEmptySumContainsNull=($null -eq $ambiguous[0]); DirectEmptyCount=$direct.Count; DirectOneErrorCount=$one.Count; DirectTwoErrorCount=$two.Count; ControlsPassed=$true; ProjectSourceInvoked=$false; FileWrites=$false } | ConvertTo-Json -Compress
