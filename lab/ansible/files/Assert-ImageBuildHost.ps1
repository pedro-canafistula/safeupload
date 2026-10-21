# Read-only prerequisite guard. The expected UUID comes from the same wrapper input that configures QEMU's SMBIOS.
param([Parameter(Mandatory)][guid] $ExpectedUuid)
$ErrorActionPreference = 'Stop'
$protected = @(
    '9D44EEE8-81CF-4CC1-9FBA-7670F11DEF4D', '9D6E3F02-B40A-49F0-A77F-439714F8F308',
    'FFCB9530-146B-43B1-8AF7-2B5CC8EDE2E3', # historical targets and qualified win10-debug3
    'C6440689-D11C-4C63-A463-F3722B7DDB69', '9A20C45F-7C79-4742-887F-5B279309FAB9' # approved builders
)
$uuid = (Get-CimInstance Win32_ComputerSystemProduct).UUID
if ($ExpectedUuid -eq [guid]::Empty -or $uuid -ine $ExpectedUuid.ToString() -or $uuid -in $protected -or
    (Get-CimInstance Win32_ComputerSystem).Name -ine 'SU-LAB-BUILD') {
    throw 'Image configuration is allowed only on a fresh Packer candidate, never on a target or builder.'
}
"ImageBuildHost=$env:COMPUTERNAME;UUID=$uuid;Transport=HTTPS-WinRM"
