#requires -Version 5.1
# Authorized retained dev disk only. Changes take effect together at the next reboot.
[CmdletBinding()]
param([string]$StageDirectory, [switch]$SelfCheckOnly)
$ErrorActionPreference = 'Stop'
function Get-ServiceArguments([string]$CommandLine) {
    if ($CommandLine -notmatch '^"[^"]+"(?<args>.*)$') { throw 'Expected quoted existing service executable.' }
    return $Matches['args']
}
function Assert-Hash([string]$Path, [string]$Expected) {
    if ($Expected -notmatch '^[A-Fa-f0-9]{64}$' -or
        (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash -ine $Expected) { throw ('Artifact hash mismatch: ' + $Path) }
}
if ((Get-ServiceArguments '"C:\Program Files\SafeUpload\Agent\SafeUpload.Agent.Service.exe" --Interception:Mode=Minifilter --Interception:StagingPrototype=true') -cne
    ' --Interception:Mode=Minifilter --Interception:StagingPrototype=true') { throw 'Service argument preservation self-check failed.' }
if ($SelfCheckOnly) { 'DevPairSelfCheck=PASS Mutations=False'; return }
if ($PSVersionTable.PSVersion.Major -ne 5 -or $PSVersionTable.PSVersion.Minor -ne 1 -or -not [Environment]::Is64BitProcess) { throw '64-bit Windows PowerShell 5.1 required.' }
if (-not $StageDirectory) { throw 'StageDirectory is required.' }
$stage = (Resolve-Path -LiteralPath $StageDirectory).Path
$manifest = Get-Content -LiteralPath (Join-Path $stage 'pair.json') -Raw | ConvertFrom-Json
$label = [string]$manifest.Label
if ($label -notmatch '^m2dev[A-Za-z0-9_-]{3,40}$') { throw 'Invalid development label.' }
$driverInput = Join-Path $stage 'driver.sys'
$agentZip = Join-Path $stage 'agent.zip'
Assert-Hash $driverInput $manifest.DriverSHA256
Assert-Hash $agentZip $manifest.ZipSHA256
$signature = Get-AuthenticodeSignature -LiteralPath $driverInput
if ($signature.Status -ne 'Valid' -or $signature.SignerCertificate.Thumbprint -ne 'A6D6CE1AA28835D509160A80ADB7894869AADF38') { throw 'Expected valid lab signing certificate.' }
$root = Join-Path $env:ProgramFiles 'SafeUpload'
$agentPath = Join-Path $root ('Agent-' + $label)
$driverDirectory = Join-Path $env:windir ('System32\drivers\SafeUpload-' + $label)
$driverPath = Join-Path $driverDirectory 'SafeUpload.sys'
$appPath = Join-Path $root 'App'
$appBackup = Join-Path $root ('App-before-' + $label)
$receipt = Join-Path $stage 'installation.json'
foreach ($destination in @($agentPath,$driverDirectory,$appBackup,$receipt)) {
    if (Test-Path -LiteralPath $destination) { throw ('Fresh development destination required: ' + $destination) }
}
$serviceKey = 'HKLM:\SYSTEM\CurrentControlSet\Services\SafeUploadAgent'
$driverKey = 'HKLM:\SYSTEM\CurrentControlSet\Services\SafeUpload'
$oldService = [string](Get-ItemProperty -LiteralPath $serviceKey).ImagePath
$oldDriver = [string](Get-ItemProperty -LiteralPath $driverKey).ImagePath
$arguments = Get-ServiceArguments $oldService
if ($arguments -notmatch '--Interception:Mode=Minifilter' -or $arguments -notmatch '--Interception:StagingPrototype=true') { throw 'Expected existing staged development configuration.' }
# Keep loaded binaries untouched; boot and service paths switch to fresh versioned directories.
[void](New-Item -ItemType Directory -Path $agentPath)
Expand-Archive -LiteralPath $agentZip -DestinationPath $agentPath
$newService = Join-Path $agentPath 'SafeUpload.Agent.Service.exe'
$newApp = Join-Path $agentPath 'App\SafeUpload.Agent.App.exe'
Assert-Hash $newService $manifest.Files.'SafeUpload.Agent.Service.exe'
Assert-Hash $newApp $manifest.Files.'App/SafeUpload.Agent.App.exe'
[void](New-Item -ItemType Directory -Path $driverDirectory)
Copy-Item -LiteralPath $driverInput -Destination $driverPath
Assert-Hash $driverPath $manifest.DriverSHA256
$oldApp = Join-Path $appPath 'SafeUpload.Agent.App.exe'
foreach ($process in @(Get-Process -Name 'SafeUpload.Agent.App' -ErrorAction SilentlyContinue | Where-Object { $_.Path -eq $oldApp })) {
    $process | Stop-Process -Force
    if (-not $process.WaitForExit(10000)) { throw 'Installed tray did not stop.' }
}
if (Test-Path -LiteralPath $appPath) { Move-Item -LiteralPath $appPath -Destination $appBackup }
Copy-Item -LiteralPath (Join-Path $agentPath 'App') -Destination $appPath -Recurse
Assert-Hash $oldApp $manifest.Files.'App/SafeUpload.Agent.App.exe'
$newCommand = '"' + $newService + '"' + $arguments
$newDriver = '\??\' + $driverPath
Set-ItemProperty -LiteralPath $serviceKey -Name ImagePath -Value $newCommand -Type ExpandString
Set-ItemProperty -LiteralPath $driverKey -Name ImagePath -Value $newDriver -Type ExpandString
if ((Get-ItemProperty -LiteralPath $serviceKey).ImagePath -cne $newCommand -or
    (Get-ItemProperty -LiteralPath $driverKey).ImagePath -cne $newDriver) { throw 'Service path readback mismatch.' }
$machine = [Microsoft.Win32.RegistryKey]::OpenBaseKey('LocalMachine','Registry64')
try {
    $run = $machine.CreateSubKey('SOFTWARE\Microsoft\Windows\CurrentVersion\Run')
    try { $run.SetValue('SafeUploadApp',('"' + $oldApp + '"'),'String') } finally { $run.Dispose() }
} finally { $machine.Dispose() }
[ordered]@{
    Label=$label;SourceCommit=$manifest.SourceCommit;DriverSource=$manifest.DriverSource
    OldService=$oldService;OldDriver=$oldDriver;NewService=$newCommand;NewDriver=$newDriver
    AgentSHA256=$manifest.Files.'SafeUpload.Agent.Service.exe';AppSHA256=$manifest.Files.'App/SafeUpload.Agent.App.exe'
    DriverSHA256=$manifest.DriverSHA256;OldAppBackup=$appBackup;RebootRequired=$true;Qualification=$false
} | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $receipt -Encoding UTF8
'DevPairStaged=True RebootRequired=True Qualification=False'
