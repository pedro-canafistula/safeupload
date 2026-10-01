<# Unfiltered link-admission investigation. Never loads or changes SafeUpload. #>
$ErrorActionPreference='Stop'
$expected='ADA9D05AB6AECDD2B6C521B0CE529FC06C732154ACB3EE85439FBDC8AA80DFCE'
if($env:COMPUTERNAME -ne 'WIN10-DEBUGGED' -or
    (Get-CimInstance Win32_ComputerSystemProduct).UUID -ne '9D44EEE8-81CF-4CC1-9FBA-7670F11DEF4D'){throw 'Wrong debuggee.'}
if((Get-FileHash 'C:\Windows\System32\drivers\SafeUpload.sys').Hash -ne $expected){throw 'Original hash mismatch.'}
if((& fltmc.exe filters) -match '^SafeUpload\s'){throw 'Expected unfiltered baseline.'}
$settings=& verifier.exe /querysettings
if(($settings -join "`n") -notmatch 'Verifier Flags: 0x00000000'){throw 'Verifier not reset.'}
$directory=Join-Path $env:TEMP ('SafeUpload-link-admission-'+[guid]::NewGuid().ToString('N'))
Add-Type -Path (Join-Path $PSScriptRoot 'NativeLinkAdmissionProbe.cs')
try {
    'UTC='+[DateTime]::UtcNow.ToString('o')
    'FixtureDirectory='+$directory
    $identity=[Security.Principal.WindowsIdentity]::GetCurrent()
    'Principal='+$identity.Name
    'Administrator='+([Security.Principal.WindowsPrincipal]::new($identity).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator))
    $identity.Dispose()
    'FixtureFilesystem='+[IO.DriveInfo]::new('C:\').DriveFormat
    Get-CimInstance Win32_OperatingSystem | Select-Object Caption,Version,BuildNumber | Format-List
    Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' |
        Select-Object CurrentBuild,UBR,DisplayVersion | Format-List
    foreach($path in @('C:\Windows\System32\ntoskrnl.exe','C:\Windows\System32\drivers\ntfs.sys',
        'C:\Windows\System32\ntdll.dll','C:\Windows\System32\drivers\fltmgr.sys')){
        (Get-Item $path).VersionInfo | Select-Object FileName,FileVersion,ProductVersion | Format-List
        Get-FileHash $path -Algorithm SHA256 | Format-List
    }
    # Console output from Add-Type bypasses PowerShell's redirection streams.
    $previousOutput=[Console]::Out
    $probeOutput=[IO.StringWriter]::new()
    try {
        [Console]::SetOut($probeOutput)
        [NativeLinkAdmissionProbe]::Run($directory)
    } finally {[Console]::SetOut($previousOutput)}
    Write-Output $probeOutput.ToString()
    $probeOutput.Dispose()
} finally {
    if(Test-Path $directory){Remove-Item $directory -Recurse -Force}
    if((Get-FileHash 'C:\Windows\System32\drivers\SafeUpload.sys').Hash -ne $expected){throw 'Original changed.'}
    if((& fltmc.exe filters) -match '^SafeUpload\s'){throw 'Unexpected filter load.'}
    'UnfilteredFixturesRemovedOriginalDriverUnchanged=True'
}
