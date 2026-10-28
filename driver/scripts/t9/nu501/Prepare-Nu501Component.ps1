#Requires -RunAsAdministrator
#Requires -Version 5.1
<# Explicitly authorized component host ONLY; zero destinations, no actor.
This changes only the disposable guest. No protected boot or qualification.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)][string] $InputDirectory,
    [Parameter(Mandatory=$true)][ValidatePattern('^[A-Fa-f0-9]{64}$')][string] $DriverSHA256,
    [Parameter(Mandatory=$true)][ValidatePattern('^[A-Fa-f0-9]{64}$')][string] $AgentZipSHA256,
    [Parameter(Mandatory=$true)][ValidatePattern('^[A-Fa-f0-9]{64}$')][string] $ServiceSHA256
)
$ErrorActionPreference = 'Stop'
function Require-Hash([string] $Path, [string] $Expected) {
    $actual = (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash
    if ($actual -ine $Expected) { throw ('Artifact hash mismatch: ' + $Path) }
    [pscustomobject]@{Path=$Path; SHA256=$actual} | ConvertTo-Json -Compress
}
if ($PSVersionTable.PSVersion.Major -ne 5 -or $PSVersionTable.PSVersion.Minor -ne 1 -or -not [Environment]::Is64BitProcess) { throw 'Requires x64 Windows PowerShell 5.1' }
$cv = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
if ([Environment]::OSVersion.Version.Build -ne 19045 -or $cv.UBR -ne 2965 -or (Get-CimInstance Win32_ComputerSystemProduct).UUID -ine 'FFCB9530-146B-43B1-8AF7-2B5CC8EDE2E3') { throw 'Wrong qualified component guest identity' }
if (Confirm-SecureBootUEFI) { throw 'Secure Boot must be off' }
$bcd = & bcdedit.exe /enum '{current}' 2>&1 | Out-String
if ($LASTEXITCODE -ne 0 -or $bcd -notmatch '(?im)^testsigning\s+Yes\s*$') { throw 'Test signing must already be enabled' }
$filters = & fltmc.exe filters 2>&1 | Out-String
if ($LASTEXITCODE -ne 0 -or $filters -match '(?im)^SafeUpload\s') { throw 'New component installation requires unloaded original driver' }
if ((Get-Service SafeUploadAgent -ErrorAction SilentlyContinue | Where-Object { $_.Status -ne 'Stopped' })) { throw 'Existing agent is active' }
Require-Hash (Join-Path $InputDirectory 'SafeUpload.sys') $DriverSHA256
Require-Hash (Join-Path $InputDirectory 'agent.zip') $AgentZipSHA256
$agentDir = 'C:\Program Files\SafeUpload\Agent'
[void](New-Item -ItemType Directory -Force -Path $agentDir)
Expand-Archive -LiteralPath (Join-Path $InputDirectory 'agent.zip') -DestinationPath $agentDir -Force
$exe = Join-Path $agentDir 'SafeUpload.Agent.Service.exe'
Require-Hash $exe $ServiceSHA256
Copy-Item -LiteralPath (Join-Path $InputDirectory 'SafeUpload.sys') -Destination 'C:\Windows\System32\drivers\SafeUpload.sys' -Force
Require-Hash 'C:\Windows\System32\drivers\SafeUpload.sys' $DriverSHA256
# Fresh installed roots with SYSTEM/Admin authority only. Stop on any prior
# data. Never repair a nonempty root or alter Windows ancestor permissions.
$data = 'C:\ProgramData\SafeUpload'
$roots = @("$data\staging", "$data\staging\.space-reservations", "$data\staging-journal", "$data\staging-journal\completed")
foreach ($root in $roots) {
    if ((Test-Path -LiteralPath $root) -and @(Get-ChildItem -LiteralPath $root -Force | Where-Object { $_.FullName -notin $roots }).Count -ne 0) { throw ('Component root is not empty: ' + $root) }
}
foreach ($root in @($data) + $roots) {
    [void](New-Item -ItemType Directory -Path $root -Force)
    if ((Get-Item -LiteralPath $root -Force).Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'Reparse component root' }
    $acl = New-Object Security.AccessControl.DirectorySecurity
    $acl.SetOwner((New-Object Security.Principal.SecurityIdentifier('S-1-5-18')))
    $acl.SetAccessRuleProtection($true, $false)
    foreach ($sid in @('S-1-5-18','S-1-5-32-544')) {
        $rule = New-Object Security.AccessControl.FileSystemAccessRule((New-Object Security.Principal.SecurityIdentifier($sid)), 'FullControl', 'ContainerInherit,ObjectInherit', 'None', 'Allow')
        [void]$acl.AddAccessRule($rule)
    }
    Set-Acl -LiteralPath $root -AclObject $acl
}
# Domain validation requires a category (RN-009). With no destinations,
# removable or network scope, this is an authentication-only inert policy.
$policy = @{version=1; activeCategories=@('Cpf'); monitoredScopes=@{extensions=@('.txt'); destinationPaths=@(); removableDrives=$false; networkPaths=$false}; failOpen=$false; auditOnly=$false; overrideEnabled=$false}
[IO.File]::WriteAllText("$data\policy.json", ($policy | ConvertTo-Json -Depth 5), (New-Object Text.UTF8Encoding($false)))
& (Join-Path $InputDirectory 'Protect-SafeUploadPolicy.ps1')
# Seed and install through the reviewed installer, including service SID.
# Do not reboot: demand-load the reviewed component and keep staging closed.
& (Join-Path $InputDirectory 'Install-SafeUploadAgent.ps1') -ServiceExecutablePath $exe -ServiceArguments @(
    '--Interception:Mode=Minifilter', '--Interception:StagingPrototype=true', '--CentroAdministracao:BaseUrl=', '--Diagnostics:Nu501ComponentHost=true')
& sc.exe config SafeUpload start= demand | Out-String | Write-Output
if ($LASTEXITCODE -ne 0) { throw 'Cannot keep component demand-start' }
& sc.exe start SafeUpload | Out-String | Write-Output
if ($LASTEXITCODE -ne 0) { throw 'Reviewed driver load failed' }
Start-Service SafeUploadAgent
$sw = [Diagnostics.Stopwatch]::StartNew()
# Pipe publication means accepted inert SetPolicy and original SYSTEM/service
# SID authentication. Modern Commit and staged product admission stay closed.
do {
    $pipes = @([IO.Directory]::GetFiles('\\.\pipe\') | Where-Object { $_ -eq '\\.\pipe\SafeUploadAdmissionEvidence.Capture' })
    if ($pipes.Count -eq 1) { break }
    if ((Get-Service SafeUploadAgent).Status -ne 'Running') { throw 'Component service stopped' }
    Start-Sleep -Milliseconds 200
} while ($sw.Elapsed.TotalSeconds -lt 30)
if ($pipes.Count -ne 1) { throw 'Component evidence binding not ready' }
$loaded = & fltmc.exe filters 2>&1 | Out-String
if ($LASTEXITCODE -ne 0 -or $loaded -notmatch '(?im)^SafeUpload\s') { throw 'Reviewed driver not loaded' }
$loaded
& verifier.exe /volatile /flags 0x13B /adddriver SafeUpload.sys | Out-String | Write-Output
if ($LASTEXITCODE -notin @(0,2)) { throw 'Runtime Verifier arm failed' }
$query = & verifier.exe /query 2>&1 | Out-String
$query
# Require actual active readback, not /querysettings or command exit alone.
if ($LASTEXITCODE -ne 0 -or $query -notmatch 'SafeUpload\.sys' -or $query -notmatch '(?i)0x0*13b\b') { throw 'Runtime Verifier readback differs from 0x13B' }
[pscustomobject]@{Kind='ComponentReady'; StagedProductReady=$false; ModernReady=$false; Destinations=0; Actor=$false; Verifier='0x13B'; Boot=(Get-CimInstance Win32_OperatingSystem).LastBootUpTime.ToUniversalTime().ToString('o')} | ConvertTo-Json -Compress
'Nu501ComponentPrepared=True'
