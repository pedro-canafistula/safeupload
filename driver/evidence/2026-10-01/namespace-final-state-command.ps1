$ErrorActionPreference='Stop'
$ProgressPreference='SilentlyContinue'
$expected='ADA9D05AB6AECDD2B6C521B0CE529FC06C732154ACB3EE85439FBDC8AA80DFCE'
$hash=(Get-FileHash C:\Windows\System32\drivers\SafeUpload.sys).Hash
if($hash -ne $expected) {throw 'Original installed driver hash mismatch'}
Write-Output ('UTC='+[DateTime]::UtcNow.ToString('o'))
Write-Output ('Host='+$env:COMPUTERNAME)
Write-Output ('UUID='+(Get-CimInstance Win32_ComputerSystemProduct).UUID)
Write-Output ('OriginalInstalledSHA256='+$hash)
Write-Output ('TestDriverSHA256='+(Get-FileHash C:\Users\vika\Documents\SafeUpload-stage-prototype.sys).Hash)
Write-Output ('ServicePackageSHA256='+(Get-FileHash C:\Users\vika\Documents\stage-service-publish.zip).Hash)
$filters=& fltmc.exe filters
$filters | Out-Host
if($filters -match '^SafeUpload\s') {throw 'Experimental filter remains loaded'}
$settings=& verifier.exe /querysettings
$settings | Out-Host
if(($settings -join "`n") -notmatch 'Verifier Flags: 0x00000000') {throw 'Verifier remains configured'}
& verifier.exe /query | Out-Host
$tasks=@(Get-ScheduledTask | Where-Object {$_.TaskName -match '^SafeUpload-(StagedTest-|StagedCleanup-|Owned-)'})
$agents=@(Get-Process -Name SafeUpload.Agent.Service -ErrorAction SilentlyContinue)
Write-Output ('TemporaryTasks='+$tasks.Count+'; ServiceProcesses='+$agents.Count)
if($tasks.Count -or $agents.Count) {throw 'Temporary task or service remains'}
foreach($path in @('S:\','C:\Users\vika\Documents\SafeUpload-owned.vhdx','C:\Users\vika\Documents\SafeUpload-owned.vhdx.txt')) {
    Write-Output ($path+'='+(Test-Path $path))
    if(Test-Path $path) {throw 'Disposable volume fixture remains'}
}
Write-Output 'IndependentRestorationVerified=True'
