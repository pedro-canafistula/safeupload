$ErrorActionPreference='Stop'
. C:\Users\vika\Documents\StagedTestAgent.ps1
$expected='ADA9D05AB6AECDD2B6C521B0CE529FC06C732154ACB3EE85439FBDC8AA80DFCE'
$installed='C:\Windows\System32\drivers\SafeUpload.sys'
$actual=(Get-FileHash $installed -Algorithm SHA256).Hash
if($actual -ne $expected) {throw 'Independent original hash verification failed'}
Write-Output ('Utc=' + [DateTime]::UtcNow.ToString('o'))
Write-Output ('Host=' + $env:COMPUTERNAME)
Write-Output ('UUID=' + (Get-CimInstance Win32_ComputerSystemProduct).UUID)
Get-CimInstance Win32_OperatingSystem | Select-Object Caption,Version,BuildNumber | Format-List
Write-Output ('OriginalInstalledSHA256=' + $actual)
Write-Output ('TestDriverSHA256=' + (Get-FileHash C:\Users\vika\Documents\SafeUpload-stage-prototype.sys).Hash)
Write-Output ('ServicePackageSHA256=' + (Get-FileHash C:\Users\vika\Documents\stage-service-publish.zip).Hash)
$filters=& fltmc.exe filters
$filters | Out-Host
if($filters -match '^SafeUpload\s') {throw 'Experimental driver remains loaded'}
Write-Output 'ExperimentalDriverLoaded=False'
& verifier.exe /querysettings | Out-Host
& verifier.exe /query | Out-Host
$tasks=@(Get-ScheduledTask | Where-Object {$_.TaskName -match '^SafeUpload-(StagedTest-|StagedCleanup-|Owned-)'})
Write-Output ('TemporaryScheduledTasks=' + $tasks.Count)
if($tasks.Count) {throw 'Temporary tasks remain'}
$agents=@(Get-Process -Name SafeUpload.Agent.Service -ErrorAction SilentlyContinue)
Write-Output ('TestServiceProcesses=' + $agents.Count)
if($agents.Count) {throw 'Test service remains'}
$artifacts=@('S:\','C:\Users\vika\Documents\SafeUpload-owned.vhdx','C:\Users\vika\Documents\SafeUpload-owned.vhdx.txt')
foreach($path in $artifacts) {
    Write-Output ($path + '=' + (Test-Path -LiteralPath $path))
    if(Test-Path -LiteralPath $path) {throw 'Disposable volume fixture remains'}
}
# Only this integration's explicitly identified failed run may be removed.
$failedRun='da4684dfce5c43b887cf1b3b3dbbc206'
$orphan=@(Get-ChildItem C:\ProgramData\SafeUpload\staging-journal -Filter '*.json' | ForEach-Object {
    $entry=Get-Content $_.FullName -Raw | ConvertFrom-Json
    if($entry.Transfer.DestinationPath.Contains($failedRun)) { $entry.Transfer.StagePath; $_.FullName }
})
Remove-StagedTestFiles $orphan
Write-Output ('FailedRunOrphanPathsRemoved=' + $orphan.Count)
Write-Output 'IndependentRestorationVerified=True'
