#Requires -Version 5.1
[CmdletBinding()]
param([string]$ResultsPath)
$ErrorActionPreference='Stop'
Import-Module (Join-Path $PSScriptRoot '../support/SafeUpload.Setup.psm1') -Force
Import-Module (Join-Path $PSScriptRoot '../support/SafeUpload.Maintenance.psm1') -Force
$fixture=Join-Path ([IO.Path]::GetTempPath()) ('safeupload-maintenance-tests-'+[Guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $fixture|Out-Null
$results=[Collections.Generic.List[object]]::new()
function Require([bool]$Value){if(-not $Value){throw 'Assertion failed.'}}
function Rejected([scriptblock]$Operation){$failed=$false;try{& $Operation|Out-Null}catch{$failed=$true};Require $failed}
function Case([string]$Name,[scriptblock]$Operation){try{& $Operation|Out-Null;$results.Add(@{name=$Name;passed=$true})}catch{$results.Add(@{name=$Name;passed=$false;error=$_.Exception.Message})}}
function Manifest([string]$Root,[string]$Version){
 $files=@(Get-ChildItem -LiteralPath $Root -File -Recurse|Where-Object Name -ne 'payload-manifest.json'|ForEach-Object{
  @{path=$_.FullName.Substring($Root.Length+1).Replace('\','/');sha256=(Get-FileHash -LiteralPath $_.FullName).Hash}
 })
 @{schemaVersion=1;version=$Version;commit=('a'*40);sourceDirty=$false;runtime='win-x64';selfContained=$true;files=$files}|
  ConvertTo-Json -Depth 6|Set-Content (Join-Path $Root payload-manifest.json) -Encoding UTF8
}
function Package([string]$Name,[string]$Version){
 $root=Join-Path $fixture $Name;New-Item -ItemType Directory -Path $root|Out-Null
 foreach($path in @('service/SafeUpload.Agent.Service.exe','service/SafeUpload.Agent.Service.dll','ui/SafeUpload.Agent.App.exe',
  'ui/SafeUpload.Agent.App.dll','setup/Invoke-AgentSetup.ps1','setup/SafeUpload.Setup.psm1','LICENSE.txt','LEIA-ME.txt')){
  $target=Join-Path $root $path;New-Item -ItemType Directory -Path (Split-Path -Parent $target) -Force|Out-Null
  [IO.File]::WriteAllText($target,($Version+':'+$path))
 };Manifest $root $Version;return $root
}
try{
 $old=Package old 1.0.0;$new=Package new 1.1.0
 [IO.File]::WriteAllText((Join-Path $new 'service/new-dependency.dll'),'new asset');Manifest $new 1.1.0
 $data=Join-Path $fixture ProgramData;New-Item -ItemType Directory -Path $data|Out-Null
 foreach($name in @('policy.json','queue.jsonl','identity.dat','cache.json')){[IO.File]::WriteAllText((Join-Path $data $name),('preserve-'+$name))}
 $before=@(Get-ChildItem $data -File|ForEach-Object{(Get-FileHash $_.FullName).Hash})-join '|'
 Case 'Copy stages a complete verified package on real files' {
  $copy=Join-Path $fixture staged;$null=Copy-SafeUploadMaintenancePayload $new $copy
  Require ((Get-SafeUploadMaintenancePayload $copy).version -eq '1.1.0')
 }
 Case 'Staging refuses a changed source and never overwrites a destination' {
  Rejected {Copy-SafeUploadMaintenancePayload $new (Join-Path $fixture staged)}
  $file=Join-Path $new 'service/new-dependency.dll';[IO.File]::WriteAllText($file,'tampered')
  Rejected {Copy-SafeUploadMaintenancePayload $new (Join-Path $fixture refused)}
  Require (-not(Test-Path (Join-Path $fixture refused)));Manifest $new 1.1.0
 }
 $live=Join-Path $fixture live;$null=Copy-SafeUploadMaintenancePayload $old $live
 $work=Join-Path $fixture transaction;New-Item -ItemType Directory -Path $work|Out-Null
 # Model the production split: public read-only application, private maintenance.
 $users=[Security.Principal.SecurityIdentifier]::new('S-1-5-32-545')
 $liveAcl=Get-Acl $live
 $liveAcl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new($users,'ReadAndExecute','ContainerInherit,ObjectInherit','None','Allow'))
 Set-Acl -LiteralPath $live -AclObject $liveAcl
 $workAcl=Get-Acl $work;$workAcl.SetAccessRuleProtection($true,$false)
 $workAcl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new([Security.Principal.WindowsIdentity]::GetCurrent().User,'FullControl','ContainerInherit,ObjectInherit','None','Allow'))
 Set-Acl -LiteralPath $work -AclObject $workAcl
 Case 'Activation changes binaries while preserving files outside managed directories' {
  [IO.File]::WriteAllText((Join-Path $live unins000.exe),'original uninstaller')
  $result=Set-SafeUploadMaintenancePayload $new $live $work
  Require ($result.version -eq '1.1.0' -and (Test-Path (Join-Path $live 'service/new-dependency.dll')))
  Require ([IO.File]::ReadAllText((Join-Path $live unins000.exe)) -eq 'original uninstaller')
  Require ((@(Get-ChildItem $data -File|ForEach-Object{(Get-FileHash $_.FullName).Hash})-join '|') -eq $before)
 }
 Case 'Rollback restores the old manifest and removes new dependencies from the active tree' {
  $result=Set-SafeUploadMaintenancePayload $old $live $work
  Require ($result.version -eq '1.0.0' -and -not(Test-Path (Join-Path $live 'service/new-dependency.dll')))
  Require ([IO.File]::ReadAllText((Join-Path $live 'service/SafeUpload.Agent.Service.exe')) -eq '1.0.0:service/SafeUpload.Agent.Service.exe')
 }
 Case 'Updated binaries retain ordinary-user read access and the installation owner' {
  $null=Set-SafeUploadMaintenancePayload $new $live $work
  $binary=Join-Path $live 'ui/SafeUpload.Agent.App.dll';$acl=Get-Acl $binary
  $rules=@($acl.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier])|Where-Object{$_.IdentityReference.Value -eq $users.Value -and $_.AccessControlType -eq 'Allow'})
  Require (@($rules|Where-Object{($_.FileSystemRights -band [Security.AccessControl.FileSystemRights]::ReadData) -ne 0}).Count -gt 0)
  Require (@($rules|Where-Object{($_.FileSystemRights -band ([Security.AccessControl.FileSystemRights]::WriteData -bor [Security.AccessControl.FileSystemRights]::ChangePermissions)) -ne 0}).Count -eq 0)
  Require ($acl.GetOwner([Security.Principal.SecurityIdentifier]).Value -eq (Get-Acl $live).GetOwner([Security.Principal.SecurityIdentifier]).Value)
  $null=Set-SafeUploadMaintenancePayload $old $live $work
 }
 Case 'Partially activated trees can be restored after a locked file is released' {
  $held=[IO.FileStream]::new((Join-Path $live 'ui/SafeUpload.Agent.App.exe'),[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read)
  try{Rejected {Set-SafeUploadMaintenancePayload $new $live $work}}finally{$held.Dispose()}
  $null=Set-SafeUploadMaintenancePayload $old $live $work
  Require ((Get-SafeUploadMaintenancePayload $live).version -eq '1.0.0')
 }
 Case 'Overlapping roots are refused before moving files' {
  $hash=(Get-FileHash (Join-Path $live 'service/SafeUpload.Agent.Service.exe')).Hash
  Rejected {Set-SafeUploadMaintenancePayload $new $live (Join-Path $live nested)}
  Require ((Get-FileHash (Join-Path $live 'service/SafeUpload.Agent.Service.exe')).Hash -eq $hash)
 }
 Case 'A junction in a live managed tree is refused before activation' {
  $outside=Join-Path $fixture outside;New-Item -ItemType Directory -Path $outside|Out-Null
  [IO.File]::WriteAllText((Join-Path $outside sentinel.txt),'keep')
  $junction=Join-Path $live 'ui/link';New-Item -ItemType Junction -Path $junction -Target $outside|Out-Null
  try{Rejected {Set-SafeUploadMaintenancePayload $new $live $work};Require ([IO.File]::ReadAllText((Join-Path $outside sentinel.txt)) -eq 'keep')}
  finally{[IO.Directory]::Delete($junction)} # PS 5.1 Remove-Item has a junction-removal bug.
 }
 Case 'A new or changed driver prerequisite is never deployed by application maintenance' {
  $driver=Join-Path $new driver;New-Item -ItemType Directory -Path $driver|Out-Null
  [IO.File]::WriteAllText((Join-Path $driver SafeUpload.sys),'different driver');Manifest $new 1.1.0
  Rejected {Set-SafeUploadMaintenancePayload $new $live $work}
  Require ((Get-SafeUploadMaintenancePayload $live).version -eq '1.0.0')
  Remove-Item -LiteralPath (Join-Path $driver SafeUpload.sys);Remove-Item -LiteralPath $driver;Manifest $new 1.1.0
 }
 Case 'Endpoint data and runtime installation records cannot be package entries' {
  $bad=Package bad 1.1.0
  [IO.File]::WriteAllText((Join-Path $bad 'setup/installation.json'),'{}');Manifest $bad 1.1.0
  Rejected {Get-SafeUploadMaintenancePayload $bad}
 }
 Case 'Dirty build provenance is refused for maintenance' {
  $bad=Package dirty 1.1.0;$path=Join-Path $bad payload-manifest.json
  $manifest=Get-Content $path -Raw|ConvertFrom-Json;$manifest.sourceDirty=$true;$manifest|ConvertTo-Json -Depth 6|Set-Content $path -Encoding UTF8
  Rejected {Get-SafeUploadMaintenancePayload $bad}
 }
 Case 'Dynamic uninstall removes newly introduced managed files and preserves untracked data' {
  $null=Set-SafeUploadMaintenancePayload $new $live $work
  [IO.File]::WriteAllText((Join-Path $live 'setup/installation.json'),'runtime state')
  [IO.File]::WriteAllText((Join-Path $live 'setup/administrator-note.txt'),'keep note')
  Remove-SafeUploadManagedPayload $live
  Require (-not(Test-Path (Join-Path $live 'service/new-dependency.dll')))
  Require ([IO.File]::ReadAllText((Join-Path $live 'setup/administrator-note.txt')) -eq 'keep note')
  Require ([IO.File]::ReadAllText((Join-Path $live unins000.exe)) -eq 'original uninstaller')
  Require ((@(Get-ChildItem $data -File|ForEach-Object{(Get-FileHash $_.FullName).Hash})-join '|') -eq $before)
 }
 $failed=@($results|Where-Object{-not $_.passed})
 $summary=@{total=$results.Count;passed=$results.Count-$failed.Count;failed=$failed.Count;tests=@($results)}
 if($ResultsPath){$summary|ConvertTo-Json -Depth 5|Set-Content $ResultsPath -Encoding UTF8}
 $failed|Format-List|Out-Host
 Write-Output ('MaintenanceContracts: '+$summary.passed+'/'+$summary.total+' passed')
 if($failed.Count){exit 1}
}finally{
 $full=[IO.Path]::GetFullPath($fixture);$temporary=[IO.Path]::GetFullPath([IO.Path]::GetTempPath()).TrimEnd('\')+'\'
 if(-not $full.StartsWith($temporary,[StringComparison]::OrdinalIgnoreCase) -or (Split-Path -Leaf $full) -notmatch '^safeupload-maintenance-tests-[a-f0-9]{32}$'){throw 'Unsafe cleanup target.'}
 Remove-Item -LiteralPath $full -Recurse -Force
}
