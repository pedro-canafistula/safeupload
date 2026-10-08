# Puts back the service-written notification record that Reset-StagedProductResidue.ps1 removed on 2026-10-07.
# R03 snapshots the record while the service is offline and its strict reader requires emissions.jsonl, head.json
# and writer.lock to exist; a reset debuggee has none until the service has run once. The bytes come unchanged
# from the reset's own archive (the record verifies itself by hash chain); only the ACL is re-applied, to the exact
# private form the service creates and the evidence reader requires: owner SYSTEM, protected DACL, SYSTEM and
# Administrators FullControl, nothing else. Requires no running agent and an empty notifications folder.
$ErrorActionPreference='Stop'
if(@(Get-Process SafeUpload.Agent.Service -ErrorAction SilentlyContinue).Count){throw 'Agent is running; refusing to restore.'}
$target='C:\ProgramData\SafeUpload\notifications'
if(@(Get-ChildItem -LiteralPath $target -Force).Count){throw 'Notifications folder is not empty; refusing to overwrite.'}
Add-Type -AssemblyName System.IO.Compression.FileSystem
$expected='emissions.jsonl,head.json,writer.lock'
$archive=$null;$entryNames=$null
foreach($candidate in @(Get-ChildItem 'C:\Users\vika\Documents' -Filter 'product-residue-*.zip' | Sort-Object LastWriteTimeUtc -Descending)){
    $zip=[IO.Compression.ZipFile]::OpenRead($candidate.FullName)
    try{$names=@($zip.Entries | Where-Object {$_.FullName -match '^notifications[\\/][^\\/]+$'} | ForEach-Object Name | Sort-Object)}finally{$zip.Dispose()}
    if(($names -join ',') -ceq $expected){$archive=$candidate;break}
}
if($null -eq $archive){throw 'No product residue archive holds a complete notification record.'}
$zip=[IO.Compression.ZipFile]::OpenRead($archive.FullName)
try{
    foreach($entry in @($zip.Entries | Where-Object {$_.FullName -match '^notifications[\\/][^\\/]+$'})){
        $path=Join-Path $target $entry.Name
        $source=$entry.Open()
        try{$stream=[IO.File]::Open($path,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None);try{$source.CopyTo($stream);$stream.Flush($true)}finally{$stream.Dispose()}}finally{$source.Dispose()}
    }
}finally{$zip.Dispose()}
foreach($name in 'emissions.jsonl','head.json','writer.lock'){
    $path=Join-Path $target $name
    $acl=New-Object Security.AccessControl.FileSecurity
    $acl.SetOwner([Security.Principal.SecurityIdentifier]'S-1-5-18')
    $acl.SetAccessRuleProtection($true,$false)
    foreach($sid in 'S-1-5-18','S-1-5-32-544'){
        $acl.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule(([Security.Principal.SecurityIdentifier]$sid),'FullControl','None','None','Allow')))
    }
    Set-Acl -LiteralPath $path -AclObject $acl
    $name+' Length='+(Get-Item -LiteralPath $path).Length+' Sha256='+(Get-FileHash -LiteralPath $path).Hash+' Sddl='+(Get-Acl -LiteralPath $path).Sddl
}
'Archive='+$archive.FullName
'NOTIFICATION_RECORD_RESTORED=True'
