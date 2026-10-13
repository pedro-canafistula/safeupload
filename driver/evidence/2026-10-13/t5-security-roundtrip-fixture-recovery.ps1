#requires -Version 5.1
$ErrorActionPreference='Stop'
& (Join-Path $PSScriptRoot 'writer-permission-native-control.ps1') -SelfCheckOnly
& (Join-Path $PSScriptRoot 'bound-publication-native-control.ps1') -SelfCheckOnly
$identity=[Security.Principal.WindowsIdentity]::GetCurrent()
try {if(-not $identity.IsSystem){throw 'Fixture recovery requires SYSTEM.'}}finally{$identity.Dispose()}
$root='C:\Windows\SystemTemp\safeupload-security-roundtrip-89a6138cd8fb44a39dc21ec192d90f34'
$rows=ConvertFrom-Json @'
[{"Case": "inherited-null-input", "SourceId": "7F2F63D64463D64AB9EC0D00000011000000000000000000"}, {"Case": "protected-read-only", "SourceId": "7F2F63D64463D64A43FF0D00000011000000000000000000"}, {"Case": "unprotected-defaulted", "SourceId": "7F2F63D64463D64A860D0E00000046000000000000000000"}, {"Case": "protected-empty-dacl", "SourceId": "7F2F63D64463D64A8E0D0E0000009D000000000000000000"}, {"Case": "null-dacl", "SourceId": "7F2F63D64463D64A940D0E0000004C000000000000000000"}, {"Case": "explicit-low-label", "SourceId": "7F2F63D64463D64A990D0E00000020000000000000000000"}, {"Case": "moved-inherited-target", "SourceId": "7F2F63D64463D64ADD0D0E0000001E000000000000000000"}]
'@
$expected=New-Object 'Collections.Generic.List[string]'
foreach($row in $rows){
    $folder=Join-Path $root $row.Case
    $parent=Join-Path $folder $(if($row.Case -eq 'moved-inherited-target'){'destination'}else{'original'})
    $source=Join-Path $parent 'source.txt'
    $temporary=Join-Path $parent 'publication.tmp'
    $expected.Add($source);$expected.Add($temporary)
    $metadata=[WriterPermissionNativeControl]::SystemMetadata($source,$false)
    try {
        if(-not $metadata.Accepted -or [BoundPublicationNativeControl]::Identity($metadata.Handle) -ne $row.SourceId){throw 'Retained fixture source identity mismatch.'}
    } finally {$metadata.Dispose()}
}
$objects=@(Get-ChildItem -LiteralPath $root -Recurse -Force)
if(@($objects|Where-Object {($_.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0}).Count){throw 'Fixture recovery refuses reparse points.'}
$files=@($objects|Where-Object {-not $_.PSIsContainer})
if($files.Count -ne 14 -or @($files|Where-Object {-not $expected.Contains($_.FullName)}).Count){throw 'Retained fixture has an unexpected file.'}
foreach($file in $files){
    $security=New-Object Security.AccessControl.FileSecurity
    $security.SetSecurityDescriptorSddlForm('D:P(A;;FA;;;SY)',[Security.AccessControl.AccessControlSections]::Access)
    [IO.File]::SetAccessControl($file.FullName,$security)
}
Remove-Item -LiteralPath $root -Recurse -Force
if(Test-Path -LiteralPath $root){throw 'Retained fixture remains.'}
Write-Output 'RetainedFixtureRecovery=PASS Sources=7 Files=14 ExactSourceIdentities=True ReparsePoints=False FixtureAbsent=True'
