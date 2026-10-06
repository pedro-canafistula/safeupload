$ErrorActionPreference='Stop'
$ProgressPreference='SilentlyContinue'
if($env:COMPUTERNAME -ne 'DESKTOP-O1LP5DG' -or (Get-CimInstance Win32_ComputerSystemProduct).UUID -ne 'C6440689-D11C-4C63-A463-F3722B7DDB69'){throw 'Wrong builder'}
$rows=@(
 @{Name='Test-StagedPreAttachmentMapping.ps1';Sha256='1c493c8a0489c1315347336d15fc0dcd7accb963fb9981c661ba5600931b4dd0'},
 @{Name='Test-StagedAdmissionDiagnostic.ps1';Sha256='98c3c72bba09ce5d97cd7a8bfa4a5dee8a7025e94af2f79eadae546072e79418'}
)
foreach($row in $rows){
 $path=Join-Path 'C:\Users\vika\Documents' ('mapgate20261005-'+$row.Name)
 if((Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash -ne $row.Sha256){throw 'Input hash mismatch'}
 $tokens=$null;$errors=$null
 $ast=[Management.Automation.Language.Parser]::ParseFile($path,[ref]$tokens,[ref]$errors)
 if($errors.Count){$errors | Format-List * | Out-String | Write-Output;throw ('Parse failed: '+$row.Name)}
 Write-Output ('PARSE_PASS '+$row.Name+' SHA256='+$row.Sha256)
 if($row.Name -eq 'Test-StagedPreAttachmentMapping.ps1'){
  $commands=@($ast.FindAll({param($node) $node -is [Management.Automation.Language.CommandAst] -and $node.GetCommandName() -eq 'Add-Type'},$true))
  if($commands.Count -ne 1){throw 'Unexpected Add-Type count'}
  $literal=$commands[0].CommandElements[-1]
  if($literal -isnot [Management.Automation.Language.StringConstantExpressionAst]){throw 'Native source must be a literal'}
  $type=Add-Type -Namespace SafeUploadReproAuthoring -Name Native -MemberDefinition $literal.Value -PassThru
  foreach($name in @('FlushFileBuffers','SetFilePointerEx','DeviceIoControl')){if(-not $type.GetMethod($name)){throw ('Missing compiled native declaration: '+$name)}}
  Write-Output 'MAPPING_NATIVE_COMPILE_PASS declarations only; no PInvoke called'
 }
}
Write-Output ('AUTHORING_VALIDATION_PASS PowerShell='+$PSVersionTable.PSVersion.ToString()+' UTC='+[DateTime]::UtcNow.ToString('o'))
