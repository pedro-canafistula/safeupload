$ErrorActionPreference='Stop'
$expectedComputer='DESKTOP-O1LP5DG';$expectedUuid='C6440689-D11C-4C63-A463-F3722B7DDB69';$product=Get-CimInstance Win32_ComputerSystemProduct
if($env:COMPUTERNAME -cne $expectedComputer -or $product.UUID -cne $expectedUuid){throw 'Builder identity mismatch.'}
$sid=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value;$root=Join-Path $env:APPDATA ('Microsoft\Protect\'+$sid);$files=@()
if(Test-Path -LiteralPath $root){foreach($f in Get-ChildItem -LiteralPath $root -File -Force -ErrorAction SilentlyContinue){$files+=[ordered]@{Name=$f.Name;Length=$f.Length;CreationUtc=$f.CreationTimeUtc.ToString('o');LastWriteUtc=$f.LastWriteTimeUtc.ToString('o');Attributes=$f.Attributes.ToString();ContentsRead=$false}}}
$result=[ordered]@{Status='Completed';UTC=[DateTime]::UtcNow.ToString('o');ComputerName=$env:COMPUTERNAME;UUID=$product.UUID;Identity=[Security.Principal.WindowsIdentity]::GetCurrent().Name;SID=$sid;ProtectDirectory=$root;ProtectDirectoryExists=(Test-Path -LiteralPath $root);DPAPIMetadataFiles=$files;ContentsRead=$false;DPAPIUnprotectAttempted=$false}
$result|ConvertTo-Json -Depth 5 -Compress
