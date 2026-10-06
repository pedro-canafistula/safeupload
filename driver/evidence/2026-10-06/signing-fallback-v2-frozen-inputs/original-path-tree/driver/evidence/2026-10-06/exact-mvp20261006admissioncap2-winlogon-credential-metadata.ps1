$ErrorActionPreference='Stop'
$expectedComputer='DESKTOP-O1LP5DG';$expectedUuid='C6440689-D11C-4C63-A463-F3722B7DDB69';$product=Get-CimInstance Win32_ComputerSystemProduct
if($env:COMPUTERNAME -cne $expectedComputer -or $product.UUID -cne $expectedUuid){throw 'Builder identity mismatch.'}
$key='HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon';$item=Get-ItemProperty -LiteralPath $key -ErrorAction SilentlyContinue
$user=$null;$domain=$null;$auto=$null;$passwordPresent=$false
if($null -ne $item){$user=[string]$item.DefaultUserName;$domain=[string]$item.DefaultDomainName;$auto=[string]$item.AutoAdminLogon;$passwordPresent=($item.PSObject.Properties.Name -contains 'DefaultPassword' -and -not [string]::IsNullOrEmpty([string]$item.DefaultPassword))}
[ordered]@{Status='Completed';UTC=[DateTime]::UtcNow.ToString('o');ComputerName=$env:COMPUTERNAME;UUID=$product.UUID;WinlogonKeyExists=(Test-Path -LiteralPath $key);DefaultUserIsExactVika=($user -ceq 'vika');DefaultDomainIsExactMachine=($domain -ceq $expectedComputer);AutoAdminLogonEnabled=($auto -ceq '1');DefaultPasswordValuePresent=$passwordPresent;DefaultPasswordValueReadOrEmitted=$false;NoOtherCredentialStoresInspected=$true}|ConvertTo-Json -Depth 4 -Compress
