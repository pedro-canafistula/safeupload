$ErrorActionPreference='Stop'
$expectedComputer='DESKTOP-O1LP5DG';$expectedUuid='C6440689-D11C-4C63-A463-F3722B7DDB69'
$product=Get-CimInstance Win32_ComputerSystemProduct
if($env:COMPUTERNAME -cne $expectedComputer -or $product.UUID -cne $expectedUuid){throw 'Builder identity mismatch.'}
$historyPath=Join-Path $env:APPDATA 'Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt';$historyRows=@()
if(Test-Path -LiteralPath $historyPath){
  $lines=Get-Content -LiteralPath $historyPath
  for($i=0;$i -lt $lines.Count;$i++){
    $line=$lines[$i]
    if($line -match '(?i)(safeupload-cert|SafeUploadTest\.pfx)'){
      $vars=@([regex]::Matches($line,'\$[A-Za-z_][A-Za-z0-9_]*')|ForEach-Object {$_.Value}|Where-Object {$_ -match '(?i)(pass|pwd|secret|cred)'}|Sort-Object -Unique)
      $params=@([regex]::Matches($line,'(?i)-[A-Za-z][A-Za-z0-9]*')|ForEach-Object {$_.Value}|Where-Object {$_ -match '(?i)(pass|pwd|secret|cred|securestring)'}|Sort-Object -Unique)
      $literalPattern='(?i)(password|pwd)\s*[:=]\s*["''][^"'']+["'']'
      $historyRows+=[ordered]@{LineNumber=$i+1;Command=($line.TrimStart() -split '\s+',2)[0];PasswordOrCredentialVariableNames=$vars;PasswordOrCredentialParameterNames=$params;AsSecureStringPromptPresent=($line -match '(?i)Read-Host.*AsSecureString');LiteralCredentialSyntaxPresent=($line -match $literalPattern);RawHistoryLineEmitted=$false}
    }
  }
}
$envNames=@(Get-ChildItem Env:|Where-Object {$_.Name -match '(?i)(safeupload.*(pfx|cert).*(pass|pwd|secret)|((pfx|cert).*(pass|pwd|secret).*safeupload))'}|ForEach-Object {$_.Name}|Sort-Object -Unique)
$cmdkeyTargets=@();$cmdkeyPath=Join-Path $env:windir 'System32\cmdkey.exe';$out=Join-Path $env:TEMP ('safeupload-cmdkey-'+[Guid]::NewGuid().ToString('N')+'.out');$err=Join-Path $env:TEMP ('safeupload-cmdkey-'+[Guid]::NewGuid().ToString('N')+'.err')
try{$p=Start-Process -FilePath $cmdkeyPath -ArgumentList '/list' -NoNewWindow -Wait -PassThru -RedirectStandardOutput $out -RedirectStandardError $err;if(Test-Path -LiteralPath $out){foreach($line in Get-Content -LiteralPath $out){if($line -match '(?i)^\s*Target:\s*(.*safeupload.*)\s*$'){$cmdkeyTargets+=$Matches[1].Trim()}}}}finally{Remove-Item -LiteralPath $out,$err -Force -ErrorAction SilentlyContinue}
[ordered]@{Status='Completed';UTC=[DateTime]::UtcNow.ToString('o');ComputerName=$env:COMPUTERNAME;UUID=$product.UUID;HistoryPath=$historyPath;PfxRelatedHistory=$historyRows;SafeUploadSpecificCredentialEnvironmentVariableNames=$envNames;SafeUploadSpecificCredentialManagerTargets=@($cmdkeyTargets|Sort-Object -Unique);RawHistoryLinesEmitted=$false;SecretValuesReadOrEmitted=$false}|ConvertTo-Json -Depth 10 -Compress
