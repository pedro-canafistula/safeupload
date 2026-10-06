$ErrorActionPreference='Stop'
$ProgressPreference='SilentlyContinue'
if($env:COMPUTERNAME -cne 'DESKTOP-O1LP5DG' -or (Get-CimInstance Win32_ComputerSystemProduct).UUID -cne 'C6440689-D11C-4C63-A463-F3722B7DDB69'){throw 'Wrong builder'}
$base='C:\Users\vika\Documents\exact-agent-matrix-admission-ready-20261006c'
$src=Join-Path $base 'src';$manifest=$base+'.manifest'
if((Get-FileHash -LiteralPath $manifest -Algorithm SHA256).Hash -cne 'FE005DCBF87216CB8A08E46C5EF7DB8BA2CD791356374673A1FA68EFD1BBB939'){throw 'Manifest drift'}
$expected=@{};foreach($line in [IO.File]::ReadAllLines($manifest)){$expected[$line.Substring(66)]=$line.Substring(0,64).ToUpperInvariant()}
function Verify-Inputs([string]$Root){
 foreach($name in $expected.Keys){if((Get-FileHash -LiteralPath (Join-Path $Root $name) -Algorithm SHA256).Hash -cne $expected[$name]){throw 'Frozen source mismatch'}}
}
Verify-Inputs $src
$out='C:\Users\vika\Documents\exact-agent-ui-admission-ready-20261006c'
if(Test-Path -LiteralPath $out){throw 'UI build directory exists'}
[void][IO.Directory]::CreateDirectory($out)
$summary=@('SourceManifestSHA256=FE005DCBF87216CB8A08E46C5EF7DB8BA2CD791356374673A1FA68EFD1BBB939')
$pass=$true
foreach($mode in @('normal','feature')){foreach($configuration in @('Debug','Release')){
 $name=$mode+'-'+$configuration.ToLowerInvariant();$copy=Join-Path $out ('src-'+$name)
 [void][IO.Directory]::CreateDirectory($copy);Copy-Item -LiteralPath (Join-Path $src 'agente') -Destination $copy -Recurse
 Verify-Inputs $copy
 $log=Join-Path $out ($name+'-ui-build.txt');$feature=if($mode -ceq 'feature'){'true'}else{'false'}
 $old=$ErrorActionPreference
 try{$ErrorActionPreference='Continue'; & dotnet.exe build (Join-Path $copy 'agente\SafeUpload.Agent.App\SafeUpload.Agent.App.csproj') -c $configuration -warnaserror ('-p:SafeUploadAdmissionEvidence='+$feature) > $log 2>&1;$code=$LASTEXITCODE}finally{$ErrorActionPreference=$old}
 $text=[IO.File]::ReadAllText($log);$warnings=[regex]::Matches($text,'(?im)\bwarning\s+[A-Z]+\d+\b').Count;$errors=[regex]::Matches($text,'(?im)\berror\s+[A-Z]+\d+\b').Count
 $summary+=($name+': exit='+$code+' warnings='+$warnings+' errors='+$errors)
 if($code -ne 0 -or $warnings -ne 0 -or $errors -ne 0){$pass=$false}
 Verify-Inputs $copy
}}
Verify-Inputs $src
$summary+=('UiBuildGate='+$pass);$summary+='BUILD_END_UTC='+[DateTime]::UtcNow.ToString('o')
$summary|Set-Content -LiteralPath (Join-Path $out 'summary.txt') -Encoding UTF8
$summary
if(-not $pass){exit 1}
