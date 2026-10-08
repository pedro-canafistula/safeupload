<# Builds the private qualification companion from a verified exact Git archive. Never installs it. #>
param([Parameter(Mandatory)][ValidatePattern('^[A-Za-z0-9._-]{3,60}$')][string]$Label,
    [Parameter(Mandatory)][ValidatePattern('^[0-9a-fA-F]{64}$')][string]$ArchiveHash,
    [Parameter(Mandatory)][ValidatePattern('^[0-9a-fA-F]{64}$')][string]$ManifestHash,
    [Parameter(Mandatory)][ValidatePattern('^[0-9a-fA-F]{40}$')][string]$CertificateThumbprint,
    [ValidateSet('CurrentUser','LocalMachine')][string]$CertificateStoreLocation='CurrentUser')
$ErrorActionPreference='Stop'
$uuid=(Get-CimInstance Win32_ComputerSystemProduct -ErrorAction Stop).UUID
if($env:COMPUTERNAME -ne 'DESKTOP-O1LP5DG' -or $uuid -ne 'C6440689-D11C-4C63-A463-F3722B7DDB69'){throw 'Builder identity mismatch'}
$d='C:\Users\vika\Documents';$run=Join-Path $d ('exact-section-fault-'+$Label)
if(Test-Path $run){throw 'Existing companion build directory'}
$zip=Join-Path $d ('exact-section-fault-'+$Label+'.zip');$manifest=Join-Path $d ('exact-section-fault-'+$Label+'.manifest')
if((Get-FileHash $zip -Algorithm SHA256).Hash -ne $ArchiveHash -or (Get-FileHash $manifest -Algorithm SHA256).Hash -ne $ManifestHash){throw 'Companion input hashes mismatch'}
$out=Join-Path $run 'out';$src=Join-Path $run 'src';[void][IO.Directory]::CreateDirectory($out)
Expand-Archive $zip $src
$expected=@{};foreach($line in [IO.File]::ReadAllLines($manifest)){$expected[$line.Substring(66).Replace('/','\')]=$line.Substring(0,64).ToUpperInvariant()}
$seen=0;foreach($file in Get-ChildItem $src -File -Recurse){$relative=$file.FullName.Substring($src.Length+1);if(-not $expected.ContainsKey($relative) -or (Get-FileHash $file.FullName -Algorithm SHA256).Hash -ne $expected[$relative]){throw 'Companion source manifest mismatch'};$seen++}
if($seen -ne $expected.Count){throw 'Companion source set mismatch'}
$msbuild='C:\Program Files\Microsoft Visual Studio\18\Community\MSBuild\Current\Bin\amd64\MSBuild.exe'
$rules='C:\Program Files (x86)\Windows Kits\10\CodeAnalysis\DriverRecommendedRules.ruleset'
$sign='C:\Program Files (x86)\Windows Kits\10\bin\10.0.28000.0\x64\signtool.exe'
$summary=@(('SOURCE_MANIFEST_VERIFIED='+$seen),('BUILDER='+$env:COMPUTERNAME),('BUILDER_UUID='+$uuid),('ARCHIVE_SHA256='+$ArchiveHash),('MANIFEST_SHA256='+$ManifestHash))
function Invoke-NativeToLog([string] $Executable, [string[]] $Arguments, [string] $Log) {
    if (-not (Test-Path -LiteralPath $Executable -PathType Leaf)) { throw 'Native build tool missing.' }
    $previousErrorPreference = $ErrorActionPreference
    try {
        # PS 5.1 converts redirected native stderr to ErrorRecords. Complete
        # the process and retain its actual stderr before evaluating its exit.
        $ErrorActionPreference = 'Continue'
        & $Executable @Arguments > $Log 2>&1
        $nativeExit = $LASTEXITCODE
    } finally { $ErrorActionPreference = $previousErrorPreference }
    return $nativeExit
}
Push-Location $src
try{
foreach($configuration in @('Debug','Release')){
 $log=Join-Path $out ($configuration+'-wdk.txt')
 $exit=Invoke-NativeToLog $msbuild @('driver\SafeUpload.SectionFault\SafeUpload.SectionFault.vcxproj','/t:Rebuild',"/p:Configuration=$configuration",'/p:Platform=x64','/p:SafeUploadSectionFaultTest=true','/warnaserror','/p:RunCodeAnalysis=true','/p:EnablePREfast=true',"/p:CodeAnalysisRuleSet=$rules") $log
 $text=[IO.File]::ReadAllText($log)
 $w=([regex]::Matches($text,'(?m)^\s*(\d+) Warning\(s\)')|ForEach-Object {$_.Groups[1].Value}) -join ','
 $e=([regex]::Matches($text,'(?m)^\s*(\d+) Error\(s\)')|ForEach-Object {$_.Groups[1].Value}) -join ','
 $summary+="$configuration : exit=$exit warnings=$w errors=$e prefast=$($text -match 'DriverRecommendedRules') apivalidator=$($text -match 'ApiValidator')"
 if($exit -eq 0){Copy-Item "driver\SafeUpload.SectionFault\x64\$configuration\SafeUploadSectionFault.sys" (Join-Path $out ($configuration+'.sys'))}
}
}finally{Pop-Location}
$unsigned = Join-Path $out 'Debug.sys'
if (Test-Path -LiteralPath $unsigned) {
    $signed = Join-Path $out 'SafeUploadSectionFault.sys'
    if (Test-Path -LiteralPath $signed) { throw 'Signing destination already exists.' }
    $unsignedHash = (Get-FileHash -LiteralPath $unsigned -Algorithm SHA256).Hash
    Copy-Item -LiteralPath $unsigned -Destination $signed
    $copyHash = (Get-FileHash -LiteralPath $signed -Algorithm SHA256).Hash
    if ($copyHash -cne $unsignedHash) { throw 'Unsigned signing-copy hash mismatch.' }
    $signArguments = @('sign', '/fd', 'sha256', '/sha1', $CertificateThumbprint)
    if ($CertificateStoreLocation -ceq 'LocalMachine') { $signArguments += '/sm' }
    $signArguments += $signed
    $signExit = Invoke-NativeToLog $sign $signArguments (Join-Path $out 'sign.txt')
    if ((Get-FileHash -LiteralPath $unsigned -Algorithm SHA256).Hash -cne $unsignedHash) {
        throw 'Original unsigned artifact changed during signing.'
    }
    $outputHash = (Get-FileHash -LiteralPath $signed -Algorithm SHA256).Hash
    $signedHash = 'NONE'
    $signatureValid = $false
    $signatureStatus = 'SigningFailed'
    $actualSigner = 'NONE'
    if ($signExit -eq 0) {
        try {
            $signature = Get-AuthenticodeSignature -LiteralPath $signed
            $signatureStatus = $signature.Status.ToString()
            if ($null -ne $signature.SignerCertificate) { $actualSigner = $signature.SignerCertificate.Thumbprint }
            $signatureValid = $signatureStatus -ceq 'Valid' -and $actualSigner -ceq $CertificateThumbprint.ToUpperInvariant()
            if ($signatureValid) { $signedHash = $outputHash }
        } catch { $signatureStatus = 'VerificationFailed' }
    }
    @{ UTC = [DateTime]::UtcNow.ToString('o'); SignExit = $signExit;
        SignatureStatus = $signatureStatus; ExpectedSigner = $CertificateThumbprint;
        CertificateStoreLocation = $CertificateStoreLocation;
        ActualSigner = $actualSigner; SignatureValid = $signatureValid;
        UnsignedSHA256 = $unsignedHash; SigningCopySHA256Before = $copyHash;
        UnsignedArtifactUnchanged = $true;
        OutputSHA256 = $outputHash; SignedSHA256 = $signedHash } |
        ConvertTo-Json | Set-Content -LiteralPath (Join-Path $out 'signature-verification.json') -Encoding UTF8
     $summary += "sign : exit=$signExit unsigned_sha256=$unsignedHash signing_copy_sha256=$copyHash unsigned_unchanged=True store=$CertificateStoreLocation output_sha256=$outputHash signed_sha256=$signedHash signature_valid=$signatureValid signer=$CertificateThumbprint"
}
else { $summary += 'sign : SKIPPED (no companion Debug SYS)' }

$summary+='BUILD_END_UTC='+[DateTime]::UtcNow.ToString('o');$summary|Set-Content (Join-Path $out 'summary.txt') -Encoding UTF8
$summary
