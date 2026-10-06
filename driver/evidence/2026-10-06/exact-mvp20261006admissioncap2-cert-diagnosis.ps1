$ErrorActionPreference = 'Stop'
$expectedComputer = 'DESKTOP-O1LP5DG'
$expectedUuid = 'C6440689-D11C-4C63-A463-F3722B7DDB69'
$expectedThumbprint = '220DD82C37FCF36048D59E4F10113185D81D5DC7'
$expectedArtifactHash = 'F1921595C78AF964CE416D34B96FE725C96F2AA114DE7C686641A1190222A119'
$runRoot = 'C:\Users\vika\Documents\exact-mvp20261006admissioncap2'
$source = Join-Path $runRoot 'out\owned-feature.sys'
$signtool = 'C:\Program Files (x86)\Windows Kits\10\bin\10.0.28000.0\x64\signtool.exe'
$result = [ordered]@{ Status = 'Started'; UTC = [DateTime]::UtcNow.ToString('o') }
try {
    $computer = Get-CimInstance Win32_ComputerSystem
    $product = Get-CimInstance Win32_ComputerSystemProduct
    if ($env:COMPUTERNAME -cne $expectedComputer -or $product.UUID -cne $expectedUuid) { throw 'Builder identity mismatch.' }
    if (-not (Test-Path -LiteralPath $source -PathType Leaf)) { throw 'Pinned source artifact is missing.' }
    $sourceHashBefore = (Get-FileHash -LiteralPath $source -Algorithm SHA256).Hash
    if ($sourceHashBefore -cne $expectedArtifactHash) { throw 'Pinned source artifact hash mismatch.' }
    if (-not (Test-Path -LiteralPath $signtool -PathType Leaf)) { throw 'Pinned SignTool path is missing.' }

    $cert = Get-Item -LiteralPath ('Cert:\CurrentUser\My\' + $expectedThumbprint)
    $ekuExtension = $null
    foreach ($extension in $cert.Extensions) {
        if ($extension.Oid.Value -eq '2.5.29.37') { $ekuExtension = $extension; break }
    }
    $ekuRows = @()
    if ($null -ne $ekuExtension) {
        $typedEku = New-Object System.Security.Cryptography.X509Certificates.X509EnhancedKeyUsageExtension($ekuExtension, $ekuExtension.Critical)
        foreach ($usage in $typedEku.EnhancedKeyUsages) {
            $ekuRows += [ordered]@{ Oid = $usage.Value; FriendlyName = $usage.FriendlyName }
        }
    }
    $keyInfo = [ordered]@{ AccessInspection = 'NotAttempted'; PrivateKeyType = $null; Provider = $null; KeyAccessible = $null; KeySize = $null; KeyAlgorithm = $null; KeyContainerType = $null; HardwareDevice = $null; MachineKeyStore = $null; IsMachineKey = $null; IsEphemeral = $null; Error = $null }
    try {
        $privateKey = $cert.PrivateKey
        if ($null -eq $privateKey) { throw 'Certificate.PrivateKey returned null.' }
        $keyInfo.PrivateKeyType = $privateKey.GetType().FullName
        $keyInfo.KeySize = $privateKey.KeySize
        $keyInfo.KeyAlgorithm = $privateKey.GetType().GetProperty('KeyExchangeAlgorithm').GetValue($privateKey, $null)
        if ($privateKey -is [System.Security.Cryptography.RSACryptoServiceProvider]) {
            $csp = $privateKey.CspKeyContainerInfo
            $keyInfo.Provider = $csp.ProviderName
            $keyInfo.KeyAccessible = [bool]$csp.Accessible
            $keyInfo['KeyContainerType'] = $csp.KeyContainerName
            $keyInfo['HardwareDevice'] = [bool]$csp.HardwareDevice
            $keyInfo['MachineKeyStore'] = [bool]$csp.MachineKeyStore
        } elseif ($privateKey -is [System.Security.Cryptography.RSACng]) {
            $cngKey = $privateKey.Key
            $keyInfo.Provider = $cngKey.Provider.Provider
            $keyInfo.KeyAccessible = $true
            $keyInfo['IsMachineKey'] = [bool]$cngKey.IsMachineKey
            $keyInfo['IsEphemeral'] = [bool]$cngKey.IsEphemeral
        } else {
            $keyInfo.Provider = 'Unclassified provider type; metadata only.'
        }
        $keyInfo.AccessInspection = 'Opened certificate private-key handle and queried provider accessibility; no key material exported and no probe signature generated.'
    } catch {
        $keyInfo.AccessInspection = 'Failed'
        $keyInfo.Error = $_.Exception.ToString()
    }

    $guid = [Guid]::NewGuid().ToString('N')
    $copy = Join-Path $runRoot ('out\sign-debug-copy-' + $guid + '.sys')
    $stdoutPath = Join-Path $runRoot ('out\sign-debug-copy-' + $guid + '.stdout.bin')
    $stderrPath = Join-Path $runRoot ('out\sign-debug-copy-' + $guid + '.stderr.bin')
    $paths = @($copy, $stdoutPath, $stderrPath)
    foreach ($path in $paths) { if (Test-Path -LiteralPath $path) { throw 'Unique diagnostic destination unexpectedly exists.' } }
    Copy-Item -LiteralPath $source -Destination $copy
    $copyHashBefore = (Get-FileHash -LiteralPath $copy -Algorithm SHA256).Hash
    if ($copyHashBefore -cne $expectedArtifactHash) { throw 'Diagnostic copy hash mismatch before SignTool.' }
    $argumentLine = 'sign /debug /fd sha256 /sha1 ' + $expectedThumbprint + ' "' + $copy + '"'
    $process = Start-Process -FilePath $signtool -ArgumentList $argumentLine -WorkingDirectory (Split-Path -Parent $signtool) -NoNewWindow -Wait -PassThru -RedirectStandardOutput $stdoutPath -RedirectStandardError $stderrPath
    $copyHashAfter = (Get-FileHash -LiteralPath $copy -Algorithm SHA256).Hash
    $sourceHashAfter = (Get-FileHash -LiteralPath $source -Algorithm SHA256).Hash
    $stdoutBytes = [IO.File]::ReadAllBytes($stdoutPath)
    $stderrBytes = [IO.File]::ReadAllBytes($stderrPath)
    $signature = Get-AuthenticodeSignature -LiteralPath $copy
    $result = [ordered]@{
        Status = 'Completed'
        UTC = [DateTime]::UtcNow.ToString('o')
        ComputerName = $env:COMPUTERNAME
        ComputerSystemUUID = $product.UUID
        User = [Security.Principal.WindowsIdentity]::GetCurrent().Name
        SourcePath = $source
        SourceSHA256Before = $sourceHashBefore
        SourceSHA256After = $sourceHashAfter
        SourceUnchanged = ($sourceHashBefore -ceq $sourceHashAfter)
        Certificate = [ordered]@{
            Thumbprint = $cert.Thumbprint
            Subject = $cert.Subject
            Issuer = $cert.Issuer
            NotBefore = $cert.NotBefore.ToUniversalTime().ToString('o')
            NotAfter = $cert.NotAfter.ToUniversalTime().ToString('o')
            HasPrivateKey = [bool]$cert.HasPrivateKey
            PublicKeyAlgorithmOid = $cert.PublicKey.Oid.Value
            PublicKeyAlgorithm = $cert.PublicKey.Oid.FriendlyName
            EkuExtensionPresent = ($null -ne $ekuExtension)
            EkuCritical = if ($null -ne $ekuExtension) { [bool]$ekuExtension.Critical } else { $null }
            EnhancedKeyUsages = @($ekuRows)
            PrivateKey = $keyInfo
        }
        DiagnosticCopy = [ordered]@{
            Path = $copy
            SHA256Before = $copyHashBefore
            SHA256After = $copyHashAfter
            SignToolExitCode = $process.ExitCode
            StdoutPath = $stdoutPath
            StdoutLength = $stdoutBytes.Length
            StdoutSHA256 = [BitConverter]::ToString([Security.Cryptography.SHA256]::Create().ComputeHash($stdoutBytes)).Replace('-', '').ToLowerInvariant()
            StdoutBase64 = [Convert]::ToBase64String($stdoutBytes)
            StderrPath = $stderrPath
            StderrLength = $stderrBytes.Length
            StderrSHA256 = [BitConverter]::ToString([Security.Cryptography.SHA256]::Create().ComputeHash($stderrBytes)).Replace('-', '').ToLowerInvariant()
            StderrBase64 = [Convert]::ToBase64String($stderrBytes)
            AuthenticodeStatus = $signature.Status.ToString()
            AuthenticodeStatusMessage = $signature.StatusMessage
            AuthenticodeSignerThumbprint = if ($null -ne $signature.SignerCertificate) { $signature.SignerCertificate.Thumbprint } else { $null }
        }
    }
} catch {
    $result.Status = 'Failed'
    $result.Error = $_.Exception.ToString()
}
$result | ConvertTo-Json -Depth 16 -Compress
if ($result.Status -ne 'Completed') { exit 2 }
