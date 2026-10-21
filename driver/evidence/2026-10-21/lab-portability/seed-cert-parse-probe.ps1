$ErrorActionPreference = 'Stop'
# In-memory only: no certificate store is touched on the builder.
$rsa = [Security.Cryptography.RSA]::Create(2048)
$request = New-Object Security.Cryptography.X509Certificates.CertificateRequest('CN=LabSeedParseProbe', $rsa,
    [Security.Cryptography.HashAlgorithmName]::SHA256, [Security.Cryptography.RSASignaturePadding]::Pkcs1)
$probe = $request.CreateSelfSigned([DateTimeOffset]::UtcNow, [DateTimeOffset]::UtcNow.AddDays(1))
$der = $probe.Export('Cert')
$pem = [Text.Encoding]::ASCII.GetBytes("-----BEGIN CERTIFICATE-----`n" + [Convert]::ToBase64String($der, 'InsertLineBreaks') + "`n-----END CERTIFICATE-----`n")
$pfx = $probe.Export('Pfx')
foreach ($case in @(@('DER', $der), @('PEM', $pem), @('PFX', $pfx))) {
    # Same call as lab-seed.ps1: the seed JSON carries base64 of the file bytes.
    $bytes = [Convert]::FromBase64String([Convert]::ToBase64String($case[1]))
    $type = [Security.Cryptography.X509Certificates.X509Certificate2]::GetCertContentType($bytes)
    if ($type -ne 'Cert') { $case[0] + ':ContentType=' + $type + ';Refused=True'; continue }
    $c = New-Object Security.Cryptography.X509Certificates.X509Certificate2 -ArgumentList (,$bytes)
    $case[0] + ':ContentType=' + $type + ';Thumbprint=' + ($c.Thumbprint -eq $probe.Thumbprint) + ';HasPrivateKey=' + $c.HasPrivateKey
}
'PS=' + $PSVersionTable.PSVersion + ';CLR=' + [Environment]::Version
