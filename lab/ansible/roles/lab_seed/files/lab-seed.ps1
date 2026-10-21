# SafeUpload lab first-boot seed. Runs at every startup as SYSTEM (scheduled task SafeUploadLabSeed) and applies the
# seed disk (volume label "cidata", file "user-data", JSON) once; later changes are refused: hostname, the admin password, the
# SSH keys allowed to sign in as the admin, time zone and the certificates the debuggee must trust (the public half of
# each colleague's own test-signing certificate). The image itself carries none of these. Without a seed disk the
# admin password stays the discarded random build password and SSH stays off.
$ErrorActionPreference = 'Stop'
$state = 'C:\ProgramData\SafeUploadLab'
New-Item -ItemType Directory -Force -Path $state | Out-Null
$log = Join-Path $state 'seed.log'
function Write-SeedLog([string] $Text) { Add-Content -LiteralPath $log -Value ((Get-Date).ToUniversalTime().ToString('o') + ' ' + $Text) }
$setup = Get-ItemProperty 'HKLM:\SYSTEM\Setup'
if ($setup.SystemSetupInProgress -or $setup.OOBEInProgress -or (Test-Path (Join-Path $state 'oobe-pending'))) {
    Write-SeedLog 'Waiting for setup completion.'
    exit 0
}

$seedPath = $null
# Startup tasks can precede optical/SCSI volume discovery on both libvirt and Hyper-V.
$deadline = [Diagnostics.Stopwatch]::StartNew()
do {
    foreach ($volume in @(Get-Volume | Where-Object { $_.DriveLetter -and $_.FileSystemLabel -in @('cidata', 'CIDATA') })) {
        $candidate = $volume.DriveLetter + ':\user-data'
        if (Test-Path -LiteralPath $candidate) { $seedPath = $candidate; break }
    }
    if ($null -ne $seedPath) { break }
    Start-Sleep -Seconds 2
} while ($deadline.Elapsed.TotalSeconds -lt 90)
if ($null -eq $seedPath) { Write-SeedLog 'No seed disk; nothing applied.'; exit 0 }

$hash = (Get-FileHash -LiteralPath $seedPath -Algorithm SHA256).Hash
$applied = Join-Path $state 'seed-applied.txt'
if (Test-Path -LiteralPath $applied) {
    if ((Get-Content -LiteralPath $applied -Raw).Trim() -ne $hash) { throw 'Seed changed after initialization; automatic reseeding is refused.' }
    Start-Service -Name sshd -ErrorAction SilentlyContinue
    exit 0
}
try {
    $seed = [IO.File]::ReadAllText($seedPath, [Text.Encoding]::UTF8) | ConvertFrom-Json
    $admin = if ($seed.admin_user) { [string] $seed.admin_user } else { 'vika' }
    if ($admin -ne 'vika' -or -not $seed.admin_password) { throw 'Seed requires the existing vika admin and a password.' }
    $lines = @($seed.authorized_keys | Where-Object { $_ })
    if ($lines.Count -eq 0) { throw 'Seed requires at least one SSH public key.' }
    foreach ($line in $lines) {
        if ($line -notmatch '^(ssh-ed25519|ssh-rsa|ecdsa-sha2-nistp(256|384|521)) [A-Za-z0-9+/=]+( [^\r\n]*)?$') {
            throw 'Seed contains an invalid OpenSSH public key.'
        }
    }

    if ($seed.admin_password) {
        Set-LocalUser -Name $admin -Password (ConvertTo-SecureString ([string] $seed.admin_password) -AsPlainText -Force)
        Write-SeedLog "Password set for $admin."
    }
    if ($seed.time_zone) { Set-TimeZone -Id ([string] $seed.time_zone); Write-SeedLog "Time zone $($seed.time_zone)." }

    foreach ($der in @($seed.trusted_certificates)) {
        if (-not $der) { continue }
        # X509Store, not Import-Certificate: as SYSTEM, Import-Certificate is denied for TrustedPublisher (E_ACCESSDENIED).
        # Check the content type first: constructing from PFX bytes would already import the private key.
        $bytes = [Convert]::FromBase64String([string] $der)
        if ([Security.Cryptography.X509Certificates.X509Certificate2]::GetCertContentType($bytes) -ne 'Cert') {
            throw 'Seed certificates must be public DER or PEM certificates; refusing other content.'
        }
        $certificate = New-Object Security.Cryptography.X509Certificates.X509Certificate2 -ArgumentList (,$bytes)
        if ($certificate.HasPrivateKey) { throw 'Seed certificates must be public; refusing a private key.' }
        foreach ($name in 'Root', 'TrustedPublisher') {
            $store = New-Object Security.Cryptography.X509Certificates.X509Store -ArgumentList $name, 'LocalMachine'
            $store.Open('ReadWrite')
            try { $store.Add($certificate) } finally { $store.Close() }
        }
        Write-SeedLog "Trusted certificate $($certificate.Thumbprint) imported (Root, TrustedPublisher)."
    }

    # SSH: fresh host keys for this machine, only the seed's keys authorized, then start sshd.
    $ssh = 'C:\ProgramData\ssh'
    New-Item -ItemType Directory -Force -Path $ssh | Out-Null
    if (-not (Test-Path -LiteralPath (Join-Path $ssh 'ssh_host_ed25519_key'))) {
        & "$env:WINDIR\System32\OpenSSH\ssh-keygen.exe" -A | Out-Null
        if ($LASTEXITCODE -ne 0) { throw 'SSH host key generation failed.' }
        Write-SeedLog 'SSH host keys generated.'
    }
    $keys = Join-Path $ssh 'administrators_authorized_keys'
    [IO.File]::WriteAllText($keys, (($lines -join "`n") + "`n"), (New-Object Text.UTF8Encoding $false))
    & icacls.exe $keys /inheritance:r /grant 'SYSTEM:F' /grant '*S-1-5-32-544:F' | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'Could not secure the seeded SSH keys.' }
    Write-SeedLog "$($lines.Count) authorized SSH key(s) written."
    if ($lines.Count -gt 0) { Set-Service -Name sshd -StartupType Automatic; Start-Service -Name sshd }

    if ($seed.hostname -and $env:COMPUTERNAME -ne ([string] $seed.hostname).ToUpperInvariant()) {
        Write-SeedLog "Renaming to $($seed.hostname) and restarting."
        Rename-Computer -NewName ([string] $seed.hostname) -Force
        Set-Content -LiteralPath $applied -Value $hash
        Restart-Computer -Force
    } else {
        Set-Content -LiteralPath $applied -Value $hash
    }
} catch {
    Write-SeedLog ('Seed failed: ' + $_.Exception.Message)
    throw
}
