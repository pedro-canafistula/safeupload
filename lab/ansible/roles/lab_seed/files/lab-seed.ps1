# SafeUpload lab first-boot seed. Runs at every startup as SYSTEM (scheduled task SafeUploadLabSeed) and applies the
# seed disk (volume label "cidata", file "user-data", JSON) once per seed content: hostname, the admin password, the
# SSH keys allowed to sign in as the admin, time zone and the certificates the debuggee must trust (the public half of
# each colleague's own test-signing certificate). The image itself carries none of these. Without a seed disk the
# admin password stays the discarded random build password and SSH stays off.
$ErrorActionPreference = 'Stop'
$state = 'C:\ProgramData\SafeUploadLab'
New-Item -ItemType Directory -Force -Path $state | Out-Null
$log = Join-Path $state 'seed.log'
function Write-SeedLog([string] $Text) { Add-Content -LiteralPath $log -Value ((Get-Date).ToUniversalTime().ToString('o') + ' ' + $Text) }

$seedPath = $null
foreach ($volume in @(Get-Volume | Where-Object { $_.DriveLetter -and $_.FileSystemLabel -in @('cidata', 'CIDATA') })) {
    $candidate = $volume.DriveLetter + ':\user-data'
    if (Test-Path -LiteralPath $candidate) { $seedPath = $candidate; break }
}
if ($null -eq $seedPath) { Write-SeedLog 'No seed disk; nothing applied.'; exit 0 }

$hash = (Get-FileHash -LiteralPath $seedPath -Algorithm SHA256).Hash
$applied = Join-Path $state 'seed-applied.txt'
if ((Test-Path -LiteralPath $applied) -and ((Get-Content -LiteralPath $applied -Raw).Trim() -eq $hash)) {
    Start-Service -Name sshd -ErrorAction SilentlyContinue
    exit 0
}
try {
    $seed = [IO.File]::ReadAllText($seedPath, [Text.Encoding]::UTF8) | ConvertFrom-Json
    $admin = if ($seed.admin_user) { [string] $seed.admin_user } else { 'vika' }

    if ($seed.admin_password) {
        Set-LocalUser -Name $admin -Password (ConvertTo-SecureString ([string] $seed.admin_password) -AsPlainText -Force)
        Write-SeedLog "Password set for $admin."
    }
    if ($seed.time_zone) { Set-TimeZone -Id ([string] $seed.time_zone); Write-SeedLog "Time zone $($seed.time_zone)." }

    foreach ($der in @($seed.trusted_certificates)) {
        if (-not $der) { continue }
        $file = Join-Path $state ('trusted-' + [guid]::NewGuid().ToString('N') + '.cer')
        [IO.File]::WriteAllBytes($file, [Convert]::FromBase64String([string] $der))
        foreach ($store in 'Root', 'TrustedPublisher') { Import-Certificate -FilePath $file -CertStoreLocation "Cert:\LocalMachine\$store" | Out-Null }
        Remove-Item -LiteralPath $file -Force
        Write-SeedLog 'Trusted certificate imported (Root, TrustedPublisher).'
    }

    # SSH: fresh host keys for this machine, only the seed's keys authorized, then start sshd.
    $ssh = 'C:\ProgramData\ssh'
    New-Item -ItemType Directory -Force -Path $ssh | Out-Null
    if (-not (Test-Path -LiteralPath (Join-Path $ssh 'ssh_host_ed25519_key'))) {
        & "$env:WINDIR\System32\OpenSSH\ssh-keygen.exe" -A | Out-Null
        Write-SeedLog 'SSH host keys generated.'
    }
    $keys = Join-Path $ssh 'administrators_authorized_keys'
    $lines = @($seed.authorized_keys | Where-Object { $_ })
    [IO.File]::WriteAllText($keys, (($lines -join "`n") + "`n"), (New-Object Text.UTF8Encoding $false))
    & icacls.exe $keys /inheritance:r /grant 'SYSTEM:F' /grant '*S-1-5-32-544:F' | Out-Null
    Write-SeedLog "$($lines.Count) authorized SSH key(s) written."
    if ($lines.Count -gt 0) { Set-Service -Name sshd -StartupType Automatic; Start-Service -Name sshd }

    Set-Content -LiteralPath $applied -Value $hash
    if ($seed.hostname -and $env:COMPUTERNAME -ne ([string] $seed.hostname).ToUpperInvariant()) {
        Write-SeedLog "Renaming to $($seed.hostname) and restarting."
        Rename-Computer -NewName ([string] $seed.hostname) -Force
        Restart-Computer -Force
    }
} catch {
    Write-SeedLog ('Seed failed: ' + $_.Exception.Message)
    throw
}
