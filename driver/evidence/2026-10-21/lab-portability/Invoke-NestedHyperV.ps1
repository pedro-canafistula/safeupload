#requires -Version 5.1
# One-off controls inside the disposable su-lab Hyper-V host candidate (nested on KVM); not a product runner.
# Follows lab/README.md as a Windows colleague would: native Hyper-V cmdlets, New-LabVM.ps1, Windows ssh.exe/scp.exe.
param([Parameter(Mandatory)][ValidateSet('enable','create','check','reboot','cleanup')][string] $Phase)
$ErrorActionPreference = 'Stop'
$work = 'C:\SafeUploadNested'
$name = 'su-lab-nested1021k'; $hostname = 'SU-LAB-NESTED'; $processors = 2
$image = "$work\image\safeupload-debuggee-19045.2965.vhdx"
$vmRoot = 'C:\SafeUploadLab'
$client = "$work\client"; $key = "$client\id_ed25519"; $known = "$client\known_hosts"
$certificate = "$work\image\seed-test.cer"  # public half only, as a colleague passes their own test-signing certificate
$protected = @('9D44EEE8-81CF-4CC1-9FBA-7670F11DEF4D','9D6E3F02-B40A-49F0-A77F-439714F8F308',
    'FFCB9530-146B-43B1-8AF7-2B5CC8EDE2E3','C6440689-D11C-4C63-A463-F3722B7DDB69','9A20C45F-7C79-4742-887F-5B279309FAB9')
if ($env:COMPUTERNAME -ine 'SU-LAB-HVHOST' -or (Get-CimInstance Win32_ComputerSystemProduct).UUID -in $protected) {
    throw 'Nested controls run only on the disposable SU-LAB-HVHOST candidate.'
}

function Invoke-Native([string] $File, [string[]] $Arguments) {
    # Windows PowerShell 5.1 turns native stderr into errors under Stop; capture both streams and the exit code.
    $out = "$client\native-out.txt"; $err = "$client\native-err.txt"
    $quoted = @($Arguments | ForEach-Object { if ($_ -match '[\s"]' -or $_ -eq '') { '"' + ($_ -replace '"','\"') + '"' } else { $_ } })
    $p = Start-Process -FilePath $File -ArgumentList ($quoted -join ' ') -Wait -PassThru -NoNewWindow `
        -RedirectStandardOutput $out -RedirectStandardError $err
    [pscustomobject]@{ Code = $p.ExitCode; Out = [IO.File]::ReadAllText($out); Err = [IO.File]::ReadAllText($err) }
}

function Get-GuestAddress {
    @((Get-VMNetworkAdapter -VMName $name).IPAddresses | Where-Object { $_ -match '^\d+\.\d+\.\d+\.\d+$' -and $_ -notlike '169.254.*' }) | Select-Object -First 1
}

function Invoke-Guest([string] $Address, [string] $Script, [string] $Identity = $key) {
    $encoded = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($Script))
    Invoke-Native "$env:WINDIR\System32\OpenSSH\ssh.exe" @('-F','NUL','-i',$Identity,'-o','IdentitiesOnly=yes','-o','BatchMode=yes',
        '-o','ConnectTimeout=8','-o','StrictHostKeyChecking=accept-new','-o',"UserKnownHostsFile=$known","vika@$Address",
        'powershell.exe','-NoProfile','-NonInteractive','-EncodedCommand',$encoded)
}

$identityScript = @'
$ErrorActionPreference='Stop'; $setup=Get-ItemProperty 'HKLM:\SYSTEM\Setup'
[pscustomobject]@{SetupDone=(-not ($setup.SystemSetupInProgress -or $setup.OOBEInProgress));Name=$env:COMPUTERNAME
UUID=(Get-CimInstance Win32_ComputerSystemProduct).UUID;Boot=(Get-CimInstance Win32_OperatingSystem).LastBootUpTime.ToUniversalTime().ToString('o')
Seed=(Get-Content 'C:\ProgramData\SafeUploadLab\seed-applied.txt' -Raw).Trim();HostKey=(Get-FileHash 'C:\ProgramData\ssh\ssh_host_ed25519_key.pub').Hash} | ConvertTo-Json -Compress
'@

function Wait-Guest([string] $PreviousBoot) {
    $timer = [Diagnostics.Stopwatch]::StartNew(); $last = 'no address'
    while ($timer.Elapsed.TotalMinutes -lt 40) {
        $address = Get-GuestAddress
        if ($address) {
            $r = Invoke-Guest $address $identityScript
            if ($r.Code -eq 0) {
                $guest = $r.Out.Trim().TrimStart([char]0xFEFF) | ConvertFrom-Json
                if ($guest.SetupDone -and $guest.Name -ieq $hostname -and $guest.Boot -ne $PreviousBoot) { return @($address, $guest) }
                $last = 'waiting for setup/seed/new boot: ' + $r.Out.Trim()
            } else { $last = $r.Err.Trim() }
        }
        Start-Sleep -Seconds 5
    }
    throw ('Nested candidate not ready: ' + $last)
}

function Invoke-Acceptance([string] $Address) {
    foreach ($pair in @(@("$work\scripts\Test-LabGuest.ps1",'C:/Windows/Temp/Test-LabGuest.ps1'),@("$key.pub",'C:/Windows/Temp/lab-test-key.pub'))) {
        $r = Invoke-Native "$env:WINDIR\System32\OpenSSH\scp.exe" @('-F','NUL','-i',$key,'-o','IdentitiesOnly=yes','-o','BatchMode=yes',
            '-o','StrictHostKeyChecking=yes','-o',"UserKnownHostsFile=$known",$pair[0],"vika@${Address}:$($pair[1])")
        if ($r.Code) { throw ('Native scp failed: ' + $r.Err) }
    }
    $r = Invoke-Guest $Address "`$ErrorActionPreference='Stop'; & C:\Windows\Temp\Test-LabGuest.ps1 -ExpectedHostname $hostname -ExpectedSshPublicKeyFiles C:\Windows\Temp\lab-test-key.pub -ExpectedProcessors $processors | ConvertTo-Json -Compress"
    if ($r.Code) { throw ('Guest acceptance failed: ' + $r.Out + $r.Err) }
    $data = $r.Out.Trim().TrimStart([char]0xFEFF) | ConvertFrom-Json
    if ($data.CandidateAcceptance -ne 'PASS' -or $data.ProductQualification) { throw 'Unexpected acceptance result.' }
    'GuestAcceptance=' + ($data | ConvertTo-Json -Compress)
    $thumbprint = (New-Object Security.Cryptography.X509Certificates.X509Certificate2 -ArgumentList $certificate).Thumbprint
    $r = Invoke-Guest $Address "`$ErrorActionPreference='Stop'; foreach (`$n in 'Root','TrustedPublisher') { `$c = Get-Item Cert:\LocalMachine\`$n\$thumbprint; if (`$c.HasPrivateKey) { throw 'private key' } }; 'PublicCertificateSeed=PASS'"
    if ($r.Code -or $r.Out -notmatch 'PublicCertificateSeed=PASS') { throw ('Seeded certificate check failed: ' + $r.Err) }
    'PublicCertificateSeed=PASS;Thumbprint=' + $thumbprint
}

switch ($Phase) {
    'enable' {
        $feature = Get-WindowsOptionalFeature -Online -FeatureName Microsoft-Hyper-V-All
        if ($feature.State -ne 'Enabled') {
            $result = Enable-WindowsOptionalFeature -Online -FeatureName Microsoft-Hyper-V-All -All -NoRestart
            'HyperVFeatureEnabled=True;RestartNeeded=' + $result.RestartNeeded
        } else { 'HyperVFeatureEnabled=AlreadyEnabled' }
    }
    'create' {
        $vmHost = Get-VMHost
        $switch = Get-VMSwitch -Name 'Default Switch'
        'HyperVHost=' + $vmHost.Name + ';Switch=' + $switch.Name + ';SwitchType=' + $switch.SwitchType
        $null = New-Item -ItemType Directory -Path $client -Force
        & icacls.exe $client /inheritance:r /grant "${env:USERNAME}:(OI)(CI)F" /grant '*S-1-5-18:(OI)(CI)F' /grant '*S-1-5-32-544:(OI)(CI)F' | Out-Null
        if ($LASTEXITCODE) { throw 'Client directory ACL failed.' }
        foreach ($k in $key, "$client\unrelated") {
            if (-not (Test-Path -LiteralPath $k)) {
                $r = Invoke-Native "$env:WINDIR\System32\OpenSSH\ssh-keygen.exe" @('-q','-t','ed25519','-N','','-C','nested-control','-f',$k)
                if ($r.Code) { throw ('ssh-keygen failed: ' + $r.Err) }
            }
        }
        $expected = ((Get-Content "$work\image\image.sha256" -Raw).Trim() -split '\s+')[0]
        $password = 'L' + [guid]::NewGuid().ToString('N').Substring(0, 20) + '!9'
        [IO.File]::WriteAllText("$client\admin-password.txt", $password)
        $settings = @{
            ImagePath = $image; ImageSha256 = $expected; VMRoot = $vmRoot; SwitchName = 'Default Switch'
            SshPublicKeyFiles = @("$key.pub"); Name = $name; Hostname = $hostname; MemoryGiB = 2; Processors = $processors
            TrustedCertificateFiles = @($certificate)
        }
        & "$work\scripts\hyperv\New-LabVM.ps1" @settings -ValidateOnly
        & "$work\scripts\hyperv\New-LabVM.ps1" @settings -AdminPassword (ConvertTo-SecureString $password -AsPlainText -Force) -Start |
            ConvertTo-Json -Compress
        $vm = Get-VM -Name $name
        'VM=' + ([pscustomobject]@{ Generation = $vm.Generation; State = [string]$vm.State; Processors = $vm.ProcessorCount
            MemoryStartupGiB = $vm.MemoryStartup / 1GB; SecureBoot = [string](Get-VMFirmware -VM $vm).SecureBoot
            Tpm = (Get-VMSecurity -VM $vm).TpmEnabled; Checkpoints = [string]$vm.CheckpointType
            Disks = @(Get-VMHardDiskDrive -VM $vm | ForEach-Object { $_.ControllerType.ToString() + ':' + (Split-Path -Leaf $_.Path) }) } | ConvertTo-Json -Compress)
    }
    'check' {
        $address, $guest = Wait-Guest ''
        'SeededIdentity=' + ($guest | ConvertTo-Json -Compress) + ';Address=' + $address
        Invoke-Acceptance $address
        $r = Invoke-Guest $address "'unrelated-key-must-fail'" "$client\unrelated"
        if ($r.Code -ne 255 -or $r.Err -notmatch 'Permission denied') { throw ('Unrelated key was not refused: ' + $r.Code + ' ' + $r.Err) }
        'UnrelatedSshKey=REFUSED'
        $guest | ConvertTo-Json -Compress | Set-Content "$client\identity-before.json"
        'NativeWindowsSshClient=' + (Invoke-Native "$env:WINDIR\System32\OpenSSH\ssh.exe" @('-V')).Err.Trim()
    }
    'reboot' {
        $before = Get-Content "$client\identity-before.json" -Raw | ConvertFrom-Json
        $address = Get-GuestAddress
        $r = Invoke-Guest $address "'REBOOT_REQUESTED'; Restart-Computer -Force"
        if ($r.Out -notmatch 'REBOOT_REQUESTED') { throw ('Reboot request failed: ' + $r.Err) }
        $address, $after = Wait-Guest $before.Boot
        if ($after.HostKey -ne $before.HostKey -or $after.Seed -ne $before.Seed -or $after.UUID -ne $before.UUID) { throw 'Seed was not idempotent.' }
        Invoke-Acceptance $address
        'RebootIdempotence=PASS;After=' + ($after | ConvertTo-Json -Compress)
    }
    'cleanup' {
        $expected = ((Get-Content "$work\image\image.sha256" -Raw).Trim() -split '\s+')[0]
        Stop-VM -Name $name -Force
        Remove-VM -Name $name -Force
        Remove-Item -LiteralPath (Join-Path $vmRoot $name) -Recurse -Force
        if (Get-VM -Name $name -ErrorAction SilentlyContinue) { throw 'VM registration remains.' }
        if (Test-Path -LiteralPath (Join-Path $vmRoot $name)) { throw 'VM directory remains.' }
        if ((Get-FileHash -LiteralPath $image -Algorithm SHA256).Hash -ine $expected) { throw 'Shared VHDX changed.' }
        if ((Get-VHD -Path $image).Attached) { throw 'Shared VHDX is attached.' }
        'HyperVCleanup=PASS;SharedVhdxUnchanged=True'
    }
}
