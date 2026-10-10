#requires -Version 5.1
# T4 runtime instrumentation only. Hold both services across the install reboot,
# enable volatile checks while the filter is unloaded, then load it exactly once.
# The disposable run disk restores the original machine on every exit path.
function Invoke-T4RuntimeNative([string]$File, [string[]]$Arguments) {
    $text = (& $File @Arguments 2>&1 | Out-String)
    if ($LASTEXITCODE -ne 0) { throw "$File failed ($LASTEXITCODE): $text" }
    return $text
}

function Get-T4RuntimeInstallState {
    $filters = Invoke-T4RuntimeNative 'fltmc.exe' @('filters')
    $driver = Invoke-T4RuntimeNative 'sc.exe' @('query', 'SafeUpload')
    [pscustomobject]@{
        FilterLoaded = [regex]::IsMatch($filters, '(?im)^\s*SafeUpload\s')
        DriverStopped = [regex]::IsMatch($driver, '(?im)^\s*STATE\s*:\s*1\s+STOPPED\s*$')
        AgentStopped = (Get-Service -Name SafeUploadAgent -ErrorAction Stop).Status -eq 'Stopped'
        DriverStart = [int](Get-ItemProperty -LiteralPath 'HKLM:\SYSTEM\CurrentControlSet\Services\SafeUpload' -Name Start -ErrorAction Stop).Start
        AgentStart = [int](Get-ItemProperty -LiteralPath 'HKLM:\SYSTEM\CurrentControlSet\Services\SafeUploadAgent' -Name Start -ErrorAction Stop).Start
    }
}

function Get-T4RuntimeDriverHash {
    (Get-FileHash -Algorithm SHA256 -LiteralPath 'C:\Windows\System32\drivers\SafeUpload.sys' -ErrorAction Stop).Hash
}

function Start-T4RuntimeAgent {
    Start-Service -Name SafeUploadAgent -ErrorAction Stop
    (Get-Service -Name SafeUploadAgent -ErrorAction Stop).WaitForStatus('Running', [TimeSpan]::FromSeconds(30))
}

function Save-T4RuntimeVerifierQuery([string]$Path) {
    $text = Invoke-T4RuntimeNative 'verifier.exe' @('/query')
    [IO.File]::WriteAllText($Path, $text, [Text.UTF8Encoding]::new($false))
    return $text
}

function Assert-T4RuntimeVerifierState([string]$Text, [bool]$Loaded) {
    $flags = [regex]::Matches($Text, '(?im)^\s*Verifier Flags:\s*0x0*13b\s*$')
    $modules = [regex]::Matches($Text, '(?im)^\s*MODULE:\s*SafeUpload\.sys\s*\(load:\s*(\d+)\s*/\s*unload:\s*(\d+)\)\s*$')
    $expectedLoads = if ($Loaded) { 1 } else { 0 }
    if ($flags.Count -ne 1 -or $modules.Count -ne 1 -or
        [int64]$modules[0].Groups[1].Value -ne $expectedLoads -or [int64]$modules[0].Groups[2].Value -ne 0) {
        throw 'Expected exact runtime Verifier flags 0x13B and an unambiguous first-load count without unloads.'
    }
}

function Assert-T4RuntimeUnloaded($State) {
    if ($State.FilterLoaded -or -not $State.DriverStopped -or -not $State.AgentStopped) {
        throw 'Runtime Verifier setup requires both installed services stopped and the filter unloaded.'
    }
}

function Set-T4RuntimeDemandBeforeReboot {
    Assert-T4RuntimeUnloaded (Get-T4RuntimeInstallState)
    $null = Invoke-T4RuntimeNative 'sc.exe' @('config', 'SafeUpload', 'start=', 'demand')
    $null = Invoke-T4RuntimeNative 'sc.exe' @('config', 'SafeUploadAgent', 'start=', 'demand')
    $state = Get-T4RuntimeInstallState
    Assert-T4RuntimeUnloaded $state
    if ($state.DriverStart -ne 3 -or $state.AgentStart -ne 3) { throw 'Both services must remain at demand start through the install reboot.' }
    'RUNTIME_DEMAND_HELD=True'
}

function Start-T4RuntimePairBeforeFirstLoad([string]$ExpectedDriverSha256, [string]$RawPrefix) {
    if ($ExpectedDriverSha256 -notmatch '^[A-Fa-f0-9]{64}$') { throw 'Expected signed-driver SHA256 required.' }
    $state = Get-T4RuntimeInstallState
    Assert-T4RuntimeUnloaded $state
    if ($state.DriverStart -ne 3 -or $state.AgentStart -ne 3) { throw 'Install reboot did not preserve both demand-start settings.' }
    if ((Get-T4RuntimeDriverHash) -ine $ExpectedDriverSha256) { throw 'Installed driver differs from the frozen signed artifact.' }
    'PRELOAD_FILTER_UNLOADED=True'
    'PRELOAD_BOTH_SERVICES_STOPPED=True'
    'PRELOAD_DRIVER_SHA256=' + $ExpectedDriverSha256.ToUpperInvariant()
    # Set target and flags in the same invocation. On the measured 19045
    # guest, flags-first with an empty list then a separate add returned zero
    # but /query still reported flags 0. Never infer activation from exit0.
    $null = Invoke-T4RuntimeNative 'verifier.exe' @('/volatile', '/flags', '0x13B', '/adddriver', 'SafeUpload.sys')
    Assert-T4RuntimeVerifierState (Save-T4RuntimeVerifierQuery ($RawPrefix + '-before-load.txt')) $false
    'VERIFIER_BEFORE_FIRST_LOAD=True'
    $null = Invoke-T4RuntimeNative 'fltmc.exe' @('load', 'SafeUpload')
    $state = Get-T4RuntimeInstallState
    if (-not $state.FilterLoaded -or $state.DriverStopped -or -not $state.AgentStopped) { throw 'Filter did not load independently before the agent.' }
    Assert-T4RuntimeVerifierState (Save-T4RuntimeVerifierQuery ($RawPrefix + '-after-load.txt')) $true
    Start-T4RuntimeAgent
    # These are the product's persistent start modes. They take effect next boot;
    # neither changing them nor starting the agent unloads/reloads this driver.
    $null = Invoke-T4RuntimeNative 'sc.exe' @('config', 'SafeUpload', 'start=', 'boot')
    $null = Invoke-T4RuntimeNative 'sc.exe' @('config', 'SafeUploadAgent', 'start=', 'auto')
    $state = Get-T4RuntimeInstallState
    if ($state.DriverStart -ne 0 -or $state.AgentStart -ne 2 -or -not $state.FilterLoaded -or $state.DriverStopped -or $state.AgentStopped) {
        throw 'Product start modes/running pair were not restored after runtime instrumentation.'
    }
    Assert-T4RuntimeVerifierState (Save-T4RuntimeVerifierQuery ($RawPrefix + '-after-agent.txt')) $true
    'PRODUCT_START_MODES_RESTORED=True'
    'RUNTIME_PAIR_STARTED=True'
}

# Verifier from the first load: the same flags configured persistently before the install reboot, so the boot-start driver is
# verified from DriverEntry and reaches Ready through the normal boot path. (A filter loaded after boot with fltmc is a late
# attach: it cannot prove that no writer predates it, so the agent never reports Ready.) The disposable run disk discards the
# persistent setting with everything else.
function Set-T4VerifierFromBoot {
    $state = Get-T4RuntimeInstallState
    if ($state.FilterLoaded -or $state.DriverStart -ne 0) { throw 'Verifier from boot requires the installed boot-start filter, not yet loaded.' }
    $null = Invoke-T4RuntimeNative 'verifier.exe' @('/flags', '0x13B', '/driver', 'SafeUpload.sys')
    $settings = Invoke-T4RuntimeNative 'verifier.exe' @('/querysettings')
    if (-not [regex]::IsMatch($settings, '(?im)^\s*Verifier Flags:\s*0x0*13b\s*$') -or
        -not [regex]::IsMatch($settings, '(?im)^\s*SafeUpload\.sys\s*$')) { throw 'Persistent Verifier 0x13B for SafeUpload.sys was not configured.' }
    'VERIFIER_FROM_BOOT_CONFIGURED=True'
}

function Assert-T4VerifierFromFirstLoad([string]$ExpectedDriverSha256, [string]$RawPrefix) {
    if ((Get-T4RuntimeDriverHash) -ine $ExpectedDriverSha256) { throw 'Installed driver differs from the frozen signed artifact.' }
    Assert-T4RuntimeVerifierState (Save-T4RuntimeVerifierQuery ($RawPrefix + '-after-boot.txt')) $true
    'VERIFIER_FROM_FIRST_LOAD=True'
}
