#requires -Version 5.1
# Exercise the actual first-load setup without loading a driver or changing SCM.
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 't4\runtime-verifier.ps1')
$count = 0
function Assert-Control([bool]$Good, [string]$Label) {
    if (-not $Good) { throw ('T4 runtime setup control failed: ' + $Label) }
    $script:count++
}

$query = "Verifier Flags: 0x0000013b`r`nMODULE: SafeUpload.sys (load: 0 / unload: 0)`r`n"
Assert-T4RuntimeVerifierState $query $false
Assert-Control $true 'unloaded driver is selected with exact flags'
Assert-T4RuntimeVerifierState ($query.Replace('load: 0 /', 'load: 1 /')) $true
Assert-Control $true 'first load remains selected without unloading'
foreach ($bad in @(
    $query.Replace('0x0000013b', '0x0000013b0'),
    $query.Replace('SafeUpload.sys', 'SafeUpload.sysx'),
    $query.Replace('load: 0 /', 'load: 1 /'),
    $query.Replace('unload: 0', 'unload: 1'),
    $query.Replace('load: 0 /', 'load: 2 /'),
    ($query + $query),
    "Verifier Flags: 0x0000013b`r`nMODULE: SafeUpload.sys`r`n"
)) {
    $refused = $false
    try { Assert-T4RuntimeVerifierState $bad $false } catch { $refused = $true }
    Assert-Control $refused 'missing/ambiguous/incorrect flags or lifetime count is refused'
}

# Also check the real native wrapper's exit-code propagation before replacing
# the native boundary with a recording fake for the ordered workflow controls.
$refused = $false
try { $null = Invoke-T4RuntimeNative 'cmd.exe' @('/d', '/c', 'exit', '7') } catch { $refused = $true }
Assert-Control $refused 'native failure cannot become successful setup'

$expected = 'A' * 64
$scratch = Join-Path $env:TEMP ('SafeUpload-T4RuntimeSelfCheck-' + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $scratch | Out-Null
function Reset-Fake {
    $script:state = [pscustomobject]@{ FilterLoaded = $false; DriverStopped = $true; AgentStopped = $true; DriverStart = 0; AgentStart = 2 }
    $script:events = [Collections.Generic.List[string]]::new()
    $script:failNative = ''
    $script:badVerifier = $false
    $script:badAfterLoad = $false
    $script:wrongHash = $false
    $script:ignoreDriverDemand = $false
    $script:ignoreAgentAuto = $false
}
function Get-T4RuntimeInstallState { $script:state }
function Get-T4RuntimeDriverHash { if ($script:wrongHash) { 'B' * 64 } else { $expected } }
function Start-T4RuntimeAgent { $script:events.Add('agent-start'); $script:state.AgentStopped = $false }
function Invoke-T4RuntimeNative([string]$File, [string[]]$Arguments) {
    $command = $File + ' ' + ($Arguments -join ' ')
    $script:events.Add($command)
    if ($command -ceq $script:failNative) { throw 'Injected native failure' }
    switch ($command) {
        'sc.exe config SafeUpload start= demand' { if (-not $script:ignoreDriverDemand) { $script:state.DriverStart = 3 } }
        'sc.exe config SafeUploadAgent start= demand' { $script:state.AgentStart = 3 }
        'sc.exe config SafeUpload start= boot' { $script:state.DriverStart = 0 }
        'sc.exe config SafeUploadAgent start= auto' { if (-not $script:ignoreAgentAuto) { $script:state.AgentStart = 2 } }
        'fltmc.exe load SafeUpload' { $script:state.FilterLoaded = $true; $script:state.DriverStopped = $false }
        'verifier.exe /query' {
            $loads = if ($script:state.FilterLoaded) { 1 } else { 0 }
            $flags = if ($script:badVerifier) { '0x00000008' } else { '0x0000013b' }
            $unloads = if ($script:badAfterLoad -and $script:state.FilterLoaded) { 1 } else { 0 }
            return "Verifier Flags: $flags`r`nMODULE: SafeUpload.sys (load: $loads / unload: $unloads)`r`n"
        }
        'verifier.exe /volatile /flags 0x13B' { }
        'verifier.exe /volatile /adddriver SafeUpload.sys' { }
        default { throw ('Unexpected native operation: ' + $command) }
    }
    return ''
}
try {
    Reset-Fake
    $held = @(Set-T4RuntimeDemandBeforeReboot)
    Assert-Control ($state.DriverStart -eq 3 -and $state.AgentStart -eq 3 -and $held -contains 'RUNTIME_DEMAND_HELD=True') 'both services held while still stopped'
    Assert-Control (($events -join '|') -ceq 'sc.exe config SafeUpload start= demand|sc.exe config SafeUploadAgent start= demand') 'hold never loads filter or starts agent'
    $started = @(Start-T4RuntimePairBeforeFirstLoad $expected (Join-Path $scratch 'ok'))
    $sequence = @('sc.exe config SafeUpload start= demand', 'sc.exe config SafeUploadAgent start= demand',
        'verifier.exe /volatile /flags 0x13B', 'verifier.exe /volatile /adddriver SafeUpload.sys', 'verifier.exe /query',
        'fltmc.exe load SafeUpload', 'verifier.exe /query', 'agent-start', 'sc.exe config SafeUpload start= boot',
        'sc.exe config SafeUploadAgent start= auto', 'verifier.exe /query')
    Assert-Control (($events -join '|') -ceq ($sequence -join '|')) 'arm and query before one load; agent starts afterwards; no late re-arm'
    Assert-Control ($started -contains 'VERIFIER_BEFORE_FIRST_LOAD=True' -and $started -contains 'PRODUCT_START_MODES_RESTORED=True' -and $started -contains 'RUNTIME_PAIR_STARTED=True') 'successful phase witnesses emitted'
    Assert-Control ($state.DriverStart -eq 0 -and $state.AgentStart -eq 2 -and $state.FilterLoaded -and -not $state.AgentStopped) 'product config restored without unload'
    foreach ($phase in 'before-load', 'after-load', 'after-agent') {
        Assert-Control (Test-Path -LiteralPath (Join-Path $scratch ('ok-' + $phase + '.txt'))) 'each actual query retained'
    }
    foreach ($scenario in 'loaded', 'driver-running', 'agent-running', 'bad-driver-start', 'bad-agent-start', 'wrong-hash', 'bad-flags', 'add-failed', 'flags-failed') {
        Reset-Fake; $state.DriverStart = 3; $state.AgentStart = 3
        switch ($scenario) {
            'loaded' { $state.FilterLoaded = $true }
            'driver-running' { $state.DriverStopped = $false }
            'agent-running' { $state.AgentStopped = $false }
            'bad-driver-start' { $state.DriverStart = 0 }
            'bad-agent-start' { $state.AgentStart = 2 }
            'wrong-hash' { $script:wrongHash = $true }
            'bad-flags' { $script:badVerifier = $true }
            'add-failed' { $script:failNative = 'verifier.exe /volatile /adddriver SafeUpload.sys' }
            'flags-failed' { $script:failNative = 'verifier.exe /volatile /flags 0x13B' }
        }
        $refused = $false
        try { $null = Start-T4RuntimePairBeforeFirstLoad $expected (Join-Path $scratch $scenario) } catch { $refused = $true }
        Assert-Control ($refused -and -not ($events -contains 'fltmc.exe load SafeUpload') -and -not ($events -contains 'agent-start')) ('no load after failed precondition: ' + $scenario)
    }
    foreach ($scenario in 'hold-sc-failed', 'hold-setting-ignored', 'hold-already-loaded') {
        Reset-Fake
        switch ($scenario) {
            'hold-sc-failed' { $script:failNative = 'sc.exe config SafeUploadAgent start= demand' }
            'hold-setting-ignored' { $script:ignoreDriverDemand = $true }
            'hold-already-loaded' { $state.FilterLoaded = $true }
        }
        $refused = $false
        try { $null = Set-T4RuntimeDemandBeforeReboot } catch { $refused = $true }
        Assert-Control ($refused -and -not ($events -contains 'fltmc.exe load SafeUpload')) ('failed hold refused: ' + $scenario)
    }
    foreach ($scenario in 'load-failed', 'load-count-bad', 'restore-ignored') {
        Reset-Fake; $state.DriverStart = 3; $state.AgentStart = 3
        switch ($scenario) {
            'load-failed' { $script:failNative = 'fltmc.exe load SafeUpload' }
            'load-count-bad' { $script:badAfterLoad = $true }
            'restore-ignored' { $script:ignoreAgentAuto = $true }
        }
        $refused = $false; $output = @()
        try { $output = @(Start-T4RuntimePairBeforeFirstLoad $expected (Join-Path $scratch $scenario)) } catch { $refused = $true }
        Assert-Control ($refused -and -not ($output -contains 'RUNTIME_PAIR_STARTED=True')) ('late failure cannot start coordinator: ' + $scenario)
        if ($scenario -ne 'restore-ignored') { Assert-Control (-not ($events -contains 'agent-start')) 'agent never starts after invalid load evidence' }
    }
    'T4RuntimeSelfCheck=PASS;Controls=' + $count + ';Qualification=False'
} finally { Remove-Item -LiteralPath $scratch -Recurse -Force }
