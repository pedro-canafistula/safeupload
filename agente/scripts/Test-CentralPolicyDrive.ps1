#Requires -Version 5.1
#Requires -RunAsAdministrator
<#
.SYNOPSIS
Verifies one centrally published CPF policy on an already configured disposable Drive/gate VM.
.DESCRIPTION
Publish through the panel before each run. This script does not publish policy, install components,
restart services or grant overrides. Run Bloquear, then Alertar with a newer idPolitica, then offline.
It leaves unique synthetic files and a JSON result. A watcher cannot pass the Drive/gate prerequisites.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)][string] $Destination,
    [Parameter(Mandatory=$true)][ValidatePattern('^[A-Za-z]:\\$')][string] $DriveRoot,
    [Parameter(Mandatory=$true)][ValidateRange(1,2147483647)][int] $PolicyVersion,
    [Parameter(Mandatory=$true)][ValidateSet('Bloquear','Alertar')][string] $Action,
    [Parameter(Mandatory=$true)][string] $GatePath,
    [Parameter(Mandatory=$true)][string] $ResultPath,
    [switch] $Offline,
    [ValidateRange(5,60)][int] $TimeoutSeconds = 30
)
$ErrorActionPreference = 'Stop'
$root = Join-Path $env:ProgramData 'SafeUpload'
$cachePath = Join-Path $root 'console-policy-cache.json'
$identityPath = Join-Path $root 'identity\host-registration.json'
$result = [ordered]@{ passed=$false; atUtc=[DateTime]::UtcNow.ToString('o'); action=$Action; revision=$PolicyVersion; offline=[bool]$Offline; checks=@() }
$runId = [guid]::NewGuid().ToString('N')
$ResultPath = [IO.Path]::GetFullPath($ResultPath)
if (Test-Path -LiteralPath $ResultPath) { throw 'Choose a new result file.' }
[void][IO.Directory]::CreateDirectory([IO.Path]::GetDirectoryName($ResultPath))
function Check([string]$Name,[bool]$Passed) {
    $result.checks += [ordered]@{name=$Name;passed=$Passed}
    if (-not $Passed) { throw "Check failed: $Name" }
}
function Status {
    $pipe = [IO.Pipes.NamedPipeClientStream]::new('.', 'SafeUpload.Agent', [IO.Pipes.PipeDirection]::In, [IO.Pipes.PipeOptions]::Asynchronous)
    $reader = $null
    try {
        $pipe.Connect(3000)
        $reader = [IO.StreamReader]::new($pipe)
        $read = $reader.ReadLineAsync()
        if (-not $read.Wait(3000)) { throw 'Status timed out.' }
        return ($read.GetAwaiter().GetResult() | ConvertFrom-Json)
    } finally { if ($reader) { $reader.Dispose() }; $pipe.Dispose() }
}
function Event([string]$Name) {
    $stream = [IO.FileStream]::new((Join-Path $root 'queue.jsonl'),[IO.FileMode]::Open,[IO.FileAccess]::Read,([IO.FileShare]::ReadWrite -bor [IO.FileShare]::Delete))
    $reader = [IO.StreamReader]::new($stream)
    try {
        if ($stream.Length -gt 16MB) { throw 'Use a disposable VM with a small queue.' }
        while ($null -ne ($line = $reader.ReadLine())) {
            try { $item = $line | ConvertFrom-Json -ErrorAction Stop } catch { continue }
            if ($item.fileName -eq $Name -and $item.eventId -and -not $item.type) { return $item }
        }
    } finally { $reader.Dispose() }
}
function Wait-Event([string]$Name) {
    $clock = [Diagnostics.Stopwatch]::StartNew()
    do {
        if (Test-Path -LiteralPath (Join-Path $root 'queue.jsonl')) { $item = Event $Name; if ($item) { return $item } }
        Start-Sleep -Milliseconds 100
    } while ($clock.Elapsed.TotalSeconds -lt $TimeoutSeconds)
    throw 'Inspection outcome timed out.'
}
try {
    $service = Get-CimInstance Win32_Service -Filter "Name='SafeUploadAgent'"
    Check 'SYSTEM service running with ConsoleByIp' ($service.State -eq 'Running' -and $service.StartName -eq 'LocalSystem' -and $service.PathName -match 'PolicyProtocol=ConsoleByIp')
    $result.processId = $service.ProcessId
    $process = Get-Process -Id $service.ProcessId
    $result.serviceStartedUtc = $process.StartTime.ToUniversalTime().ToString('o')
    $result.serviceSha256 = (Get-FileHash -LiteralPath $process.Path).Hash
    $result.gateSha256 = (Get-FileHash -LiteralPath $GatePath).Hash
    $result.identitySha256 = (Get-FileHash -LiteralPath $identityPath).Hash
    $result.localPolicySha256 = (Get-FileHash -LiteralPath (Join-Path $root 'policy.json')).Hash
    $result.cacheSha256 = (Get-FileHash -LiteralPath $cachePath).Hash
    $identity = Get-Content -LiteralPath $identityPath -Raw | ConvertFrom-Json
    $cache = Get-Content -LiteralPath $cachePath -Raw | ConvertFrom-Json
    $local = Get-Content -LiteralPath (Join-Path $root 'policy.json') -Raw | ConvertFrom-Json
    $target = [IO.Path]::GetFullPath($Destination).TrimEnd('\')
    Check 'Local scope includes TXT and DOCX without justification' (-not $local.overrideAllowed -and
        $local.monitoredScopes.extensions -contains '.txt' -and $local.monitoredScopes.extensions -contains '.docx' -and
        @($local.monitoredScopes.destinationPaths | Where-Object { [IO.Path]::GetFullPath($_).TrimEnd('\') -eq $target }).Count -eq 1)
    Check 'Test process is inspected' ($local.excludedProcesses -notcontains (Get-Process -Id $PID).ProcessName -and
        $local.excludedProcesses -notcontains ((Get-Process -Id $PID).ProcessName + '.exe'))
    Check 'Cache bound to identity, CPF and requested revision/action' ($cache.hostId -eq $identity.registeredHostId -and
        $cache.server -eq $identity.serverBaseUrl -and $cache.policy.version -eq $PolicyVersion -and
        $cache.policy.activeCategories -contains 'Cpf' -and [bool]$cache.policy.auditOnly -eq ($Action -eq 'Alertar'))
    $route = $cache.server + 'api/policy?ip=' + [Uri]::EscapeDataString($cache.ip)
    $networkFailed = $false
    try { $published = Invoke-RestMethod -Uri $route -TimeoutSec 3 }
    catch { if ($_.Exception.Response) { throw }; $networkFailed = $true }
    if ($Offline) { Check 'Backend is unreachable for this phase' $networkFailed }
    else { Check 'Real backend serves expected host and publication' (-not $networkFailed -and $published.idPolitica -eq $PolicyVersion -and
        $published.destino.idHost -eq $cache.hostId -and $published.destino.ip -eq $cache.ip -and $published.acao -eq $Action.ToLowerInvariant()) }
    $status = Status
    Check 'Drive mounts and gate accepted under applied policy' ($status.type -eq 'status' -and $status.policyVersion -eq $PolicyVersion -and
        $status.protectionActive -and [bool]$status.auditOnly -eq ($Action -eq 'Alertar') -and $status.driveProtection.gatePolicyApplied -and
        $status.driveProtection.requiredDrives -gt 0 -and $status.driveProtection.mountedDrives -eq $status.driveProtection.requiredDrives)
    $result.protection = $status.driveProtection
    $name = "central-cpf-$runId.txt"
    $text = 'Synthetic CPF: 529.982.247-25'
    [IO.File]::WriteAllText((Join-Path $DriveRoot $name),$text,[Text.UTF8Encoding]::new($false))
    $event = Wait-Event $name
    Check 'CPF inspected under applied publication' ($event.policyVersion -eq $PolicyVersion -and $event.categories -contains 'Cpf' -and -not $event.notInspectedReason)
    if ($Action -eq 'Bloquear') {
        Check 'CPF blocked and retained on drive' ($event.verdict -eq 'Blocked' -and -not (Test-Path -LiteralPath (Join-Path $target $name)) -and (Test-Path -LiteralPath (Join-Path $DriveRoot $name)))
    } else {
        Check 'CPF published intact and audited as Approved with findings' ($event.verdict -eq 'Approved' -and
            [IO.File]::ReadAllText((Join-Path $target $name)) -ceq $text -and $event.publishedSha256Hex -eq (Get-FileHash -LiteralPath (Join-Path $target $name)).Hash)
    }
    $result.cpfEvent = $event
    $invalid = "central-invalid-$runId.docx"
    # No recognized archive signature; a NUL prevents text sniffing from reclassifying it as TXT.
    [IO.File]::WriteAllBytes((Join-Path $DriveRoot $invalid),[byte[]]@(0,1,2,3,0,4,5,6))
    $failure = Wait-Event $invalid
    Check 'Inspection failure remains blocked including Alertar' ($failure.verdict -eq 'Blocked' -and $failure.policyVersion -eq $PolicyVersion -and
        $failure.notInspectedReason -and -not (Test-Path -LiteralPath (Join-Path $target $invalid)))
    $result.failureEvent = $failure
    Check 'Identity and policy stable during phase' ((Get-FileHash -LiteralPath $identityPath).Hash -eq $result.identitySha256 -and
        (Get-FileHash -LiteralPath $cachePath).Hash -eq $result.cacheSha256 -and (Get-FileHash -LiteralPath (Join-Path $root 'policy.json')).Hash -eq $result.localPolicySha256)
    $result.passed = $true
} catch { $result.error = $_.Exception.Message; throw }
finally { [IO.File]::WriteAllText($ResultPath,($result | ConvertTo-Json -Depth 12),[Text.UTF8Encoding]::new($false)) }
