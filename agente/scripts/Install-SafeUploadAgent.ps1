#Requires -RunAsAdministrator
#Requires -Version 5.1
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateScript({ Test-Path -LiteralPath $_ -PathType Leaf })]
    [string] $ServiceExecutablePath,

    # Central policy server. Empty (the default) keeps the agent autonomous: it reads C:\ProgramData\SafeUpload\policy.json.
    # appsettings.json ships a panel address, and with any address configured the agent takes its policy from the
    # panel and falls back to a built-in default (other folder, removable and network scopes) when it cannot reach
    # it, so the installer states the choice explicitly instead of inheriting the shipped address.
    [string] $AdminBaseUrl = '',

    # The staged-write driver only works with the agent in staged minifilter mode. Without these arguments the
    # agent runs outside staged mode (admissionCoverage NotAvailable, auditOnly true) and the driver, which fails
    # closed, refuses every standard-user save into a protected folder.
    [string[]] $ServiceArguments = @('--Interception:Mode=Minifilter', '--Interception:StagingPrototype=true',
        ('--CentroAdministracao:BaseUrl=' + $AdminBaseUrl))
)

$ErrorActionPreference = 'Stop'
$serviceName = 'SafeUploadAgent'
$serviceExecutable = (Resolve-Path -LiteralPath $ServiceExecutablePath).Path
$quotedExecutable = '"' + $serviceExecutable + '"'
$binaryPath = (@($quotedExecutable) + $ServiceArguments) -join ' '
$agentServiceKey = 'HKLM:\SYSTEM\CurrentControlSet\Services\SafeUploadAgent'
$driverServiceKey = 'HKLM:\SYSTEM\CurrentControlSet\Services\SafeUpload'

function Invoke-ScChecked([string[]] $Arguments, [string] $Description) {
    $output = & sc.exe @Arguments 2>&1
    if ($LASTEXITCODE -ne 0) {
        throw "$Description failed (sc.exe $LASTEXITCODE): $($output -join ' ')"
    }
    $output | Out-Host
}

# sc.exe on Windows 10 prints "SERVICE_SID_TYPE:  UNRESTRICTED"; other builds and docs use "SERVICE_SID_TYPE_UNRESTRICTED".
function Test-ServiceSidTypeUnrestricted([string] $QueryOutput) {
    return $QueryOutput -match 'SERVICE_SID_TYPE[_:\s]+UNRESTRICTED'
}

# Windows PowerShell 5.1 mangles embedded quotes when it passes an argument to sc.exe, so the command line (quoted
# executable plus arguments) is written to the ImagePath value directly and read back.
function Set-SafeUploadAgentImagePath {
    Set-ItemProperty -LiteralPath $agentServiceKey -Name ImagePath -Value $binaryPath -Type ExpandString
    $written = [string](Get-ItemProperty -LiteralPath $agentServiceKey -Name ImagePath).ImagePath
    if ($written -ne $binaryPath) {
        throw "SafeUploadAgent ImagePath was not written as expected: $written"
    }
    Write-Output "ServiceCommandLine=$written"
}

function Invoke-BootPolicySeedAsSystem {
    $taskName = 'SafeUpload-BootPolicySeed-' + [guid]::NewGuid().ToString('N')
    $action = New-ScheduledTaskAction -Execute $serviceExecutable -Argument '--seed-boot-policy'
    $principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
    $settings = New-ScheduledTaskSettingsSet -ExecutionTimeLimit ([TimeSpan]::FromMinutes(2))
    $registered = $false
    try {
        Register-ScheduledTask -TaskName $taskName -Action $action -Principal $principal -Settings $settings | Out-Null
        $registered = $true
        Start-ScheduledTask -TaskName $taskName

        $deadline = [DateTime]::UtcNow.AddSeconds(60)
        do {
            $task = Get-ScheduledTask -TaskName $taskName -ErrorAction Stop
            $info = Get-ScheduledTaskInfo -TaskName $taskName -ErrorAction Stop
            if ($task.State -eq 'Ready' -and $info.LastRunTime -gt [DateTime]::FromFileTimeUtc(0)) {
                if ([int]$info.LastTaskResult -ne 0) {
                    throw "SYSTEM boot-policy seed failed (task result $($info.LastTaskResult))."
                }
                Write-Output 'BootPolicySeededAsSystem=True'
                return
            }
            Start-Sleep -Milliseconds 200
        } while ([DateTime]::UtcNow -lt $deadline)

        throw 'SYSTEM boot-policy seed timed out; installation cannot continue.'
    }
    finally {
        if ($registered) {
            Stop-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
            Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction SilentlyContinue
        }
    }
}

function Set-SafeUploadDriverDemandBeforeSeed {
    if (-not (Test-Path -LiteralPath $driverServiceKey)) {
        throw 'SafeUpload minifilter service is not installed. Install the driver package before the agent.'
    }

    # The INF can already have written BOOT_START. Hold the unloaded filter at
    # demand start until the SYSTEM seeder has durably verified BootPolicy.
    Invoke-ScChecked @('config', 'SafeUpload', 'start=', 'demand') 'Holding SafeUpload at demand-start before policy seed'
    $driverStart = [int](Get-ItemProperty -LiteralPath $driverServiceKey -Name Start -ErrorAction Stop).Start
    if ($driverStart -ne 3) {
        throw "SafeUpload could not be held at demand-start before policy seeding (Start=$driverStart)."
    }
}

function Set-SafeUploadDriverBootStart {
    Invoke-ScChecked @('config', 'SafeUpload', 'start=', 'boot') 'Staging SafeUpload as boot-start'
    $driverStart = [int](Get-ItemProperty -LiteralPath $driverServiceKey -Name Start -ErrorAction Stop).Start
    if ($driverStart -ne 0) {
        throw "SafeUpload was not staged as boot-start after policy seeding (Start=$driverStart)."
    }
    Write-Output 'DriverBootStartConfigured=True'
    Write-Output 'DriverStartedByInstaller=False'
}

if (-not (Test-Path -LiteralPath $driverServiceKey)) {
    throw 'SafeUpload minifilter service is not installed. Install the driver package before the agent.'
}

# This record must be durable and verified while the filter is still unloaded.
# Keep the INF-installed service at demand-start until the SYSTEM task succeeds.
Set-SafeUploadDriverDemandBeforeSeed
Invoke-BootPolicySeedAsSystem
Set-SafeUploadDriverBootStart

$existing = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
if ($null -eq $existing) {
    Invoke-ScChecked @('create', $serviceName, 'binPath=', $quotedExecutable,
        'start=', 'auto', 'obj=', 'LocalSystem') 'Creating SafeUploadAgent'
}
else {
    if ($existing.Status -ne [System.ServiceProcess.ServiceControllerStatus]::Stopped) {
        throw 'Stop SafeUploadAgent before changing its image path.'
    }
    Invoke-ScChecked @('config', $serviceName, 'binPath=', $quotedExecutable,
        'start=', 'auto', 'obj=', 'LocalSystem') 'Configuring SafeUploadAgent'
}
Set-SafeUploadAgentImagePath

# SCM adds this service SID to the service process token. Unrestricted mode
# retains the LocalSystem token while including NT SERVICE\SafeUploadAgent.
Invoke-ScChecked @('sidtype', $serviceName, 'unrestricted') 'Configuring the service SID'
$sidType = (& sc.exe qsidtype $serviceName 2>&1 | Out-String)
if ($LASTEXITCODE -ne 0 -or -not (Test-ServiceSidTypeUnrestricted $sidType)) {
    throw "SafeUploadAgent does not have an unrestricted service SID: $sidType"
}

Write-Output "ServiceName=$serviceName"
Write-Output 'ServiceSidType=UNRESTRICTED'
Write-Output 'ServiceConfigured=True'
Write-Output 'ServiceStarted=False'
Write-Output 'Protection activates after reboot.'
