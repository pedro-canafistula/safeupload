<#
Cross-volume feasibility test on the isolated debuggee VM. Creates a disposable
NTFS VHDX at S:, writes to S:\SafeUpload\Escopo Monitorado, and verifies the
unapproved bytes are held on C:. Always unloads the prototype, restores the
known installed driver, and detaches the VHDX. Requires an elevated session.
#>
$ErrorActionPreference = 'Stop'
$installed = 'C:\Windows\System32\drivers\SafeUpload.sys'
$backup = 'C:\Users\vika\Documents\SafeUpload-original-before-stage.sys'
$prototype = 'C:\Users\vika\Documents\SafeUpload-stage-prototype.sys'
$stageDir = 'C:\SafeUpload\_staging'
$journalDir = 'C:\SafeUpload\_staging-journal'
$serviceZip = 'C:\Users\vika\Documents\stage-service-publish.zip'
$serviceDir = 'C:\Users\vika\Documents\stage-service-publish'
$vhd = 'C:\Users\vika\Documents\SafeUpload-stage-crossvolume.vhdx'
$diskpartScript = 'C:\Users\vika\Documents\SafeUpload-stage-diskpart.txt'
$expectedOriginal = 'ADA9D05AB6AECDD2B6C521B0CE529FC06C732154ACB3EE85439FBDC8AA80DFCE'
$name = 'safeupload-crossvolume-' + [guid]::NewGuid().ToString('N') + '.txt'
$targetDir = 'S:\SafeUpload\Escopo Monitorado'
$target = "$targetDir\$name"
$renameTarget = "$targetDir\$name.renamed.txt"
$hardLinkTarget = "C:\SafeUpload\Escopo Monitorado\$name.linked.txt"
$mounted = $false
$replaced = $false
$loaded = $false
$serviceProcess = $null
$stagePath = $null
$manifestPath = $null

if ((Get-FileHash $installed -Algorithm SHA256).Hash -ne $expectedOriginal) {
    throw 'Installed driver is not the known original.'
}
if (-not (Test-Path $prototype)) { throw 'Signed prototype missing.' }
if (-not (Test-Path $serviceZip)) { throw 'Self-contained test service missing.' }
if (Test-Path S:\) { throw 'S: is already in use.' }
if (Test-Path $vhd) { throw 'Test VHDX already exists.' }

function Invoke-TestDiskpart([string[]] $commands) {
    Set-Content -LiteralPath $diskpartScript -Value $commands -Encoding Ascii
    $output = & diskpart.exe /s $diskpartScript 2>&1
    $output | Out-Host
    if ($LASTEXITCODE -ne 0 -or ($output -match 'DiskPart has encountered an error')) {
        throw "DiskPart failed: $LASTEXITCODE"
    }
}

try {
    Invoke-TestDiskpart @(
        "create vdisk file=`"$vhd`" maximum=128 type=expandable",
        "select vdisk file=`"$vhd`"",
        'attach vdisk',
        'create partition primary',
        'format fs=ntfs quick label=SafeUploadTest',
        'assign letter=S'
    )
    $mounted = $true
    if (-not (Test-Path S:\)) { throw 'S: did not appear.' }
    New-Item -ItemType Directory -Force -Path @(
        $targetDir, $stageDir, 'C:\SafeUpload\Escopo Monitorado') | Out-Null

    Copy-Item $installed $backup -Force
    Copy-Item $prototype $installed -Force
    $replaced = $true
    & fltmc.exe load SafeUpload | Out-Host
    if ($LASTEXITCODE -ne 0) { throw 'Prototype load failed.' }
    $loaded = $true

    $deniedWithoutService = $false
    try { [IO.File]::WriteAllText($target, 'must not reach destination') }
    catch { $deniedWithoutService = $true }
    Write-Output "DeniedWithoutService=$deniedWithoutService"
    if (-not $deniedWithoutService -or [IO.File]::Exists($target)) {
        throw 'The prototype did not fail closed without a service.'
    }

    New-Item -ItemType Directory -Force -Path $serviceDir | Out-Null
    & tar.exe -xf $serviceZip -C $serviceDir
    if ($LASTEXITCODE -ne 0) { throw 'Could not unpack the test service.' }
    $env:Interception__Mode = 'Minifilter'
    $env:Interception__StagingPrototype = 'true'
    $serviceProcess = Start-Process -FilePath (Join-Path $serviceDir 'SafeUpload.Agent.Service.exe') `
        -PassThru -WindowStyle Hidden `
        -RedirectStandardOutput 'C:\Users\vika\Documents\stage-service-out.log' `
        -RedirectStandardError 'C:\Users\vika\Documents\stage-service-err.log'
    Remove-Item Env:Interception__Mode,Env:Interception__StagingPrototype -ErrorAction SilentlyContinue

    $saved = $false
    for ($attempt = 0; $attempt -lt 15 -and -not $saved; $attempt++) {
        Start-Sleep -Milliseconds 500
        if ($serviceProcess.HasExited) { throw 'Test service exited before connecting.' }
        try {
            [IO.File]::WriteAllText($target, 'cross-volume staged bytes')
            $saved = $true
        }
        catch [System.UnauthorizedAccessException] { }
        catch [System.IO.IOException] { }
    }
    if (-not $saved) { throw 'Service never completed a stage allocation.' }

    $writerRead = [IO.File]::ReadAllText($target)
    $otherProcessExists = & powershell.exe -NoProfile -Command "[IO.File]::Exists('$target')"
    $entries = @(Get-ChildItem -LiteralPath $journalDir -Filter '*.json' |
        ForEach-Object { Get-Content -LiteralPath $_.FullName -Raw | ConvertFrom-Json } |
        Where-Object { $_.Transfer.DestinationPath -eq $target })
    if ($entries.Count -ne 1) { throw "Expected one durable transfer, found $($entries.Count)." }
    $stagePath = $entries[0].Transfer.StagePath
    $transferId = [guid] $entries[0].Transfer.TransferId
    $manifestPath = Join-Path $journalDir ($transferId.ToString('N') + '.json')
    $destinationEntries = @(Get-ChildItem -LiteralPath $targetDir -Filter $name)
    $directStageReadDenied = $false
    try { [IO.File]::ReadAllText($stagePath) | Out-Null }
    catch { $directStageReadDenied = $true }

    Write-Output "WriterRead=$writerRead"
    Write-Output "OtherProcessExists=$otherProcessExists"
    Write-Output "JournalTransferCount=$($entries.Count)"
    Write-Output "JournalState=$($entries[0].State)"
    Write-Output "DestinationEntryCount=$($destinationEntries.Count)"
    Write-Output "DirectStageReadDenied=$directStageReadDenied"

    $renameBlocked = $false
    try { Move-Item -LiteralPath $target -Destination $renameTarget -ErrorAction Stop }
    catch { $renameBlocked = $true }
    $hardLinkBlocked = $false
    try { New-Item -ItemType HardLink -Path $hardLinkTarget -Target $target -ErrorAction Stop | Out-Null }
    catch { $hardLinkBlocked = $true }
    Write-Output "RenameBlocked=$renameBlocked"
    Write-Output "HardLinkBlocked=$hardLinkBlocked"

    if ($writerRead -ne 'cross-volume staged bytes' -or
        $otherProcessExists -ne 'False' -or
        -not $directStageReadDenied -or
        $entries[0].State -ne 0 -or
        $destinationEntries.Count -ne 0 -or
        -not $renameBlocked -or -not $hardLinkBlocked -or
        [IO.File]::Exists($renameTarget) -or
        [IO.File]::Exists($hardLinkTarget)) {
        throw 'Cross-volume staging invariant failed.'
    }

    # Simulate an agent crash while the driver still has the writer mapping.
    # Restart must retain this unsealed version; it cannot infer approval.
    Stop-Process -Id $serviceProcess.Id -Force
    $serviceProcess.WaitForExit()
    $env:Interception__Mode = 'Minifilter'
    $env:Interception__StagingPrototype = 'true'
    $serviceProcess = Start-Process -FilePath (Join-Path $serviceDir 'SafeUpload.Agent.Service.exe') `
        -PassThru -WindowStyle Hidden `
        -RedirectStandardOutput 'C:\Users\vika\Documents\stage-service-restart-out.log' `
        -RedirectStandardError 'C:\Users\vika\Documents\stage-service-restart-err.log'
    Remove-Item Env:Interception__Mode,Env:Interception__StagingPrototype -ErrorAction SilentlyContinue
    $retained = $false
    for ($attempt = 0; $attempt -lt 20 -and -not $retained; $attempt++) {
        Start-Sleep -Milliseconds 250
        if ($serviceProcess.HasExited) { throw 'Test service exited during recovery.' }
        $recovered = Get-Content -LiteralPath $manifestPath -Raw | ConvertFrom-Json
        $retained = $recovered.State -eq 7
    }
    Write-Output "RetainedAfterServiceRestart=$retained"
    if (-not $retained -or [IO.File]::Exists($target)) {
        throw 'An interrupted transfer was not safely retained.'
    }
}
finally {
    if ($serviceProcess -and -not $serviceProcess.HasExited) {
        Stop-Process -Id $serviceProcess.Id -Force
        $serviceProcess.WaitForExit()
    }
    if ($loaded) { & fltmc.exe unload SafeUpload | Out-Host }
    if ($stagePath -and (Test-Path -LiteralPath $stagePath)) {
        Write-Output "LocalStageContentAfterUnload=$([IO.File]::ReadAllText($stagePath))"
    }
    if ($replaced) { Copy-Item $backup $installed -Force }
    if ((Get-FileHash $installed -Algorithm SHA256).Hash -ne $expectedOriginal) {
        throw 'Original driver restoration failed.'
    }
    if ($stagePath) { Remove-Item -LiteralPath $stagePath -Force -ErrorAction SilentlyContinue }
    if ($manifestPath) { Remove-Item -LiteralPath $manifestPath -Force -ErrorAction SilentlyContinue }
    Remove-Item -LiteralPath $hardLinkTarget -Force -ErrorAction SilentlyContinue
    if ($mounted) {
        Invoke-TestDiskpart @("select vdisk file=`"$vhd`"", 'detach vdisk')
    }
    Remove-Item -LiteralPath $vhd,$diskpartScript -Force -ErrorAction SilentlyContinue
    Write-Output 'OriginalDriverRestored=True'
}
