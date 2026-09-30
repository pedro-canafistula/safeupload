<#
Runs only on the isolated debuggee VM. The prototype is intentionally
incomplete: this checks writer reopen, non-owner visibility, and the rename
safety gate while recording the missing directory-enumeration behavior.
The original installed driver is verified and restored in finally.
#>
$ErrorActionPreference = 'Stop'
$installed = 'C:\Windows\System32\drivers\SafeUpload.sys'
$backup = 'C:\Users\vika\Documents\SafeUpload-original-before-stage.sys'
$prototype = 'C:\Users\vika\Documents\SafeUpload-stage-prototype.sys'
$targetDir = 'C:\SafeUpload\Escopo Monitorado'
$stageDir = 'C:\SafeUpload\_staging'
$expectedOriginal = 'ADA9D05AB6AECDD2B6C521B0CE529FC06C732154ACB3EE85439FBDC8AA80DFCE'
$name = 'safeupload-namespace-' + [guid]::NewGuid().ToString('N') + '.txt'
$target = Join-Path $targetDir $name
$renameTemp = Join-Path $targetDir ($name + '.tmp')
$renameFinal = Join-Path $targetDir ($name + '.renamed.txt')
$hardLinkFinal = Join-Path $targetDir ($name + '.linked.txt')
$loaded = $false
$replaced = $false

if ((Get-FileHash $installed -Algorithm SHA256).Hash -ne $expectedOriginal) {
    throw 'The installed driver is not the known original; refusing to replace it.'
}
if (-not (Test-Path $prototype)) { throw 'Signed prototype driver missing.' }
New-Item -ItemType Directory -Force -Path $targetDir,$stageDir | Out-Null
Copy-Item $installed $backup -Force

try {
    Copy-Item $prototype $installed -Force
    $replaced = $true
    & fltmc.exe load SafeUpload | Out-Host
    if ($LASTEXITCODE -ne 0) { throw 'Prototype load failed.' }
    $loaded = $true

    [IO.File]::WriteAllText($target, 'staged clean content')
    $reopened = [IO.File]::ReadAllText($target)
    $sameProcessExists = [IO.File]::Exists($target)
    $otherProcessExists = & powershell.exe -NoProfile -Command "[IO.File]::Exists('$target')"
    $stage = @(Get-ChildItem $stageDir -Filter "*-$name")

    Write-Output "SameProcessRead=$reopened"
    Write-Output "SameProcessExists=$sameProcessExists"
    Write-Output "OtherProcessExists=$otherProcessExists"
    Write-Output "DestinationVisibleOutsideWriter=$otherProcessExists"
    Write-Output "StagedFiles=$($stage.Count)"
    Write-Output "WriterFolderListingCount=$(@(Get-ChildItem $targetDir -Filter $name).Count)"

    [IO.File]::WriteAllText($renameTemp, 'clean rename bytes')
    $renameTempRead = [IO.File]::ReadAllText($renameTemp)
    $renameBlocked = $false
    try { Move-Item -LiteralPath $renameTemp -Destination $renameFinal -ErrorAction Stop }
    catch { $renameBlocked = $true }
    $renamedVisibleOutside = & powershell.exe -NoProfile -Command "[IO.File]::Exists('$renameFinal')"
    Write-Output "RenameBlocked=$renameBlocked"
    Write-Output "RenamedDestinationVisibleOutsideWriter=$renamedVisibleOutside"

    $hardLinkBlocked = $false
    try { New-Item -ItemType HardLink -Path $hardLinkFinal -Target $renameTemp -ErrorAction Stop | Out-Null }
    catch { $hardLinkBlocked = $true }
    $hardLinkVisibleOutside = & powershell.exe -NoProfile -Command "[IO.File]::Exists('$hardLinkFinal')"
    Write-Output "HardLinkBlocked=$hardLinkBlocked"
    Write-Output "HardLinkVisibleOutsideWriter=$hardLinkVisibleOutside"

    if ($reopened -ne 'staged clean content' -or -not $sameProcessExists -or $stage.Count -ne 1) {
        throw 'The writer could not reopen its staged bytes.'
    }
    if ($renameTempRead -ne 'clean rename bytes') {
        throw 'The writer could not reopen its temporary stage file.'
    }
    if ($otherProcessExists -ne 'False') {
        throw 'Another process could see the unapproved file.'
    }
    if (-not $renameBlocked -or $renamedVisibleOutside -ne 'False') {
        throw 'Rename leaked unapproved content to the destination.'
    }
    if (-not $hardLinkBlocked -or $hardLinkVisibleOutside -ne 'False') {
        throw 'Hard link leaked unapproved content to the destination.'
    }
}
finally {
    if ($loaded) { & fltmc.exe unload SafeUpload | Out-Host }
    if ($replaced) { Copy-Item $backup $installed -Force }
    if ((Get-FileHash $installed -Algorithm SHA256).Hash -ne $expectedOriginal) {
        throw 'Original driver restoration failed.'
    }
    Get-ChildItem $stageDir -Filter "*-$name" -ErrorAction SilentlyContinue | Remove-Item -Force
    Get-ChildItem $stageDir -Filter "*-$name*" -ErrorAction SilentlyContinue | Remove-Item -Force
    Remove-Item $target -Force -ErrorAction SilentlyContinue
    Remove-Item $renameTemp,$renameFinal,$hardLinkFinal -Force -ErrorAction SilentlyContinue
    Write-Output 'OriginalDriverRestored=True'
}
