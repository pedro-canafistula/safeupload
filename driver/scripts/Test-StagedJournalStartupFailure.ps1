<# Real service startup must refuse a corrupt publication record and keep public
   bytes unchanged. Run only after a frozen/restored debuggee checkpoint. #>
param([string] $EvidencePrefix = 'C:\Users\vika\Documents\journal-startup-negative')
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
. (Join-Path $PSScriptRoot 'StagedTestAgent.ps1')
$original = 'ADA9D05AB6AECDD2B6C521B0CE529FC06C732154ACB3EE85439FBDC8AA80DFCE'
if ($env:COMPUTERNAME -ne 'WIN10-DEBUGGED' -or
    (Get-CimInstance Win32_ComputerSystemProduct).UUID -ne '9D44EEE8-81CF-4CC1-9FBA-7670F11DEF4D') { throw 'Wrong VM.' }
if ((Get-FileHash C:\Windows\System32\drivers\SafeUpload.sys).Hash -ne $original -or
    ((& fltmc.exe filters) -match '^SafeUpload\s')) { throw 'Original unloaded baseline required.' }
if ((Get-FileHash C:\Users\vika\Documents\SafeUpload-stage-prototype.sys).Hash -ne
    '4B60DFA21CC9800DAEA7363208A13C783E59CA37BFC288D91918803E83F19E20') { throw 'Qualified feature driver required.' }
if ((& verifier.exe /query | Out-String) -notmatch 'No drivers are currently verified' -or
    (& verifier.exe /querysettings | Out-String) -notmatch 'Verifier Flags: 0x00000000') { throw 'Verifier must be off for this managed-startup gate.' }
if (Test-Path S:\) { throw 'Disposable S: is occupied.' }
if (@(Get-Process SafeUpload.Agent.Service -ErrorAction SilentlyContinue).Count) { throw 'Agent already running.' }
if ((Get-FileHash C:\Users\vika\Documents\stage-service-publish.zip).Hash -ne
    'D887E0D7F38AD64AD40CEE18B841C6D38AD2BED4D6F760B1BDE4464927381997') { throw 'Qualified journal service package required.' }
$id = [guid]::NewGuid().ToString('N')
$vhd = 'C:\Users\vika\Documents\SafeUpload-journal-negative-' + $id + '.vhdx'
$diskScript = $vhd + '.txt'
$backup = $vhd + '.original.sys'
$directory = 'S:\SafeUpload\Escopo Monitorado'
$target = [IO.Path]::Combine($directory, $id + '.txt')
$manifest = 'C:\ProgramData\SafeUpload\staging-journal\' + $id + '.json'
$agent = $null; $replaced = $false; $loaded = $false; $mounted = $false
$public = 'BENIGN PUBLIC STARTUP CONTROL'
function Invoke-JournalDisk([string[]] $Commands) {
    Set-Content -LiteralPath $diskScript -Value $Commands -Encoding ASCII
    $output = & diskpart.exe /s $diskScript 2>&1
    $output | Out-Host
    if ($LASTEXITCODE -ne 0 -or $output -match 'DiskPart has encountered an error') { throw 'Disposable disk operation failed.' }
}
try {
    Invoke-JournalDisk @("create vdisk file=`"$vhd`" maximum=128 type=expandable", "select vdisk file=`"$vhd`"",
        'attach vdisk','create partition primary','format fs=ntfs quick label=SafeUploadJournal','assign letter=S')
    $mounted = $true
    New-Item -ItemType Directory -Path $directory | Out-Null
    [IO.File]::WriteAllText($target, $public)
    $digest = (Get-FileHash -LiteralPath $target).Hash
    # A Publishing record with an exact public digest but NO sealing evidence.
    # Recovery must reject it before interpreting the digest as publication.
    $entry = @{ Transfer = @{ TransferId=[guid]$id;
        StagePath=('C:\ProgramData\SafeUpload\staging\'+$id+'.stage'); DestinationPath=$target;
        Destination=0; ProcessName='powershell.exe'; ProcessId=$PID; SessionId=0 };
        State=4; Sha256Hex=$digest; UpdatedAtUtc=[DateTimeOffset]::UtcNow.ToString('o');
        SealedOnce=$false; DestinationGeneration=1 }
    if (Test-Path -LiteralPath $manifest) { throw 'Fixture identity collision.' }
    [IO.File]::WriteAllText($manifest, ($entry | ConvertTo-Json -Depth 5))
    $malformedDigest = (Get-FileHash -LiteralPath $manifest).Hash
    Backup-StagedTestDriver $backup
    Copy-Item C:\Users\vika\Documents\SafeUpload-stage-prototype.sys C:\Windows\System32\drivers\SafeUpload.sys -Force
    $replaced = $true
    & fltmc.exe load SafeUpload | Out-Host
    if ($LASTEXITCODE -ne 0) { throw 'Feature load failed.' }
    $loaded = $true
    $agent = Start-StagedTestAgent 'C:\Users\vika\Documents\stage-service-publish' ($EvidencePrefix + '-' + $id)
    $log = $EvidencePrefix + '-' + $id + '-out.log'
    $observed = ''
    for ($attempt=0; $attempt -lt 80; $attempt++) {
        if (Test-Path $log) { $observed = Get-Content -LiteralPath $log -Raw }
        if ($observed -match 'Falha ao recuperar o diario' -and $observed -match 'invalid seal/publication evidence') { break }
        Start-Sleep -Milliseconds 250
    }
    if ($observed -notmatch 'invalid seal/publication evidence') { throw 'Real service did not report the exact schema rejection.' }
    $denied = $false
    try { [IO.File]::WriteAllText($target, 'CPF: 123.456.789-09 UNAPPROVED') } catch [UnauthorizedAccessException] { $denied = $true }
    if (-not $denied) { throw 'Writable open was admitted after failed journal recovery.' }
    if ((Get-FileHash -LiteralPath $manifest).Hash -ne $malformedDigest) { throw 'Corrupt manifest bytes were silently changed.' }
    Write-Output 'RealServiceRejectsUnsealedPublishingRecord=True; WritableAdmissionDenied=True; CorruptBytesRetained=True'
}
finally {
    Stop-StagedTestAgent $agent
    if ($replaced) { Restore-StagedTestDriver $backup $loaded }
    # Failed restore throws above, preserving the volume and malformed fixture.
    if ($mounted) {
        $check = & powershell.exe -NoProfile -NonInteractive -Command "[IO.File]::ReadAllText('$target')"
        if ($LASTEXITCODE -ne 0 -or $check -ne $public) { throw 'Independent public bytes changed during rejected startup.' }
        Write-Output 'IndependentPublicBytesUnchangedAfterRejectedStartup=True'
    }
    if (Test-Path -LiteralPath $manifest) { Remove-StagedTestFiles @($manifest) }
    if ($mounted -or (Test-Path $vhd)) { Invoke-JournalDisk @("select vdisk file=`"$vhd`"",'detach vdisk') }
    Remove-Item -LiteralPath $vhd,$diskScript -Force -ErrorAction SilentlyContinue
    Write-Output ('RetainedOriginalBackup='+$backup)
    Write-Output ('ServiceLog='+$log)
}
