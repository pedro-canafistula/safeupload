<# Synthetic preexisting-link probe. Only on the recorded isolated debuggee. #>
param([switch] $ReproduceKnownGap, [switch] $Verifier, [switch] $LinkLimitCases)
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
. (Join-Path $PSScriptRoot 'StagedTestAgent.ps1')
Add-Type -Path (Join-Path $PSScriptRoot 'StagedIdentityProbe.cs')
$installed = 'C:\Windows\System32\drivers\SafeUpload.sys'
$expected = 'ADA9D05AB6AECDD2B6C521B0CE529FC06C732154ACB3EE85439FBDC8AA80DFCE'
$backup = 'C:\Users\vika\Documents\SafeUpload-original-before-alias.sys'
$id = [guid]::NewGuid().ToString('N')
$target = 'C:\SafeUpload\Escopo Monitorado\alias-' + $id + '.txt'
$alias = 'C:\Users\vika\Documents\alias-' + $id + '.txt'
$controls = 'C:\Users\vika\Documents\SafeUpload-alias-controls-' + $id
$unrelated = Join-Path $controls 'original.txt'
$peer = Join-Path $controls 'nested\peer.txt'
$newLink = Join-Path $controls 'new-link.txt'
$limit64 = Join-Path $controls 'limit-64.txt'
$limit65 = Join-Path $controls 'limit-65.txt'
$serviceDir = 'C:\Users\vika\Documents\stage-service-publish'
$agent = $null; $loaded = $false; $replaced = $false; $observer = $null
$verified = $false
$oldWriter = $null
if ($env:COMPUTERNAME -ne 'WIN10-DEBUGGED' -or
    (Get-CimInstance Win32_ComputerSystemProduct).UUID -ne '9D44EEE8-81CF-4CC1-9FBA-7670F11DEF4D') { throw 'Wrong debuggee.' }
if ((Get-FileHash $installed -Algorithm SHA256).Hash -ne $expected) { throw 'Original driver hash mismatch.' }
if ((& fltmc.exe filters) -match '^SafeUpload\s') { throw 'Original baseline requires unloaded filter.' }
if ((& verifier.exe /query | Out-String) -notmatch 'No drivers are currently verified' -or
    (& verifier.exe /querysettings | Out-String) -notmatch 'Verifier Flags: 0x00000000') { throw 'Verifier baseline must be off.' }
$systemDriver = Get-CimInstance Win32_SystemDriver -Filter "Name='SafeUpload'"
if ($systemDriver.StartMode -ne 'Manual' -or $systemDriver.State -ne 'Stopped') { throw 'Original service baseline mismatch.' }
if (@(Get-Process SafeUpload.Agent.Service -ErrorAction SilentlyContinue).Count) { throw 'An agent is already running.' }
$policyHash = (Get-FileHash 'C:\ProgramData\SafeUpload\policy.json').Hash
if ($policyHash -ne '29DC8A341BD7C549996596D2477A0CCCAF19602C362A2167FB4FDD5C66663731') { throw 'Original policy baseline mismatch.' }
try {
    [IO.File]::WriteAllText($target, 'approved fixture')
    New-Item -ItemType HardLink -Path $alias -Target $target | Out-Null
    New-Item -ItemType Directory -Path (Join-Path $controls 'nested') | Out-Null
    [IO.File]::WriteAllText($unrelated, 'UNRELATED CONTROL')
    New-Item -ItemType HardLink -Path $peer -Target $unrelated | Out-Null
    if ($LinkLimitCases) {
        foreach ($limit in @(64,65)) {
            $original = Join-Path $controls ('limit-' + $limit + '.txt')
            [IO.File]::WriteAllText($original, 'LINK LIMIT ORIGINAL')
            for ($index=1; $index -lt $limit; $index++) {
                New-Item -ItemType HardLink -Path (Join-Path $controls ('limit-'+$limit+'-'+$index+'.txt')) -Target $original | Out-Null
            }
        }
        'UnfilteredLinkLimitFixtures=True; Counts=64,65'
    }
    & fsutil.exe file queryfileid $target
    & fsutil.exe file queryfileid $alias
    & fsutil.exe hardlink list $target
    # Held physical reader predates the filter; source classification cannot
    # hide a destination-byte leak by denying a new sensitive source open.
    $observer = [IO.FileStream]::new($target, [IO.FileMode]::Open,
        [IO.FileAccess]::Read, [IO.FileShare]::ReadWrite -bor [IO.FileShare]::Delete)
    $oldWriter = [StagedIdentityProbe]::Open($alias, $true, $false)
    Backup-StagedTestDriver $backup
    "FeatureSHA256=$((Get-FileHash 'C:\Users\vika\Documents\SafeUpload-stage-prototype.sys').Hash)"
    "ServiceZipSHA256=$((Get-FileHash 'C:\Users\vika\Documents\stage-service-publish.zip').Hash)"
    $replaced = $true
    Copy-Item 'C:\Users\vika\Documents\SafeUpload-stage-prototype.sys' $installed -Force
    if ($Verifier) {
        & verifier.exe /volatile /flags 0x13B /adddriver SafeUpload.sys | Out-Host
        if ($LASTEXITCODE -ne 0) { throw 'Runtime Verifier setup failed.' }
        $verified = $true
    }
    & fltmc.exe load SafeUpload | Out-Host
    if ($LASTEXITCODE -ne 0) { throw 'Load failed.' }
    $loaded = $true
    $agent = Start-StagedTestAgent $serviceDir 'C:\Users\vika\Documents\stage-alias-service'
    Start-Sleep -Seconds 2
    # A fresh process has no source-read taint and no private view.
    $write = & powershell.exe -NoProfile -Command "try { [IO.File]::WriteAllText('$alias','CPF: 529.982.247-25'); 'written' } catch { 'denied' }"
    if ($LASTEXITCODE -ne 0) { throw 'Writer probe failed.' }
    $bytes = New-Object byte[] 128
    $count = $observer.Read($bytes,0,$bytes.Length)
    $observed = [Text.Encoding]::UTF8.GetString($bytes,0,$count)
    $isolated = $observed -eq 'approved fixture'
    Write-Output "OutsideAliasWrite=$write; IndependentDestinationIsolated=$isolated"
    if ($ReproduceKnownGap) {
        if ($write -ne 'written' -or $observed -ne 'CPF: 529.982.247-25') { throw 'Expected alias gap was not reproduced.' }
        Write-Output 'KnownPathIdentityGapReproduced=True'
    } else {
        if (-not $isolated -or $write -ne 'denied') { throw 'Preexisting hard-link alias changed protected physical bytes.' }
        if ([StagedIdentityProbe]::TryWrite($oldWriter) -ne 5 -or
            [StagedIdentityProbe]::TrySize($oldWriter,$false) -ne 5 -or
            [StagedIdentityProbe]::TrySize($oldWriter,$true) -ne 5 -or
            [StagedIdentityProbe]::TryRename($oldWriter,($alias+'-moved')) -ne 5) { throw 'Pre-attachment physical handle mutation was admitted.' }
        'PreAttachmentHandleWriteSizeAndRenameDenied=True; NativeError=5'
        foreach ($extended in @($false,$true)) {
            if ([StagedIdentityProbe]::TryLink($alias,($alias+'-linked'),$extended) -ne 5 -or
                [StagedIdentityProbe]::TryLink($target,($alias+'-linked'),$extended) -ne 5) { throw 'Access-zero source link escaped the protected object.' }
        }
        'ProtectedAliasAndDirectSourceLinksDenied=True; SourceAccess=0; InformationClasses=11,72'
        [IO.File]::WriteAllText($peer, 'UNRELATED EDIT')
        if ([IO.File]::ReadAllText($unrelated) -ne 'UNRELATED EDIT') { throw 'Unrelated linked-file write failed.' }
        foreach ($extended in @($false,$true)) {
            if ([StagedIdentityProbe]::TryLink($peer,$newLink,$extended) -ne 0) { throw 'Unrelated native link control failed.' }
            [IO.File]::WriteAllText($newLink, 'UNRELATED THREE LINKS')
            if ([IO.File]::ReadAllText($unrelated) -ne 'UNRELATED THREE LINKS') { throw 'Unrelated three-link write failed.' }
            Remove-Item -LiteralPath $newLink
        }
        'UnrelatedTwoAndThreeLinkWritesAllowed=True; NativeLinkControls=11,72; DifferentParents=True'
        if ($LinkLimitCases) {
            $timer=[Diagnostics.Stopwatch]::StartNew()
            [IO.File]::WriteAllText($limit64, '64 LINKS ADMITTED')
            $timer.Stop()
            if ([IO.File]::ReadAllText($limit64) -ne '64 LINKS ADMITTED') { throw 'Exact link bound did not admit an unrelated file.' }
            "UnrelatedExact64LinksAdmitted=True; WriteAndCloseMilliseconds=$($timer.Elapsed.TotalMilliseconds.ToString('F3',[Globalization.CultureInfo]::InvariantCulture))"
            $denied=$false
            try { [IO.File]::WriteAllText($limit65, '65 LINKS MUST BE REFUSED') }
            catch [UnauthorizedAccessException] { $denied=$true }
            if (-not $denied -or [IO.File]::ReadAllText($limit65) -ne 'LINK LIMIT ORIGINAL') { throw 'Excess-link mutation was admitted or changed public bytes.' }
            'Unrelated65LinksRefused=True; ExistingBytesPreserved=True'
        }
        $observer.Position=0; $count=$observer.Read($bytes,0,$bytes.Length)
        if ([Text.Encoding]::UTF8.GetString($bytes,0,$count) -ne 'approved fixture') { throw 'A namespace or held-handle mutation leaked public bytes.' }
        'AllIndependentPhysicalBytesUnchanged=True'
    }
}
finally {
    if ($null -ne $oldWriter) { $oldWriter.Dispose() }
    if ($null -ne $observer) { $observer.Dispose() }
    Stop-StagedTestAgent $agent
    Save-StagedVerifierEvidence
    if ($replaced) { Restore-StagedTestDriver $backup $loaded $verified }
    if ((Get-FileHash 'C:\ProgramData\SafeUpload\policy.json').Hash -ne $policyHash) { throw 'Policy baseline changed.' }
    Remove-StagedTestFiles @($alias, $target)
    if (Test-Path -LiteralPath $controls) { Remove-Item -LiteralPath $controls -Recurse -Force }
    Write-Output 'DisposableAliasFixturesRemoved=True'
}
