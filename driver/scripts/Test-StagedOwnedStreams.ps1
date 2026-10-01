<# Integrated owned-stream gate. Run only on the isolated debuggee. #>
param([switch] $Verifier, [switch] $ReplacementCases, [ValidateRange(0,64)][int] $PublicationIterations = 0)
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'StagedTestAgent.ps1')
Add-Type -Path (Join-Path $PSScriptRoot 'StagedIdentityProbe.cs')
$installed = 'C:\Windows\System32\drivers\SafeUpload.sys'
$expectedOriginal = 'ADA9D05AB6AECDD2B6C521B0CE529FC06C732154ACB3EE85439FBDC8AA80DFCE'
$driver = 'C:\Users\vika\Documents\SafeUpload-stage-prototype.sys'
$backup = 'C:\Users\vika\Documents\SafeUpload-original-before-owned.sys'
$serviceDir = 'C:\Users\vika\Documents\stage-service-publish'
$journal = 'C:\ProgramData\SafeUpload\staging-journal'
$vhd = 'C:\Users\vika\Documents\SafeUpload-owned.vhdx'
$diskpart = $vhd + '.txt'
$id = [guid]::NewGuid().ToString('N')
$directory = 'S:\SafeUpload\Escopo Monitorado'
$target = [IO.Path]::Combine($directory, $id + '.tmp')
$renamed = [IO.Path]::ChangeExtension($target, '.txt')
$mappedTarget = [IO.Path]::Combine($directory, $id + '-mapped.txt')
$parallelTarget = [IO.Path]::Combine($directory, $id + '-parallel.txt')
$restartTarget = [IO.Path]::Combine($directory, $id + '-restart.txt')
$systemScript = Join-Path $env:TEMP ('SafeUpload-owned-' + $id + '.ps1')
$systemResult = $systemScript + '.result'
$taskName = 'SafeUpload-Owned-' + $id
$observerScript = $systemScript + '.observer.ps1'
$observerLog = $systemScript + '.observer.log'
$observerStop = $systemScript + '.stop'
$observerRequest = $systemScript + '.request'
$observerAck = $systemScript + '.ack'
$mounted = $false; $replaced = $false; $loaded = $false; $verifierEnabled = $false
$agent = $null; $observer = $null; $file = $null; $second = $null; $native = $null
$mapping = $null; $view = $null; $oldRead = $null
$cleanup = @()
$observerRules = @{}
$observerRules[$target] = @('ABSENT')
$observerRules[$renamed] = @('ABSENT')
$observerRules[$mappedTarget] = @('ABSENT')
$observerRules[$restartTarget] = @('ABSENT')
$observerRules[$parallelTarget] = @('ABSENT')

Add-Type -TypeDefinition @'
using System;
using System.IO;
using System.Text;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;
public static class SafeUploadArchitectureNative {
    [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
    static extern uint GetFinalPathNameByHandle(SafeFileHandle handle, StringBuilder path, uint length, uint flags);
    [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
    public static extern SafeFileHandle CreateFile(string path, uint access, uint share, IntPtr security,
        uint disposition, uint flags, IntPtr template);
    [DllImport("kernel32.dll", SetLastError=true)]
    static extern bool SetFileInformationByHandle(SafeFileHandle handle, int cls, IntPtr info, uint length);
    [StructLayout(LayoutKind.Sequential)]
    struct IoStatus { public IntPtr Status; public UIntPtr Information; }
    [DllImport("ntdll.dll")]
    static extern int NtQueryInformationFile(SafeFileHandle handle, out IoStatus status, IntPtr buffer, uint length, int cls);
    public static string FinalPath(SafeFileHandle handle, uint flags) {
        var buffer = new StringBuilder(2048);
        uint size = GetFinalPathNameByHandle(handle, buffer, 2048, flags);
        if(size == 0) throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error());
        if(size >= 2048) throw new Exception("Final path overflow");
        return buffer.ToString();
    }
    public static string VolumeName(SafeFileHandle handle) {
        return QueryName(handle,58);
    }
    public static string QueryName(SafeFileHandle handle, int informationClass) {
        IntPtr buffer=Marshal.AllocHGlobal(4096);
        try {
            IoStatus io;
            int status=NtQueryInformationFile(handle,out io,buffer,4096,informationClass);
            if(status!=0) throw new Exception("Volume query: 0x"+status.ToString("X8"));
            int length=Marshal.ReadInt32(buffer);
            if(length<0 || length>4092 || (length&1)!=0) throw new Exception("Invalid volume name length");
            return Marshal.PtrToStringUni(IntPtr.Add(buffer,4),length/2);
        } finally { Marshal.FreeHGlobal(buffer); }
    }
    public static void Rename(SafeFileHandle handle, string destination) { RenameFlags(handle,destination,0,false); }
    public static void RenameFlags(SafeFileHandle handle, string destination, int flags, bool extended) {
        byte[] name=Encoding.Unicode.GetBytes(destination);
        int header=IntPtr.Size==8 ? 20 : 12;
        int lengthOffset=IntPtr.Size==8 ? 16 : 8;
        IntPtr info=Marshal.AllocHGlobal(header+name.Length+2);
        try {
            Marshal.Copy(new byte[header],0,info,header);
            Marshal.WriteInt32(info,flags);
            Marshal.WriteInt32(info,lengthOffset,name.Length);
            Marshal.Copy(name,0,IntPtr.Add(info,header),name.Length);
            Marshal.WriteInt16(info,header+name.Length,0);
            if(!SetFileInformationByHandle(handle,extended ? 22 : 3,info,(uint)(header+name.Length+2)))
                throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error());
        } finally { Marshal.FreeHGlobal(info); }
    }
    public static void ParallelWrites(FileStream first, FileStream second) {
        first.Position = 0; second.Position = 4096;
        System.Threading.Tasks.Task.WaitAll(
            System.Threading.Tasks.Task.Run(() => {
                byte[] bytes = Encoding.ASCII.GetBytes(new string('A', 64));
                for (int i=0; i<64; i++) first.Write(bytes,0,bytes.Length);
                first.Flush();
            }),
            System.Threading.Tasks.Task.Run(() => {
                byte[] bytes = Encoding.ASCII.GetBytes(new string('B', 64));
                for (int i=0; i<64; i++) second.Write(bytes,0,bytes.Length);
                second.Flush();
            }));
    }
    public static System.IO.MemoryMappedFiles.MemoryMappedFile Map(FileStream file, long capacity) {
        return System.IO.MemoryMappedFiles.MemoryMappedFile.CreateFromFile(file, null, capacity,
            System.IO.MemoryMappedFiles.MemoryMappedFileAccess.ReadWrite,
            System.IO.HandleInheritability.None, true);
    }
}
'@

function Invoke-ProbeSystem([string] $Script) {
    Remove-Item -LiteralPath $systemResult -Force -ErrorAction SilentlyContinue
    $wrapped = '$ErrorActionPreference = ''Stop''; try {' + "`n" + $Script + "`n" +
        "[IO.File]::WriteAllText('$systemResult','OK')" + "`n} catch {" +
        "[IO.File]::WriteAllText('$systemResult',`$_.Exception.ToString()); exit 1 }"
    Set-Content -LiteralPath $systemScript -Value $wrapped -Encoding UTF8
    $action = New-ScheduledTaskAction -Execute 'powershell.exe' `
        -Argument ('-NoProfile -ExecutionPolicy Bypass -File "' + $systemScript + '"')
    $principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
    Register-ScheduledTask -TaskName $taskName -Action $action -Principal $principal -Force | Out-Null
    try {
        Start-ScheduledTask -TaskName $taskName
        for ($attempt=0; $attempt -lt 120 -and -not (Test-Path -LiteralPath $systemResult); $attempt++) {
            Start-Sleep -Milliseconds 250
        }
        if (-not (Test-Path -LiteralPath $systemResult)) { throw 'SYSTEM operation timed out.' }
        $result = Get-Content -LiteralPath $systemResult -Raw
        if ($result -ne 'OK') { throw $result }
    }
    finally { Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction SilentlyContinue }
}

function Invoke-ProbeDisk([string[]] $Commands) {
    Set-Content -LiteralPath $diskpart -Value $Commands -Encoding Ascii
    $result = & diskpart.exe /s $diskpart 2>&1
    $result | Out-Host
    if ($LASTEXITCODE -ne 0 -or ($result -match 'DiskPart has encountered an error')) {
        throw 'Disposable volume operation failed.'
    }
}

function Read-OwnedManifest([string] $Path) {
    for ($retry=0; $retry -lt 50; $retry++) {
        try {
            $input = [IO.FileStream]::new($Path,[IO.FileMode]::Open,[IO.FileAccess]::Read,
                [IO.FileShare]::ReadWrite -bor [IO.FileShare]::Delete)
            $text = [IO.StreamReader]::new($input)
            try { return ($text.ReadToEnd() | ConvertFrom-Json) } finally { $text.Dispose() }
        }
        catch [IO.IOException] { Start-Sleep -Milliseconds 20 }
    }
    throw "Manifest remained unavailable: $Path"
}
function Get-OwnedEntries([string] $Destination) {
    @(Get-ChildItem -LiteralPath $journal -Filter '*.json' | ForEach-Object {
        Read-OwnedManifest $_.FullName
    } | Where-Object { $_.Transfer.DestinationPath -eq $Destination })
}
function Wait-OwnedState([guid] $Transfer, [int] $State) {
    $path = Join-Path $journal ($Transfer.ToString('N') + '.json')
    for ($attempt=0; $attempt -lt 120; $attempt++) {
        $entry = Read-OwnedManifest $path
        if ($entry.State -eq $State) { return $entry }
        if ($agent.Process.HasExited) { throw 'Agent exited.' }
        if ($observer -and $observer.HasExited) { Get-Content $observerLog | Out-Host; throw 'Destination observer failed.' }
        Start-Sleep -Milliseconds 250
    }
    throw "Version $Transfer stayed in state $($entry.State), expected $State."
}
function Set-OwnedObserver([string] $Phase) {
    # Readers retry incomplete JSON. No rename of a coordination file held by
    # another reader: classic NTFS replacement may deny that operation.
    $requestJson = @{ Phase=$Phase; Rules=$observerRules } | ConvertTo-Json -Depth 4
    [IO.File]::WriteAllText($observerRequest, $requestJson)
    for ($attempt=0; $attempt -lt 100; $attempt++) {
        if ($observer.HasExited) { Get-Content $observerLog | Out-Host; throw "Destination observer exited during $Phase." }
        if ((Test-Path $observerAck) -and (Get-Content $observerAck -Raw) -eq $Phase) { return }
        Start-Sleep -Milliseconds 100
    }
    throw "Observer did not sample $Phase."
}
function Write-OwnedText($Stream, [string] $Text) {
    $bytes = [Text.Encoding]::UTF8.GetBytes($Text)
    $Stream.Write($bytes, 0, $bytes.Length)
    $Stream.Flush()
}
function Read-OwnedPrivate([string] $Path) {
    $input = [IO.FileStream]::new($Path,[IO.FileMode]::Open,[IO.FileAccess]::Read,
        [IO.FileShare]::ReadWrite -bor [IO.FileShare]::Delete)
    $textReader = [IO.StreamReader]::new($input)
    try { $textReader.ReadToEnd() } finally { $textReader.Dispose() }
}
function Read-OwnedPublic([string] $Path) {
    & powershell.exe -NoProfile -Command "[IO.File]::ReadAllText('$Path')"
}

if ((Get-FileHash $installed -Algorithm SHA256).Hash -ne $expectedOriginal) { throw 'Original installed driver mismatch.' }
if ((Test-Path S:\) -or (Test-Path $vhd)) { throw 'Disposable S: already present.' }
try {
    Invoke-ProbeDisk @("create vdisk file=`"$vhd`" maximum=128 type=expandable", "select vdisk file=`"$vhd`"",
        'attach vdisk','create partition primary','format fs=ntfs quick label=SafeUploadOwned','assign letter=S')
    $mounted = $true
    New-Item -ItemType Directory -Force -Path $directory,$serviceDir | Out-Null
    $fixture = Join-Path $directory 'identity.txt'
    [IO.File]::WriteAllText($fixture, 'approved')
    $identity = [IO.File]::OpenRead($fixture)
    try { $expectedVolume = [SafeUploadArchitectureNative]::VolumeName($identity.SafeFileHandle) }
    finally { $identity.Dispose() }
    $controlRename = Join-Path $directory 'identity-renamed.txt'
    $controlHandle = [SafeUploadArchitectureNative]::CreateFile($fixture,0x10000,7,[IntPtr]::Zero,3,0x80,[IntPtr]::Zero)
    try {
        [SafeUploadArchitectureNative]::Rename($controlHandle,$controlRename)
        if ([SafeUploadArchitectureNative]::FinalPath($controlHandle,0) -ine ('\\?\' + $controlRename)) {
            throw 'The native rename helper failed the unfiltered control.'
        }
    } finally { $controlHandle.Dispose(); Remove-Item $controlRename -Force }
    Write-Output 'UnfilteredNativeRenameControl=True'
    & tar.exe -xf 'C:\Users\vika\Documents\stage-service-publish.zip' -C $serviceDir
    if ($LASTEXITCODE -ne 0) { throw 'Service extraction failed.' }
    Copy-Item $installed $backup -Force
    Copy-Item $driver $installed -Force
    $replaced = $true
    if ($Verifier) {
        & verifier.exe /volatile /flags 0x13B /adddriver SafeUpload.sys | Out-Host
        if ($LASTEXITCODE -ne 0) { throw 'Verifier enable failed.' }
        $verifierEnabled = $true
    }
    & fltmc.exe load SafeUpload | Out-Host
    if ($LASTEXITCODE -ne 0) { throw 'Owned driver load failed.' }
    $loaded = $true
    Write-Output ('IntegratedDriverLoaded=' + (Get-FileHash $driver -Algorithm SHA256).Hash)
    $denied = $false
    try { [IO.File]::WriteAllText($target, 'must stay absent') }
    catch { $denied = $true }
    if (-not $denied -or [IO.File]::Exists($target)) { throw 'Missing service did not deny create.' }
    Write-Output 'DeniedWithoutService=True'
    $agent = Start-StagedTestAgent $serviceDir 'C:\Users\vika\Documents\stage-owned-service'
    Start-Sleep -Seconds 2
    $watch = @'
$ErrorActionPreference='Stop'; $samples=0
while (-not (Test-Path '__STOP__')) {
    if (Test-Path '__REQUEST__') {
        try { $request = Get-Content '__REQUEST__' -Raw | ConvertFrom-Json } catch { continue }
        $complete = $true
        foreach ($rule in $request.Rules.PSObject.Properties) {
            $actual = if ([IO.File]::Exists($rule.Name)) {
                try {
                    $input = [IO.FileStream]::new($rule.Name,[IO.FileMode]::Open,[IO.FileAccess]::Read,
                        [IO.FileShare]::ReadWrite -bor [IO.FileShare]::Delete)
                    $memory = [IO.MemoryStream]::new()
                    try { $input.CopyTo($memory); [Convert]::ToBase64String($memory.ToArray()) }
                    finally { $input.Dispose(); $memory.Dispose() }
                }
                catch [IO.IOException] { $complete = $false; continue }
            } else { 'ABSENT' }
            if (@($rule.Value) -notcontains $actual) {
                Add-Content '__LOG__' ('LEAK phase=' + $request.Phase + ' path=' + $rule.Name + ' bytes=' + $actual)
                exit 2
            }
        }
        if (-not $complete) { Start-Sleep -Milliseconds 20; continue }
        $samples++
        [IO.File]::WriteAllText('__ACK__', $request.Phase)
    }
    Start-Sleep -Milliseconds 20
}
Add-Content '__LOG__' ('samples=' + $samples)
'@
    Set-Content $observerScript ($watch.Replace('__STOP__',$observerStop).Replace('__REQUEST__',$observerRequest).
        Replace('__LOG__',$observerLog).Replace('__ACK__',$observerAck)) -Encoding UTF8
    $observer = Start-Process powershell.exe -PassThru -WindowStyle Hidden -ArgumentList @(
        '-NoProfile','-ExecutionPolicy','Bypass','-File',('"' + $observerScript + '"'))
    $null = $observer.Handle
    Set-OwnedObserver 'ready'

    $share = [IO.FileShare]::ReadWrite -bor [IO.FileShare]::Delete
    $file = [IO.FileStream]::new($target, [IO.FileMode]::CreateNew, [IO.FileAccess]::ReadWrite, $share)
    Write-OwnedText $file 'alphabeta'
    $entry = @(Get-OwnedEntries $target)
    if ($entry.Count -ne 1 -or $entry[0].State -ne 0) { throw 'Allocation was not durably journaled before CREATE.' }
    $firstId = [guid]$entry[0].Transfer.TransferId
    $firstStage = $entry[0].Transfer.StagePath
    if ([SafeUploadArchitectureNative]::VolumeName($file.SafeFileHandle) -ne $expectedVolume -or
        [SafeUploadArchitectureNative]::FinalPath($file.SafeFileHandle,0) -ine ('\\?\' + $target)) {
        throw 'Original destination path/volume identity lost.'
    }
    Write-Output "DurableAllocationAndNativeIdentity=True; Volume=$expectedVolume"
    $privateId=[StagedIdentityProbe]::Identity($file.SafeFileHandle)
    $volumeId=[StagedIdentityProbe]::VolumeIdentity('S:\')
    if([BitConverter]::ToUInt64($privateId,0) -ne [BitConverter]::ToUInt64($volumeId,0)){
        throw 'Private identity reports the backing volume serial.'
    }
    $idHandle=[StagedIdentityProbe]::ById('S:\',$privateId,$false)
    try{if([StagedIdentityProbe]::Read($idHandle) -ne 'alphabeta'){throw 'Cross-volume private file-ID read lost data.'}}
    finally{$idHandle.Dispose()}
    if([StagedIdentityProbe]::TryById('C:\',$privateId,$false) -ne 5){throw 'Wrong-volume hint resolved a private ID.'}
    Write-Output 'PrivateFileIdReportsOriginalVolumeAndRejectsWrongVolume=True'
    Set-OwnedObserver 'ordinary-write'
    $second = [IO.FileStream]::new($target, [IO.FileMode]::Open, [IO.FileAccess]::ReadWrite, $share)
    $second.Position = 9
    Write-OwnedText $second 'tail'
    $file.Dispose(); $file = $null
    Start-Sleep -Milliseconds 700
    if ((Get-OwnedEntries $target)[0].State -ne 0) { throw 'First cleanup sealed a concurrent writer.' }
    $native = [SafeUploadArchitectureNative]::CreateFile($target,0x10000,7,[IntPtr]::Zero,3,0x80,[IntPtr]::Zero)
    if ($native.IsInvalid) { throw 'Native delete handle failed.' }
    [SafeUploadArchitectureNative]::Rename($native, $renamed)
    $heldName = [SafeUploadArchitectureNative]::FinalPath($second.SafeFileHandle,0)
    Write-Output ('RenameRequested=' + $renamed)
    Write-Output ('RenameNativeFileName=' + [SafeUploadArchitectureNative]::QueryName($second.SafeFileHandle,9))
    Write-Output ('RenameJournalDestination=' + ((Read-OwnedManifest (Join-Path $journal ($firstId.ToString('N') + '.json'))).Transfer.DestinationPath))
    $oldExists = [IO.File]::Exists($target)
    Write-Output "RenameHeldName=$heldName; OldNameExists=$oldExists"
    if ($heldName -ine ('\\?\' + $renamed) -or $oldExists) { throw 'Rename failed to update held names or hide the old path.' }
    $native.Dispose(); $native = $null
    Write-Output 'ConcurrentWritersAndNativeCrossVolumeRename=True'
    Set-OwnedObserver 'renamed-unsealed'
    $observerRules[$renamed] = @('ABSENT',[Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes('alphabetatail')))
    Set-OwnedObserver 'allow-approved-first-version'
    $second.Dispose(); $second = $null
    $released = Wait-OwnedState $firstId 5
    if (-not $released.SealedOnce -or (Read-OwnedPublic $renamed) -ne 'alphabetatail') { throw 'Real approved publication failed.' }
    Write-Output ('ApprovedPublication=alphabetatail; Digest=' + $released.Sha256Hex)

    # Keep a sealed read object alive while a NEW writable version is allocated.
    $oldRead = [IO.File]::OpenRead($renamed)
    $file = [IO.FileStream]::new($renamed, [IO.FileMode]::Open, [IO.FileAccess]::ReadWrite, $share)
    $file.Position = $file.Length
    Write-OwnedText $file ' CPF: 529.982.247-25'
    $file.Dispose(); $file = $null
    $newEntry = @(Get-OwnedEntries $renamed | Where-Object { [guid]$_.Transfer.TransferId -ne $firstId })
    if ($newEntry.Count -ne 1) { throw 'Later edit did not allocate a new version.' }
    $blocked = Wait-OwnedState ([guid]$newEntry[0].Transfer.TransferId) 6
    $oldRead.Position = 1
    $oldRead.Position = 0 # a sealed read handle still supports seeks
    $reader = [IO.StreamReader]::new($oldRead)
    try { $oldBytes = $reader.ReadToEnd() } finally { $reader.Dispose(); $oldRead = $null }
    if ($oldBytes -ne 'alphabetatail' -or [IO.File]::ReadAllText($renamed) -ne 'alphabetatail CPF: 529.982.247-25' -or
        (Read-OwnedPublic $renamed) -ne 'alphabetatail') { throw 'Old version or destination changed during private append.' }
    Write-Output 'ReopenAllocatesNewVersionPreservesPrivateAndPriorBytes=True'
    Set-OwnedObserver 'sensitive-new-version'

    $observerRules[$renamed] += [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes('clean replacement'))
    Set-OwnedObserver 'allow-approved-replacement'
    [IO.File]::WriteAllText($renamed, 'clean replacement')
    $replacement = @(Get-OwnedEntries $renamed | Where-Object {
        $_.Transfer.TransferId -ne $released.Transfer.TransferId -and $_.Transfer.TransferId -ne $blocked.Transfer.TransferId })
    if ($replacement.Count -ne 1) { throw 'Overwrite did not allocate a distinct version.' }
    $null = Wait-OwnedState ([guid]$replacement[0].Transfer.TransferId) 5
    if ((Read-OwnedPublic $renamed) -ne 'clean replacement') { throw 'Clean overwrite failed publication.' }
    Write-Output 'LaterCleanOverwritePublished=True'

    for ($iteration = 0; $iteration -lt $PublicationIterations; $iteration++) {
        $content = 'approved iteration ' + $iteration
        $priorIds = @(Get-OwnedEntries $renamed | ForEach-Object { $_.Transfer.TransferId })
        $observerRules[$renamed] += [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($content))
        Set-OwnedObserver ('allow-approved-iteration-' + $iteration)
        [IO.File]::WriteAllText($renamed,$content)
        $iterationEntry = @(Get-OwnedEntries $renamed | Where-Object { $priorIds -notcontains $_.Transfer.TransferId })
        if ($iterationEntry.Count -ne 1) { throw 'Repeated publication allocated unexpected versions.' }
        $null = Wait-OwnedState ([guid]$iterationEntry[0].Transfer.TransferId) 5
        if ((Read-OwnedPublic $renamed) -ne $content) { throw 'Repeated publication bytes differ.' }
        Write-Output ('ApprovedPublicationIteration=' + $iteration)
    }

    if ($ReplacementCases) {
        $approvedBeforeNative = Read-OwnedPublic $renamed
        # Reuse the old temporary slot and replace a sealed current private
        # version. Held old readers remain on the displaced version under POSIX.
        $oldRead = [IO.FileStream]::new($renamed,[IO.FileMode]::Open,[IO.FileAccess]::Read,$share)
        $file = [IO.FileStream]::new($target,[IO.FileMode]::CreateNew,[IO.FileAccess]::ReadWrite,$share)
        Write-OwnedText $file 'native replacement'
        $replaceEntry = (Get-OwnedEntries $target)[0]
        $native = [SafeUploadArchitectureNative]::CreateFile($target,0x10000,7,[IntPtr]::Zero,3,0x80,[IntPtr]::Zero)
        $denied = $false
        try { [SafeUploadArchitectureNative]::RenameFlags($native,$renamed,1,$false) } catch { $denied = $true }
        if (-not $denied) { throw 'Ordinary replacement accepted an open private target.' }
        [SafeUploadArchitectureNative]::RenameFlags($native,$renamed,3,$true)
        if ([IO.File]::Exists($target) -or (Read-OwnedPrivate $renamed) -ne 'native replacement') {
            throw 'Replacement private namespace did not change atomically.'
        }
        $reader = [IO.StreamReader]::new($oldRead)
        try { $prior = $reader.ReadToEnd() } finally { $reader.Dispose(); $oldRead = $null }
        if ($prior -ne $approvedBeforeNative -or (Read-OwnedPublic $renamed) -ne $approvedBeforeNative) {
            throw 'Replacement changed an old reader or public bytes before approval.'
        }
        $listing = @([IO.Directory]::GetFiles($directory))
        if (@($listing | Where-Object { $_ -eq $renamed }).Count -ne 1 -or $listing -contains $target) {
            throw 'Replacement directory overlay duplicated the active slot or exposed its tombstone.'
        }
        Set-OwnedObserver 'native-replacement-private'
        $observerRules[$renamed] += [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes('native replacement'))
        Set-OwnedObserver 'allow-native-replacement'
        $native.Dispose(); $native = $null; $file.Dispose(); $file = $null
        $committed = Wait-OwnedState ([guid]$replaceEntry.Transfer.TransferId) 5
        if ((Read-OwnedPublic $renamed) -ne 'native replacement' -or -not $committed.NamespaceTombstones) {
            throw 'Replacement did not durably tombstone and publish the exact version.'
        }
        Write-Output 'NativePosixReplacementPreservesOldReaderAndPublishes=True'

        # Closed-target ordinary replacement uses the same transaction; a
        # sensitive replacement remains private while the public version stays.
        $file = [IO.FileStream]::new($target,[IO.FileMode]::CreateNew,[IO.FileAccess]::ReadWrite,$share)
        Write-OwnedText $file 'CPF: 529.982.247-25'
        $sensitiveReplacement = (Get-OwnedEntries $target)[0]
        $native = [SafeUploadArchitectureNative]::CreateFile($target,0x10000,7,[IntPtr]::Zero,3,0x80,[IntPtr]::Zero)
        [SafeUploadArchitectureNative]::RenameFlags($native,$renamed,1,$false)
        $native.Dispose(); $native = $null; $file.Dispose(); $file = $null
        $null = Wait-OwnedState ([guid]$sensitiveReplacement.Transfer.TransferId) 6
        if ((Read-OwnedPublic $renamed) -ne 'native replacement' -or [IO.File]::ReadAllText($renamed) -ne 'CPF: 529.982.247-25') {
            throw 'Blocked replacement damaged the private/public split.'
        }
        Set-OwnedObserver 'blocked-native-replacement'
        Write-Output 'OrdinaryNativeReplacementBlockedBytesRemainPrivate=True'
    }

    $file = [IO.FileStream]::new($parallelTarget, [IO.FileMode]::CreateNew, [IO.FileAccess]::ReadWrite, $share)
    $file.SetLength(8192)
    $second = [IO.FileStream]::new($parallelTarget, [IO.FileMode]::Open, [IO.FileAccess]::ReadWrite, $share)
    [SafeUploadArchitectureNative]::ParallelWrites($file,$second)
    $parallelEntry = (Get-OwnedEntries $parallelTarget)[0]
    $file.Dispose(); $file = $null
    if ((Get-OwnedEntries $parallelTarget)[0].State -ne 0) { throw 'Concurrent threads sealed before final handle closure.' }
    $expectedParallel = [Text.Encoding]::ASCII.GetBytes(('A' * 4096) + ('B' * 4096))
    $observerRules[$parallelTarget] = @('ABSENT',[Convert]::ToBase64String($expectedParallel))
    Set-OwnedObserver 'allow-approved-parallel-writes'
    $second.Dispose(); $second = $null
    $null = Wait-OwnedState ([guid]$parallelEntry.Transfer.TransferId) 5
    $actualParallel = & powershell.exe -NoProfile -Command "[Convert]::ToBase64String([IO.File]::ReadAllBytes('$parallelTarget'))"
    if ($actualParallel -ne [Convert]::ToBase64String($expectedParallel)) { throw 'Parallel cached writes lost bytes.' }
    Write-Output 'ParallelWriterThreadsPublishedExact8192Bytes=True'

    $file = [IO.FileStream]::new($mappedTarget, [IO.FileMode]::CreateNew, [IO.FileAccess]::ReadWrite, $share)
    $file.SetLength(257)
    $file.WriteByte(0x41); $file.Flush()
    $file.SetLength(4096)
    $file.Position = 0
    if ($file.ReadByte() -ne 0x41) { throw 'Unaligned growth lost its previous partial sector.' }
    $file.Position = 4095
    if ($file.ReadByte() -ne 0) { throw 'Unaligned growth did not zero the tail.' }
    Write-Output 'UnalignedGrowthPreservesAndZeroes=True'
    $mapping = [SafeUploadArchitectureNative]::Map($file,4096)
    $view = $mapping.CreateViewAccessor(0,4096,[IO.MemoryMappedFiles.MemoryMappedFileAccess]::ReadWrite)
    $view.Write(0,[byte]0x41)
    $file.Position=0
    if ($file.ReadByte() -ne 0x41) { throw 'Mapped and cached views are incoherent.' }
    $mappedEntry = (Get-OwnedEntries $mappedTarget)[0]
    $file.Dispose(); $file = $null
    $view.Write(1,[byte]0x42)
    Start-Sleep -Seconds 1
    if ((Get-OwnedEntries $mappedTarget)[0].State -ne 0) { throw 'Live mapping was sealed after handle cleanup.' }
    Set-OwnedObserver 'mapped-write-after-handle-close'
    Stop-StagedTestAgent $agent; $agent = $null
    & fltmc.exe unload SafeUpload | Out-Host
    if ($LASTEXITCODE -eq 0) { $loaded = $false; throw 'Unload accepted a surviving writable mapping.' }
    Write-Output 'UnloadRefusedWithOnlyMappedWriter=True'
    $agent = Start-StagedTestAgent $serviceDir 'C:\Users\vika\Documents\stage-owned-mapped-restart-service'
    $null = Wait-OwnedState ([guid]$mappedEntry.Transfer.TransferId) 8
    $view.Write(2,[byte]0x43)
    $expectedMapped = [byte[]]::new(4096); $expectedMapped[0]=0x41; $expectedMapped[1]=0x42; $expectedMapped[2]=0x43
    $observerRules[$mappedTarget] = @('ABSENT',[Convert]::ToBase64String($expectedMapped))
    Set-OwnedObserver 'allow-approved-mapped'
    # No Flush call: retirement must drain dirty mapped pages itself.
    $view.Dispose(); $view = $null; $mapping.Dispose(); $mapping = $null
    $mappedReleased = Wait-OwnedState ([guid]$mappedEntry.Transfer.TransferId) 5
    $actualMapped = & powershell.exe -NoProfile -Command "[Convert]::ToBase64String([IO.File]::ReadAllBytes('$mappedTarget'))"
    if ($actualMapped -ne [Convert]::ToBase64String($expectedMapped)) { throw 'Paging drainage lost mapped writes.' }
    Write-Output 'MappedWritesAfterCleanupDrainedAndPublishedExactly=True'

    $file = [IO.FileStream]::new($restartTarget, [IO.FileMode]::CreateNew, [IO.FileAccess]::ReadWrite, $share)
    Write-OwnedText $file 'survives service restart'
    $restartEntry = (Get-OwnedEntries $restartTarget)[0]
    Stop-StagedTestAgent $agent; $agent = $null
    $agent = Start-StagedTestAgent $serviceDir 'C:\Users\vika\Documents\stage-owned-restarted-service'
    $null = Wait-OwnedState ([guid]$restartEntry.Transfer.TransferId) 8
    Set-OwnedObserver 'service-restart-unsealed'
    $observerRules[$restartTarget] = @('ABSENT',[Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes('survives service restart')))
    Set-OwnedObserver 'allow-approved-recovery'
    $file.Dispose(); $file = $null
    $null = Wait-OwnedState ([guid]$restartEntry.Transfer.TransferId) 5
    if ((Read-OwnedPublic $restartTarget) -ne 'survives service restart') { throw 'Service reconnection did not retry sealing.' }
    Write-Output 'ServiceRestartRetainsThenSealsAndPublishes=True'
    Set-OwnedObserver 'completed'
    Set-Content $observerStop 'stop'
    if (-not $observer.WaitForExit(10000) -or $observer.ExitCode -ne 0) { throw 'Observer failed.' }
    $observed = Get-Content $observerLog -Raw
    if ($observed -match 'LEAK' -or $observed -notmatch 'samples=[1-9]') { throw 'No continuous isolation evidence.' }
    Write-Output ('DestinationByteObserver=' + $observed.Trim())
    if ($Verifier) { Save-StagedVerifierEvidence; & verifier.exe /query | Out-Host }
    Write-Output 'IntegratedOwnedStreamMilestone=True'
}
finally {
    foreach ($disposable in @($reader,$oldRead,$native,$file,$second,$view,$mapping)) {
        if ($null -ne $disposable) { $disposable.Dispose() }
    }
    if ($observer -and -not $observer.HasExited) { Stop-Process $observer.Id -Force }
    Stop-StagedTestAgent $agent
    if ($replaced) { Restore-StagedTestDriver $backup $loaded $verifierEnabled }
    # A failed restoration throws above, retaining the fixtures for diagnosis.
    if ($mounted) {
        $physical = @(Get-ChildItem -LiteralPath $directory -File)
        Write-Output ('PhysicalDestinationAfterUnload=' + ($physical.Name -join ','))
    }
    if ($firstStage) {
        $denied = $false
        try { [IO.File]::ReadAllBytes($firstStage) | Out-Null } catch [UnauthorizedAccessException] { $denied = $true }
        if (-not $denied) { throw 'Private bytes were accessible after driver unload.' }
        Write-Output 'PrivateACLProtectsAfterUnload=True'
    }
    foreach ($manifest in @(Get-ChildItem -LiteralPath $journal -Filter '*.json')) {
        $entry = Read-OwnedManifest $manifest.FullName
        if ($entry.Transfer.DestinationPath.Contains($id)) {
            $cleanup += $entry.Transfer.StagePath
            $cleanup += Join-Path $journal (([guid]$entry.Transfer.TransferId).ToString('N') + '.json')
        }
    }
    Remove-StagedTestFiles $cleanup
    if ($mounted) { Invoke-ProbeDisk @("select vdisk file=`"$vhd`"", 'detach vdisk') }
    Remove-Item -LiteralPath $vhd,$diskpart,$systemScript,$systemResult,$observerScript,$observerStop,$observerRequest,$observerAck -Force -ErrorAction SilentlyContinue
    Remove-Item -LiteralPath ($observerRequest + '.next'),($observerAck + '.next') -Force -ErrorAction SilentlyContinue
    # Retain observerLog as evidence, with its path printed on every run.
    Write-Output "ObserverLog=$observerLog"
}
