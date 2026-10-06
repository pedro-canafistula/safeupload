<#
.SYNOPSIS
    Protocol, model, and local transport checks for Invoke-AdmissionEvidenceCapture.ps1.

.DESCRIPTION
    Opens only fresh isolated local fake named pipes, not the service pipe.
    It does not inspect a live process, create evidence files, or call the
    minifilter. It constructs producer-shaped SAEF frames and probes bounds,
    ordering, raw hashes, partial retention, summary schema, identity
    comparisons, private ACL models, and bounded pipe transport behavior.
#>
[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'Invoke-AdmissionEvidenceCapture.ps1')

if (-not ('SafeUploadAdmissionEvidence.Client.SelfCheckPipeFixture' -as [type])) {
    Add-Type -Language CSharp -TypeDefinition @'
using System;
using System.IO.Pipes;
using System.Threading;
using System.Threading.Tasks;

namespace SafeUploadAdmissionEvidence.Client
{
    public static class SelfCheckPipeFixture
    {
        public static Task StartAccept(NamedPipeServerStream server)
        {
            return Task.Factory.StartNew(new Action(delegate { server.WaitForConnection(); }),
                CancellationToken.None, TaskCreationOptions.LongRunning, TaskScheduler.Default);
        }

        public static Task WriteFragmentsAndClose(NamedPipeServerStream server,
            byte[] first, int delayMilliseconds, byte[] second)
        {
            return Task.Factory.StartNew(new Action(delegate
            {
                try
                {
                    if (first != null && first.Length != 0) server.Write(first, 0, first.Length);
                    Thread.Sleep(delayMilliseconds);
                    if (second != null && second.Length != 0) server.Write(second, 0, second.Length);
                }
                finally { server.Dispose(); }
            }), CancellationToken.None, TaskCreationOptions.LongRunning, TaskScheduler.Default);
        }

        public static Task<int> StartRoundtrip(NamedPipeServerStream server,
            byte[] requestBytes, byte[] responseBytes)
        {
            return Task.Factory.StartNew<int>(delegate
            {
                int length = 0;
                try
                {
                    while (length < requestBytes.Length)
                    {
                        int read = server.Read(requestBytes, length, requestBytes.Length - length);
                        if (read <= 0) throw new System.IO.EndOfStreamException();
                        length += read;
                    }
                    server.Write(responseBytes, 0, responseBytes.Length);
                    return length;
                }
                finally { server.Dispose(); }
            }, CancellationToken.None, TaskCreationOptions.LongRunning, TaskScheduler.Default);
        }
    }
}
'@
}

function Assert-AdmissionSelfCheck([bool] $Condition, [string] $Message) {
    if (-not $Condition) { throw ('Admission evidence self-check failed: ' + $Message) }
}

function Assert-AdmissionSelfCheckThrows([scriptblock] $Action, [string] $Message) {
    $threw = $false
    try { & $Action } catch { $threw = $true }
    Assert-AdmissionSelfCheck $threw $Message
}

function New-AdmissionSelfCheckConnectedPipePair {
    $pipeName = 'AdmissionEvidenceSelfCheck_' + [Guid]::NewGuid().ToString('N')
    $server = [IO.Pipes.NamedPipeServerStream]::new($pipeName,
        [IO.Pipes.PipeDirection]::InOut, 1, [IO.Pipes.PipeTransmissionMode]::Byte,
        [IO.Pipes.PipeOptions]::Asynchronous, 4096, 4096)
    $acceptTask = [SafeUploadAdmissionEvidence.Client.SelfCheckPipeFixture]::StartAccept($server)
    $client = $null
    try {
        $client = [IO.Pipes.NamedPipeClientStream]::new('.', $pipeName,
            [IO.Pipes.PipeDirection]::InOut, [IO.Pipes.PipeOptions]::Asynchronous,
            [Security.Principal.TokenImpersonationLevel]::Identification)
        $client.Connect(3000)
        if (-not $acceptTask.Wait(3000)) { throw 'Self-check fake named-pipe server did not accept its client.' }
        return [pscustomobject]@{ Server = $server; Client = $client }
    } catch {
        if ($null -ne $client) { try { $client.Dispose() } catch { } }
        try { $server.Dispose() } catch { }
        try { [void]$acceptTask.Wait(1000) } catch { }
        throw
    }
}

function Close-AdmissionSelfCheckPipePair($Pair) {
    if ($null -ne $Pair.Client) { try { $Pair.Client.Dispose() } catch { } }
    if ($null -ne $Pair.Server) { try { $Pair.Server.Dispose() } catch { } }
}

function Test-AdmissionSelfCheckByteArrays([byte[]] $Actual, [byte[]] $Expected) {
    if ($null -eq $Actual -or $null -eq $Expected -or $Actual.Length -ne $Expected.Length) { return $false }
    for ($i = 0; $i -lt $Expected.Length; $i++) {
        if ($Actual[$i] -ne $Expected[$i]) { return $false }
    }
    return $true
}

function New-AdmissionSelfCheckTargetIdentity([string] $VolumeGuid, [uint64] $Serial, [byte[]] $FileId) {
    $type = [SafeUploadAdmissionEvidence.Client.TargetIdentity]
    $flags = [Reflection.BindingFlags]::Instance -bor [Reflection.BindingFlags]::NonPublic
    $constructor = $type.GetConstructor($flags, $null,
        [Type[]]@([string], [uint64], [byte[]]), $null)
    if ($null -eq $constructor) { throw 'TargetIdentity constructor changed; update the identity model check.' }
    $arguments = New-Object object[] 3
    $arguments[0] = $VolumeGuid
    $arguments[1] = $Serial
    $arguments[2] = $FileId
    return $constructor.Invoke($arguments)
}

function New-AdmissionSelfCheckProcessIdentity([int] $ProcessId, [long] $Birth, [string] $Path,
    [string] $Sha256, $ImageIdentity) {
    $type = [SafeUploadAdmissionEvidence.Client.ProcessIdentity]
    $flags = [Reflection.BindingFlags]::Instance -bor [Reflection.BindingFlags]::NonPublic
    $constructor = $type.GetConstructor($flags, $null,
        [Type[]]@([int], [long], [string], [string], [SafeUploadAdmissionEvidence.Client.TargetIdentity]), $null)
    if ($null -eq $constructor) { throw 'ProcessIdentity constructor changed; update the identity model check.' }
    $arguments = New-Object object[] 5
    $arguments[0] = $ProcessId
    $arguments[1] = $Birth
    $arguments[2] = $Path
    $arguments[3] = $Sha256
    $arguments[4] = $ImageIdentity
    return $constructor.Invoke($arguments)
}

function Set-AdmissionSelfCheckBytes([byte[]] $Destination, [int] $Offset, [byte[]] $Source) {
    [Array]::Copy($Source, 0, $Destination, $Offset, $Source.Length)
}

function New-AdmissionSelfCheckControlInput([uint32] $Command, [uint32] $StartIndex) {
    $bytes = New-Object byte[] 16
    [Array]::Copy([BitConverter]::GetBytes([uint32]18), 0, $bytes, 0, 4)
    [Array]::Copy([BitConverter]::GetBytes([uint32]16), 0, $bytes, 4, 4)
    [Array]::Copy([BitConverter]::GetBytes($Command), 0, $bytes, 8, 4)
    [Array]::Copy([BitConverter]::GetBytes($StartIndex), 0, $bytes, 12, 4)
    return ,$bytes
}

function Get-AdmissionSelfCheckSha256([byte[]] $Bytes) {
    $sha = [Security.Cryptography.SHA256]::Create()
    try { return ConvertTo-AdmissionEvidenceHex ($sha.ComputeHash($Bytes)) }
    finally { $sha.Dispose() }
}

function Get-AdmissionSelfCheckSha256Bytes([byte[]] $Bytes) {
    $sha = [Security.Cryptography.SHA256]::Create()
    try { return ,([byte[]]$sha.ComputeHash($Bytes)) }
    finally { $sha.Dispose() }
}

function New-AdmissionSelfCheckRawCallBody($Expected, [byte] $Kind, [byte] $Hook,
    [uint32] $Command, [uint32] $Attempt, [uint32] $StartIndex,
    [int] $HResult = 0, [int] $ReplyLength = 0, [bool] $WireValid = $true,
    [byte[]] $ValidationError = [byte[]]@()) {
    $input = New-AdmissionSelfCheckControlInput $Command $StartIndex
    $reply = New-Object byte[] $ReplyLength
    if ($reply.Length -ge 4) {
        [Array]::Copy([BitConverter]::GetBytes([uint32]$ReplyLength), 0, $reply, 0, 4)
    }
    $body = New-Object byte[] (292 + $ValidationError.Length + $input.Length + $reply.Length)
    Set-AdmissionSelfCheckBytes $body 0 ([Text.Encoding]::ASCII.GetBytes('SAEF'))
    [Array]::Copy([BitConverter]::GetBytes([uint16]1), 0, $body, 4, 2)
    $body[6] = $Kind
    $body[7] = $Hook
    $flags = 0
    if ($reply.Length -gt 0) { $flags = $flags -bor 1 }
    if ($HResult -eq 0) { $flags = $flags -bor 2 }
    $body[8] = [byte]$flags
    $body[9] = if ($WireValid) { 1 } else { 0 }
    [Array]::Copy([BitConverter]::GetBytes([uint16]$ValidationError.Length), 0, $body, 10, 2)
    if ($Kind -eq 2) {
        Set-AdmissionSelfCheckBytes $body 12 $Expected.RunGuid.ToByteArray()
        Set-AdmissionSelfCheckBytes $body 28 $Expected.RequestGuid.ToByteArray()
    }
    [Array]::Copy([BitConverter]::GetBytes($Command), 0, $body, 44, 4)
    [Array]::Copy([BitConverter]::GetBytes($Attempt), 0, $body, 48, 4)
    [Array]::Copy([BitConverter]::GetBytes($StartIndex), 0, $body, 52, 4)
    [Array]::Copy([BitConverter]::GetBytes([int32]$HResult), 0, $body, 56, 4)
    $returned = if ($HResult -eq 0) { [uint32]$ReplyLength } else { [uint32]305419896 }
    [Array]::Copy([BitConverter]::GetBytes($returned), 0, $body, 60, 4)
    [Array]::Copy([BitConverter]::GetBytes([uint32]$input.Length), 0, $body, 64, 4)
    [Array]::Copy([BitConverter]::GetBytes([uint32]$reply.Length), 0, $body, 68, 4)
    $utc = [DateTime]::UtcNow.Ticks
    [Array]::Copy([BitConverter]::GetBytes([int64]$utc), 0, $body, 72, 8)
    [Array]::Copy([BitConverter]::GetBytes([int64]($utc + 1)), 0, $body, 80, 8)
    [Array]::Copy([BitConverter]::GetBytes([int64]100), 0, $body, 88, 8)
    [Array]::Copy([BitConverter]::GetBytes([int64]101), 0, $body, 96, 8)
    [Array]::Copy([BitConverter]::GetBytes([int64]10000000), 0, $body, 104, 8)
    [Array]::Copy([BitConverter]::GetBytes([int64]$Expected.FrameBinding.BindingGeneration), 0, $body, 112, 8)
    [Array]::Copy([BitConverter]::GetBytes([int32]$Expected.FrameBinding.AcceptedPolicyVersion), 0, $body, 120, 4)
    $fingerprint = [byte[]]$Expected.FrameFingerprintBytes
    Set-AdmissionSelfCheckBytes $body 124 $fingerprint
    Set-AdmissionSelfCheckBytes $body 156 (Get-AdmissionSelfCheckSha256Bytes $input)
    Set-AdmissionSelfCheckBytes $body 188 (Get-AdmissionSelfCheckSha256Bytes $reply)
    if ($Kind -eq 2) {
        [Array]::Copy([BitConverter]::GetBytes([uint64]$Expected.Identity.VolumeSerial), 0, $body, 220, 8)
        Set-AdmissionSelfCheckBytes $body 228 ([byte[]]$Expected.Identity.FileId)
        Set-AdmissionSelfCheckBytes $body 244 ([Text.Encoding]::ASCII.GetBytes([string]$Expected.Identity.NativeVolumeGuid))
    }
    Set-AdmissionSelfCheckBytes $body (292 + $ValidationError.Length) $input
    Set-AdmissionSelfCheckBytes $body (292 + $ValidationError.Length + $input.Length) $reply
    if ($ValidationError.Length -gt 0) { Set-AdmissionSelfCheckBytes $body 292 $ValidationError }
    return ,$body
}

function New-AdmissionSelfCheckSummary([hashtable] $Changes) {
    $summary = [ordered]@{
        RunId = $script:AdmissionSelfCheckExpected.RunGuid.ToString('D')
        RequestId = $script:AdmissionSelfCheckExpected.RequestGuid.ToString('D')
        HookOrdinal = [byte]$script:AdmissionSelfCheckExpected.HookOrdinal
        VolumeGuid = [string]$script:AdmissionSelfCheckExpected.Identity.NativeVolumeGuid
        VolumeSerial = [uint64]$script:AdmissionSelfCheckExpected.Identity.VolumeSerial
        FileIdHex = [string]$script:AdmissionSelfCheckExpected.Identity.FileIdHex
        Outcome = 'EvidenceCaptured'
        Reason = 'EvidenceCaptured'
        StableActivatingSnapshot = $true
        RawActivatingBytes = [long]36136
        TargetEntryMatches = [uint32]1
        TargetAssessment = 'Unique'
        TargetState = [uint32]1
        TargetGeneration = [uint32]8
        TargetH = [uint32]1
        TargetS = [uint32]2
        TargetC = [uint32]3
        TargetT = [uint32]4
        TargetW = [uint32]5
        TargetUnknownReasons = [uint32]0
        VolumeGuidMatchesBefore = [uint32]2
        VolumeGuidMatchesAfter = [uint32]2
        VolumeGuidAssessmentBefore = 'Ambiguous'
        VolumeGuidAssessmentAfter = 'Ambiguous'
        VolumeSnapshotsByteIdentical = $true
        PolicyGenerationBefore = [uint32]8
        EpochGenerationBefore = [uint32]9
        PolicyGenerationAfter = [uint32]8
        EpochGenerationAfter = [uint32]9
        ActivatingPolicyGeneration = [uint32]8
        ActivatingChangeSequence = [uint64]10
        BindingGenerationStable = $true
        BindingGeneration = [long]$script:AdmissionSelfCheckExpected.FrameBinding.BindingGeneration
        AcceptedPolicyVersion = [int]$script:AdmissionSelfCheckExpected.FrameBinding.AcceptedPolicyVersion
        CanonicalCandidatePolicyFingerprint = [string]$script:AdmissionSelfCheckExpected.FrameBinding.CanonicalCandidatePolicyFingerprint
        BindingPolicyGeneration = [uint32]8
        BindingEpochGeneration = [uint32]9
        BindingEpochFlags = [uint32]0
        BindingChangeSequence = [uint64]10
        ServiceProcessId = [int]$script:AdmissionSelfCheckExpected.ServiceIdentity.ProcessId
        ServiceSid = 'S-1-5-18'
        CallerProcessId = [uint32]9999
        CallerSid = 'S-1-5-21-100-200-300-1001'
        BindingReceiptIncluded = $true
        ReadyClaim = $false
    }
    foreach ($key in $Changes.Keys) { $summary[$key] = $Changes[$key] }
    return $summary
}

function New-AdmissionSelfCheckSummaryBody([hashtable] $Changes) {
    $payload = [Text.Encoding]::UTF8.GetBytes((ConvertTo-Json -InputObject (New-AdmissionSelfCheckSummary $Changes) -Depth 4 -Compress))
    $body = New-Object byte[] (8 + $payload.Length)
    Set-AdmissionSelfCheckBytes $body 0 ([Text.Encoding]::ASCII.GetBytes('SAEF'))
    [Array]::Copy([BitConverter]::GetBytes([uint16]1), 0, $body, 4, 2)
    $body[6] = 3
    $body[7] = 0
    Set-AdmissionSelfCheckBytes $body 8 $payload
    return ,$body
}

function Add-AdmissionSelfCheckProducerSequence($State, $Expected) {
    $epoch = New-AdmissionSelfCheckRawCallBody $Expected 1 0 20 0 0 0 32 $true
    Add-AdmissionEvidenceFrameToState $State $epoch $Expected
    $beforeEpoch = New-AdmissionSelfCheckRawCallBody $Expected 2 2 20 0 0 0 32 $true
    Add-AdmissionEvidenceFrameToState $State $beforeEpoch $Expected
    $beforeVolume = New-AdmissionSelfCheckRawCallBody $Expected 2 2 23 0 0 0 6672 $true
    Add-AdmissionEvidenceFrameToState $State $beforeVolume $Expected
    $page = New-AdmissionSelfCheckRawCallBody $Expected 2 2 19 1 0 0 36136 $true
    Add-AdmissionEvidenceFrameToState $State $page $Expected
    $afterVolume = New-AdmissionSelfCheckRawCallBody $Expected 2 2 23 0 0 0 6672 $true
    Add-AdmissionEvidenceFrameToState $State $afterVolume $Expected
    $afterEpoch = New-AdmissionSelfCheckRawCallBody $Expected 2 2 20 0 0 0 32 $true
    Add-AdmissionEvidenceFrameToState $State $afterEpoch $Expected
}

function New-AdmissionSelfCheckPreSampleState($Expected) {
    $state = New-AdmissionEvidenceFrameState
    $epochReceipt = New-AdmissionSelfCheckRawCallBody $Expected 1 0 20 0 0 0 32 $true
    Add-AdmissionEvidenceFrameToState $state $epochReceipt $Expected
    $beforeEpoch = New-AdmissionSelfCheckRawCallBody $Expected 2 2 20 0 0 0 32 $true
    Add-AdmissionEvidenceFrameToState $state $beforeEpoch $Expected
    $beforeVolume = New-AdmissionSelfCheckRawCallBody $Expected 2 2 23 0 0 0 6672 $true
    Add-AdmissionEvidenceFrameToState $state $beforeVolume $Expected
    return $state
}

$volumeGuid = '\??\Volume{11111111-2222-3333-4444-555555555555}'
$fileId = New-Object byte[] 16
for ($index = 0; $index -lt $fileId.Length; $index++) { $fileId[$index] = [byte]($index + 1) }
$imageIdentity = New-AdmissionSelfCheckTargetIdentity $volumeGuid ([uint64]1234) $fileId
$targetIdentity = New-AdmissionSelfCheckTargetIdentity $volumeGuid ([uint64]::MaxValue) $fileId
$otherIdentity = New-AdmissionSelfCheckTargetIdentity $volumeGuid ([uint64]::MaxValue) $fileId
$changedFileId = [byte[]]$fileId.Clone(); $changedFileId[15] = 0
$changedIdentity = New-AdmissionSelfCheckTargetIdentity $volumeGuid ([uint64]::MaxValue) $changedFileId
$serviceIdentity = New-AdmissionSelfCheckProcessIdentity 4321 638952192000000000 `
    'C:\Program Files\SafeUpload\SafeUpload.Agent.Service.exe' ('A' * 64) $imageIdentity
$sameServiceIdentity = New-AdmissionSelfCheckProcessIdentity 4321 638952192000000000 `
    'C:\Program Files\SafeUpload\SafeUpload.Agent.Service.exe' ('A' * 64) $imageIdentity
$changedServiceIdentity = New-AdmissionSelfCheckProcessIdentity 4321 638952192000000001 `
    'C:\Program Files\SafeUpload\SafeUpload.Agent.Service.exe' ('A' * 64) $imageIdentity
$runGuid = [Guid]::Parse('aaaaaaaa-1111-2222-3333-444444444444')
$requestGuid = [Guid]::Parse('bbbbbbbb-1111-2222-3333-444444444444')
$fingerprintBytes = New-Object byte[] 32
for ($index = 0; $index -lt $fingerprintBytes.Length; $index++) { $fingerprintBytes[$index] = 0xAB }
$fingerprintHex = ConvertTo-AdmissionEvidenceHex $fingerprintBytes
$continuity = New-AdmissionEvidenceBindingContinuity
$script:AdmissionSelfCheckExpected = [pscustomobject]@{
    Identity = $targetIdentity
    ServiceIdentity = $serviceIdentity
    BindingContinuity = $continuity
    RunGuid = $runGuid
    RequestGuid = $requestGuid
    HookOrdinal = [byte]2
    FrameFingerprintBytes = $fingerprintBytes
    FrameBinding = [pscustomobject]@{
        BindingGeneration = [long]7
        AcceptedPolicyVersion = [int]3
        CanonicalCandidatePolicyFingerprint = $fingerprintHex
    }
}

Assert-AdmissionSelfCheck ($targetIdentity.HasSameTuple($otherIdentity)) 'same immutable target tuple'
Assert-AdmissionSelfCheck (-not $targetIdentity.HasSameTuple($changedIdentity)) 'changed FileID rejection'
$copy = $targetIdentity.FileId; $copy[0] = 0
Assert-AdmissionSelfCheck ((ConvertTo-AdmissionEvidenceHex ([byte[]]$targetIdentity.FileId)) -eq (ConvertTo-AdmissionEvidenceHex $fileId)) 'defensive FILE_ID_INFO copy'
Assert-AdmissionSelfCheck ($serviceIdentity.HasSameIdentity($sameServiceIdentity)) 'same service PID/birth/path/hash/file tuple'
Assert-AdmissionSelfCheck (-not $serviceIdentity.HasSameIdentity($changedServiceIdentity)) 'changed service birth time rejection'

$request = New-AdmissionEvidenceRequestBytes $targetIdentity $runGuid $requestGuid ([byte]2)
Assert-AdmissionSelfCheck ($request.Length -eq 117) 'exact 65-byte fixed request plus 48-byte native volume GUID and prefix'
Assert-AdmissionSelfCheck (([Text.Encoding]::ASCII.GetString($request, 4, 4)) -ceq 'SAER') 'SAER magic'
Assert-AdmissionSelfCheck ([BitConverter]::ToUInt16($request, 8) -eq 1) 'SAER version'
Assert-AdmissionSelfCheck ($request[10] -eq 2 -and $request[11] -eq 0) 'SAER hook and reserved flag'
Assert-AdmissionSelfCheck ([BitConverter]::ToUInt64($request, 44) -eq [uint64]::MaxValue) 'unsigned 64-bit target volume serial preservation'
Assert-AdmissionSelfCheckThrows { New-AdmissionEvidenceRequestBytes $targetIdentity $runGuid $requestGuid ([byte]1) } 'prelaunch hook rejection'
Assert-AdmissionSelfCheckThrows { New-AdmissionEvidenceRequestBytes $targetIdentity ([Guid]::Empty) $requestGuid ([byte]2) } 'empty Run GUID rejection'

$fileRights = [int][System.Security.AccessControl.FileSystemRights]::FullControl
$directoryInheritance = [int]([Security.AccessControl.InheritanceFlags]::ContainerInherit -bor [Security.AccessControl.InheritanceFlags]::ObjectInherit)
$goodFileRules = @(
    [pscustomobject]@{ Sid = 'S-1-5-18'; Type = 'Allow'; Rights = $fileRights; Inheritance = 0; Propagation = 0; IsInherited = $false },
    [pscustomobject]@{ Sid = 'S-1-5-32-544'; Type = 'Allow'; Rights = $fileRights; Inheritance = 0; Propagation = 0; IsInherited = $false })
$goodDirectoryRules = @(
    [pscustomobject]@{ Sid = 'S-1-5-18'; Type = 'Allow'; Rights = $fileRights; Inheritance = $directoryInheritance; Propagation = 0; IsInherited = $false },
    [pscustomobject]@{ Sid = 'S-1-5-32-544'; Type = 'Allow'; Rights = $fileRights; Inheritance = $directoryInheritance; Propagation = 0; IsInherited = $false })
Assert-AdmissionSelfCheck (Test-AdmissionEvidenceAclModel 'S-1-5-32-544' 'S-1-5-32-544' $true $goodFileRules) 'SYSTEM/BA file ACL model'
Assert-AdmissionSelfCheck (Test-AdmissionEvidenceAclModel 'S-1-5-32-544' 'S-1-5-32-544' $true $goodDirectoryRules -Directory) 'SYSTEM/BA inheritable directory ACL model'
Assert-AdmissionSelfCheck (-not (Test-AdmissionEvidenceAclModel 'S-1-5-32-544' 'S-1-5-32-544' $false $goodFileRules)) 'unprotected ACL rejection'
$untrustedFileRules = $goodFileRules + @([pscustomobject]@{ Sid = 'S-1-5-21-1'; Type = 'Allow'; Rights = [int][System.Security.AccessControl.FileSystemRights]::Write; Inheritance = 0; Propagation = 0; IsInherited = $false })
Assert-AdmissionSelfCheck (-not (Test-AdmissionEvidenceAclModel 'S-1-5-32-544' 'S-1-5-32-544' $true $untrustedFileRules)) 'untrusted file ACE rejection'
$goodAncestorRules = @([pscustomobject]@{ Sid = 'S-1-5-18'; Type = 'Allow'; Rights = [long][System.Security.AccessControl.FileSystemRights]::FullControl; InheritOnly = $false })
$benignDirectParentRules = $goodAncestorRules + @([pscustomobject]@{ Sid = 'S-1-5-21-1'; Type = 'Allow'; Rights = [long][System.Security.AccessControl.FileSystemRights]::ReadAndExecute; InheritOnly = $false })
$benignAncestorRules = $goodAncestorRules + @([pscustomobject]@{ Sid = 'S-1-5-11'; Type = 'Allow'; Rights = [long][System.Security.AccessControl.FileSystemRights]::AppendData; InheritOnly = $false })
$badAncestorRules = $goodAncestorRules + @([pscustomobject]@{ Sid = 'S-1-5-21-1'; Type = 'Allow'; Rights = [long][System.Security.AccessControl.FileSystemRights]::Delete; InheritOnly = $false })
$trustedInstallerSid = 'S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464'
Assert-AdmissionSelfCheck (Test-AdmissionEvidenceAncestorAclModel $trustedInstallerSid $goodAncestorRules -DirectParent) 'trusted Program Files ACL model'
Assert-AdmissionSelfCheck (Test-AdmissionEvidenceAncestorAclModel $trustedInstallerSid $benignDirectParentRules -DirectParent) 'benign untrusted read/execute parent ACE acceptance'
Assert-AdmissionSelfCheck (Test-AdmissionEvidenceAncestorAclModel $trustedInstallerSid $benignAncestorRules) 'benign non-direct ancestor create-directory ACE acceptance'
foreach ($blockedRight in @(
    [long][System.Security.AccessControl.FileSystemRights]::Write,
    [long][System.Security.AccessControl.FileSystemRights]::WriteData,
    [long][System.Security.AccessControl.FileSystemRights]::AppendData,
    [long][System.Security.AccessControl.FileSystemRights]::CreateFiles,
    [long][System.Security.AccessControl.FileSystemRights]::CreateDirectories,
    [long][System.Security.AccessControl.FileSystemRights]::DeleteSubdirectoriesAndFiles,
    [long][System.Security.AccessControl.FileSystemRights]::Delete,
    [long][System.Security.AccessControl.FileSystemRights]::ChangePermissions,
    [long][System.Security.AccessControl.FileSystemRights]::TakeOwnership
)) {
    $blockedParentRules = $goodAncestorRules + @([pscustomobject]@{
        Sid = 'S-1-5-21-1'; Type = 'Allow'; Rights = $blockedRight; InheritOnly = $false
    })
    Assert-AdmissionSelfCheck (-not (Test-AdmissionEvidenceAncestorAclModel $trustedInstallerSid $blockedParentRules -DirectParent)) "untrusted direct-parent mutation rights $blockedRight rejection"
}
Assert-AdmissionSelfCheck (-not (Test-AdmissionEvidenceAncestorAclModel $trustedInstallerSid $badAncestorRules)) 'untrusted ancestor delete/rename ACE rejection'

$frameState = New-AdmissionEvidenceFrameState
Add-AdmissionSelfCheckProducerSequence $frameState $script:AdmissionSelfCheckExpected
$summaryBody = New-AdmissionSelfCheckSummaryBody @{}
Add-AdmissionEvidenceFrameToState $frameState $summaryBody $script:AdmissionSelfCheckExpected
Assert-AdmissionSelfCheck ($frameState.TerminalKind -ceq 'Summary' -and $frameState.RawCallCount -eq 5) 'producer-shaped complete frame sequence'
Assert-AdmissionSelfCheck ($frameState.Summary.TargetAssessment -ceq 'Unique') 'Control 19 target assessment remains independent'
Assert-AdmissionSelfCheck ($frameState.Summary.VolumeGuidAssessmentBefore -ceq 'Ambiguous' -and $frameState.Summary.VolumeGuidAssessmentAfter -ceq 'Ambiguous') 'Control 23 ambiguous assessments remain independent'
Assert-AdmissionSelfCheck (-not $frameState.Summary.ReadyClaim) 'summary cannot claim Ready'
Assert-AdmissionSelfCheck ($frameState.BindingGeneration -eq 7 -and
    $frameState.AcceptedPolicyVersion -eq 3 -and
    $frameState.CanonicalCandidatePolicyFingerprint -ceq $fingerprintHex -and
    $frameState.ServiceProcessId -eq $serviceIdentity.ProcessId) 'frame state retains summary binding and service identity'
Assert-AdmissionSelfCheck ($continuity.Bound -and $continuity.BindingGeneration -eq 7 -and
    $continuity.AcceptedPolicyVersion -eq 3 -and $continuity.CanonicalCandidatePolicyFingerprint -ceq $fingerprintHex) 'binding continuity pinned from first receipt'

$incompleteExpected = [pscustomobject]@{
    Identity = $targetIdentity; ServiceIdentity = $serviceIdentity; RunGuid = $runGuid; RequestGuid = $requestGuid
    HookOrdinal = [byte]2; FrameBinding = $script:AdmissionSelfCheckExpected.FrameBinding; RawActivatingBytes = [long]36136
}
$incompleteChanges = @{
    Outcome = 'EvidenceIncomplete'; Reason = 'ActivatingStatusUnstableAfterFiveAttempts'
    StableActivatingSnapshot = $false; TargetEntryMatches = [uint32]1; TargetAssessment = 'Unavailable'
    TargetState = $null; TargetGeneration = $null; TargetH = $null; TargetS = $null; TargetC = $null
    TargetT = $null; TargetW = $null; TargetUnknownReasons = $null
    VolumeGuidMatchesBefore = [uint32]0; VolumeGuidMatchesAfter = [uint32]1
    VolumeGuidAssessmentBefore = 'Absent'; VolumeGuidAssessmentAfter = 'Unique'
    VolumeSnapshotsByteIdentical = $false; BindingGenerationStable = $false
}
$incompleteJson = ConvertTo-Json -InputObject (New-AdmissionSelfCheckSummary $incompleteChanges) -Depth 4 -Compress
$incompleteSummary = ConvertFrom-AdmissionEvidenceSummary ([Text.Encoding]::UTF8.GetBytes($incompleteJson)) $incompleteExpected
Assert-AdmissionSelfCheck ($incompleteSummary.TargetAssessment -ceq 'Unavailable' -and
    $incompleteSummary.TargetEntryMatches -eq 1) 'partial Control 19 count remains distinct from unavailable assessment'
Assert-AdmissionSelfCheck ($incompleteSummary.VolumeGuidAssessmentBefore -ceq 'Absent' -and
    $incompleteSummary.VolumeGuidAssessmentAfter -ceq 'Unique') 'Control 23 absent and unique assessments stay separate'
Assert-AdmissionSelfCheck (-not $incompleteSummary.ReadyClaim) 'incomplete attribution cannot imply Ready'

$noSummaryState = New-AdmissionEvidenceFrameState
Add-AdmissionSelfCheckProducerSequence $noSummaryState $script:AdmissionSelfCheckExpected
Assert-AdmissionSelfCheck ((Complete-AdmissionEvidenceFrameState $noSummaryState) -ceq 'INCOMPLETE_NO_TERMINAL_FRAME') 'missing summary is incomplete'
$noCallExpected = [pscustomobject]@{
    Identity = $targetIdentity; ServiceIdentity = $serviceIdentity; RunGuid = $runGuid; RequestGuid = $requestGuid
    HookOrdinal = [byte]2; FrameBinding = $script:AdmissionSelfCheckExpected.FrameBinding; RawActivatingBytes = [long]0
}
$noCallChanges = @{
    Outcome = 'EvidenceIncomplete'; Reason = 'PortUnbound'; StableActivatingSnapshot = $false
    RawActivatingBytes = [long]0; TargetEntryMatches = [uint32]0; TargetAssessment = 'Unavailable'
    TargetState = $null; TargetGeneration = $null; TargetH = $null; TargetS = $null; TargetC = $null
    TargetT = $null; TargetW = $null; TargetUnknownReasons = $null
    VolumeGuidMatchesBefore = [uint32]0; VolumeGuidMatchesAfter = [uint32]0
    VolumeGuidAssessmentBefore = 'Unavailable'; VolumeGuidAssessmentAfter = 'Unavailable'
    VolumeSnapshotsByteIdentical = $false; PolicyGenerationBefore = $null; EpochGenerationBefore = $null
    PolicyGenerationAfter = $null; EpochGenerationAfter = $null; ActivatingPolicyGeneration = $null
    ActivatingChangeSequence = $null; BindingGenerationStable = $false; BindingPolicyGeneration = $null
    BindingEpochGeneration = $null; BindingEpochFlags = $null; BindingChangeSequence = $null
}
$noCallState = New-AdmissionEvidenceFrameState
$noCallReceipt = New-AdmissionSelfCheckRawCallBody $script:AdmissionSelfCheckExpected 1 0 20 0 0 0 32 $true
Add-AdmissionEvidenceFrameToState $noCallState $noCallReceipt $script:AdmissionSelfCheckExpected
$noCallSummary = New-AdmissionSelfCheckSummaryBody $noCallChanges
Add-AdmissionEvidenceFrameToState $noCallState $noCallSummary $noCallExpected
Assert-AdmissionSelfCheck ($noCallState.Summary.Outcome -ceq 'EvidenceIncomplete' -and
    $noCallState.RawCallCount -eq 0 -and $noCallState.Summary.RawActivatingBytes -eq 0) 'incomplete summary can preserve an unavailable-send prefix'

$badHashBody = New-AdmissionSelfCheckRawCallBody $script:AdmissionSelfCheckExpected 1 0 20 0 0 0 32 $true
$badHashBody[188] = [byte]($badHashBody[188] -bxor 1)
Assert-AdmissionSelfCheckThrows { Add-AdmissionEvidenceFrameToState (New-AdmissionEvidenceFrameState) $badHashBody $script:AdmissionSelfCheckExpected } 'raw response hash mismatch rejection'

$badOrderState = New-AdmissionEvidenceFrameState
$bindingBody = New-AdmissionSelfCheckRawCallBody $script:AdmissionSelfCheckExpected 1 0 20 0 0 0 32 $true
Add-AdmissionEvidenceFrameToState $badOrderState $bindingBody $script:AdmissionSelfCheckExpected
$wrongFirstCall = New-AdmissionSelfCheckRawCallBody $script:AdmissionSelfCheckExpected 2 2 23 0 0 0 6672 $true
Assert-AdmissionSelfCheckThrows { Add-AdmissionEvidenceFrameToState $badOrderState $wrongFirstCall $script:AdmissionSelfCheckExpected } 'raw status call order enforcement'

$badFlag = New-AdmissionSelfCheckRawCallBody $script:AdmissionSelfCheckExpected 1 0 20 0 0 0 32 $true
$badFlag[8] = 4
Assert-AdmissionSelfCheckThrows { Add-AdmissionEvidenceFrameToState (New-AdmissionEvidenceFrameState) $badFlag $script:AdmissionSelfCheckExpected } 'reserved SAEF call flag rejection'
$oversized = New-Object byte[] ($script:AdmissionEvidenceMaxFrameBytes + 1)
Assert-AdmissionSelfCheckThrows { Add-AdmissionEvidenceFrameToState (New-AdmissionEvidenceFrameState) $oversized $script:AdmissionSelfCheckExpected } 'SAEF body-size bound enforcement'
$badMagic = New-AdmissionSelfCheckRawCallBody $script:AdmissionSelfCheckExpected 1 0 20 0 0 0 32 $true
$badMagic[0] = 0
Assert-AdmissionSelfCheckThrows { Add-AdmissionEvidenceFrameToState (New-AdmissionEvidenceFrameState) $badMagic $script:AdmissionSelfCheckExpected } 'malformed SAEF magic rejection'
$mismatchedTargetState = New-AdmissionEvidenceFrameState
Add-AdmissionEvidenceFrameToState $mismatchedTargetState $bindingBody $script:AdmissionSelfCheckExpected
$mismatchedTarget = New-AdmissionSelfCheckRawCallBody $script:AdmissionSelfCheckExpected 2 2 20 0 0 0 32 $true
$mismatchedTarget[228] = [byte]($mismatchedTarget[228] -bxor 0x80)
Assert-AdmissionSelfCheckThrows { Add-AdmissionEvidenceFrameToState $mismatchedTargetState $mismatchedTarget $script:AdmissionSelfCheckExpected } 'SAEF target FileID tuple mismatch rejection'
$badPageStart = New-AdmissionSelfCheckRawCallBody $script:AdmissionSelfCheckExpected 2 2 19 1 1 0 36136 $true
$badPageStartState = New-AdmissionSelfCheckPreSampleState $script:AdmissionSelfCheckExpected
Assert-AdmissionSelfCheckThrows { Add-AdmissionEvidenceFrameToState $badPageStartState $badPageStart $script:AdmissionSelfCheckExpected } 'unaligned Control 19 start index rejection'
$badPageAttempt = New-AdmissionSelfCheckRawCallBody $script:AdmissionSelfCheckExpected 2 2 19 6 0 0 36136 $true
$badPageAttemptState = New-AdmissionSelfCheckPreSampleState $script:AdmissionSelfCheckExpected
Assert-AdmissionSelfCheckThrows { Add-AdmissionEvidenceFrameToState $badPageAttemptState $badPageAttempt $script:AdmissionSelfCheckExpected } 'sixth Control 19 attempt rejection'
$tooManyPagesState = New-AdmissionSelfCheckPreSampleState $script:AdmissionSelfCheckExpected
$tooManyPagesState.ActivatingAttempt = 1
$tooManyPagesState.ActivatingAttemptCount = 1
$tooManyPagesState.ActivatingPagesInAttempt = $script:AdmissionEvidenceMaxActivatingPagesPerAttempt
$tooManyPagesState.ActivatingLastStart = [uint32]20448
$tooManyPages = New-AdmissionSelfCheckRawCallBody $script:AdmissionSelfCheckExpected 2 2 19 1 20480 0 36136 $true
Assert-AdmissionSelfCheckThrows { Add-AdmissionEvidenceFrameToState $tooManyPagesState $tooManyPages $script:AdmissionSelfCheckExpected } '641st Control 19 page rejection'
$tooManyBytesState = New-AdmissionSelfCheckPreSampleState $script:AdmissionSelfCheckExpected
$tooManyBytesState.ActivatingAttempt = 1
$tooManyBytesState.ActivatingAttemptCount = 1
$tooManyBytesState.ActivatingPagesInAttempt = 1
$tooManyBytesState.ActivatingLastStart = [uint32]0
$tooManyBytesState.RawActivatingBytes = [long]$script:AdmissionEvidenceMaxActivatingBytes
$tooManyBytes = New-AdmissionSelfCheckRawCallBody $script:AdmissionSelfCheckExpected 2 2 19 1 32 0 36136 $true
Assert-AdmissionSelfCheckThrows { Add-AdmissionEvidenceFrameToState $tooManyBytesState $tooManyBytes $script:AdmissionSelfCheckExpected } 'Control 19 raw byte budget rejection'
$duplicateSummary = $summaryBody.Clone()
$summaryText = [Text.Encoding]::UTF8.GetString($summaryBody, 8, $summaryBody.Length - 8)
$duplicateText = $summaryText.Substring(0, $summaryText.Length - 1) + ',"ReadyClaim":false}'
Assert-AdmissionSelfCheckThrows { ConvertFrom-AdmissionEvidenceSummary ([Text.Encoding]::UTF8.GetBytes($duplicateText)) $incompleteExpected } 'duplicate summary key rejection'
$unknownSummary = $summaryText.Substring(0, $summaryText.Length - 1) + ',"Unexpected":0}'
Assert-AdmissionSelfCheckThrows { ConvertFrom-AdmissionEvidenceSummary ([Text.Encoding]::UTF8.GetBytes($unknownSummary)) $incompleteExpected } 'unknown summary field rejection'

$partialPipe = New-Object IO.MemoryStream
$partialResponse = New-Object IO.MemoryStream
$partialSha = [Security.Cryptography.SHA256]::Create()
$partialCounter = [pscustomobject]@{ Value = [long]0 }
$partialClock = [Diagnostics.Stopwatch]::StartNew()
$partialPipe.Write((New-Object byte[] 3), 0, 3)
$partialPipe.Position = 0
try {
    [void](Read-AdmissionEvidenceExact $partialPipe $partialResponse $partialSha $partialCounter 8 $partialClock 10000)
    throw 'Partial frame read unexpectedly completed.'
} catch [IO.EndOfStreamException] { }
Assert-AdmissionSelfCheck ($partialResponse.Length -eq 3 -and $partialCounter.Value -eq 3) 'partial bytes are flushed into the raw response stream before EOF'
$partialSha.Dispose(); $partialResponse.Dispose(); $partialPipe.Dispose()

$lengthPipe = New-Object IO.MemoryStream
$lengthResponse = New-Object IO.MemoryStream
$lengthSha = [Security.Cryptography.SHA256]::Create()
$lengthCounter = [pscustomobject]@{ Value = [long]0 }
$oversizePrefix = [BitConverter]::GetBytes([uint32]($script:AdmissionEvidenceMaxFrameBytes + 1))
$lengthPipe.Write($oversizePrefix, 0, $oversizePrefix.Length); $lengthPipe.Position = 0
Assert-AdmissionSelfCheckThrows {
    [void](Receive-AdmissionEvidenceFrames $lengthPipe $lengthResponse $lengthSha $lengthCounter `
        ([Diagnostics.Stopwatch]::StartNew()) 10000 $script:AdmissionSelfCheckExpected (New-AdmissionEvidenceFrameState))
} 'oversized framed response rejected before allocation'
Assert-AdmissionSelfCheck ($lengthResponse.Length -eq 4) 'framing prefix retained before rejecting oversized body length'
$lengthSha.Dispose(); $lengthResponse.Dispose(); $lengthPipe.Dispose()

$continuityMismatch = New-AdmissionEvidenceBindingContinuity
$continuityMismatch.Bound = $true
$continuityMismatch.BindingGeneration = 99
$continuityMismatch.AcceptedPolicyVersion = 3
$continuityMismatch.CanonicalCandidatePolicyFingerprint = $fingerprintHex
$mismatchExpected = [pscustomobject]@{
    Identity = $targetIdentity; ServiceIdentity = $serviceIdentity; BindingContinuity = $continuityMismatch
    RunGuid = $runGuid; RequestGuid = $requestGuid; HookOrdinal = [byte]2
}
$mismatchState = New-AdmissionEvidenceFrameState
$mismatchReceipt = New-AdmissionSelfCheckRawCallBody $script:AdmissionSelfCheckExpected 1 0 20 0 0 0 32 $true
Assert-AdmissionSelfCheckThrows { Add-AdmissionEvidenceFrameToState $mismatchState $mismatchReceipt $mismatchExpected } 'different binding generation rejected across target streams'

$roundtripPair = New-AdmissionSelfCheckConnectedPipePair
$roundtripResponse = New-Object IO.MemoryStream
$roundtripSha = [Security.Cryptography.SHA256]::Create()
$roundtripCounter = [pscustomobject]@{ Value = [long]0 }
$serverTransactionTask = $null
try {
    Assert-AdmissionSelfCheck (-not $roundtripPair.Client.CanTimeout) 'fake pipe reports unsupported timeout setters'
    Assert-AdmissionSelfCheckThrows { $roundtripPair.Client.ReadTimeout = 100 } 'ReadTimeout setter remains unsupported and is not required'
    Assert-AdmissionSelfCheckThrows { $roundtripPair.Client.WriteTimeout = 100 } 'WriteTimeout setter remains unsupported and is not required'
    $roundtripClock = [Diagnostics.Stopwatch]::StartNew()
    $roundtripWriteState = [pscustomobject]@{ State = 'NOT_ATTEMPTED'; AbortedTask = $null }
    $serverRequest = New-Object byte[] $request.Length
    $roundtripReply = [byte[]](0x53, 0x41, 0x45, 0x46, 0x01, 0x02, 0x03)
    $serverTransactionTask = [SafeUploadAdmissionEvidence.Client.SelfCheckPipeFixture]::StartRoundtrip(
        $roundtripPair.Server, $serverRequest, $roundtripReply)
    Write-AdmissionEvidencePipeWithDeadline $roundtripPair.Client $request $roundtripClock 3000 $roundtripWriteState
    Assert-AdmissionSelfCheck ($roundtripWriteState.State -ceq 'REQUEST_DELIVERY_COMPLETE') 'successful fake pipe write marks exact request delivery complete'
    $roundtripReadClock = $roundtripClock
    $capturedReply = Read-AdmissionEvidenceExact $roundtripPair.Client $roundtripResponse $roundtripSha `
        $roundtripCounter $roundtripReply.Length $roundtripReadClock 3000
    if (-not $serverTransactionTask.Wait(3000)) { throw 'Fake pipe server transaction did not finish within the self-check bound.' }
    Assert-AdmissionSelfCheck ($serverTransactionTask.Result -eq $request.Length) 'fake pipe server consumes the complete request before replying'
    Assert-AdmissionSelfCheck (Test-AdmissionSelfCheckByteArrays $serverRequest $request) 'bounded asynchronous request write roundtrip preserves exact SAER bytes'
    Assert-AdmissionSelfCheck (Test-AdmissionSelfCheckByteArrays $capturedReply $roundtripReply) 'Peek-bounded fake pipe response roundtrip'
    Assert-AdmissionSelfCheck ($roundtripCounter.Value -eq $roundtripReply.Length -and
        (Test-AdmissionSelfCheckByteArrays $roundtripResponse.ToArray() $roundtripReply)) 'roundtrip raw response bytes retained exactly'
    $roundtripClosed = Confirm-AdmissionEvidenceTerminalPipeClose $roundtripPair.Client $roundtripResponse `
        $roundtripSha $roundtripCounter $roundtripReadClock 3000
    Assert-AdmissionSelfCheck ($roundtripClosed.Closed -and -not $roundtripClosed.TrailingBytes) 'fake pipe terminal close is observed without timeout setters'
} finally {
    $roundtripSha.Dispose(); $roundtripResponse.Dispose(); Close-AdmissionSelfCheckPipePair $roundtripPair
    if ($null -ne $serverTransactionTask) { try { [void]$serverTransactionTask.Wait(1000) } catch { } }
}

$fragmentPair = New-AdmissionSelfCheckConnectedPipePair
$fragmentResponse = New-Object IO.MemoryStream
$fragmentSha = [Security.Cryptography.SHA256]::Create()
$fragmentCounter = [pscustomobject]@{ Value = [long]0 }
$firstFragment = [byte[]](0x11, 0x22, 0x33)
$secondFragment = [byte[]](0x44, 0x55)
$fragmentWriter = $null
$fragmentClock = [Diagnostics.Stopwatch]::StartNew()
$sawPartialClose = $false
try {
    $fragmentWriter = [SafeUploadAdmissionEvidence.Client.SelfCheckPipeFixture]::WriteFragmentsAndClose(
        $fragmentPair.Server, $firstFragment, 75, $secondFragment)
    try {
        [void](Read-AdmissionEvidenceExact $fragmentPair.Client $fragmentResponse $fragmentSha `
            $fragmentCounter 9 $fragmentClock 3000)
    } catch [IO.EndOfStreamException] { $sawPartialClose = $true }
    if (-not $fragmentWriter.Wait(3000)) { throw 'Delayed fake pipe writer did not close within the self-check bound.' }
    Assert-AdmissionSelfCheck $sawPartialClose 'fragmented delayed fake pipe closes before completing the requested frame'
    $expectedFragments = [byte[]]($firstFragment + $secondFragment)
    Assert-AdmissionSelfCheck ($fragmentClock.ElapsedMilliseconds -ge 50) 'response reader waits for a delayed second fragment'
    Assert-AdmissionSelfCheck ($fragmentCounter.Value -eq $expectedFragments.Length -and
        (Test-AdmissionSelfCheckByteArrays $fragmentResponse.ToArray() $expectedFragments)) 'all partial response bytes survive delayed EOF'
} finally {
    if ($null -ne $fragmentWriter) { try { [void]$fragmentWriter.Wait(1000) } catch { } }
    $fragmentSha.Dispose(); $fragmentResponse.Dispose(); Close-AdmissionSelfCheckPipePair $fragmentPair
}

$silentPair = New-AdmissionSelfCheckConnectedPipePair
$silentResponse = New-Object IO.MemoryStream
$silentSha = [Security.Cryptography.SHA256]::Create()
$silentCounter = [pscustomobject]@{ Value = [long]0 }
$silentClock = [Diagnostics.Stopwatch]::StartNew()
$silentTimedOut = $false
try {
    try {
        [void](Read-AdmissionEvidenceExact $silentPair.Client $silentResponse $silentSha `
            $silentCounter 1 $silentClock 150)
    } catch [TimeoutException] { $silentTimedOut = $true }
    Assert-AdmissionSelfCheck ($silentTimedOut -and $silentClock.ElapsedMilliseconds -ge 100) 'silent fake pipe read expires at its whole-operation deadline'
    Assert-AdmissionSelfCheck ($silentResponse.Length -eq 0 -and $silentCounter.Value -eq 0) 'silent fake pipe deadline invents no response bytes'
} finally {
    $silentSha.Dispose(); $silentResponse.Dispose(); Close-AdmissionSelfCheckPipePair $silentPair
}

$blockedWritePair = New-AdmissionSelfCheckConnectedPipePair
$blockedWrite = New-Object byte[] 1048576
$blockedWriteClock = [Diagnostics.Stopwatch]::StartNew()
$blockedWriteTimedOut = $false
try {
    $blockedWriteState = [pscustomobject]@{ State = 'NOT_ATTEMPTED'; AbortedTask = $null }
    try { Write-AdmissionEvidencePipeWithDeadline $blockedWritePair.Client $blockedWrite $blockedWriteClock 150 $blockedWriteState }
    catch [TimeoutException] { $blockedWriteTimedOut = $true }
    Assert-AdmissionSelfCheck $blockedWriteTimedOut 'unread fake pipe cancels a backpressured asynchronous write at deadline'
    Assert-AdmissionSelfCheck ($blockedWriteState.State -ceq 'REQUEST_DELIVERY_INDETERMINATE') 'timed-out write preserves indeterminate request delivery state'
    Assert-AdmissionSelfCheck ($null -ne $blockedWriteState.AbortedTask) 'timed-out write retains its canceled task for cleanup verification'
    $abortedWriteFinished = $false
    try { $abortedWriteFinished = [bool]$blockedWriteState.AbortedTask.Wait(3000) }
    catch { $abortedWriteFinished = [bool]$blockedWriteState.AbortedTask.IsCompleted }
    Assert-AdmissionSelfCheck ($abortedWriteFinished -and $blockedWriteState.AbortedTask.IsCompleted) 'timed-out overlapped write reaches a terminal task state after pipe disposal'
    Assert-AdmissionSelfCheck (-not $blockedWritePair.Client.IsConnected) 'timed-out asynchronous write disposes the client pipe handle'
} finally {
    Close-AdmissionSelfCheckPipePair $blockedWritePair
}

'AdmissionEvidenceCaptureSelfCheck=PASS; ProtocolFrames=ProducerShaped; PartialRetention=Checked; PipeTransport=LocalFakePipe; Privacy=RawOnly'
