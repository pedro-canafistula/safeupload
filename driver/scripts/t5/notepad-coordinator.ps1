<#
T5 coordinator (SYSTEM). Drives the standard-user notepad-actor.ps1 through the common file-dialog probe sequence and real Notepad Save As.
The destination is observed both through an ordinary buffered path read and through StagedInvariantObserver's independent raw NTFS
volume capture. Raw samples, the complete parent-directory index, native probe codes, hand-back bytes and the publication journal are
retained under C:\T5. This row records observed evidence; without a driver lower-mutation ledger it does not claim an authoritative
"never public" proof.
Results: C:\T5\result.json.
#>
param([string]$ActorUser = 't5actor', [string]$ActorTask = 't5-actor',
    [string]$Diagnostics = 'C:\Users\vika\Documents\Get-SafeUploadDiagnostics.ps1',
    [string]$ObserverModule = 'C:\Users\vika\Documents\StagedInvariantObserver.psm1')
$ErrorActionPreference = 'Stop'
$out = 'C:\T5'; $control = Join-Path $out 'control'; $root = 'C:\Protected\t5'
$journalDir = 'C:\ProgramData\SafeUpload\staging-journal'
$leaves = @('probe-delete.txt', 'probe-after-publication.txt', 'probe-before-cpf.txt', 'probe-after-cpf.txt',
    'probe-doc.txt', 'probe-onclose.txt', 'ok.txt', 'cpf.txt')
$frequency = [Diagnostics.Stopwatch]::Frequency
$rawContext = $null; $rawBaseline = $null; $script:rawSequence = 0
$probeControlPhase = 'ControlProbeAfterTestCreateCloseBeforeDeleteOrSave'
$cpfText = 'T5 notepad CPF: 529.982.247-25'
$cpfBytes = [Text.Encoding]::ASCII.GetBytes($cpfText)
$cpfNumberBytes = [Text.Encoding]::ASCII.GetBytes('529.982.247-25')
$result = [ordered]@{ Started = [DateTime]::UtcNow.ToString('o'); Cases = @(); Error = $null; ActorTaskStartIssued = $false; RawObserver = [ordered]@{ Samples = @() } }

function Read-ControlText([string]$Path) {
    $deadline = [Diagnostics.Stopwatch]::GetTimestamp() + 5 * $frequency
    for (;;) {
        try {
            $stream = [IO.FileStream]::new($Path, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::ReadWrite, 4096, [IO.FileOptions]::None)
            try { $reader = [IO.StreamReader]::new($stream); try { return $reader.ReadToEnd() } finally { $reader.Dispose() } }
            finally { $stream.Dispose() }
        } catch [IO.IOException] {
            $ioFailure = $_.Exception
            while ($ioFailure.InnerException) { $ioFailure = $ioFailure.InnerException }
            if (($ioFailure.HResult -band 0xffff) -notin @(32,33) -or [Diagnostics.Stopwatch]::GetTimestamp() -ge $deadline) { throw }
            Start-Sleep -Milliseconds 2
        }
    }
}
function Read-Public([string]$Path) {
    try {
        $stream = [IO.FileStream]::new($Path, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::ReadWrite, 65536, [IO.FileOptions]::None)
        try {
            $buffer = New-Object byte[] $stream.Length; $read = 0
            while ($read -lt $buffer.Length) { $n = $stream.Read($buffer, $read, $buffer.Length - $read); if ($n -le 0) { throw 'Short buffered destination read.' }; $read += $n }
            return [pscustomobject]@{ Status = 'OK'; Bytes = $buffer; Length = [long]$buffer.Length; Sha256 = (Sha $buffer); Error = $null }
        } finally { $stream.Dispose() }
    } catch [IO.FileNotFoundException] { return [pscustomobject]@{ Status = 'ABSENT'; Bytes = $null; Length = $null; Sha256 = $null; Error = $null } }
      catch [IO.DirectoryNotFoundException] { return [pscustomobject]@{ Status = 'ABSENT'; Bytes = $null; Length = $null; Sha256 = $null; Error = $null } }
      catch { return [pscustomobject]@{ Status = 'ERROR'; Bytes = $null; Length = $null; Sha256 = $null; Error = $_.Exception.ToString() } }
}
function Same([byte[]]$A, [byte[]]$B) {
    if ($null -eq $A -or $null -eq $B -or $A.Length -ne $B.Length) { return $false }
    for ($i = 0; $i -lt $A.Length; ++$i) { if ($A[$i] -ne $B[$i]) { return $false } }
    return $true
}
function Sha([byte[]]$B) {
    if ($null -eq $B) { return $null }
    $h = [Security.Cryptography.SHA256]::Create()
    try { return [BitConverter]::ToString($h.ComputeHash($B)).Replace('-', '') } finally { $h.Dispose() }
}
function Contains-Bytes([byte[]]$Haystack, [byte[]]$Needle) {
    if ($null -eq $Haystack -or $null -eq $Needle -or $Needle.Length -eq 0 -or $Haystack.Length -lt $Needle.Length) { return $false }
    for ($i = 0; $i -le $Haystack.Length - $Needle.Length; ++$i) {
        $same = $true
        for ($j = 0; $j -lt $Needle.Length; ++$j) { if ($Haystack[$i + $j] -ne $Needle[$j]) { $same = $false; break } }
        if ($same) { return $true }
    }
    return $false
}
function Get-CurrentRawImage($Sample, [string]$Path) {
    $images = @($Sample.Images | Where-Object { $_.Role -ceq 'Current' -and $_.Path -ieq $Path })
    if ($images.Count -ne 1) { throw ('Expected one raw Current image for ' + $Path + '; found ' + $images.Count) }
    return $images[0]
}
function Get-RawImageBytes($Image) {
    if ($Image.Absent -eq $true) { return $null }
    if ($Image.Absent -ne $false -or $null -eq $Image.LogicalArtifact -or [string]::IsNullOrWhiteSpace($Image.LogicalArtifact.Path)) { throw 'Raw current image is missing its logical artifact.' }
    $bytes = [IO.File]::ReadAllBytes($Image.LogicalArtifact.Path)
    if ($bytes.Length -ne $Image.Length -or $bytes.Length -ne $Image.LogicalArtifact.Length -or
        [StagedInvariant.Native]::Hash($bytes) -cne $Image.Sha256 -or $Image.Sha256 -cne $Image.LogicalArtifact.Sha256) {
        throw 'Raw logical artifact length/digest does not match the observer record.'
    }
    return ,$bytes
}
function Get-DirectoryImage($Sample) {
    $parents = @($Sample.Images | Where-Object { $_.Role -ceq 'Parent' -and $_.Path -ieq $root })
    if ($parents.Count -ne 1) { throw ('Expected one raw parent-directory image; found ' + $parents.Count) }
    return $parents[0]
}
function Capture-T5Observation($Case, [string]$Phase) {
    $script:rawSequence++
    $entry = [ordered]@{ Phase = $Phase; Sequence = $script:rawSequence; Status = 'ERROR'; Start = $null; End = $null
        CurrentImages = @(); ParentFileId = $null; ParentReference = $null; DirectoryEntries = @(); PublicReaders = @(); RawComplete = $false; IndependentReadersAgree = $false
        DirectoryComplete = $false; ForbiddenBytesObserved = $false; TargetAbsent = $false; Error = $null }
    try {
        $sample = Capture-InvariantSample $rawContext $rawBaseline $Phase $script:rawSequence
        $entry.Status = $sample.Status; $entry.Start = $sample.Start; $entry.End = $sample.End
        if ($sample.Status -cne 'OK') { throw ('Raw sample status=' + $sample.Status + '; ' + ($sample.Error | ConvertTo-Json -Depth 8 -Compress)) }
        $parent = Get-DirectoryImage $sample
        $entry.ParentFileId = [string]$parent.Identity.FileId
        $entry.ParentReference = [string]$parent.Identity.Reference
        if ([string]::IsNullOrWhiteSpace([string]$entry.ParentFileId) -or [string]::IsNullOrWhiteSpace([string]$entry.ParentReference)) {
            throw 'Raw parent directory identity is incomplete.'
        }
        if ($entry.ParentFileId -cne $script:baselineParentFileId -or $entry.ParentReference -cne $script:baselineParentReference) {
            throw 'Raw sample parent FileId/reference differs from the independently captured baseline parent.'
        }
        $imageSummaries = @(); $readerSummaries = @(); $observerReaderSummaries = @{}
        $allArtifactReadsOk = $true; $independentAgree = $true; $forbidden = $false; $nativeReaderCoverageOk = $true
        foreach ($leaf in $leaves) {
            $path = Join-Path $root $leaf; $image = Get-CurrentRawImage $sample $path
            $direct = Read-Public $path; $logical = $null; $imageError = $null
            try { $logical = Get-RawImageBytes $image } catch { $allArtifactReadsOk = $false; $imageError = $_.Exception.Message }
            $nativeReaders = @($sample.Readers | Where-Object { $_.Path -ieq $path })
            if ($image.Absent -eq $true) {
                if ($direct.Status -cne 'ABSENT' -or $nativeReaders.Count -ne 0) { $independentAgree = $false }
            } elseif ($image.Absent -eq $false -and $null -ne $logical) {
                if ($direct.Status -cne 'OK' -or -not (Same $logical $direct.Bytes)) { $independentAgree = $false }
                if ($Case.Sensitive -and $path -ieq $Case.Path -and $logical.Length -gt 0) { $forbidden = $true }
                elseif ((Contains-Bytes $logical $cpfBytes) -or (Contains-Bytes $logical $cpfNumberBytes)) { $forbidden = $true }
                $readerShapeOk = ($nativeReaders.Count -eq 2 -and @($nativeReaders | Where-Object { $_.Unbuffered }).Count -eq 1)
                if (-not $readerShapeOk) { $nativeReaderCoverageOk = $false; $independentAgree = $false }
                foreach ($nativeReader in $nativeReaders) {
                    $readerResult = $nativeReader.Result
                    $readerOk = ($nativeReader.Status -ceq 'OK' -and $null -ne $readerResult -and
                        $readerResult.Status -ceq 'OK' -and $readerResult.Length -eq $image.Length -and
                        $readerResult.Digest -ceq $image.Sha256 -and
                        $readerResult.Before.FileId -ceq $image.Identity.FileId -and
                        $readerResult.After.FileId -ceq $image.Identity.FileId)
                    if (-not $readerOk) { $nativeReaderCoverageOk = $false; $independentAgree = $false }
                    $observerReaderSummaries += [pscustomobject]@{ Path = $path; Unbuffered = [bool]$nativeReader.Unbuffered;
                        Status = [string]$nativeReader.Status; Length = $(if ($readerResult) { $readerResult.Length } else { $null });
                        Sha256 = $(if ($readerResult) { $readerResult.Digest } else { $null });
                        BeforeFileId = $(if ($readerResult -and $readerResult.Before) { $readerResult.Before.FileId } else { $null });
                        AfterFileId = $(if ($readerResult -and $readerResult.After) { $readerResult.After.FileId } else { $null });
                        Error = $(if ($nativeReader.Error) { $nativeReader.Error } else { $null }) }
                }
            } else { $independentAgree = $false }
            if ($direct.Status -eq 'ERROR') { $independentAgree = $false }
            $readerSummaries += [pscustomobject]@{ Path = $path; Status = $direct.Status; Length = $direct.Length; Sha256 = $direct.Sha256; Error = $direct.Error }
            $imageSummaries += [pscustomobject]@{ Path = $path; Absent = [bool]$image.Absent; FileId = $(if ($image.Identity) { $image.Identity.FileId } else { $null });
                Reference = $(if ($image.Identity) { $image.Identity.Reference } else { $null }); Length = $image.Length; Sha256 = $image.Sha256;
                LogicalArtifact = $image.LogicalArtifact; FileNames = @($image.FileNames | ForEach-Object { [pscustomobject]@{ Name = $_.Name; Namespace = $_.Namespace; Reference = $_.Reference; Parent = $_.Parent } }); Error = $imageError }
        }
        $entries = @($parent.DirectoryEntries)
        $expectedEntryKeys = @{}; $actualEntryKeys = @{}; $unexpected = @(); $missing = @()
        foreach ($image in @($sample.Images | Where-Object { $_.Role -ceq 'Current' -and $_.Absent -eq $false })) {
            foreach ($fileName in @($image.FileNames | Where-Object { $_.Parent -eq $parent.Identity.Reference })) {
                $key = ([string]$fileName.Name).ToLowerInvariant() + '|' + [string]$fileName.Namespace + '|' + [string]$fileName.Reference
                $expectedEntryKeys[$key] = $true
            }
        }
        foreach ($directoryEntry in $entries) {
            $key = ([string]$directoryEntry.Name).ToLowerInvariant() + '|' + [string]$directoryEntry.Namespace + '|' + [string]$directoryEntry.Reference
            if ($actualEntryKeys.ContainsKey($key) -or -not $expectedEntryKeys.ContainsKey($key)) { $unexpected += $directoryEntry }
            $actualEntryKeys[$key] = $true
        }
        $missing = @($expectedEntryKeys.Keys | Where-Object { -not $actualEntryKeys.ContainsKey($_) })
        $directoryComplete = ($unexpected.Count -eq 0 -and $missing.Count -eq 0 -and $actualEntryKeys.Count -eq $expectedEntryKeys.Count)
        $entry.DirectoryEntries = @($entries | ForEach-Object { [pscustomobject]@{ Name = $_.Name; Namespace = $_.Namespace; Reference = $_.Reference; Eof = $_.Eof; Attributes = $_.Attributes } })
        $entry.CurrentImages = $imageSummaries; $entry.PublicReaders = $readerSummaries; $entry.ObserverReaders = $observerReaderSummaries
        $entry.RawComplete = ($sample.Status -ceq 'OK' -and $imageSummaries.Count -eq $leaves.Count -and $allArtifactReadsOk)
        $entry.NativeReaderCoverageComplete = $nativeReaderCoverageOk
        $entry.IndependentReadersAgree = ($independentAgree -and $nativeReaderCoverageOk)
        $entry.DirectoryComplete = $directoryComplete
        $entry.ForbiddenBytesObserved = $forbidden
        $targetImage = Get-CurrentRawImage $sample $Case.Path
        $entry.TargetAbsent = ($targetImage.Absent -eq $true)
        if (-not $entry.RawComplete) { throw 'One or more raw target images or artifacts are missing/incomplete.' }
        if (-not $independentAgree -or -not $nativeReaderCoverageOk) { throw 'Raw image, buffered read, and both fresh native readers do not agree (including absence).' }
        if (-not $directoryComplete) { throw ('Raw parent index has unexpected/missing file references; unexpected=' + $unexpected.Count + '; missing=' + $missing.Count) }
        if ($forbidden) { $Case.Leaked = $true; throw 'CPF bytes were observed in a raw public image.' }
        $entry.Status = 'OK'; $entry.ModuleSequence = $sample.Sequence
    } catch { $entry.Status = 'ERROR'; $entry.Error = $_.Exception.ToString() }
    $result.RawObserver.Samples += [pscustomobject]$entry
    $Case.RawSamples += [pscustomobject]$entry
    if ($entry.Status -cne 'OK') { $Case.RawCoverageComplete = $false; $Case.IndependentReadersAgree = $false }
    if ($entry.ForbiddenBytesObserved) { $Case.Leaked = $true }
    return [pscustomobject]$entry
}
function Get-NativeStepCode([string]$Text, [string]$Name) {
    if ([string]::IsNullOrWhiteSpace($Text)) { return $null }
    $match = [regex]::Matches($Text, '(?:^|\s)' + [regex]::Escape($Name) + '=(-?[0-9]+)')
    if ($match.Count -ne 1) { return $null }
    return [int]$match[0].Groups[1].Value
}
function Test-NativeSteps($Case, [string[]]$Names, [hashtable]$Expected) {
    $ok = $true; $missing = @(); $bad = @()
    foreach ($name in $Names) {
        $actual = Get-NativeStepCode ([string]$Case.Ack.Steps) $name
        if ($null -eq $actual) { $ok = $false; $missing += $name; continue }
        if ($actual -ne $Expected[$name]) { $ok = $false; $bad += ($name + '=' + $actual + ' expected=' + $Expected[$name]) }
    }
    $Case.NativeStepsChecked = $true; $Case.NativeStepsOk = $ok; $Case.NativeStepsReason = 'missing=' + ($missing -join ',') + '; mismatch=' + ($bad -join ',')
}
function Write-ActorCommand([string]$Op, [string]$Path, [string]$Text, [int]$N) {
    $json = [ordered]@{ N = $N; Op = $Op; Path = $Path; Text = $Text } | ConvertTo-Json -Compress
    $part = Join-Path $control ('next-' + $N + '.part'); [IO.File]::WriteAllText($part, $json)
    [IO.File]::Move($part, (Join-Path $control ('cmd-' + $N + '.json')))
}
function Invoke-Actor([string]$Op, [string]$Path, [string]$Text, [scriptblock]$Observe,
    [string[]]$BaselineTransferIds, [System.Collections.IDictionary]$CaseRecord) {
    $script:n++
    Write-ActorCommand $Op $Path $Text $script:n
    $ack = Join-Path $control ('ack-' + $script:n + '.json')
    $ready = Join-Path $control ('probe-ready-' + $script:n + '.json')
    $go = Join-Path $control ('probe-go-' + $script:n + '.json')
    $deadline = [Diagnostics.Stopwatch]::GetTimestamp() + 240 * $frequency
    $gatedOps = @('probe-delete-before-seal', 'probe-delete-after-publication', 'probe-doc')
    $probeGateHandled = $false; $lastObserve = [long]0
    while (-not (Test-Path -LiteralPath $ack)) {
        if (-not $probeGateHandled -and $Op -cin $gatedOps -and (Test-Path -LiteralPath $ready)) {
            $readyRecord = (Read-ControlText $ready) | ConvertFrom-Json
            if ($readyRecord.N -ne $script:n -or $readyRecord.Op -cne $Op -or $readyRecord.ProbeCreated -ne $true) {
                throw 'The native probe did not create the exact gated test file.'
            }
            if ($Op -ceq 'probe-delete-before-seal' -and
                ($readyRecord.WritableProbeHandleHeld -ne $true -or $readyRecord.ForcedOrder -cne 'DeleteBeforeSeal')) {
                throw 'The before-seal actor did not retain its writable probe handle.'
            }
            if ($Op -ceq 'probe-delete-after-publication' -and
                ($readyRecord.WritableProbeHandleHeld -ne $false -or $readyRecord.RequiredObservation -cne 'PublicEmptyFile' -or
                 $readyRecord.ForcedOrder -cne 'DeleteAfterObservedPublication')) {
                throw 'The after-publication actor did not request the exact publication observation.'
            }
            $gateDeadline = [Diagnostics.Stopwatch]::GetTimestamp() + 35 * $frequency
            $gateSamples = @(); $gateJournal = $null; $gateSatisfied = $false
            do {
                $sample = & $Observe $probeControlPhase
                if ($null -eq $sample -or $sample.Status -cne 'OK' -or -not $sample.RawComplete -or
                    -not $sample.IndependentReadersAgree -or -not $sample.DirectoryComplete) {
                    throw 'The forced-order gate lacks a complete independent raw observation.'
                }
                $gateSamples += $sample
                $gateJournal = Get-JournalFor -Destination $Path -BaselineTransferIds $BaselineTransferIds -RequireHistoryForNewRecords
                if (@($gateJournal.ParseErrors).Count -gt 0 -or @($gateJournal.SchemaErrors).Count -gt 0) {
                    throw 'The forced-order gate has invalid journal evidence.'
                }
                $fresh = @($gateJournal.Records | Where-Object { $BaselineTransferIds -notcontains $_.TransferId })
                $target = @($sample.CurrentImages | Where-Object { $_.Path -ieq $Path })
                if ($target.Count -ne 1) { throw 'The forced-order gate has no unique raw destination image.' }
                if ($Op -ceq 'probe-delete-before-seal') {
                    $unsealed = @($fresh | Where-Object { $_.IsV20 -and $_.State -in @('0','8') -and
                        $_.SealedOnce -eq $false -and $null -eq $_.SealedLength -and $null -eq $_.Sha256Hex })
                    $gateSatisfied = ($gateSamples.Count -ge 2 -and
                        @($gateSamples | Where-Object { -not $_.TargetAbsent }).Count -eq 0 -and
                        $target[0].Absent -eq $true -and $fresh.Count -eq 1 -and $unsealed.Count -eq 1)
                } elseif ($Op -ceq 'probe-delete-after-publication') {
                    $publishedEmpty = @($fresh | Where-Object { $_.IsV20 -and $_.State -eq '5' -and $_.SealedOnce -eq $true -and
                        $_.SealedLength -eq 0 -and $_.Sha256Hex -ceq 'E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855' })
                    $gateSatisfied = ($target[0].Absent -eq $false -and $target[0].Length -eq 0 -and
                        $target[0].Sha256 -ceq 'E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855' -and
                        -not [string]::IsNullOrWhiteSpace([string]$target[0].FileId) -and $publishedEmpty.Count -eq 1)
                } else {
                    # The existing private delete-on-close row retains its independently observed absence assertions.
                    $gateSatisfied = ($gateSamples.Count -ge 2 -and
                        @($gateSamples | Where-Object { -not $_.TargetAbsent }).Count -eq 0)
                }
                if (-not $gateSatisfied) { Start-Sleep -Milliseconds 100 }
            } while (-not $gateSatisfied -and [Diagnostics.Stopwatch]::GetTimestamp() -lt $gateDeadline)
            if (-not $gateSatisfied) { throw ('The required native order was not proved: ' + $Op) }
            $CaseRecord.ForcedOrderProof = [pscustomobject]@{ Verified = $true; Op = $Op; ActorReady = $readyRecord;
                RawSequences = @($gateSamples | ForEach-Object Sequence); FinalRawSequence = $sample.Sequence;
                Target = $target[0]; Journal = $fresh; CapturedBeforeGoQpc = [Diagnostics.Stopwatch]::GetTimestamp() }
            [IO.File]::WriteAllText(($go + '.tmp'), (@{ N = $script:n; Proceed = $true } | ConvertTo-Json -Compress))
            [IO.File]::Move(($go + '.tmp'), $go)
            $probeGateHandled = $true
        }
        $now = [Diagnostics.Stopwatch]::GetTimestamp()
        if ($null -ne $Observe -and ($lastObserve -eq 0 -or $now - $lastObserve -ge [long]([Diagnostics.Stopwatch]::Frequency / 2))) {
            [void](& $Observe 'ActorRunning'); $lastObserve = [Diagnostics.Stopwatch]::GetTimestamp()
        }
        if ($now -ge $deadline) { throw "actor $Op timed out" }
        Start-Sleep -Milliseconds 50
    }
    if ($Op -cin $gatedOps -and -not $probeGateHandled) { throw 'probe actor completed without its raw-observation gate' }
    $value = (Read-ControlText $ack) | ConvertFrom-Json
    Remove-Item -LiteralPath $ack -Force
    return $value
}
function Test-T5HasProperty($Object, [string]$Name) {
    if ($null -eq $Object) { return $false }
    if ($Object -is [System.Collections.IDictionary]) { return $Object.Contains($Name) }
    return $null -ne $Object.PSObject.Properties[$Name]
}
function Test-T5Object($Value) {
    if ($null -eq $Value -or $Value -is [string] -or $Value -is [Array] -or
        $Value.GetType().IsValueType) { return $false }
    return $true
}
function Get-T5IntegerText($Value) {
    if ($null -eq $Value -or $Value -is [string] -or $Value -is [bool] -or
        $Value -is [double] -or $Value -is [single]) { return $null }
    if ($Value -is [decimal]) {
        if ([decimal]::Truncate($Value) -ne $Value) { return $null }
        return $Value.ToString('0', [Globalization.CultureInfo]::InvariantCulture)
    }
    if ($Value -is [System.Numerics.BigInteger]) {
        return $Value.ToString([Globalization.CultureInfo]::InvariantCulture)
    }
    if ($Value -is [byte] -or $Value -is [sbyte] -or $Value -is [int16] -or
        $Value -is [uint16] -or $Value -is [int32] -or $Value -is [uint32] -or
        $Value -is [int64] -or $Value -is [uint64]) {
        return [Convert]::ToString($Value, [Globalization.CultureInfo]::InvariantCulture)
    }
    return $null
}
function Test-T5IntegerRange($Value, [long]$Minimum, [long]$Maximum) {
    $text = Get-T5IntegerText $Value
    if ($null -eq $text) { return $false }
    $parsed = [long]0
    if (-not [long]::TryParse($text, [Globalization.NumberStyles]::Integer,
            [Globalization.CultureInfo]::InvariantCulture, [ref]$parsed)) { return $false }
    return ($parsed -ge $Minimum -and $parsed -le $Maximum)
}
function Test-T5NextGeneration($ParentGeneration, $ChildGeneration) {
    $parentText = Get-T5IntegerText $ParentGeneration
    $childText = Get-T5IntegerText $ChildGeneration
    if ($null -eq $parentText -or $null -eq $childText) { return $false }
    $parentValue = [decimal]0; $childValue = [decimal]0
    if (-not [decimal]::TryParse($parentText, [Globalization.NumberStyles]::Integer,
            [Globalization.CultureInfo]::InvariantCulture, [ref]$parentValue) -or
        -not [decimal]::TryParse($childText, [Globalization.NumberStyles]::Integer,
            [Globalization.CultureInfo]::InvariantCulture, [ref]$childValue)) { return $false }
    return ($parentValue -ge 1 -and $childValue -eq ($parentValue + [decimal]1))
}
function Get-T5UInt64Text($Value) {
    $text = Get-T5IntegerText $Value
    if ($null -eq $text) { return $null }
    $parsed = [uint64]0
    if (-not [uint64]::TryParse($text, [Globalization.NumberStyles]::None,
            [Globalization.CultureInfo]::InvariantCulture, [ref]$parsed)) { return $null }
    return $parsed.ToString([Globalization.CultureInfo]::InvariantCulture)
}
function Test-T5UInt64($Value) { return $null -ne (Get-T5UInt64Text $Value) }
function Get-T5GuidText($Value) {
    if ($null -eq $Value) { return $null }
    $parsed = [guid]::Empty
    if (-not [guid]::TryParse([string]$Value, [ref]$parsed) -or $parsed -eq [guid]::Empty) { return $null }
    return $parsed.ToString('N')
}
function Get-T5UtcValue($Value) {
    if ($Value -is [DateTimeOffset]) {
        if ($Value.Offset -ne [TimeSpan]::Zero -or $Value -eq [DateTimeOffset]::MinValue) { return $null }
        return $Value
    }
    if ($Value -is [DateTime]) {
        if ($Value.Kind -ne [DateTimeKind]::Utc -or $Value -eq [DateTime]::MinValue) { return $null }
        return [DateTimeOffset]$Value
    }
    # DateTimeOffset.TryParse treats an unqualified local time as UTC on a UTC
    # host. Service manifests serialize UTC with an explicit zone, so require
    # that evidence before parsing rather than letting the builder's timezone
    # change what the coordinator accepts.
    if ($Value -isnot [string] -or [string]::IsNullOrWhiteSpace($Value) -or
        $Value -notmatch '(?:Z|\+00:00)$') { return $null }
    $parsed = [DateTimeOffset]::MinValue
    if (-not [DateTimeOffset]::TryParse($Value, [Globalization.CultureInfo]::InvariantCulture,
            [Globalization.DateTimeStyles]::None, [ref]$parsed) -or
        $parsed -eq [DateTimeOffset]::MinValue -or $parsed.Offset -ne [TimeSpan]::Zero) { return $null }
    return $parsed
}
function Get-T5StateName([int]$State) {
    switch ($State) {
        0 { return 'Allocated' } 1 { return 'Sealed' } 2 { return 'Inspecting' }
        3 { return 'Approved' } 4 { return 'Publishing' } 5 { return 'Released' }
        6 { return 'Blocked' } 7 { return 'Retained' } 8 { return 'Unsealed' }
        9 { return 'Discarded' } 10 { return 'SealPending' } 11 { return 'EmptyHeld' }
        12 { return 'DiscardPending' }
        default { return ('Unknown(' + $State + ')') }
    }
}
function Test-T5StateTransition([int]$From, [int]$To) {
    $allowed = switch ($From) {
        0 { @(10, 12, 1, 8, 9) }
        1 { @(12, 11, 2, 7) }
        2 { @(11, 3, 6, 7, 1) }
        3 { @(7, 4) }
        4 { @(5, 7) }
        5 { @() }
        6 { @(7, 2, 1) }
        7 { @(12, 11, 1, 2) }
        8 { @(10, 12, 1, 9) }
        9 { @() }
        10 { @(12, 1, 11) }
        11 { @() }
        12 { @() }
        default { @() }
    }
    return (@($allowed) -contains $To)
}
function Test-T5NormalizedPath([string]$Path) {
    if ([string]::IsNullOrWhiteSpace($Path) -or $Path.Length -gt 511 -or
        -not [IO.Path]::IsPathRooted($Path)) { return $false }
    try { return [string]::Equals([IO.Path]::GetFullPath($Path), $Path, [StringComparison]::OrdinalIgnoreCase) }
    catch { return $false }
}
function Test-T5JsonDepthBound([string]$Json, [int]$MaximumDepth = 32) {
    if ([string]::IsNullOrEmpty($Json) -or $MaximumDepth -lt 1) { return $false }
    $depth = 0; $inString = $false; $escaped = $false
    for ($index = 0; $index -lt $Json.Length; ++$index) {
        $character = $Json[$index]
        if ($inString) {
            if ($escaped) { $escaped = $false; continue }
            if ($character -eq [char]92) { $escaped = $true; continue }
            if ($character -eq [char]34) { $inString = $false }
            continue
        }
        if ($character -eq [char]34) { $inString = $true; continue }
        if ($character -eq [char]123 -or $character -eq [char]91) {
            $depth++
            if ($depth -gt $MaximumDepth) { return $false }
        } elseif ($character -eq [char]125 -or $character -eq [char]93) {
            $depth--
            if ($depth -lt 0) { return $false }
        }
    }
    return (-not $inString -and -not $escaped -and $depth -eq 0)
}
function Get-T5StageIdentityKey($Identity) {
    if (-not (Test-T5Object $Identity)) { return $null }
    foreach ($name in @('VolumeSerialNumber', 'FileIdHigh', 'FileIdLow')) {
        if (-not (Test-T5HasProperty $Identity $name) -or
            $null -eq (Get-T5UInt64Text $Identity.$name)) { return $null }
    }
    $high = Get-T5UInt64Text $Identity.FileIdHigh
    $low = Get-T5UInt64Text $Identity.FileIdLow
    if ($high -eq '0' -and $low -eq '0') { return $null }
    return ((Get-T5UInt64Text $Identity.VolumeSerialNumber) + ':' + $high + ':' + $low)
}
function Test-T5StageIdentity($Identity) {
    return $null -ne (Get-T5StageIdentityKey $Identity)
}
function Get-T5VersionIdentityKey($Identity) {
    if (-not (Test-T5Object $Identity) -or
        -not (Test-T5HasProperty $Identity 'TransferId') -or
        -not (Test-T5HasProperty $Identity 'DestinationGeneration') -or
        -not (Test-T5HasProperty $Identity 'StageIdentity')) { return $null }
    $id = Get-T5GuidText $Identity.TransferId
    $generation = Get-T5IntegerText $Identity.DestinationGeneration
    if ($null -eq $id -or $null -eq $generation -or
        -not (Test-T5IntegerRange $Identity.DestinationGeneration 1 ([long]::MaxValue))) { return $null }
    $stage = Get-T5StageIdentityKey $Identity.StageIdentity
    if ($null -eq $stage) { return $null }
    return ($id + '/' + $generation + '/' + $stage)
}
function Test-T5VersionIdentity($Identity) { return $null -ne (Get-T5VersionIdentityKey $Identity) }
function Test-T5LifecycleEvidence($Entry, [int]$AttachmentState, [int]$State) {
    foreach ($name in @('AttachPrepareRequestIdV20', 'AttachCommitRequestIdV20', 'AttachAbortRequestIdV20',
            'CompletionPermitRequestIdV20', 'RetireRequestIdV20', 'HandleObservedRequestIdV20')) {
        if ($null -ne $Entry.$name -and -not (Test-T5UInt64 $Entry.$name)) { return $false }
        if ($null -ne $Entry.$name -and (Get-T5UInt64Text $Entry.$name) -eq '0') { return $false }
    }
    $prepare = Get-T5UInt64Text $Entry.AttachPrepareRequestIdV20
    $commit = Get-T5UInt64Text $Entry.AttachCommitRequestIdV20
    $abort = Get-T5UInt64Text $Entry.AttachAbortRequestIdV20
    $permit = Get-T5UInt64Text $Entry.CompletionPermitRequestIdV20
    $retire = Get-T5UInt64Text $Entry.RetireRequestIdV20
    $observed = Get-T5UInt64Text $Entry.HandleObservedRequestIdV20
    $commitResult = if (Test-T5IntegerRange $Entry.AttachCommitResultV20 7 9) { [int]$Entry.AttachCommitResultV20 } else { -1 }
    $discardKind = if (Test-T5IntegerRange $Entry.DiscardKind 1 7) { [int]$Entry.DiscardKind } else { 0 }
    $reservation = Get-T5GuidText $Entry.DiscardReservationId
    $selfTransferId = if (Test-T5HasProperty $Entry 'Transfer') {
        $Entry.Transfer.TransferId
    } elseif (Test-T5HasProperty $Entry 'TransferId') {
        $Entry.TransferId
    } else { $null }
    $self = Get-T5GuidText $selfTransferId
    if ($null -eq $self) { return $false }
    if (($null -eq $Entry.AttachCommitRequestIdV20) -ne ($null -eq $Entry.AttachCommitResultV20)) { return $false }
    if ($State -eq 12 -and $discardKind -eq 6 -and $AttachmentState -notin @(7, 8)) { return $false }
    if ($State -eq 12 -and $discardKind -eq 7 -and $AttachmentState -notin @(9, 10)) { return $false }
    $seen = @{}
    foreach ($request in @($prepare, $commit, $abort, $permit, $retire, $observed)) {
        if ($null -eq $request) { continue }
        if ($seen.ContainsKey($request)) { return $false }
        $seen[$request] = $true
    }
    switch ($AttachmentState) {
        0 {
            return ($null -eq $Entry.AttachPrepareRequestIdV20 -and $null -eq $Entry.AttachCommitRequestIdV20 -and
                $null -eq $Entry.AttachCommitResultV20 -and $null -eq $Entry.AttachAbortRequestIdV20 -and
                $null -eq $Entry.CompletionPermitRequestIdV20 -and $null -eq $Entry.RetireRequestIdV20 -and
                $null -eq $Entry.HandleObservedRequestIdV20)
        }
        1 { return ($null -ne $prepare -and $null -eq $commit -and $null -eq $Entry.AttachCommitResultV20 -and $null -eq $abort -and $null -eq $permit -and $null -eq $retire -and $null -eq $observed) }
        2 { return ($null -ne $prepare -and $null -ne $commit -and $commitResult -eq 7 -and $null -eq $abort -and $null -eq $permit -and $null -eq $retire -and $null -eq $observed) }
        3 { return ($null -ne $prepare -and $null -ne $commit -and $commitResult -eq 9 -and $null -eq $abort -and $null -eq $permit -and $null -eq $retire -and $null -eq $observed) }
        4 { return ($null -ne $prepare -and $null -ne $abort -and ($null -eq $commit -or $commitResult -eq 9) -and
                $null -eq $permit -and $null -eq $retire -and $null -eq $observed -and $State -eq 12 -and
                $discardKind -eq 5 -and $reservation -eq $self) }
        5 { return ($null -ne $prepare -and $null -ne $commit -and $commitResult -eq 7 -and $null -eq $abort -and
                $null -ne $permit -and $null -eq $retire -and $null -eq $observed) }
        6 { return ($null -ne $prepare -and $null -ne $commit -and $commitResult -eq 7 -and $null -eq $abort -and
                $null -ne $permit -and $null -eq $retire -and $null -ne $observed) }
        7 { return ($null -ne $prepare -and $null -ne $commit -and $commitResult -eq 7 -and $null -eq $abort -and
                $null -eq $permit -and $null -ne $retire -and $null -eq $observed -and $State -eq 12 -and
                $discardKind -eq 6 -and $reservation -eq $self -and $null -eq $Entry.DiscardAcknowledgedAtUtc -and
                $Entry.SealedOnce -eq $false -and $null -eq $Entry.SealedLength -and $null -eq $Entry.Sha256Hex) }
        8 { return ($null -ne $prepare -and $null -ne $commit -and $commitResult -eq 7 -and $null -eq $abort -and
                $null -eq $permit -and $null -ne $retire -and $null -eq $observed -and $State -eq 12 -and
                $discardKind -eq 6 -and $reservation -eq $self -and $null -ne $Entry.DiscardAcknowledgedAtUtc -and
                $Entry.SealedOnce -eq $false -and $null -eq $Entry.SealedLength -and $null -eq $Entry.Sha256Hex) }
        9 { return ($null -ne $prepare -and $null -ne $commit -and $commitResult -eq 7 -and $null -eq $abort -and
                $null -ne $permit -and $null -ne $retire -and $null -eq $observed -and $State -eq 12 -and
                $discardKind -eq 7 -and $reservation -eq $self -and $null -eq $Entry.DiscardAcknowledgedAtUtc -and
                $Entry.SealedOnce -eq $false -and $null -eq $Entry.SealedLength -and $null -eq $Entry.Sha256Hex) }
        10 { return ($null -ne $prepare -and $null -ne $commit -and $commitResult -eq 7 -and $null -eq $abort -and
                $null -ne $permit -and $null -ne $retire -and $null -eq $observed -and $State -eq 12 -and
                $discardKind -eq 7 -and $reservation -eq $self -and $null -ne $Entry.DiscardAcknowledgedAtUtc -and
                $Entry.SealedOnce -eq $false -and $null -eq $Entry.SealedLength -and $null -eq $Entry.Sha256Hex) }
        default { return $false }
    }
}
function Get-JournalSchemaErrors($Entry, [string]$ManifestPath, [switch]$RequireStateHistory, [switch]$RequireV20) {
    $errors = @()
    if (-not (Test-T5Object $Entry)) { return @('manifest root is not an object') }
    $profileV20 = ($RequireV20 -or
        ((Test-T5HasProperty $Entry 'DriverInstanceId') -and $null -ne $Entry.DriverInstanceId))
    foreach ($name in @('Transfer', 'State', 'Sha256Hex', 'UpdatedAtUtc', 'SealedOnce',
            'HandbackState', 'StageDeleted', 'DestinationGeneration')) {
        if (-not (Test-T5HasProperty $Entry $name)) { $errors += ('missing top-level ' + $name) }
    }
    if (($profileV20 -or $RequireStateHistory) -and -not (Test-T5HasProperty $Entry 'StateHistory')) {
        $errors += 'measured record is missing StateHistory'
    }
    if ($profileV20) {
        foreach ($name in @('StageIdentity', 'SealedLength', 'StateHistory', 'ParentVersionIdentity',
                'DeleteVersionIdentity', 'CreateReservationId', 'CreateAfterReservationId',
                'AllocationReferenceId', 'AllocationReferenceKind', 'DriverInstanceId',
                'ParentDirectoryIdentity', 'AllocationDisposition', 'AttachmentStateV20',
                'AttachPrepareRequestIdV20', 'AttachCommitRequestIdV20', 'AttachCommitResultV20',
                'AttachAbortRequestIdV20', 'CompletionPermitRequestIdV20', 'RetireRequestIdV20',
                'HandleObservedRequestIdV20', 'DiscardReservationId', 'DiscardKind',
                'DiscardRequestedAtUtc', 'DiscardAcknowledgedAtUtc', 'EmptyHeldNotificationAttemptedAtUtc',
                'EmptyHeldNotificationAttemptedByInstanceId', 'EmptyHeldNotificationQueuedAtUtc',
                'EmptyHeldNotificationQueuedByInstanceId', 'DestinationGeneration', 'NamespaceTombstones',
                'PendingRename', 'LastRenameTransactionId', 'LastRenameDestination', 'LastRenameCommitted',
                'BlockedPolicyVersion', 'BlockedInspectionFailure', 'JustificationExpiresAtUtc',
                'JustificationWindowClosed', 'HandbackPath', 'HandbackLength', 'HandbackFailureReason',
                'HandbackLastAttemptAtUtc', 'StageCleanupStarted')) {
            if (-not (Test-T5HasProperty $Entry $name)) { $errors += ('v20 record is missing ' + $name) }
        }
    }
    if (-not (Test-T5Object $Entry.Transfer)) { return ($errors + @('Transfer is not an object')) }
    foreach ($name in @('TransferId', 'StagePath', 'DestinationPath', 'Destination', 'ProcessName', 'ProcessId', 'SessionId')) {
        if (-not (Test-T5HasProperty $Entry.Transfer $name)) { $errors += ('missing Transfer.' + $name) }
    }
    if ($profileV20) {
        foreach ($name in @('RequestorSid', 'RequestorProcessCreationTime')) {
            if (-not (Test-T5HasProperty $Entry.Transfer $name)) { $errors += ('v20 record is missing Transfer.' + $name) }
        }
    }
    if ($errors.Count -gt 0) { return $errors }
    $transfer = $Entry.Transfer
    $transferId = Get-T5GuidText $transfer.TransferId
    if ($null -eq $transferId -or
        $transferId -cne [IO.Path]::GetFileNameWithoutExtension($ManifestPath).ToLowerInvariant()) {
        $errors += 'TransferId does not bind to manifest filename'
    }
    if (-not (Test-T5NormalizedPath ([string]$transfer.StagePath)) -or
        -not (Test-T5NormalizedPath ([string]$transfer.DestinationPath))) {
        $errors += 'transfer paths are missing, unrooted, overlong, or not normalized'
    }
    if ($transfer.ProcessName -isnot [string] -or [string]::IsNullOrWhiteSpace([string]$transfer.ProcessName) -or
        ([string]$transfer.ProcessName).Length -gt 63 -or
        -not (Test-T5IntegerRange $transfer.ProcessId 1 ([int]::MaxValue))) {
        $errors += 'transfer process identity is invalid'
    }
    if (-not (Test-T5IntegerRange $transfer.Destination 0 4)) { $errors += 'Transfer.Destination is not a defined numeric value' }
    if ($null -ne $transfer.SessionId -and -not (Test-T5IntegerRange $transfer.SessionId 0 4294967295)) {
        $errors += 'Transfer.SessionId is invalid'
    }
    if ($null -ne $transfer.RequestorSid -and
        ($transfer.RequestorSid -isnot [string] -or [string]$transfer.RequestorSid -notmatch '^S-\d+-\d+(?:-\d+)+$' -or
         ([string]$transfer.RequestorSid).Length -gt 184)) { $errors += 'Transfer.RequestorSid is invalid' }
    if ($null -ne $transfer.RequestorProcessCreationTime -and
        -not (Test-T5IntegerRange $transfer.RequestorProcessCreationTime 1 ([long]::MaxValue))) {
        $errors += 'Transfer.RequestorProcessCreationTime is invalid'
    }
    if ($profileV20 -and ($null -eq $transfer.RequestorSid -or $null -eq $transfer.SessionId -or
            $null -eq $transfer.RequestorProcessCreationTime)) {
        $errors += 'v20 transfer lacks exact owner, session, or process-creation identity'
    }
    if (-not (Test-T5IntegerRange $Entry.State 0 12)) { $errors += 'State is not a defined numeric value' }
    if ($Entry.SealedOnce -isnot [bool] -or $Entry.StageDeleted -isnot [bool]) { $errors += 'seal/deletion fields are not booleans' }
    if (-not (Test-T5IntegerRange $Entry.HandbackState 0 3)) { $errors += 'HandbackState is not a defined numeric value' }
    if (($profileV20 -and $Entry.StageCleanupStarted -isnot [bool]) -or
        ($null -ne $Entry.StageCleanupStarted -and $Entry.StageCleanupStarted -isnot [bool])) {
        $errors += 'StageCleanupStarted is not a boolean'
    }
    if ($null -ne $Entry.JustificationWindowClosed -and $Entry.JustificationWindowClosed -isnot [bool]) { $errors += 'JustificationWindowClosed is not a boolean' }
    if (-not (Test-T5IntegerRange $Entry.DestinationGeneration 0 ([long]::MaxValue))) { $errors += 'DestinationGeneration is invalid' }
    if ($null -ne $Entry.SealedLength -and -not (Test-T5IntegerRange $Entry.SealedLength 0 ([long]::MaxValue))) {
        $errors += 'SealedLength is invalid'
    }
    if ($null -ne $Entry.Sha256Hex -and ($Entry.Sha256Hex -isnot [string] -or [string]$Entry.Sha256Hex -notmatch '^[A-Fa-f0-9]{64}$')) {
        $errors += 'Sha256Hex is neither null nor a SHA-256 digest'
    }
    if ($null -ne $Entry.HandbackPath -and -not (Test-T5NormalizedPath ([string]$Entry.HandbackPath))) {
        $errors += 'HandbackPath is not a normalized rooted path'
    }
    if ($null -ne $Entry.HandbackLength -and -not (Test-T5IntegerRange $Entry.HandbackLength 0 ([long]::MaxValue))) {
        $errors += 'HandbackLength is invalid'
    }
    if ($null -ne $Entry.HandbackFailureReason -and
        ($Entry.HandbackFailureReason -isnot [string] -or ([string]$Entry.HandbackFailureReason).Length -gt 256)) {
        $errors += 'HandbackFailureReason is invalid'
    }
    if ($null -ne $Entry.HandbackLastAttemptAtUtc -and $null -eq (Get-T5UtcValue $Entry.HandbackLastAttemptAtUtc)) {
        $errors += 'HandbackLastAttemptAtUtc is not UTC'
    }
    if ($null -ne $Entry.JustificationExpiresAtUtc -and $null -eq (Get-T5UtcValue $Entry.JustificationExpiresAtUtc)) {
        $errors += 'JustificationExpiresAtUtc is not UTC'
    }
    foreach ($name in @('EmptyHeldNotificationAttemptedAtUtc', 'EmptyHeldNotificationQueuedAtUtc')) {
        if ($null -ne $Entry.$name -and $null -eq (Get-T5UtcValue $Entry.$name)) {
            $errors += ($name + ' is not an exact UTC timestamp')
        }
    }
    foreach ($name in @('EmptyHeldNotificationAttemptedByInstanceId', 'EmptyHeldNotificationQueuedByInstanceId')) {
        if ($null -ne $Entry.$name -and $null -eq (Get-T5GuidText $Entry.$name)) {
            $errors += ($name + ' is not a nonempty driver instance ID')
        }
    }
    $attemptedAt = Get-T5UtcValue $Entry.EmptyHeldNotificationAttemptedAtUtc
    $queuedAt = Get-T5UtcValue $Entry.EmptyHeldNotificationQueuedAtUtc
    $attemptedBy = Get-T5GuidText $Entry.EmptyHeldNotificationAttemptedByInstanceId
    $queuedBy = Get-T5GuidText $Entry.EmptyHeldNotificationQueuedByInstanceId
    if (($null -eq $Entry.EmptyHeldNotificationAttemptedAtUtc) -ne ($null -eq $Entry.EmptyHeldNotificationAttemptedByInstanceId) -or
        ($null -eq $Entry.EmptyHeldNotificationQueuedAtUtc) -ne ($null -eq $Entry.EmptyHeldNotificationQueuedByInstanceId) -or
        ($null -ne $queuedAt -and $null -eq $attemptedAt) -or
        ($null -ne $queuedAt -and $null -ne $attemptedAt -and $queuedAt -lt $attemptedAt) -or
        ($null -ne $queuedBy -and $null -ne $attemptedBy -and $queuedBy -cne $attemptedBy) -or
        (($null -ne $attemptedAt -or $null -ne $queuedAt) -and $Entry.State -ne 11)) {
        $errors += 'EmptyHeld notification attempt/queue evidence is inconsistent'
    }
    if ($null -ne $Entry.LastRenameTransactionId -and -not (Test-T5UInt64 $Entry.LastRenameTransactionId)) {
        $errors += 'LastRenameTransactionId is not an exact UInt64'
    }
    if ($null -ne $Entry.LastRenameDestination -and
        -not (Test-T5NormalizedPath ([string]$Entry.LastRenameDestination))) {
        $errors += 'LastRenameDestination is not a normalized rooted path'
    }
    if ($null -ne $Entry.LastRenameCommitted -and $Entry.LastRenameCommitted -isnot [bool]) {
        $errors += 'LastRenameCommitted is not a boolean'
    }
    $lastRenameId = Get-T5UInt64Text $Entry.LastRenameTransactionId
    if (($lastRenameId -eq '0' -and ($null -ne $Entry.LastRenameDestination -or $Entry.LastRenameCommitted -eq $true)) -or
        ($null -ne $lastRenameId -and $lastRenameId -ne '0' -and $null -eq $Entry.LastRenameDestination)) {
        $errors += 'last rename transaction fields have an invalid combination'
    }
    if ($null -ne $Entry.PendingRename) {
        if (-not (Test-T5Object $Entry.PendingRename) -or
            -not (Test-T5HasProperty $Entry.PendingRename 'TransactionId') -or
            -not (Test-T5HasProperty $Entry.PendingRename 'DestinationPath') -or
            -not (Test-T5HasProperty $Entry.PendingRename 'SealedVersion') -or
            -not (Test-T5UInt64 $Entry.PendingRename.TransactionId) -or
            (Get-T5UInt64Text $Entry.PendingRename.TransactionId) -eq '0' -or
            -not (Test-T5NormalizedPath ([string]$Entry.PendingRename.DestinationPath)) -or
            $Entry.PendingRename.SealedVersion -isnot [bool] -or
            $Entry.PendingRename.SealedVersion -ne $Entry.SealedOnce) {
            $errors += 'PendingRename is not an exact bounded rename transaction'
        }
    }
    $handbackState = if (Test-T5IntegerRange $Entry.HandbackState 0 3) { [int]$Entry.HandbackState } else { -1 }
    if (($handbackState -eq 2 -and ($null -eq $Entry.HandbackPath -or
            ($null -ne $transfer.RequestorSid -and $null -eq $Entry.HandbackLength) -or
            $null -ne $Entry.HandbackFailureReason)) -or
        ($handbackState -ne 2 -and ($null -ne $Entry.HandbackPath -or $null -ne $Entry.HandbackLength)) -or
        ($handbackState -eq 3 -and $null -eq $Entry.HandbackFailureReason) -or
        ($handbackState -ne 3 -and $null -ne $Entry.HandbackFailureReason) -or
        ($Entry.StageCleanupStarted -eq $true -and
            ($handbackState -ne 2 -or $Entry.JustificationWindowClosed -ne $true))) {
        $errors += 'handback and cleanup fields have an invalid state combination'
    }
    $state = if (Test-T5IntegerRange $Entry.State 0 12) { [int]$Entry.State } else { -1 }
    if ($state -in @(3, 4, 5, 6) -and $null -eq $Entry.Sha256Hex) { $errors += 'approved/publishing/released/blocked state lacks its digest' }
    if ($profileV20 -and $state -in @(1, 2, 3, 4, 5, 6) -and
        ($null -eq $Entry.Sha256Hex -or $null -eq $Entry.StageIdentity -or
         $null -eq $Entry.SealedLength -or -not (Test-T5IntegerRange $Entry.SealedLength 0 ([long]::MaxValue)))) {
        $errors += 'sealed/inspection/publication state lacks an exact measured seal'
    }
    if ($null -ne $Entry.SealedLength -and $Entry.SealedLength -ge 0 -and $null -eq $Entry.StageIdentity) {
        $errors += 'measured length lacks its exact stage identity'
    }
    if ($Entry.SealedLength -eq 0 -and $state -notin @(1, 2, 3, 4, 5, 6, 7, 11, 12)) {
        $errors += 'zero measured length is outside a measured sealed or discard state'
    }
    if ($Entry.SealedLength -eq 0 -and $state -in @(1, 2, 3, 4, 5, 6, 7) -and
        $Entry.Sha256Hex -ine 'E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855') {
        $errors += 'ordinary measured-zero seal lacks the empty-content digest'
    }
    if ($state -eq 9 -and ($null -ne $Entry.Sha256Hex -or $Entry.SealedOnce -ne $false)) { $errors += 'Discarded must have a null digest and SealedOnce=false' }
    if ($state -in @(0, 8, 9) -and $Entry.SealedOnce -ne $false) { $errors += 'Allocated/Unsealed/Discarded must have SealedOnce=false' }
    if ($state -in @(1, 2, 3, 4, 5, 6, 10, 11) -and $Entry.SealedOnce -ne $true) { $errors += 'sealed/inspection/publication/empty state must have SealedOnce=true' }
    if ($state -eq 10 -and ($null -ne $Entry.SealedLength -or $null -eq $Entry.StageIdentity)) { $errors += 'SealPending lacks exact unmeasured seal evidence' }
    if ($state -eq 11 -and ($Entry.SealedLength -ne 0 -or $null -eq $Entry.StageIdentity -or
            $null -ne $Entry.Sha256Hex -or $Entry.StageCleanupStarted -eq $true -or $Entry.StageDeleted -eq $true)) {
        $errors += 'EmptyHeld is not an exact zero-length private stage'
    }
    if ($profileV20 -and $state -in @(1, 2, 3, 4, 5, 6, 7, 10, 11) -and
        [int]$Entry.AttachmentStateV20 -ne 6) {
        # SealAsync and inspection/publication transitions require op19 for
        # every measured v20 sealed state, including EmptyHeld.
        $errors += 'v20 sealed, inspection, or publication state lacks its exact HandleObserved receipt'
    }
    if ($state -eq 11 -and ($Entry.BlockedPolicyVersion -ne 0 -or $null -ne $Entry.BlockedInspectionFailure -or
            $handbackState -ne 0 -or $null -ne $Entry.HandbackPath -or $null -ne $Entry.HandbackLength -or
            $null -ne $Entry.HandbackFailureReason -or $null -ne $Entry.JustificationExpiresAtUtc -or
            $Entry.JustificationWindowClosed -eq $true)) {
        $errors += 'EmptyHeld contains policy, handback, or justification state that is forbidden for an empty private save'
    }
    if (($profileV20 -or (Test-T5HasProperty $Entry 'BlockedPolicyVersion')) -and
        -not (Test-T5IntegerRange $Entry.BlockedPolicyVersion 0 ([int]::MaxValue))) {
        $errors += 'BlockedPolicyVersion is invalid'
    }
    if ($null -ne $Entry.BlockedInspectionFailure -and
        -not (Test-T5IntegerRange $Entry.BlockedInspectionFailure 0 3)) {
        $errors += 'BlockedInspectionFailure is outside the inspection failure enum'
    }
    if ($Entry.StageDeleted -eq $true -and -not (
            ($state -eq 5 -and $Entry.SealedOnce -eq $true -and
                (Test-T5IntegerRange $Entry.SealedLength 0 ([long]::MaxValue)) -and
                $null -ne $Entry.Sha256Hex -and $handbackState -eq 0 -and
                $Entry.StageCleanupStarted -eq $false) -or
            ($state -in @(5, 6) -and $handbackState -eq 2 -and
                $Entry.JustificationWindowClosed -eq $true -and $Entry.StageCleanupStarted -eq $false))) {
        $errors += 'StageDeleted has no service-authorized release or verified-handback state'
    }
    $updated = Get-T5UtcValue $Entry.UpdatedAtUtc
    if ($null -eq $updated) { $errors += 'UpdatedAtUtc is not an exact UTC timestamp' }
    if ($null -ne $Entry.StateHistory -and $Entry.StateHistory -isnot [Array]) { $errors += 'StateHistory is not an array or null legacy history' }
    $history = @()
    if ($Entry.StateHistory -is [Array]) { $history = $Entry.StateHistory }
    if ($RequireStateHistory -and $history.Count -eq 0) { $errors += 'new measured-run record has no StateHistory' }
    if ($history.Count -gt 64) { $errors += 'StateHistory exceeds the service limit of 64 entries' }
    if ($history.Count -gt 0) {
        $previousState = -1; $previousTime = $null; $index = 0
        foreach ($change in $history) {
            if (-not (Test-T5Object $change) -or -not (Test-T5HasProperty $change 'State') -or
                -not (Test-T5HasProperty $change 'OccurredAtUtc') -or
                -not (Test-T5IntegerRange $change.State 0 12)) {
                $errors += 'StateHistory contains an invalid state change'; break
            }
            $occurred = Get-T5UtcValue $change.OccurredAtUtc
            if ($null -eq $occurred) { $errors += 'StateHistory timestamp is not exact UTC'; break }
            $nextState = [int]$change.State
            if ($index -eq 0 -and $nextState -ne 0) { $errors += 'StateHistory must begin at Allocated'; break }
            if ($index -gt 0 -and ($occurred -le $previousTime -or -not (Test-T5StateTransition $previousState $nextState))) {
                $errors += 'StateHistory timestamps or state transition are invalid'; break
            }
            $previousState = $nextState; $previousTime = $occurred; $index++
        }
        if ($history.Count -gt 0 -and $previousState -ne $state) { $errors += 'StateHistory terminal state differs from State' }
    }
    if ($null -ne $Entry.StageIdentity -and -not (Test-T5StageIdentity $Entry.StageIdentity)) {
        $errors += 'StageIdentity is not an exact volume/FileId tuple'
    }
    if ($null -ne $Entry.ParentVersionIdentity -and -not (Test-T5VersionIdentity $Entry.ParentVersionIdentity)) {
        $errors += 'ParentVersionIdentity is malformed'
    }
    if ($null -ne $Entry.DeleteVersionIdentity -and -not (Test-T5VersionIdentity $Entry.DeleteVersionIdentity)) {
        $errors += 'DeleteVersionIdentity is malformed'
    }
    if ($profileV20) {
        if ($history.Count -eq 0) { $errors += 'v20 record has no exact state history' }
        if ($null -eq $Entry.DriverInstanceId -or $null -eq (Get-T5GuidText $Entry.DriverInstanceId)) {
            $errors += 'v20 record has no exact driver epoch'
        }
        if ($null -eq $Entry.StageIdentity -or -not (Test-T5StageIdentity $Entry.StageIdentity) -or
            -not (Test-T5IntegerRange $Entry.DestinationGeneration 1 ([long]::MaxValue)) -or
            $null -eq $Entry.CreateReservationId -or
            (Get-T5GuidText $Entry.CreateReservationId) -ne (Get-T5GuidText $transfer.TransferId) -or
            -not (Test-T5StageIdentity $Entry.ParentDirectoryIdentity)) {
            $errors += 'v20 allocation lacks exact stage, generation, reservation, or parent-directory identity'
        }
        if ($null -eq $transfer.SessionId -or $null -eq $transfer.RequestorSid -or
            $null -eq (Get-T5GuidText $Entry.DriverInstanceId) -or
            -not (Test-T5IntegerRange $transfer.RequestorProcessCreationTime 1 ([long]::MaxValue))) {
            $errors += 'v20 allocation lacks exact owner/session identity'
        }
        if (-not (Test-T5IntegerRange $Entry.AllocationReferenceKind 0 2) -or
            -not (Test-T5IntegerRange $Entry.AllocationDisposition 0 5)) {
            $errors += 'v20 allocation reference or disposition is outside the service enum'
        }
        $referenceKind = if (Test-T5IntegerRange $Entry.AllocationReferenceKind 0 2) { [int]$Entry.AllocationReferenceKind } else { -1 }
        $referenceId = Get-T5GuidText $Entry.AllocationReferenceId
        $expectedParentReferenceId = if ($null -ne $Entry.DeleteVersionIdentity) {
            Get-T5GuidText $Entry.DeleteVersionIdentity.TransferId
        } elseif ($null -ne $Entry.ParentVersionIdentity) {
            Get-T5GuidText $Entry.ParentVersionIdentity.TransferId
        } else { $null }
        if (($referenceKind -eq 0 -and $null -ne $Entry.AllocationReferenceId) -or
            ($referenceKind -in @(1, 2) -and $null -eq $referenceId) -or
            ($null -ne $Entry.ParentVersionIdentity -and ($referenceKind -ne 1 -or $referenceId -ne $expectedParentReferenceId)) -or
            ($null -eq $Entry.ParentVersionIdentity -and $referenceKind -eq 1)) {
            $errors += 'v20 allocation reference does not match exact parent ancestry'
        }
        if ($null -ne $Entry.CreateAfterReservationId -and
            ($null -eq (Get-T5GuidText $Entry.CreateAfterReservationId) -or
             $state -ne 12 -or $Entry.DiscardKind -ne 1 -or
             (Get-T5GuidText $Entry.DiscardReservationId) -ne (Get-T5GuidText $transfer.TransferId))) {
            $errors += 'CreateAfterReservationId is not bound to this exact V2 private-delete reservation'
        }
        if (-not (Test-T5IntegerRange $Entry.AttachmentStateV20 0 10) -or
            -not (Test-T5LifecycleEvidence $Entry ([int]$Entry.AttachmentStateV20) $state)) {
            $errors += 'v20 attachment receipts have invalid phase order or result binding'
        }
    }
    $discardRequest = Get-T5UtcValue $Entry.DiscardRequestedAtUtc
    $discardAck = Get-T5UtcValue $Entry.DiscardAcknowledgedAtUtc
    if ($null -ne $Entry.DiscardReservationId -and $null -eq (Get-T5GuidText $Entry.DiscardReservationId)) {
        $errors += 'DiscardReservationId is invalid'
    }
    if ($null -ne $Entry.DiscardKind -and -not (Test-T5IntegerRange $Entry.DiscardKind 1 7)) {
        $errors += 'DiscardKind is outside the service enum'
    }
    if (($null -ne $Entry.DiscardRequestedAtUtc -and $null -eq $discardRequest) -or
        ($null -ne $Entry.DiscardAcknowledgedAtUtc -and $null -eq $discardAck) -or
        ($null -ne $discardAck -and ($null -eq $discardRequest -or $discardAck -lt $discardRequest))) {
        $errors += 'discard request/ack timestamps are malformed or unordered'
    }
    $discardKindValue = if (Test-T5IntegerRange $Entry.DiscardKind 1 7) { [int]$Entry.DiscardKind } else { 0 }
    if ($state -eq 12) {
        if (-not $profileV20 -or $null -eq $Entry.StageIdentity -or
            -not (Test-T5IntegerRange $Entry.DestinationGeneration 1 ([long]::MaxValue)) -or
            (Get-T5GuidText $Entry.DiscardReservationId) -ne (Get-T5GuidText $transfer.TransferId) -or
            $null -eq $discardRequest -or
            $discardKindValue -notin @(1, 5, 6, 7) -or
            $Entry.StageCleanupStarted -eq $true -or $Entry.StageDeleted -eq $true) {
            $errors += 'DiscardPending lacks an exact private cleanup reservation'
        }
    } elseif ($state -eq 11 -and $null -ne $discardRequest) {
        if (-not $profileV20 -or (Get-T5GuidText $Entry.DiscardReservationId) -eq $null -or
            $discardKindValue -notin @(2, 3, 4)) {
            $errors += 'EmptyHeld cleanup request lacks an exact v20 reservation'
        }
        if ($discardKindValue -in @(3, 4) -and
            (Get-T5GuidText $Entry.DiscardReservationId) -ne (Get-T5GuidText $transfer.TransferId)) {
            $errors += 'Owner/unload empty cleanup is not self-reserved'
        }
    } elseif ($null -ne $Entry.DiscardReservationId -or $null -ne $Entry.DiscardKind -or
        $null -ne $discardRequest -or $null -ne $discardAck) {
        $errors += 'discard evidence exists outside DiscardPending or EmptyHeld'
    }
    if ($null -ne $Entry.NamespaceTombstones) {
        $node = $Entry.NamespaceTombstones; $count = 0
        while ($null -ne $node) {
            if (-not (Test-T5Object $node) -or -not (Test-T5HasProperty $node 'DestinationPath') -or
                -not (Test-T5HasProperty $node 'Generation') -or -not (Test-T5HasProperty $node 'Previous') -or
                -not (Test-T5NormalizedPath ([string]$node.DestinationPath)) -or
                -not (Test-T5IntegerRange $node.Generation 1 ([long]::MaxValue)) -or ++$count -gt 16) {
                $errors += 'NamespaceTombstones exceeds bounds or contains invalid identity'; break
            }
            $node = $node.Previous
        }
    }
    return $errors
}
function Get-T5Projection($Entry, [string]$ManifestPath) {
    $states = @(); $stateNames = @(); $stateDetails = @()
    if ($Entry.StateHistory -is [Array]) {
        $states = @($Entry.StateHistory | ForEach-Object { [string]$_.State })
        $stateNames = @($Entry.StateHistory | ForEach-Object { Get-T5StateName ([int]$_.State) })
        $stateDetails = @($Entry.StateHistory | ForEach-Object {
            [pscustomobject]@{ State = [int]$_.State; OccurredAtUtc = $_.OccurredAtUtc }
        })
    }
    $v20 = ((Test-T5HasProperty $Entry 'DriverInstanceId') -and $null -ne $Entry.DriverInstanceId)
    return [pscustomobject]@{
        TransferId = [string]$Entry.Transfer.TransferId; DestinationPath = [string]$Entry.Transfer.DestinationPath
        Destination = $Entry.Transfer.Destination; ProcessName = [string]$Entry.Transfer.ProcessName
        ProcessId = $Entry.Transfer.ProcessId; SessionId = $Entry.Transfer.SessionId
        RequestorSid = $Entry.Transfer.RequestorSid; RequestorProcessCreationTime = $Entry.Transfer.RequestorProcessCreationTime
        StagePath = [string]$Entry.Transfer.StagePath; State = [string]$Entry.State; UpdatedAtUtc = $Entry.UpdatedAtUtc
        StateName = (Get-T5StateName ([int]$Entry.State)); Sha256Hex = $Entry.Sha256Hex
        SealedOnce = $Entry.SealedOnce; SealedLength = $Entry.SealedLength
        StateHistory = $states; StateHistoryNames = $stateNames; StateHistoryDetails = $stateDetails
        HandbackState = [string]$Entry.HandbackState; StageDeleted = $Entry.StageDeleted
        StageCleanupStarted = $Entry.StageCleanupStarted; JustificationWindowClosed = $Entry.JustificationWindowClosed
        DestinationGeneration = $Entry.DestinationGeneration; StageIdentity = $Entry.StageIdentity
        ParentVersionIdentity = $Entry.ParentVersionIdentity; DeleteVersionIdentity = $Entry.DeleteVersionIdentity
        CreateReservationId = $Entry.CreateReservationId; CreateAfterReservationId = $Entry.CreateAfterReservationId
        AllocationReferenceId = $Entry.AllocationReferenceId; AllocationReferenceKind = $Entry.AllocationReferenceKind
        AllocationDisposition = $Entry.AllocationDisposition; DriverInstanceId = $Entry.DriverInstanceId
        ParentDirectoryIdentity = $Entry.ParentDirectoryIdentity; AttachmentStateV20 = $Entry.AttachmentStateV20
        AttachPrepareRequestIdV20 = $Entry.AttachPrepareRequestIdV20; AttachCommitRequestIdV20 = $Entry.AttachCommitRequestIdV20
        AttachCommitResultV20 = $Entry.AttachCommitResultV20; AttachAbortRequestIdV20 = $Entry.AttachAbortRequestIdV20
        CompletionPermitRequestIdV20 = $Entry.CompletionPermitRequestIdV20; RetireRequestIdV20 = $Entry.RetireRequestIdV20
        HandleObservedRequestIdV20 = $Entry.HandleObservedRequestIdV20
        DiscardReservationId = $Entry.DiscardReservationId; DiscardKind = $Entry.DiscardKind
        DiscardRequestedAtUtc = $Entry.DiscardRequestedAtUtc; DiscardAcknowledgedAtUtc = $Entry.DiscardAcknowledgedAtUtc
        EmptyHeldNotificationAttemptedAtUtc = $Entry.EmptyHeldNotificationAttemptedAtUtc
        EmptyHeldNotificationAttemptedByInstanceId = $Entry.EmptyHeldNotificationAttemptedByInstanceId
        EmptyHeldNotificationQueuedAtUtc = $Entry.EmptyHeldNotificationQueuedAtUtc
        EmptyHeldNotificationQueuedByInstanceId = $Entry.EmptyHeldNotificationQueuedByInstanceId
        NamespaceTombstones = $Entry.NamespaceTombstones; PendingRename = $Entry.PendingRename
        LastRenameTransactionId = $Entry.LastRenameTransactionId; LastRenameDestination = $Entry.LastRenameDestination
        LastRenameCommitted = $Entry.LastRenameCommitted; BlockedPolicyVersion = $Entry.BlockedPolicyVersion
        BlockedInspectionFailure = $Entry.BlockedInspectionFailure; JustificationExpiresAtUtc = $Entry.JustificationExpiresAtUtc
        HandbackPath = $Entry.HandbackPath; HandbackLength = $Entry.HandbackLength
        HandbackFailureReason = $Entry.HandbackFailureReason; HandbackLastAttemptAtUtc = $Entry.HandbackLastAttemptAtUtc
        Manifest = $ManifestPath; SchemaProfile = $(if ($v20) { 'V20' } else { 'LegacyBaseline' }); IsV20 = $v20
    }
}
function Get-T5EntryVersionKey($Entry) {
    if (-not $Entry.IsV20 -or -not (Test-T5StageIdentity $Entry.StageIdentity) -or
        -not (Test-T5IntegerRange $Entry.DestinationGeneration 1 ([long]::MaxValue))) { return $null }
    return ((Get-T5GuidText $Entry.TransferId) + '/' +
        (Get-T5IntegerText $Entry.DestinationGeneration) + '/' + (Get-T5StageIdentityKey $Entry.StageIdentity))
}
function Get-T5StateAtUtc($Entry, [int]$State) {
    if ($null -eq $Entry.StateHistoryDetails) { return $null }
    $matches = @($Entry.StateHistoryDetails | Where-Object { $_.State -eq $State })
    if ($matches.Count -eq 0) { return $null }
    $timestamp = $matches[-1].OccurredAtUtc
    return (Get-T5UtcValue $timestamp)
}
function Test-T5SameWriter($Left, $Right) {
    return ($Left.ProcessId -eq $Right.ProcessId -and $Left.SessionId -eq $Right.SessionId -and
        [string]::Equals([string]$Left.RequestorSid, [string]$Right.RequestorSid, [StringComparison]::OrdinalIgnoreCase) -and
        $Left.RequestorProcessCreationTime -eq $Right.RequestorProcessCreationTime)
}
function Test-T5SameWriterAndEpoch($Left, $Right) {
    return ($Left.IsV20 -and $Right.IsV20 -and (Test-T5SameWriter $Left $Right) -and
        (Get-T5GuidText $Left.DriverInstanceId) -ceq (Get-T5GuidText $Right.DriverInstanceId) -and
        $Left.Destination -eq $Right.Destination -and
        [string]::Equals([string]$Left.DestinationPath, [string]$Right.DestinationPath, [StringComparison]::OrdinalIgnoreCase))
}
function Get-T5TombstonesForPath($Entry, [string]$Path) {
    $matches = @(); $node = $Entry.NamespaceTombstones
    while ($null -ne $node) {
        if ([string]::Equals([string]$node.DestinationPath, $Path, [StringComparison]::OrdinalIgnoreCase)) {
            $matches += $node
        }
        $node = $node.Previous
    }
    return $matches
}
function Test-T5TerminalPrivateVersion($Entry) {
    if ($null -eq $Entry) { return $false }
    $state = [string]$Entry.State
    if ($state -notin @('11', '12') -or
        $null -eq $Entry.DiscardRequestedAtUtc -or $null -eq $Entry.DiscardAcknowledgedAtUtc -or
        $Entry.StageDeleted -isnot [bool] -or $Entry.StageDeleted -or
        $Entry.StageCleanupStarted -isnot [bool] -or $Entry.StageCleanupStarted -or
        -not (Test-T5StageIdentity $Entry.StageIdentity)) { return $false }
    $requested = Get-T5UtcValue $Entry.DiscardRequestedAtUtc
    $acknowledged = Get-T5UtcValue $Entry.DiscardAcknowledgedAtUtc
    if ($null -eq $requested -or $null -eq $acknowledged -or $acknowledged -lt $requested -or
        -not (Test-T5LifecycleEvidence $Entry ([int]$Entry.AttachmentStateV20) 12)) { return $false }
    $kind = if ($null -eq $Entry.DiscardKind) { 0 } else { [int]$Entry.DiscardKind }
    $reservation = Get-T5GuidText $Entry.DiscardReservationId
    $self = Get-T5GuidText $Entry.TransferId
    if ($null -eq $self -or $null -eq $reservation -or $reservation -cne $self) { return $false }
    if ($state -eq '11') {
        return ($kind -in @(3, 4) -and $Entry.SealedOnce -is [bool] -and $Entry.SealedOnce -and
            (Test-T5IntegerRange $Entry.SealedLength 0 0) -and $null -eq $Entry.Sha256Hex -and
            (Test-T5LifecycleEvidence $Entry ([int]$Entry.AttachmentStateV20) 11))
    }
    if ($state -ne '12') { return $false }
    switch ($kind) {
        1 { return $true }
        5 { return ($Entry.SealedOnce -is [bool] -and -not $Entry.SealedOnce -and $null -eq $Entry.SealedLength -and
                $null -eq $Entry.Sha256Hex -and [int]$Entry.AttachmentStateV20 -in @(0, 4)) }
        6 { return ($Entry.SealedOnce -is [bool] -and -not $Entry.SealedOnce -and $null -eq $Entry.SealedLength -and
                $null -eq $Entry.Sha256Hex -and [int]$Entry.AttachmentStateV20 -eq 8 -and
                $null -ne (Get-T5UInt64Text $Entry.RetireRequestIdV20)) }
        7 { return ($Entry.SealedOnce -is [bool] -and -not $Entry.SealedOnce -and $null -eq $Entry.SealedLength -and
                $null -eq $Entry.Sha256Hex -and [int]$Entry.AttachmentStateV20 -eq 10 -and
                $null -ne (Get-T5UInt64Text $Entry.RetireRequestIdV20)) }
        default { return $false }
    }
}
function Test-T5DirectEmptyHeldChildTerminal($Parent, $Child, [bool]$RequireReleasedStageDeleted) {
    if ($null -eq $Parent -or $null -eq $Child) { return $false }
    $parentId = Get-T5GuidText $Parent.TransferId
    $childId = Get-T5GuidText $Child.TransferId
    if ($null -eq $parentId -or $null -eq $childId -or $parentId -ceq $childId -or
        $Parent.State -ne '11' -or $Parent.SealedOnce -isnot [bool] -or -not $Parent.SealedOnce -or
        -not (Test-T5IntegerRange $Parent.SealedLength 0 0) -or
        $Parent.DiscardKind -ne 2 -or
        -not (Test-T5StageIdentity $Parent.StageIdentity) -or
        -not (Test-T5LifecycleEvidence $Parent ([int]$Parent.AttachmentStateV20) 11) -or
        -not (Test-T5SameWriterAndEpoch $Parent $Child) -or
        (Get-T5VersionIdentityKey $Child.ParentVersionIdentity) -cne (Get-T5EntryVersionKey $Parent) -or
        $null -ne $Child.DeleteVersionIdentity -or $null -ne $Child.CreateAfterReservationId -or
        (Get-T5GuidText $Parent.DiscardReservationId) -cne $childId -or
        (Get-T5GuidText $Child.CreateReservationId) -cne $childId -or
        -not (Test-T5NextGeneration $Parent.DestinationGeneration $Child.DestinationGeneration) -or
        -not (Test-T5IntegerRange $Child.AllocationDisposition 0 5) -or
        [int]$Child.AllocationReferenceKind -ne 1 -or
        (Get-T5GuidText $Child.AllocationReferenceId) -cne (Get-T5GuidText $Parent.TransferId) -or
        -not (Test-T5StageIdentity $Child.StageIdentity) -or
        (Get-T5StageIdentityKey $Child.StageIdentity) -ceq (Get-T5StageIdentityKey $Parent.StageIdentity) -or
        $null -ne $Child.PendingRename -or
        $Child.StageCleanupStarted -isnot [bool] -or $Child.StageCleanupStarted) { return $false }

    $privateDeleteAck = Test-T5TerminalPrivateVersion $Child
    $emptyOwnerExitAck = ($Child.State -eq '11' -and $Child.SealedOnce -is [bool] -and $Child.SealedOnce -and
        (Test-T5IntegerRange $Child.SealedLength 0 0) -and $null -eq $Child.Sha256Hex -and $Child.DiscardKind -in @(3, 4) -and
        (Get-T5GuidText $Child.DiscardReservationId) -ceq (Get-T5GuidText $Child.TransferId) -and
        $null -ne (Get-T5UtcValue $Child.DiscardRequestedAtUtc) -and
        $null -ne (Get-T5UtcValue $Child.DiscardAcknowledgedAtUtc) -and
        (Get-T5UtcValue $Child.DiscardAcknowledgedAtUtc) -ge (Get-T5UtcValue $Child.DiscardRequestedAtUtc) -and
        $Child.StageDeleted -is [bool] -and -not $Child.StageDeleted -and
        $Child.StageCleanupStarted -is [bool] -and -not $Child.StageCleanupStarted -and
        (Test-T5LifecycleEvidence $Child ([int]$Child.AttachmentStateV20) 11))
    $releasedStage = ($Child.State -eq '5' -and $Child.SealedOnce -is [bool] -and $Child.SealedOnce -and
        (Test-T5IntegerRange $Child.SealedLength 1 ([long]::MaxValue)) -and
        $Child.Sha256Hex -is [string] -and $Child.Sha256Hex -match '^[A-Fa-f0-9]{64}$' -and
        $Child.StageDeleted -is [bool] -and $Child.StageCleanupStarted -is [bool] -and
        -not $Child.StageCleanupStarted -and
        (Test-T5LifecycleEvidence $Child ([int]$Child.AttachmentStateV20) 5) -and
        ($Child.HandbackState -eq '0' -or
            ($Child.HandbackState -eq '2' -and $Child.JustificationWindowClosed -is [bool] -and $Child.JustificationWindowClosed -and
                $Child.StageDeleted -eq $true)))
    if (-not ($privateDeleteAck -or $emptyOwnerExitAck -or $releasedStage)) { return $false }
    if ($releasedStage -and $RequireReleasedStageDeleted -and $Child.StageDeleted -ne $true) { return $false }
    return $true
}
function Get-T5JournalLineageErrors($Entries) {
    $errors = @(); $byId = @{}
    foreach ($entry in @($Entries)) {
        $id = Get-T5GuidText $entry.TransferId
        if ($null -ne $id) { $byId[$id] = $entry }
    }
    foreach ($entry in @($Entries | Where-Object { $_.IsV20 })) {
        if ($entry.State -in @('1', '2', '3', '4', '5', '6', '7', '10', '11') -and
            [int]$entry.AttachmentStateV20 -ne 6) {
            $errors += [pscustomobject]@{ TransferId = $entry.TransferId; Error = 'sealed v20 state lacks the exact HandleObserved attachment receipt' }
        }
        $parentIdentity = $entry.ParentVersionIdentity
        $deletedIdentity = $entry.DeleteVersionIdentity
        $parent = $null; $deleted = $null
        if ($null -ne $parentIdentity) {
            $parentId = Get-T5GuidText $parentIdentity.TransferId
            if ($null -eq $parentId -or -not $byId.ContainsKey($parentId)) {
                $errors += [pscustomobject]@{ TransferId = $entry.TransferId; Error = 'v20 parent manifest is missing; legacy identity cannot be inferred' }
                continue
            }
            $parent = $byId[$parentId]
            $expectedReferenceId = if ($null -ne $deletedIdentity) {
                Get-T5GuidText $deletedIdentity.TransferId
            } else { $parentId }
            if (-not (Test-T5SameWriterAndEpoch $parent $entry) -or
                (Get-T5EntryVersionKey $parent) -cne (Get-T5VersionIdentityKey $parentIdentity) -or
                [int]$entry.AllocationReferenceKind -ne 1 -or
                (Get-T5GuidText $entry.AllocationReferenceId) -cne $expectedReferenceId) {
                $errors += [pscustomobject]@{ TransferId = $entry.TransferId; Error = 'v20 parent identity, allocation reference, writer, or epoch does not match' }
                continue
            }
            if ($null -eq $deletedIdentity) {
                if (-not (Test-T5NextGeneration $parent.DestinationGeneration $entry.DestinationGeneration)) {
                    $errors += [pscustomobject]@{ TransferId = $entry.TransferId; Error = 'direct v20 successor has invalid generation or CREATE_AFTER ancestry' }
                    continue
                }
                if ($null -ne $entry.CreateAfterReservationId) {
                    $afterId = Get-T5GuidText $entry.CreateAfterReservationId
                    if (-not $byId.ContainsKey($afterId)) {
                        $errors += [pscustomobject]@{ TransferId = $entry.TransferId; Error = 'CREATE_AFTER reservation has no exact child manifest' }
                        continue
                    }
                    $afterChild = $byId[$afterId]
                    if ($entry.State -ne '12' -or [int]$entry.DiscardKind -ne 1 -or
                        (Get-T5GuidText $entry.DiscardReservationId) -cne (Get-T5GuidText $entry.TransferId) -or
                        [int]$entry.AttachmentStateV20 -ne 6 -or
                        $null -eq (Get-T5UInt64Text $entry.CompletionPermitRequestIdV20) -or
                        $null -eq (Get-T5UInt64Text $entry.HandleObservedRequestIdV20) -or
                        (Get-T5UInt64Text $entry.CompletionPermitRequestIdV20) -eq
                            (Get-T5UInt64Text $entry.HandleObservedRequestIdV20) -or
                        (Get-T5VersionIdentityKey $afterChild.ParentVersionIdentity) -cne (Get-T5EntryVersionKey $parent) -or
                        (Get-T5VersionIdentityKey $afterChild.DeleteVersionIdentity) -cne (Get-T5EntryVersionKey $entry) -or
                        -not (Test-T5SameWriterAndEpoch $entry $afterChild) -or
                        -not (Test-T5NextGeneration $entry.DestinationGeneration $afterChild.DestinationGeneration)) {
                        $errors += [pscustomobject]@{ TransferId = $entry.TransferId; Error = 'CREATE_AFTER successor reservation does not resolve to the exact V3 child' }
                        continue
                    }
                }
            } else {
                $deletedId = Get-T5GuidText $deletedIdentity.TransferId
                if ($null -eq $deletedId -or -not $byId.ContainsKey($deletedId)) {
                    $errors += [pscustomobject]@{ TransferId = $entry.TransferId; Error = 'v20 deleted-version manifest is missing' }
                    continue
                }
                $deleted = $byId[$deletedId]
                if ((Get-T5EntryVersionKey $deleted) -cne (Get-T5VersionIdentityKey $deletedIdentity) -or
                    -not (Test-T5SameWriterAndEpoch $parent $deleted) -or
                    -not (Test-T5SameWriterAndEpoch $deleted $entry) -or
                    (Get-T5VersionIdentityKey $deleted.ParentVersionIdentity) -cne (Get-T5EntryVersionKey $parent) -or
                    -not (Test-T5NextGeneration $parent.DestinationGeneration $deleted.DestinationGeneration) -or
                    -not (Test-T5NextGeneration $deleted.DestinationGeneration $entry.DestinationGeneration) -or
                $deleted.AttachmentStateV20 -ne 6 -or
                $null -eq (Get-T5UInt64Text $deleted.CompletionPermitRequestIdV20) -or
                $null -eq (Get-T5UInt64Text $deleted.HandleObservedRequestIdV20) -or
                (Get-T5UInt64Text $deleted.CompletionPermitRequestIdV20) -eq
                    (Get-T5UInt64Text $deleted.HandleObservedRequestIdV20) -or
                    $deleted.State -ne '12' -or [int]$deleted.DiscardKind -ne 1 -or
                    (Get-T5GuidText $deleted.DiscardReservationId) -cne $deletedId -or
                    (Get-T5GuidText $deleted.CreateAfterReservationId) -cne (Get-T5GuidText $entry.TransferId) -or
                    [int]$entry.AllocationDisposition -ne 5) {
                    $errors += [pscustomobject]@{ TransferId = $entry.TransferId; Error = 'CREATE_AFTER does not bind the exact V1/V2/V3 identities and reservation' }
                    continue
                }
            }
        } elseif ([int]$entry.AllocationReferenceKind -eq 1 -or $null -ne $entry.DeleteVersionIdentity) {
            $errors += [pscustomobject]@{ TransferId = $entry.TransferId; Error = 'v20 allocation has a reference/delete tuple without its exact parent' }
            continue
        } elseif ([int]$entry.AllocationReferenceKind -eq 2) {
            $referenceId = Get-T5GuidText $entry.AllocationReferenceId
            if ($null -eq $referenceId -or -not $byId.ContainsKey($referenceId) -or
                -not (Test-T5SameWriter $byId[$referenceId] $entry) -or
                [int]$entry.AllocationDisposition -ne 2) {
                $errors += [pscustomobject]@{ TransferId = $entry.TransferId; Error = 'tombstone allocation reference is missing or belongs to a different writer' }
                continue
            }
            $owner = $byId[$referenceId]
            $requiredTombstoneGeneration = [decimal]([long]$entry.DestinationGeneration - 1)
            $matchingTombstones = @(Get-T5TombstonesForPath $owner $entry.DestinationPath | Where-Object {
                (Test-T5IntegerRange $_.Generation 1 ([long]::MaxValue)) -and
                [decimal]::Parse((Get-T5IntegerText $_.Generation), [Globalization.CultureInfo]::InvariantCulture) -eq $requiredTombstoneGeneration
            })
            if ($matchingTombstones.Count -ne 1) {
                $errors += [pscustomobject]@{ TransferId = $entry.TransferId; Error = 'tombstone allocation lacks one exact owner path/generation claim' }
                continue
            }
        }
        if ($entry.State -eq '12' -and $null -ne $entry.DiscardAcknowledgedAtUtc -and
            (Get-T5GuidText $entry.DiscardReservationId) -cne (Get-T5GuidText $entry.TransferId)) {
            $errors += [pscustomobject]@{ TransferId = $entry.TransferId; Error = 'acknowledged private cleanup is not self-reserved' }
        }
    }
    foreach ($parent in @($Entries | Where-Object { $_.IsV20 -and $_.State -eq '11' -and $null -ne $_.DiscardRequestedAtUtc })) {
        $kind = [int]$parent.DiscardKind
        $reservation = Get-T5GuidText $parent.DiscardReservationId
        $parentId = Get-T5GuidText $parent.TransferId
        if ($kind -in @(3, 4)) {
            if ($reservation -cne $parentId) {
                $errors += [pscustomobject]@{ TransferId = $parent.TransferId; Error = 'EmptyHeld owner/unload cleanup is not self-reserved' }
            }
            if ([int]$parent.AttachmentStateV20 -ne 6) {
                $errors += [pscustomobject]@{ TransferId = $parent.TransferId; Error = 'EmptyHeld owner/unload cleanup lacks exact HandleObserved proof' }
            }
            continue
        }
        if ($kind -ne 2) { continue }
        if ([int]$parent.AttachmentStateV20 -ne 6) {
            $errors += [pscustomobject]@{ TransferId = $parent.TransferId; Error = 'EmptyHeld predecessor cleanup lacks exact HandleObserved proof' }
        }
        if (-not $byId.ContainsKey($reservation)) {
            $errors += [pscustomobject]@{ TransferId = $parent.TransferId; Error = 'EmptyHeld predecessor cleanup names no exact child reservation' }
            continue
        }
        $child = $byId[$reservation]
        if (-not (Test-T5SameWriterAndEpoch $parent $child)) {
            $errors += [pscustomobject]@{ TransferId = $parent.TransferId; Error = 'EmptyHeld cleanup child has a different writer or driver epoch' }
            continue
        }
        if ($null -eq $child.DeleteVersionIdentity) {
            $childTerminal = Test-T5DirectEmptyHeldChildTerminal $parent $child $false
            $childTerminalForAck = Test-T5DirectEmptyHeldChildTerminal $parent $child $true
            if (-not $childTerminal) {
                $errors += [pscustomobject]@{ TransferId = $parent.TransferId; Error = 'direct EmptyHeld cleanup child fails exact identity, rename, attachment, or terminal-state checks' }
                continue
            }
            if ($null -ne $parent.DiscardAcknowledgedAtUtc -and -not $childTerminalForAck) {
                $errors += [pscustomobject]@{ TransferId = $parent.TransferId; Error = 'acknowledged direct EmptyHeld cleanup lacks child terminal or HandleObserved proof' }
            }
            if ($null -ne $parent.DiscardAcknowledgedAtUtc -and $child.State -eq '5' -and
                (Get-T5UtcValue $child.UpdatedAtUtc) -gt (Get-T5UtcValue $parent.DiscardAcknowledgedAtUtc)) {
                $errors += [pscustomobject]@{ TransferId = $parent.TransferId; Error = 'released child disposal receipt is newer than EmptyHeld cleanup ACK' }
            }
            $directProofAt = if (Test-T5TerminalPrivateVersion $child) {
                Get-T5UtcValue $child.DiscardAcknowledgedAtUtc
            } elseif ($child.State -eq '5') {
                Get-T5StateAtUtc $child 5
            } else { $null }
            if ($null -ne $directProofAt -and $null -ne $parent.DiscardRequestedAtUtc -and
                $directProofAt -gt (Get-T5UtcValue $parent.DiscardRequestedAtUtc)) {
                $errors += [pscustomobject]@{ TransferId = $parent.TransferId; Error = 'direct child terminal receipt occurs after predecessor cleanup intent' }
            }
        } else {
            $v2Id = Get-T5GuidText $child.DeleteVersionIdentity.TransferId
            if ($reservation -cne (Get-T5GuidText $child.TransferId) -or
                $null -eq $v2Id -or -not $byId.ContainsKey($v2Id)) {
                if ($null -ne $parent.DiscardRequestedAtUtc) {
                    $errors += [pscustomobject]@{ TransferId = $parent.TransferId; Error = 'pending CREATE_AFTER cleanup has no exact V2 delete manifest' }
                }
                continue
            }
            $v2 = $byId[$v2Id]
            if ($v2.State -ne '12' -or [int]$v2.DiscardKind -ne 1 -or
                (Get-T5GuidText $v2.DiscardReservationId) -cne $v2Id -or
                (Get-T5GuidText $v2.CreateAfterReservationId) -cne (Get-T5GuidText $child.TransferId) -or
                $null -eq $v2.DiscardAcknowledgedAtUtc) {
                if ($null -ne $parent.DiscardRequestedAtUtc) {
                    $errors += [pscustomobject]@{ TransferId = $parent.TransferId; Error = 'pending CREATE_AFTER cleanup lacks V2 delete ACK and exact V3 child' }
                }
                continue
            }
            $v3 = $child
            $validV3 = ((Get-T5VersionIdentityKey $v3.ParentVersionIdentity) -ceq (Get-T5EntryVersionKey $parent) -and
                (Get-T5VersionIdentityKey $v3.DeleteVersionIdentity) -ceq (Get-T5EntryVersionKey $v2) -and
                (Test-T5SameWriterAndEpoch $parent $v3) -and
                ((Test-T5TerminalPrivateVersion $v3) -or
                    ($v3.AttachmentStateV20 -eq 6 -and
                     $null -ne (Get-T5UInt64Text $v3.HandleObservedRequestIdV20) -and
                     $null -ne (Get-T5UInt64Text $v3.CompletionPermitRequestIdV20))))
            if ($null -ne $parent.DiscardRequestedAtUtc -and -not $validV3) {
                $errors += [pscustomobject]@{ TransferId = $parent.TransferId; Error = 'pending CREATE_AFTER parent cleanup lacks exact V3 HandleObserved or terminal cleanup proof' }
            }
            if ($null -ne $parent.DiscardRequestedAtUtc -and $validV3) {
                $parentIntentAt = Get-T5UtcValue $parent.DiscardRequestedAtUtc
                $v2AckAt = Get-T5UtcValue $v2.DiscardAcknowledgedAtUtc
                $v3TerminalProofAt = if (Test-T5TerminalPrivateVersion $v3) {
                    Get-T5UtcValue $v3.DiscardAcknowledgedAtUtc
                } else { $null }
                if (($null -ne $v2AckAt -and $v2AckAt -gt $parentIntentAt) -or
                    ($null -ne $v3TerminalProofAt -and $v3TerminalProofAt -gt $parentIntentAt)) {
                    $errors += [pscustomobject]@{ TransferId = $parent.TransferId; Error = 'CREATE_AFTER predecessor cleanup intent precedes its exact V2/V3 terminal receipts' }
                }
            }
        }
    }
    return $errors
}
function Get-T5EmptyProbeOutcome($Journal, [bool]$NativeStepsOk) {
    $held = @($Journal | Where-Object { $_.IsV20 -and $_.State -eq '11' -and
        $_.SealedOnce -is [bool] -and $_.SealedOnce -and (Test-T5IntegerRange $_.SealedLength 0 0) -and
        (Test-T5StageIdentity $_.StageIdentity) })
    $discarded = @($Journal | Where-Object { $_.IsV20 -and $_.State -eq '9' -and
        $_.SealedOnce -is [bool] -and -not $_.SealedOnce -and
        $null -eq $_.Sha256Hex -and $_.StateHistory -contains '9' })
    $unsealedAck = @($Journal | Where-Object { $_.IsV20 -and $_.State -eq '12' -and
        $_.SealedOnce -is [bool] -and -not $_.SealedOnce -and $null -eq $_.SealedLength -and
        $null -ne $_.DiscardAcknowledgedAtUtc -and $_.DiscardKind -in @(1, 5, 6, 7) -and
        (Test-T5TerminalPrivateVersion $_) })
    $unsealedPending = @($Journal | Where-Object { $_.IsV20 -and $_.State -eq '12' -and
        $_.SealedOnce -is [bool] -and -not $_.SealedOnce -and $null -eq $_.SealedLength -and $null -eq $_.Sha256Hex -and
        $null -ne $_.DiscardRequestedAtUtc -and $null -eq $_.DiscardAcknowledgedAtUtc -and
        $_.DiscardKind -in @(1, 5, 6, 7) -and (Test-T5StageIdentity $_.StageIdentity) -and
        (Test-T5LifecycleEvidence $_ ([int]$_.AttachmentStateV20) 12) })
    $cleanup = @($Journal | Where-Object { $null -ne $_.DiscardRequestedAtUtc -and
        $null -ne $_.DiscardAcknowledgedAtUtc })
    $lineageErrors = @(Get-T5JournalLineageErrors $Journal)
    $heldAck = @($held | Where-Object {
        $requested = Get-T5UtcValue $_.DiscardRequestedAtUtc
        $acknowledged = Get-T5UtcValue $_.DiscardAcknowledgedAtUtc
        $_.DiscardKind -in @(3, 4) -and
        (Get-T5GuidText $_.DiscardReservationId) -ceq (Get-T5GuidText $_.TransferId) -and
        $null -ne $requested -and $null -ne $acknowledged -and $acknowledged -ge $requested -and
        $_.StageDeleted -is [bool] -and -not $_.StageDeleted -and
        $_.StageCleanupStarted -is [bool] -and -not $_.StageCleanupStarted -and
        (Test-T5LifecycleEvidence $_ ([int]$_.AttachmentStateV20) 11)
    })
    $heldPredecessorAck = @($held | Where-Object {
        $record = $_
        $requested = Get-T5UtcValue $record.DiscardRequestedAtUtc
        $acknowledged = Get-T5UtcValue $record.DiscardAcknowledgedAtUtc
        $record.DiscardKind -eq 2 -and $null -ne $record.DiscardAcknowledgedAtUtc -and
        (Get-T5GuidText $record.DiscardReservationId) -cne (Get-T5GuidText $record.TransferId) -and
        $null -ne $requested -and $null -ne $acknowledged -and $acknowledged -ge $requested -and
        $record.StageDeleted -is [bool] -and -not $record.StageDeleted -and
        $record.StageCleanupStarted -is [bool] -and -not $record.StageCleanupStarted -and
        (@($lineageErrors | Where-Object {
            (Get-T5GuidText $_.TransferId) -ceq (Get-T5GuidText $record.TransferId)
        }).Count -eq 0)
    })
    $privateCleanup = @($heldAck + $heldPredecessorAck + $unsealedAck)
    $privateRecords = @($held + $discarded + $unsealedAck)
    $outcomeKind = 'NONE'
    if ($NativeStepsOk -and $held.Count -gt 0) { $outcomeKind = 'EMPTY_HELD_PRIVATE' }
    elseif ($NativeStepsOk -and $discarded.Count -gt 0) { $outcomeKind = 'PRESEAL_PRIVATE_DELETE' }
    elseif ($NativeStepsOk -and $unsealedAck.Count -gt 0) { $outcomeKind = 'PRIVATE_DELETE_ACKNOWLEDGED' }
    elseif ($NativeStepsOk -and $unsealedPending.Count -gt 0) { $outcomeKind = 'PRIVATE_DELETE_PENDING_ACK' }
    return [pscustomobject]@{
        Verified = ($NativeStepsOk -and ($privateRecords.Count + $unsealedPending.Count) -gt 0)
        Kind = $outcomeKind
        EmptyHeldRecords = $held
        PresealDiscardedRecords = $discarded
        UnsealedCleanupAcknowledgedRecords = $unsealedAck
        UnsealedCleanupPendingRecords = $unsealedPending
        CleanupAcknowledgedRecords = $cleanup
        PrivateOutcomeCleanupAcknowledgedRecords = $privateCleanup
        CleanupAcknowledged = ($privateCleanup.Count -gt 0)
    }
}
function Get-JournalFor([string]$Destination, [string[]]$BaselineTransferIds, [switch]$RequireHistoryForNewRecords) {
    $records = @(); $parseErrors = @(); $schemaErrors = @(); $allEntries = @(); $allById = @{}
    $files = @()
    try { $files = @(Get-ChildItem -LiteralPath $journalDir -Filter '*.json' -File -Force -ErrorAction Stop) }
    catch {
        $parseErrors += [pscustomobject]@{ Path = $journalDir; Error = $_.Exception.Message }
        return [pscustomobject]@{ Records = $records; ParseErrors = $parseErrors; SchemaErrors = $schemaErrors }
    }
    if ($files.Count -gt 1024) {
        $parseErrors += [pscustomobject]@{ Path = $journalDir; Error = 'Journal exceeds the 1024-manifest inspection bound.' }
        return [pscustomobject]@{ Records = $records; ParseErrors = $parseErrors; SchemaErrors = $schemaErrors }
    }
    $totalManifestBytes = [long]0
    foreach ($file in $files) {
        try {
            if ($file.Length -gt 131072) { throw 'Manifest exceeds the service 128-KiB limit.' }
            $totalManifestBytes += [long]$file.Length
            if ($totalManifestBytes -gt 67108864) { throw 'Journal exceeds the 64-MiB inspection bound.' }
            $json = [IO.File]::ReadAllText($file.FullName)
            if (-not (Test-T5JsonDepthBound $json 32)) { throw 'Manifest JSON exceeds the 32-level depth bound or is unbalanced.' }
            $entry = $json | ConvertFrom-Json -ErrorAction Stop
            if (-not (Test-T5Object $entry) -or -not (Test-T5Object $entry.Transfer) -or
                -not (Test-T5HasProperty $entry.Transfer 'DestinationPath') -or $entry.Transfer.DestinationPath -isnot [string] -or
                [string]::IsNullOrWhiteSpace([string]$entry.Transfer.DestinationPath)) {
                $schemaErrors += [pscustomobject]@{ Path = $file.FullName; Error = 'Cannot bind manifest to a destination; required Transfer.DestinationPath is missing or invalid.' }
                continue
            }
            $id = Get-T5GuidText $entry.Transfer.TransferId
            if ($null -eq $id -or $id -cne [IO.Path]::GetFileNameWithoutExtension($file.Name).ToLowerInvariant()) {
                $schemaErrors += [pscustomobject]@{ Path = $file.FullName; Error = 'TransferId does not bind to manifest filename.' }
                continue
            }
            $allById[$id] = [pscustomobject]@{ Entry = $entry; Path = $file.FullName; Id = $id }
        } catch { $parseErrors += [pscustomobject]@{ Path = $file.FullName; Error = $_.Exception.Message } }
    }
    $targetIds = @($allById.Values | Where-Object {
        [string]::Equals([string]$_.Entry.Transfer.DestinationPath, $Destination, [StringComparison]::OrdinalIgnoreCase)
    } | ForEach-Object { $_.Id })
    $relevant = @{}; $queue = New-Object 'System.Collections.Generic.Queue[string]'
    foreach ($id in $targetIds) { if (-not $relevant.ContainsKey($id)) { $relevant[$id] = $true; $queue.Enqueue($id) } }
    while ($queue.Count -gt 0) {
        $currentId = $queue.Dequeue()
        $current = $allById[$currentId].Entry
        $references = @()
        foreach ($name in @('ParentVersionIdentity', 'DeleteVersionIdentity')) {
            if ($null -ne $current.$name -and (Test-T5HasProperty $current.$name 'TransferId')) {
                $references += Get-T5GuidText $current.$name.TransferId
            }
        }
        foreach ($name in @('CreateAfterReservationId')) {
            if ($null -ne $current.$name) { $references += Get-T5GuidText $current.$name }
        }
        if ($null -ne $current.DiscardReservationId -and $current.DiscardKind -eq 2) {
            $references += Get-T5GuidText $current.DiscardReservationId
        }
        if ($null -ne $current.AllocationReferenceId -and $current.AllocationReferenceKind -eq 2) {
            $references += Get-T5GuidText $current.AllocationReferenceId
        }
        foreach ($reference in $references) {
            if ($null -ne $reference -and $allById.ContainsKey($reference) -and -not $relevant.ContainsKey($reference)) {
                $relevant[$reference] = $true; $queue.Enqueue($reference)
            }
        }
    }
    $lineageEntries = @()
    foreach ($id in @($relevant.Keys)) {
        $item = $allById[$id]; $entry = $item.Entry
        $isTarget = $targetIds -contains $id
        $isBaseline = @($BaselineTransferIds) -contains $id
        $requireHistory = ($RequireHistoryForNewRecords -and $isTarget -and -not $isBaseline)
        $requireV20 = ($requireHistory -or ($null -ne $entry.DriverInstanceId))
        $entryErrors = @(Get-JournalSchemaErrors $entry $item.Path -RequireStateHistory:$requireHistory -RequireV20:$requireV20)
        if ($entryErrors.Count -gt 0) {
            foreach ($errorText in $entryErrors) { $schemaErrors += [pscustomobject]@{ Path = $item.Path; Error = [string]$errorText } }
            continue
        }
        $lineageEntries += Get-T5Projection $entry $item.Path
    }
    foreach ($lineageError in @(Get-T5JournalLineageErrors $lineageEntries)) {
        $path = $null
        $lineageId = Get-T5GuidText $lineageError.TransferId
        if ($null -ne $lineageId -and $allById.ContainsKey($lineageId)) { $path = $allById[$lineageId].Path }
        $schemaErrors += [pscustomobject]@{ Path = $path; Error = [string]$lineageError.Error }
    }
    $records = @($lineageEntries | Where-Object {
        [string]::Equals([string]$_.DestinationPath, $Destination, [StringComparison]::OrdinalIgnoreCase)
    })
    return [pscustomobject]@{ Records = $records; ParseErrors = $parseErrors; SchemaErrors = $schemaErrors }
}
function Get-Handback([string]$Directory, [string[]]$BeforePaths, [byte[]]$Expected) {
    $all = @(Get-ChildItem -LiteralPath $Directory -Filter '*.txt' -File -Force -ErrorAction SilentlyContinue)
    $new = @($all | Where-Object { $BeforePaths -notcontains $_.FullName })
    $receipt = [ordered]@{ Status = 'INCOMPLETE'; NewFileCount = $new.Count; Path = $null; Length = $null; Sha256 = $null; Readers = @(); Error = $null }
    if ($new.Count -ne 1) { $receipt.Error = 'Expected exactly one newly created hand-back file.'; return [pscustomobject]$receipt }
    $path = $new[0].FullName; $direct = Read-Public $path; $receipt.Path = $path; $receipt.Length = $direct.Length; $receipt.Sha256 = $direct.Sha256
    $readers = @(); $allGood = ($direct.Status -ceq 'OK' -and (Same $direct.Bytes $Expected))
    foreach ($raw in @($false, $true)) {
        try {
            $native = [StagedInvariant.Native]::Fresh($path, $raw, $rawContext.Geometry.Alignment)
            $good = ($native.Status -ceq 'OK' -and $native.Length -eq $Expected.Length -and $native.Digest -ceq (Sha $Expected))
            if (-not $good) { $allGood = $false }
            $readers += [pscustomobject]@{ Unbuffered = $raw; Status = $native.Status; Length = $native.Length; Sha256 = $native.Digest; NativeCode = 0 }
        } catch {
            $allGood = $false; $readers += [pscustomobject]@{ Unbuffered = $raw; Status = 'ERROR'; Length = $null; Sha256 = $null; NativeCode = $null; Error = $_.Exception.ToString() }
        }
    }
    $receipt.Readers = $readers
    if ($allGood) { $receipt.Status = 'PASS' } else { $receipt.Status = 'FAIL'; $receipt.Error = 'Buffered hand-back and both fresh readers must match the exact unapproved fixture.' }
    return [pscustomobject]$receipt
}

$script:n = 0
New-Item -ItemType Directory -Force -Path $out, $control | Out-Null
try {
    Import-Module -Name $ObserverModule -Force -DisableNameChecking -ErrorAction Stop
    $rawContext = Open-InvariantObserver ([StagedInvariant.Native]::ResolveGuid($root)) $root (Join-Path $out 'raw') 'T5'
    if ($rawContext.Status -cne 'OK') { throw ('Raw observer open failed: ' + ($rawContext.Error | ConvertTo-Json -Depth 12 -Compress)) }
    $rawContext | Add-Member -NotePropertyName NamedOpenAttributesOnly -NotePropertyValue $true
    $observerProcess = Get-CimInstance Win32_Process -Filter ('ProcessId=' + $PID)
    $observerOwner = Invoke-CimMethod -InputObject $observerProcess -MethodName GetOwnerSid
    if ($observerOwner.ReturnValue -ne 0 -or $observerOwner.Sid -cne 'S-1-5-18' -or $rawContext.ObserverSid -cne 'S-1-5-18') { throw 'Raw observer is not the independent SYSTEM process.' }
    $expected = @{}; foreach ($leaf in $leaves) { $expected[$leaf] = $null }
    $rawBaseline = Capture-InvariantBaseline $rawContext $leaves $expected
    if ($rawBaseline.Status -cne 'OK' -or $rawBaseline.CaseId -cne 'T5' -or $rawBaseline.ObserverPid -ne $PID -or $rawBaseline.ObserverSid -cne 'S-1-5-18') {
        throw ('Raw baseline missing/invalid: ' + ($rawBaseline.Error | ConvertTo-Json -Depth 12 -Compress))
    }
    $baselineParent = @($rawBaseline.Images | Where-Object { $_.Role -ceq 'Parent' -and $_.Path -ieq $root })
    if ($baselineParent.Count -ne 1 -or @($baselineParent[0].DirectoryEntries).Count -ne 0) { throw 'T5 destination must start with an independently raw-observed empty directory.' }
    $baselineParentIdentity = $baselineParent[0].Identity
    if ($null -eq $baselineParentIdentity -or [string]::IsNullOrWhiteSpace([string]$baselineParentIdentity.FileId) -or
        [string]::IsNullOrWhiteSpace([string]$baselineParentIdentity.Reference)) { throw 'Raw baseline parent FileId/reference identity is missing.' }
    $script:baselineParentFileId = [string]$baselineParentIdentity.FileId
    $script:baselineParentReference = [string]$baselineParentIdentity.Reference
    $actorStarted = Join-Path $control 'actor-started.txt'
    if (Test-Path -LiteralPath $actorStarted) { Remove-Item -LiteralPath $actorStarted -Force }
    Start-ScheduledTask -TaskName $ActorTask -ErrorAction Stop
    $result.ActorTaskStartIssued = $true
    'ACTOR_TASK_START_ISSUED=True'
    $deadline = [Diagnostics.Stopwatch]::GetTimestamp() + 120 * $frequency
    while (-not (Test-Path -LiteralPath $actorStarted)) { if ([Diagnostics.Stopwatch]::GetTimestamp() -gt $deadline) { throw 'the actor did not start' }; Start-Sleep -Milliseconds 200 }
    $result.Actor = (Read-ControlText $actorStarted).Trim()
    $sid = (New-Object Security.Principal.NTAccount($env:COMPUTERNAME, $ActorUser)).Translate([Security.Principal.SecurityIdentifier]).Value
    $actorMatch = [regex]::Match($result.Actor, 'pid=(\d+).*user=([^ ]+).*session=(\d+)')
    if (-not $actorMatch.Success -or $actorMatch.Groups[2].Value -ine ($env:COMPUTERNAME + '\' + $ActorUser) -or $sid -ceq 'S-1-5-18') { throw 'Standard-user actor identity/session receipt is incomplete.' }
    $actorPid = [int]$actorMatch.Groups[1].Value
    if ($actorPid -eq $rawContext.ObserverPid -or $rawContext.ObserverSid -ceq $sid) { throw 'Actor and raw observer are not independent processes/principals.' }
    $profile = @(Get-CimInstance Win32_UserProfile | Where-Object { $_.SID -eq $sid })
    if ($profile.Count -ne 1) { throw 'Exactly one actor profile must bind to the actor SID.' }
    $handback = Join-Path $profile[0].LocalPath 'SafeUpload\_bloqueados'
    $cases = @(
        @{ Op = 'probe-delete-before-seal'; Leaf = 'probe-delete.txt'; Sensitive = $false; Kind = 'ProbeDelete' },
        @{ Op = 'probe-delete-after-publication'; Leaf = 'probe-after-publication.txt'; Sensitive = $false; Kind = 'ProbeDeleteAfterPublication' },
        @{ Op = 'probe-delete-before-seal'; Leaf = 'probe-before-cpf.txt'; Sensitive = $true; Kind = 'ProbeDeleteBeforeSealCpf' },
        @{ Op = 'probe-delete-after-publication'; Leaf = 'probe-after-cpf.txt'; Sensitive = $true; Kind = 'ProbeDeleteAfterPublicationCpf' },
        @{ Op = 'probe-doc'; Leaf = 'probe-doc.txt'; Sensitive = $false; Kind = 'ProbeDeleteOnClose' },
        @{ Op = 'probe-onclose'; Leaf = 'probe-onclose.txt'; Sensitive = $false; Kind = 'OnCloseCancellation' },
        @{ Op = 'notepad'; Leaf = 'ok.txt'; Sensitive = $false; Kind = 'NotepadApprove' },
        @{ Op = 'notepad'; Leaf = 'cpf.txt'; Sensitive = $true; Kind = 'NotepadHandBack' }
    )
    foreach ($case in $cases) {
        $path = Join-Path $root $case.Leaf
        $text = if ($case.Sensitive) { $cpfText } else { 'T5 ' + $case.Kind + ' clean text' }
        $bytes = [Text.Encoding]::ASCII.GetBytes($text)
        $beforeJournal = Get-JournalFor $path
        if (@($beforeJournal.ParseErrors).Count -gt 0 -or @($beforeJournal.SchemaErrors).Count -gt 0) { throw 'Pre-case journal parsing/schema validation failed; the case cannot bind a trustworthy baseline.' }
        $beforeIds = @($beforeJournal.Records | ForEach-Object { $_.TransferId })
        $beforeHandback = @(Get-ChildItem -LiteralPath $handback -Filter '*.txt' -File -Force -ErrorAction SilentlyContinue | ForEach-Object { $_.FullName })
        $record = [ordered]@{ Op = $case.Op; Kind = $case.Kind; Leaf = $case.Leaf; Path = $path; Sensitive = [bool]$case.Sensitive; ExpectedLength = $bytes.Length;
            ExpectedSha256 = (Sha $bytes); Ack = $null; Published = $false; HandedBack = $false; Handback = $null; Leaked = $false; FinalLength = -1;
            FinalSha256 = $null; Owner = $null; Journal = @(); JournalParseErrors = @(); JournalSchemaErrors = @(); ProbeDiscarded = $false;
            ProbeEmptyPrivateOutcome = $false; ProbeEmptyPrivateOutcomeKind = 'NONE'; ProbeEmptyPrivateBlocked = $false;
            ProbeEmptyHeldPrivateRecords = @();
            ProbePresealPrivateDeleteRecords = @(); ProbeCleanupPendingRecords = @(); ProbeCleanupAcknowledged = $false; ProbeCleanupAcknowledgedRecords = @();
            ProbeAllCleanupAcknowledgedRecords = @();
            NoEmptyLeftover = $false; ForcedOrderProof = $null;
            EmptyVersionPublicationRecords = @(); EmptyRawPublicationSamples = @(); FinalJournalOutcomeVerified = $false; SettlementStatus = 'INCOMPLETE';
            NativeStepsChecked = $false; NativeStepsOk = $true; NativeStepsReason = ''; RawSamples = @(); RawCoverageComplete = $true; IndependentReadersAgree = $true;
            ProbeControlSamples = 0; ProbeControlTargetAbsentThroughout = $false; FinalRawMatches = $false; Error = $null }
        $observe = { param($phase) Capture-T5Observation $record ([string]$phase) }.GetNewClosure()
        $record.Ack = Invoke-Actor $case.Op $path $text $observe $beforeIds $record
        if ($record.Ack.Error) { $record.Error = [string]$record.Ack.Error }
        # Empty content may publish normally. Wait for the exact final nonempty save/handback outcome;
        # an intermediate empty probe neither passes this outcome nor terminates settlement.
        $emptyDigest = 'E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855'
        $publishedStates = @('3','4','5','Approved','Publishing','Released')
        $settleDeadline = [Diagnostics.Stopwatch]::GetTimestamp() + 90 * $frequency
        $lastSettleSample = [long]0; $settled = $false
        while (-not $settled -and [Diagnostics.Stopwatch]::GetTimestamp() -lt $settleDeadline) {
            $now = [Diagnostics.Stopwatch]::GetTimestamp()
            if ($lastSettleSample -eq 0 -or $now - $lastSettleSample -ge [long]($frequency / 2)) {
                [void](Capture-T5Observation $record 'AfterActorAcknowledgementSettlement')
                $lastSettleSample = [Diagnostics.Stopwatch]::GetTimestamp()
            }
            $journalNow = Get-JournalFor -Destination $path -BaselineTransferIds $beforeIds -RequireHistoryForNewRecords
            $newNow = @($journalNow.Records | Where-Object { $beforeIds -notcontains $_.TransferId })
            $record.JournalParseErrors = $journalNow.ParseErrors
            $record.JournalSchemaErrors = $journalNow.SchemaErrors
            $record.Journal = $journalNow.Records
            if (@($journalNow.ParseErrors).Count -gt 0 -or @($journalNow.SchemaErrors).Count -gt 0) { Start-Sleep -Milliseconds 100; continue }
            $emptyNow = @($newNow | Where-Object { $_.Sha256Hex -ieq $emptyDigest -and
                (@($_.StateHistory | Where-Object { $publishedStates -contains $_ }).Count -gt 0 -or $publishedStates -contains $_.State) })
            $record.EmptyVersionPublicationRecords = $emptyNow
            if ($case.Sensitive) {
                $finalRecords = @($newNow | Where-Object { $_.Sha256Hex -ieq $record.ExpectedSha256 -and
                    $_.State -in @('5','6','Released','Blocked') -and $_.HandbackState -in @('2','Verified') })
                if ($finalRecords.Count -gt 0) {
                    $record.Handback = Get-Handback $handback $beforeHandback $bytes
                    if ($record.Handback.Status -ceq 'PASS') { $record.SettlementStatus = 'PASS'; $record.FinalJournalOutcomeVerified = $true; $settled = $true }
                }
            } else {
                $finalRecords = @($newNow | Where-Object { $_.Sha256Hex -ieq $record.ExpectedSha256 -and $_.State -in @('5','Released') })
                if ($finalRecords.Count -gt 0) { $record.SettlementStatus = 'PASS'; $record.FinalJournalOutcomeVerified = $true; $settled = $true }
            }
            Start-Sleep -Milliseconds 100
        }
        if (-not $settled -and $record.SettlementStatus -eq 'INCOMPLETE') { $record.SettlementStatus = 'TIMEOUT' }
        # A final three-sample bracket binds the result to the settled public generation.
        for ($i = 0; $i -lt 3; ++$i) { [void](Capture-T5Observation $record 'AfterActorOutcomeSettlement'); Start-Sleep -Milliseconds 150 }
        if (@($record.RawSamples).Count -eq 0 -or @($record.RawSamples | Where-Object { $_.Status -cne 'OK' }).Count -gt 0) { $record.RawCoverageComplete = $false }
        if (@($record.RawSamples | Where-Object { -not $_.IndependentReadersAgree }).Count -gt 0) { $record.IndependentReadersAgree = $false }
        $targetRows = @($record.RawSamples | ForEach-Object { @($_.CurrentImages | Where-Object { $_.Path -ieq $path }) } | Where-Object { $null -ne $_ })
        $lastTarget = if ($targetRows.Count) { $targetRows[-1] } else { $null }
        if ($null -ne $lastTarget -and -not $case.Sensitive) {
            $record.FinalRawMatches = ($lastTarget.Absent -eq $false -and $lastTarget.Length -eq $bytes.Length -and $lastTarget.Sha256 -ceq (Sha $bytes))
        } elseif ($null -ne $lastTarget -and $case.Sensitive) { $record.FinalRawMatches = ($lastTarget.Absent -eq $true) }
        $final = Read-Public $path
        if ($final.Status -eq 'OK') { $record.FinalLength = $final.Length; $record.FinalSha256 = $final.Sha256; $record.Owner = try { (Get-Acl -LiteralPath $path).Owner } catch { $null } }
        if ($case.Sensitive) {
            $record.Leaked = [bool]$record.Leaked -or @($record.RawSamples | Where-Object { $_.ForbiddenBytesObserved }).Count -gt 0 -or
                ($final.Status -eq 'OK' -and $final.Length -gt 0)
            $record.Handback = Get-Handback $handback $beforeHandback $bytes
            $record.HandedBack = ($record.Handback.Status -ceq 'PASS')
        }
        $afterJournal = Get-JournalFor -Destination $path -BaselineTransferIds $beforeIds -RequireHistoryForNewRecords
        $record.JournalParseErrors = $afterJournal.ParseErrors
        $record.JournalSchemaErrors = $afterJournal.SchemaErrors
        $record.Journal = $afterJournal.Records
        $newJournal = @($afterJournal.Records | Where-Object { $beforeIds -notcontains $_.TransferId })
        $record.EmptyVersionPublicationRecords = @($newJournal | Where-Object { $_.Sha256Hex -ieq $emptyDigest -and
            (@($_.StateHistory | Where-Object { $publishedStates -contains $_ }).Count -gt 0 -or $publishedStates -contains $_.State) })
        $record.EmptyRawPublicationSamples = @($record.RawSamples | ForEach-Object {
            $sample = $_
            @($sample.CurrentImages | Where-Object { $_.Path -ieq $path -and $_.Absent -eq $false -and $_.Length -eq 0 } | ForEach-Object {
                [pscustomobject]@{ Sequence = $sample.Sequence; Phase = $sample.Phase; Path = $_.Path; FileId = $_.FileId; Sha256 = $_.Sha256 }
            })
        })
        $record.NoEmptyLeftover = ($null -ne $lastTarget -and ($lastTarget.Absent -eq $true -or $lastTarget.Length -gt 0) -and
            ($final.Status -ceq 'ABSENT' -or ($final.Status -ceq 'OK' -and $final.Length -gt 0)) -and
            @($record.JournalParseErrors).Count -eq 0 -and @($record.JournalSchemaErrors).Count -eq 0)
        if ($case.Op -cin @('probe-delete-before-seal', 'probe-delete-after-publication', 'probe-doc')) {
            $probeSamples = @($record.RawSamples | Where-Object Phase -ceq $probeControlPhase)
            $record.ProbeControlSamples = $probeSamples.Count
            $record.ProbeControlTargetAbsentThroughout = ($probeSamples.Count -ge 2 -and @($probeSamples | Where-Object { $_.Status -cne 'OK' -or -not $_.TargetAbsent }).Count -eq 0)
            $names = @('test-create', 'test-close', 'save-create', 'save-write', 'save-close')
            $expectedCodes = @{ 'test-create' = 0; 'test-close' = 0; 'save-create' = 0; 'save-write' = 0; 'save-close' = 0 }
            if ($case.Op -cne 'probe-doc') { $names += 'test-delete'; $expectedCodes['test-delete'] = 0 }
            else { $names += 'open-after-doc-flag'; $expectedCodes['open-after-doc-flag'] = 303 }
            Test-NativeSteps $record $names $expectedCodes
            $probeOutcome = Get-T5EmptyProbeOutcome $newJournal $record.NativeStepsOk
            $record.ProbeEmptyPrivateOutcome = ($probeOutcome.Verified -and $probeOutcome.EmptyHeldRecords.Count -eq 0)
            $record.ProbeEmptyPrivateOutcomeKind = $probeOutcome.Kind
            $record.ProbeEmptyPrivateBlocked = ($probeOutcome.EmptyHeldRecords.Count -gt 0)
            $record.ProbeEmptyHeldPrivateRecords = $probeOutcome.EmptyHeldRecords
            $record.ProbePresealPrivateDeleteRecords = @($probeOutcome.PresealDiscardedRecords +
                $probeOutcome.UnsealedCleanupAcknowledgedRecords + $probeOutcome.UnsealedCleanupPendingRecords)
            $record.ProbeCleanupPendingRecords = $probeOutcome.UnsealedCleanupPendingRecords
            $record.ProbeCleanupAcknowledged = $probeOutcome.CleanupAcknowledged
            $record.ProbeCleanupAcknowledgedRecords = $probeOutcome.PrivateOutcomeCleanupAcknowledgedRecords
            $record.ProbeAllCleanupAcknowledgedRecords = $probeOutcome.CleanupAcknowledgedRecords
            # Exact private discard is required for the held-writer and private delete-on-close orders.
            # A published probe is an ordinary public-delete case, never an EmptyHeld/private outcome.
            $record.ProbeDiscarded = $record.ProbeEmptyPrivateOutcome
        } elseif ($case.Op -ceq 'probe-onclose') {
            $names = @('first-create','second-open','first-on-close-delete','open-after-first-flag','second-on-close-delete',
                'first-on-close-clear','open-after-first-clear','second-on-close-clear','open-after-both-clear','save-write','save-close','first-close','second-close')
            $expectedCodes = @{ 'first-create' = 0; 'second-open' = 0; 'first-on-close-delete' = 0; 'open-after-first-flag' = 303;
                'second-on-close-delete' = 0; 'first-on-close-clear' = 0; 'open-after-first-clear' = 303; 'second-on-close-clear' = 0;
                'open-after-both-clear' = 0; 'save-write' = 0; 'save-close' = 0; 'first-close' = 0; 'second-close' = 0 }
            Test-NativeSteps $record $names $expectedCodes
        }
        if ($case.Op -ceq 'notepad') {
            $ui = $record.Ack.Ui
            $windows = if ($ui) { @($ui.WindowsAfterSave) } else { @() }
            $record.NoUiErrorWindow = ($null -ne $ui -and $windows.Count -eq 1 -and -not [string]::IsNullOrWhiteSpace([string]$ui.Title))
        }
        if ($case.Op -ceq 'probe-onclose' -and $record.FinalRawMatches) { $record.Published = ($final.Status -eq 'OK' -and (Same $final.Bytes $bytes)) }
        elseif (-not $case.Sensitive) { $record.Published = ($final.Status -eq 'OK' -and (Same $final.Bytes $bytes)) }
        $record.RawCoverageComplete = ($record.RawCoverageComplete -and $record.RawSamples.Count -gt 0)
        $record.IndependentReadersAgree = ($record.IndependentReadersAgree -and $record.RawCoverageComplete)
        $result.Cases += [pscustomobject]$record
    }
    try {
        $ring = @(& $Diagnostics -Query deny-ring)
        $result.Ring = @($ring | Select-Object -Last 60 | ForEach-Object { $_ | ConvertTo-Json -Compress })
    } catch { $result.RingError = $_.Exception.Message }
    $result.RawObserver.NoUnapprovedByteVerdict = 'INCONCLUSIVE'
    $result.RawObserver.NoUnapprovedByteReason = 'The raw module requires a complete driver lower-admission/completion mutation ledger and causal timeline; this T5 diagnostic adapter has neither. Raw samples establish observed images only.'
    $stop = Join-Path $control 'stop.part'; [IO.File]::WriteAllText($stop, '{"Op":"stop"}'); [IO.File]::Move($stop, (Join-Path $control 'cmd-stop.json'))
} catch {
    $result.Error = $_.Exception.Message
    $result.ErrorScriptStackTrace = $_.ScriptStackTrace
} finally {
    if ($null -ne $rawContext) {
        try { $result.RawObserver.Disposal = Close-InvariantObserver $rawContext } catch { $result.RawObserver.DisposalError = $_.Exception.ToString() }
    }
    if ($null -ne $rawContext -and $null -ne $rawBaseline) {
        if ($null -eq $result.RawObserver) { $result.RawObserver = [ordered]@{} }
        $baselineImages = @($rawBaseline.Images | ForEach-Object {
            [pscustomobject]@{ Role = $_.Role; Path = $_.Path; Absent = $_.Absent;
                FileId = $(if ($_.Identity) { $_.Identity.FileId } else { $null });
                Reference = $(if ($_.Identity) { [string]$_.Identity.Reference } else { $null });
                Length = $_.Length; Sha256 = $_.Sha256; LogicalArtifact = $_.LogicalArtifact;
                DirectoryEntries = $(if ($_.Role -ceq 'Parent') { @($_.DirectoryEntries | ForEach-Object { [pscustomobject]@{ Name = $_.Name; Namespace = $_.Namespace; Reference = $_.Reference; Eof = $_.Eof; Attributes = $_.Attributes } }) } else { @() }) }
        })
        $result.RawObserver = [ordered]@{ Status = $rawContext.Status; CaseId = $rawContext.CaseId; Build = $rawContext.Build; BootId = $rawContext.BootId;
            ObserverPid = $rawContext.ObserverPid; ObserverSid = $rawContext.ObserverSid; VolumeGuid = $rawContext.Geometry.Guid; ScopePath = $rawContext.ScopePath;
            ModuleSha256 = $rawContext.ModuleSha256; Baseline = [pscustomobject]@{ Status = $rawBaseline.Status; CaseId = $rawBaseline.CaseId; ObserverPid = $rawBaseline.ObserverPid;
                ObserverSid = $rawBaseline.ObserverSid; Time = $rawBaseline.Time; Names = $rawBaseline.Names; Images = $baselineImages }; Samples = @($result.RawObserver.Samples);
            Disposal = $result.RawObserver.Disposal; DisposalError = $result.RawObserver.DisposalError; NoUnapprovedByteVerdict = $result.RawObserver.NoUnapprovedByteVerdict;
            NoUnapprovedByteReason = $result.RawObserver.NoUnapprovedByteReason; EvidenceDirectory = $rawContext.EvidenceDirectory }
    }
    $result.Finished = [DateTime]::UtcNow.ToString('o')
    $part = Join-Path $out 'result.part'
    [IO.File]::WriteAllText($part, ($result | ConvertTo-Json -Depth 32), [Text.UTF8Encoding]::new($false))
    [IO.File]::Move($part, (Join-Path $out 'result.json'))
}
