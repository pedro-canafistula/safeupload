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
    [string]$ObserverModule = 'C:\Users\vika\Documents\StagedInvariantObserver.psm1',
    [string]$CasesPath = (Join-Path $PSScriptRoot 't5-notepad-cases.json'), [switch]$OfficeBase,
    [ValidateSet('', 'Excel', 'Word')][string]$OfficeApp = '')
$ErrorActionPreference = 'Stop'
$out = 'C:\T5'; $control = Join-Path $out 'control'; $root = 'C:\Protected\t5'
$journalDir = 'C:\ProgramData\SafeUpload\staging-journal'
$script:T5JournalEvidenceDirectory = Join-Path $out 'journal-evidence'
function Read-T5CaseInventory([string]$Path) {
    # Windows PowerShell 5.1 writes a top-level JSON array as one object; assign it before enumerating (m2t5ord5).
    $parsed = [IO.File]::ReadAllText($Path) | ConvertFrom-Json
    @($parsed)
}
$cases = @(Read-T5CaseInventory $CasesPath | Where-Object { [bool]$_.Office -eq [bool]$OfficeBase -and ($OfficeApp -ceq '' -or ([string]$_.Kind).StartsWith($OfficeApp, [StringComparison]::Ordinal)) })
$leaves = @($cases | ForEach-Object { $_.Leaf; @($_.AuxiliaryLeaves) } | Where-Object { $_ } | Sort-Object -Unique)
$frequency = [Diagnostics.Stopwatch]::Frequency
$rawContext = $null; $rawBaseline = $null; $script:rawSequence = 0
$script:T5WordDiagActive = $false; $script:T5LastStreams = [long]0
$script:T5WorkflowPublicHashes = @{}
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
      catch [UnauthorizedAccessException] {
        # .NET drops the NTSTATUS; a native attributes open reports whether the name is delete-pending (m2t5ord6).
        $first = $_.Exception.ToString(); $nt = $null; $h = $null
        try { $h = [StagedInvariant.Native]::OpenAttributes($Path) } catch { $nt = $_.Exception.InnerException.NativeNtStatus; if ($null -eq $nt) { $nt = $_.Exception.NativeNtStatus } } finally { if ($null -ne $h) { $h.Dispose() } }
        $status = if ($nt -ceq '0xC0000056') { 'DELETE_PENDING' } else { 'ERROR' }
        return [pscustomobject]@{ Status = $status; Bytes = $null; Length = $null; Sha256 = $null; Error = ($first + '; native NTSTATUS=' + $nt) }
      }
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
function Test-T5SamePublicRead($A, $B) { return ($A.Status -ceq $B.Status -and $A.Sha256 -ceq $B.Sha256) }
function Test-T5ApprovedPublicRead([string]$Path, $Read) {
    # A state this row may legitimately make public: absent, delete-pending, empty, a workflow's approved bytes, or a non-sensitive
    # case's clean text. CPF or any other bytes are never approved.
    if ($Read.Status -ceq 'ABSENT' -or $Read.Status -ceq 'DELETE_PENDING') { return $true }
    if ($Read.Status -cne 'OK') { return $false }
    if ($Read.Length -eq 0) { return $true }
    if ($script:T5WorkflowPublicHashes.ContainsKey($Path) -and $script:T5WorkflowPublicHashes[$Path] -ccontains $Read.Sha256) { return $true }
    $owners = @($cases | Where-Object { -not $_.Workflow -and -not $_.Sensitive -and (Join-Path $root $_.Leaf) -ieq $Path })
    foreach ($owner in $owners) { if ((Sha ([Text.Encoding]::ASCII.GetBytes('T5 ' + $owner.Kind + ' clean text'))) -ceq $Read.Sha256) { return $true } }
    return $false
}
# Owner 2026-10-22: a raw sample taken while the actor or the agent is mid-operation may fail because a name appeared or vanished
# between its independent reads. Such an ERROR sample stays in the result; it only stops counting against the row when the very next
# sample of the same case (any phase: owner 2026-10-22, since the last ActorRunning sample is followed by the next phase) is fully valid.
# Only these observation-race messages in these phases qualify, never leaked bytes or a bad parent.
$script:T5TransientObservationPhases = @('ActorRunning', 'WorkflowSettlement', 'AfterActorAcknowledgementSettlement')
# Owner 2026-10-22 (third rule, deny-list): in these phases any capture failure is a race unless it is one of the verdict-class errors below.
$script:T5FatalObservationErrors = @(
    'CPF or unexpected nonempty fixture bytes',
    'Office observation journal is invalid',
    'differs from the independently captured baseline parent',
    'Raw parent directory identity is incomplete',
    'One or more raw target images or artifacts are missing/incomplete',
    'Raw parent index has unexpected/missing file references',
    '"Verdict":"FAIL"',
    '"Verdict":"VIOLATION"')
function Test-T5TransientObservationError($Sample) {
    if ($Sample.Status -ceq 'OK' -or $Sample.ForbiddenBytesObserved -or $Sample.Phase -cnotin $script:T5TransientObservationPhases) { return $false }
    $text = ([string]$Sample.Error).Replace('\"', '"')
    if ([string]::IsNullOrWhiteSpace($text)) { return $false }
    foreach ($fatal in $script:T5FatalObservationErrors) {
        if ($text.Contains($fatal)) { return $false }
    }
    return $true
}
function Test-T5SampleSuperseded($Sample) { return ($null -ne $Sample.PSObject.Properties['SupersededBySequence']) }
function Get-T5UnresolvedRawSamples($Case) {
    return @($Case.RawSamples | Where-Object { $_.Status -cne 'OK' -and -not (Test-T5SampleSuperseded $_) })
}
function Capture-T5Observation($Case, [string]$Phase) {
    $script:rawSequence++
    $entry = [ordered]@{ Phase = $Phase; Sequence = $script:rawSequence; Status = 'ERROR'; Start = $null; End = $null
        CurrentImages = @(); ParentFileId = $null; ParentReference = $null; DirectoryEntries = @(); PublicReaders = @(); RawComplete = $false; IndependentReadersAgree = $false
        DirectoryComplete = $false; ForbiddenBytesObserved = $false; TargetAbsent = $false; Error = $null }
    try {
        if($OfficeBase){Update-T5OfficePublicHashes $Case}
        # Owner 2026-10-21: a sample taken while the actor runs is bracketed by public reads before and after the raw capture; the
        # raw image must match one of them, and a change between them must be approved bytes. Every other phase stays strict.
        $bracketed = ($Phase -ceq 'ActorRunning'); $before = @{}
        if ($bracketed) { foreach ($leaf in $leaves) { $p = Join-Path $root $leaf; $before[$p] = Read-Public $p } }
        $sample = Capture-InvariantSample $rawContext $rawBaseline $Phase $script:rawSequence
        if($OfficeBase){Update-T5OfficePublicHashes $Case}
        $entry.Status = $sample.Status; $entry.Start = $sample.Start; $entry.End = $sample.End
        if ($sample.Sequence -is [int] -or $sample.Sequence -is [long]) { $entry.ModuleSequence = $sample.Sequence }
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
        $imageSummaries = @(); $readerSummaries = @(); $beforeSummaries = @(); $observerReaderSummaries = @()
        $allArtifactReadsOk = $true; $independentAgree = $true; $forbidden = $false; $nativeReaderCoverageOk = $true
        foreach ($leaf in $leaves) {
            $path = Join-Path $root $leaf; $image = Get-CurrentRawImage $sample $path
            $direct = Read-Public $path; $logical = $null; $imageError = $null
            try { $logical = Get-RawImageBytes $image } catch { $allArtifactReadsOk = $false; $imageError = $_.Exception.Message }
            $nativeReaders = @($sample.Readers | Where-Object { $_.Path -ieq $path })
            $pre = if ($bracketed) { $before[$path] } else { $null }
            if ($image.Absent -eq $true) {
                # A raw-absent name the filter reports delete-pending must read as delete-pending to the buffered reader too.
                $expectedDirect = if ($image.NamedLookup -ceq 'DELETE_PENDING') { 'DELETE_PENDING' } else { 'ABSENT' }
                $publicAgrees = ($direct.Status -ceq $expectedDirect -or ($null -ne $pre -and $pre.Status -ceq $expectedDirect))
                if (-not $publicAgrees -or $nativeReaders.Count -ne 0) { $independentAgree = $false }
            } elseif ($image.Absent -eq $false -and $null -ne $logical) {
                $publicAgrees = (($direct.Status -ceq 'OK' -and (Same $logical $direct.Bytes)) -or
                    ($null -ne $pre -and $pre.Status -ceq 'OK' -and (Same $logical $pre.Bytes)))
                if (-not $publicAgrees) { $independentAgree = $false }
                if ($Case.Sensitive -and $path -ieq $Case.Path -and $logical.Length -gt 0) { $forbidden = $true }
                elseif ((Contains-Bytes $logical $cpfBytes) -or (Contains-Bytes $logical $cpfNumberBytes)) { $forbidden = $true }
                if($logical.Length -gt 0 -and $script:T5WorkflowPublicHashes.ContainsKey($path) -and
                    $script:T5WorkflowPublicHashes[$path] -cnotcontains (Sha $logical)){$forbidden=$true}
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
            if ($null -ne $pre) {
                if ($pre.Status -eq 'ERROR') { $independentAgree = $false }
                if (-not (Test-T5SamePublicRead $pre $direct) -and
                    (-not (Test-T5ApprovedPublicRead $path $pre) -or -not (Test-T5ApprovedPublicRead $path $direct))) { $independentAgree = $false }
                $beforeSummaries += [pscustomobject]@{ Path = $path; Status = $pre.Status; Length = $pre.Length; Sha256 = $pre.Sha256; Error = $pre.Error }
            }
            $readerSummaries += [pscustomobject]@{ Path = $path; Status = $direct.Status; Length = $direct.Length; Sha256 = $direct.Sha256; Error = $direct.Error }
            $imageSummaries += [pscustomobject]@{ Path = $path; Absent = [bool]$image.Absent; NamedLookup = $image.NamedLookup; FileId = $(if ($image.Identity) { $image.Identity.FileId } else { $null });
                Reference = $(if ($image.Identity) { $image.Identity.Reference } else { $null }); Length = $image.Length; Sha256 = $image.Sha256;
                LogicalArtifact = $image.LogicalArtifact; FileNames = @(foreach ($imageFileName in @($image.FileNames)) { if ($null -ne $imageFileName) { [pscustomobject]@{ Name = $imageFileName.Name; Namespace = $imageFileName.Namespace; Reference = $imageFileName.Reference; Parent = $imageFileName.Parent } } }); Error = $imageError }
        }
        $entries = @($parent.DirectoryEntries)
        $expectedEntryKeys = @{}; $actualEntryKeys = @{}; $unexpected = @(); $missing = @()
        foreach ($image in @($sample.Images | Where-Object { $_.Role -ceq 'Current' -and $_.Absent -eq $false })) {
            foreach ($fileName in @($image.FileNames | Where-Object { $_.Parent -eq $parent.Identity.Reference })) {
                $key = ([string]$fileName.Name).ToLowerInvariant() + '|' + [string]$fileName.Namespace + '|' + [string]$fileName.Reference
                $expectedEntryKeys[$key] = $true
            }
        }
        # Office writes its owner lock file (~$name.docx and its 8.3 alias) next to an open document; it is inspected and published like any
        # other new file (mvpBWdiag12: Released), so it is an expected companion of an Office case, not an unexpected reference.
        $officeCase = ([string]$Case.Kind) -cmatch '^(Word|Excel)'
        foreach ($directoryEntry in $entries) {
            if ($officeCase -and ([string]$directoryEntry.Name).StartsWith('~$', [StringComparison]::Ordinal)) { continue }
            $key = ([string]$directoryEntry.Name).ToLowerInvariant() + '|' + [string]$directoryEntry.Namespace + '|' + [string]$directoryEntry.Reference
            if ($actualEntryKeys.ContainsKey($key) -or -not $expectedEntryKeys.ContainsKey($key)) { $unexpected += $directoryEntry }
            $actualEntryKeys[$key] = $true
        }
        $missing = @($expectedEntryKeys.Keys | Where-Object { -not $actualEntryKeys.ContainsKey($_) })
        $directoryComplete = ($unexpected.Count -eq 0 -and $missing.Count -eq 0 -and $actualEntryKeys.Count -eq $expectedEntryKeys.Count)
        $entry.DirectoryEntries = @($entries | ForEach-Object { [pscustomobject]@{ Name = $_.Name; Namespace = $_.Namespace; Reference = $_.Reference; Eof = $_.Eof; Attributes = $_.Attributes } })
        $entry.CurrentImages = $imageSummaries; $entry.PublicReaders = $readerSummaries; $entry.ObserverReaders = $observerReaderSummaries
        if ($bracketed) { $entry.PublicReadersBefore = $beforeSummaries }
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
        if ($forbidden) { $Case.Leaked = $true; throw 'CPF or unexpected nonempty fixture bytes were observed in a raw public image.' }
        $entry.Status = 'OK'; $entry.ModuleSequence = $sample.Sequence
    } catch { $entry.Status = 'ERROR'; $entry.Error = $_.Exception.ToString() }
    $object = [pscustomobject]$entry
    $previous = if (@($Case.RawSamples).Count) { @($Case.RawSamples)[-1] } else { $null }
    $result.RawObserver.Samples += $object
    $Case.RawSamples += $object
    if ($object.Status -ceq 'OK' -and $null -ne $previous -and $previous.Sequence -eq ($object.Sequence - 1) -and
        (Test-T5TransientObservationError $previous)) {
        $previous | Add-Member -NotePropertyName SupersededBySequence -NotePropertyValue $object.Sequence
    }
    # A transient observation error may still be superseded by the next sample; the case flags are settled from the unresolved
    # errors when the case or its workflow ends. Every other failure lowers them at once.
    if ($object.Status -cne 'OK' -and -not (Test-T5TransientObservationError $object)) { $Case.RawCoverageComplete = $false; $Case.IndependentReadersAgree = $false }
    if ($object.ForbiddenBytesObserved) { $Case.Leaked = $true }
    return $object
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
function Start-T5WordDiagTrace {
    # Diagnostic only (T5_WORD_DIAG=1): file-I/O trace and driver stream snapshots around the Word overwrite save (T8 Word drop 2, W0).
    $script:T5WordDiagActive = $true; $script:T5LastStreams = [long]0
    try { (& wpr.exe -start FileIO 2>&1 | Out-String) | Set-Content -LiteralPath 'C:\T5\word-diag\wpr-start.txt' } catch { $_.Exception.Message | Set-Content -LiteralPath 'C:\T5\word-diag\wpr-start.txt' }
}
function Save-T5DiagStreams {
    $script:T5LastStreams = [Diagnostics.Stopwatch]::GetTimestamp()
    try {
        $json = (& $Diagnostics -Query stage-streams | ConvertTo-Json -Depth 8 -Compress)
        if ($json -match 'word-overwrite|WRD|WRL') { Add-Content -LiteralPath 'C:\T5\word-diag\streams.ndjson' -Value ((Get-Date).ToUniversalTime().ToString('o') + ' ' + $json) }
    } catch { Add-Content -LiteralPath 'C:\T5\word-diag\streams-error.txt' -Value $_.Exception.Message }
}
function Stop-T5WordDiagTrace {
    $script:T5WordDiagActive = $false
    $etl = 'C:\T5\word-diag\overwrite.etl'; $csv = 'C:\T5\word-diag\overwrite.csv'
    try {
        (& wpr.exe -stop $etl 'T5 word overwrite' 2>&1 | Out-String) | Set-Content -LiteralPath 'C:\T5\word-diag\wpr-stop.txt'
        (& tracerpt.exe $etl -of CSV -o $csv -summary 'C:\T5\word-diag\overwrite-summary.txt' -y 2>&1 | Out-String) | Set-Content -LiteralPath 'C:\T5\word-diag\tracerpt.txt'
        if (Test-Path -LiteralPath $csv) {
            'etl-bytes=' + (Get-Item -LiteralPath $etl -ErrorAction SilentlyContinue).Length + ' csv-bytes=' + (Get-Item -LiteralPath $csv).Length | Set-Content -LiteralPath 'C:\T5\word-diag\sizes.txt'
            $head = Get-Content -LiteralPath $csv -TotalCount 2
            $hit = Select-String -LiteralPath $csv -Pattern 'word-overwrite|~WRD|~WRL|wd-native' | ForEach-Object { $_.Line }
            @($head) + @($hit) | Set-Content -LiteralPath 'C:\T5\word-diag\overwrite-filtered.csv'
            Remove-Item -LiteralPath $csv -Force; Remove-Item -LiteralPath $etl -Force -ErrorAction SilentlyContinue
        }
    } catch { $_.Exception.ToString() | Set-Content -LiteralPath 'C:\T5\word-diag\trace-error.txt' }
}
function Invoke-Actor([string]$Op, [string]$Path, [string]$Text, [scriptblock]$Observe,
    [string[]]$BaselineTransferIds, [System.Collections.IDictionary]$CaseRecord) {
    if (-not ($Op -ceq 'word-overwrite' -and [IO.File]::Exists('C:\T5\word-diag.flag'))) { return Invoke-ActorCore $Op $Path $Text $Observe $BaselineTransferIds $CaseRecord }
    Start-T5WordDiagTrace
    try { return Invoke-ActorCore $Op $Path $Text $Observe $BaselineTransferIds $CaseRecord } finally { Stop-T5WordDiagTrace }
}
function Invoke-ActorCore([string]$Op, [string]$Path, [string]$Text, [scriptblock]$Observe,
    [string[]]$BaselineTransferIds, [System.Collections.IDictionary]$CaseRecord) {
    $script:n++
    Write-ActorCommand $Op $Path $Text $script:n
    $ack = Join-Path $control ('ack-' + $script:n + '.json')
    $ready = Join-Path $control ('probe-ready-' + $script:n + '.json')
    $go = Join-Path $control ('probe-go-' + $script:n + '.json')
    $deadline = [Diagnostics.Stopwatch]::GetTimestamp() + 240 * $frequency
    $gatedOps = @('probe-delete-before-seal', 'probe-delete-after-publication', 'probe-doc', 'inflight-before', 'inflight-after')
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
                # Reading the hot journal while the agent archives can fail once ('Completed bytes changed during hot collection');
                # that is retried like any other not-yet-settled gate. A schema error or any other parse error stays fatal.
                if (@($gateJournal.SchemaErrors).Count -gt 0 -or
                    @($gateJournal.ParseErrors | Where-Object { [string]$_.Error -notlike 'Completed bytes changed during hot collection*' }).Count -gt 0) {
                    throw 'The forced-order gate has invalid journal evidence.'
                }
                if (@($gateJournal.ParseErrors).Count -gt 0) { Start-Sleep -Milliseconds 100; continue }
                $fresh = @($gateJournal.Records | Where-Object { $BaselineTransferIds -notcontains $_.TransferId })
                $target = @($sample.CurrentImages | Where-Object { $_.Path -ieq $Path })
                if ($target.Count -ne 1) { throw 'The forced-order gate has no unique raw destination image.' }
                if($Op -cin @('inflight-before','inflight-after')) {
                    $wantHeld=$Op -ceq 'inflight-before'
                    if($readyRecord.WritableProbeHandleHeld -ne $wantHeld){throw 'In-flight ready handle lifetime mismatch'}
                    $candidate=@($fresh | Where-Object { $_.IsV20 -and $_.ProcessId -eq $readyRecord.ActorPid })
                    if($wantHeld){
                        $candidate=@($candidate | Where-Object { $_.State -in @('0','8') -and -not $_.SealedOnce -and $null -eq $_.SealedLength })
                    }else{
                        $candidate=@($candidate | Where-Object { $_.State -eq '5' -and $_.Sha256Hex -ceq $CaseRecord.GateSha256 -and $_.SealedLength -eq $CaseRecord.GateLength })
                    }
                    # The verdict requires every gate sample to show the exact gate content, so only consecutive samples that do count (m2t5ord12:
                    # the first of two samples still showed the prior content while the publication was landing).
                    $targetMatches=($target[0].Absent -eq $false -and $target[0].Sha256 -ceq $CaseRecord.GateSha256 -and $target[0].Length -eq $CaseRecord.GateLength)
                    if(-not $targetMatches){$gateSamples=@()}
                    $gateSatisfied=($gateSamples.Count -ge 2 -and $candidate.Count -eq 1 -and $targetMatches)
                } elseif ($Op -ceq 'probe-delete-before-seal') {
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
        if ($script:T5WordDiagActive -and $now - $script:T5LastStreams -ge [long]([Diagnostics.Stopwatch]::Frequency / 5)) { Save-T5DiagStreams }
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
    # On Linux, .NET treats C:\ as relative. Validate Windows fixture paths
    # lexically for offline replay; Windows still uses its original native check.
    if($env:OS -ne 'Windows_NT' -and $Path -match '^[A-Za-z]:\\') {
        if($Path.Length -gt 511){return $false}
        $parts=$Path.Substring(3).Split([char]'\')
        return @($parts | Where-Object {$_ -in @('','.','..') -or $_ -match '[<>:"/|?*\x00-\x1F]'}).Count -eq 0
    }
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
    if($null -ne $Entry.UnboundCancellation){
        $cancel=$Entry.UnboundCancellation
        $version=[pscustomobject]@{TransferId=$Entry.Transfer.TransferId;DestinationGeneration=$Entry.DestinationGeneration;StageIdentity=$Entry.StageIdentity}
        if($null -eq (Get-T5GuidText $cancel.OperationId) -or
            (Get-T5VersionIdentityKey $cancel.Version) -cne (Get-T5VersionIdentityKey $version) -or
            -not (Test-T5IntegerRange $cancel.Generation 1 ([long]::MaxValue)) -or $cancel.Generation -le $Entry.DestinationGeneration -or
            $Entry.State -ne 7 -or $Entry.SealedOnce -ne $true -or $null -ne $Entry.PendingRename -or $null -ne $Entry.BoundAllocation){$errors+='invalid exact unbound cancellation receipt'}
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
    # D8: the service's completed cleanup of an irrevocably cancelled unbound version (the receipt above is validated exactly): the
    # exact stage is deleted and nothing was released or handed back. The agent's own terminal-archive rule is the same shape.
    $cancelledCleanup = ($null -ne $Entry.UnboundCancellation -and $state -eq 7 -and $Entry.SealedOnce -eq $true -and
        $handbackState -eq 0 -and $Entry.StageCleanupStarted -eq $false)
    if ($Entry.StageDeleted -eq $true -and -not ($cancelledCleanup -or
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
        UnboundCancellation = $Entry.UnboundCancellation;
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
function Get-StableJournalChildren([string]$Journal) {
    $limit=[Diagnostics.Stopwatch]::GetTimestamp()+[long](5*[Diagnostics.Stopwatch]::Frequency)
    while($true) {
        $children=@(Get-ChildItem -LiteralPath $Journal -Force | Sort-Object Name)
        $transient=@($children | Where-Object {$_.Name -match '^(?:[0-9a-f]{32}\.json|driver-epoch\.state|segments\.state)\.[0-9a-f]{32}\.tmp$'})
        if(-not $transient.Count -or [Diagnostics.Stopwatch]::GetTimestamp() -ge $limit){return $children}
        Start-Sleep -Milliseconds 25
    }
}
function ConvertFrom-ServiceDriverEpoch([byte[]]$Bytes) {
    if($Bytes.Length -gt 4096){throw 'Driver epoch exceeds its product bound.'}
    $epoch=[Text.UTF8Encoding]::new($false,$true).GetString($Bytes) | ConvertFrom-Json -ErrorAction Stop
    foreach($field in @('DriverInstanceId','AcceptedAtUtc','DrainRequestId','DrainNonce','DrainedAtUtc')){
        if($null -eq $epoch.PSObject.Properties[$field]){throw 'Incomplete driver epoch record.'}
    }
    if([guid]$epoch.DriverInstanceId -eq [guid]::Empty){throw 'Empty driver epoch identity.'}
    $accepted=[DateTimeOffset]$epoch.AcceptedAtUtc
    if($accepted -eq [DateTimeOffset]::MinValue -or $accepted.Offset -ne [TimeSpan]::Zero){throw 'Invalid driver epoch acceptance time.'}
    $active=$null -eq $epoch.DrainRequestId -and $null -eq $epoch.DrainNonce -and $null -eq $epoch.DrainedAtUtc
    if(-not $active){
        foreach($value in @($epoch.DrainRequestId,$epoch.DrainNonce)){
            if($null -eq $value -or $value -is [string] -or $value -is [bool] -or $value -is [double] -or $value -is [single] -or
                [string]$value -notmatch '^\d+$' -or [decimal]$value -le 0 -or [decimal]$value -gt [uint64]::MaxValue){throw 'Unpaired driver epoch drain receipt.'}
        }
        if($null -eq $epoch.DrainedAtUtc){throw 'Missing driver epoch drain time.'}
        $drained=[DateTimeOffset]$epoch.DrainedAtUtc
        if($drained.Offset -ne [TimeSpan]::Zero -or $drained -lt $accepted){throw 'Invalid driver epoch drain time.'}
    }
    return $epoch
}
function ConvertFrom-ServiceArchive($Records,[string]$Journal) {
    # StagedTerminalArchive.cs SUAC/SUJA v1. Decode only authenticated retained
    # bytes. Keep 131072 bytes per manifest; the 4 MiB container bound is the
    # product's separate segment bound, never a larger manifest allowance.
    $inventory=@($Records | Where-Object {($_.Path -split '[\\/]')[-1] -ceq 'segments.state'})
    if($inventory.Count -ne 1 -or $inventory[0].Bytes.Length -gt 4096){throw 'Missing/invalid completed inventory.'}
    $head=[Text.UTF8Encoding]::new($false,$true).GetString($inventory[0].Bytes) | ConvertFrom-Json -ErrorAction Stop
    if(($head.Version -isnot [int] -and $head.Version -isnot [long]) -or $head.Version -ne 1 -or
        ($head.SegmentCount -isnot [int] -and $head.SegmentCount -isnot [long]) -or $head.SegmentCount -lt 0 -or $head.SegmentCount -gt [int]::MaxValue){throw 'Invalid completed inventory version/count.'}
    $segments=@($Records | Where-Object {($_.Path -split '[\\/]')[-1] -cne 'segments.state'} | Sort-Object Path)
    if($segments.Count -ne $head.SegmentCount){throw 'Completed inventory lost or has an uncommitted segment.'}
    $rows=@();$seen=@{};$number=0;$sha=[Security.Cryptography.SHA256]::Create()
    try{
        foreach($segment in $segments){
            $number++;$leaf=($segment.Path -split '[\\/]')[-1]
            if($leaf -cne ($number.ToString('X8')+'.pack')){throw 'Completed segment gap or unexpected name.'}
            [byte[]]$b=$segment.Bytes
            if($b.Length -lt 4096 -or $b.Length -gt 4194304){throw 'Completed segment outside product bound.'}
            $frontier=[BitConverter]::ToInt64($b,8)
            if([BitConverter]::ToUInt32($b,0) -ne 0x43415553 -or [BitConverter]::ToInt32($b,4) -ne 1 -or
                $frontier -ne $b.Length -or
                [Convert]::ToBase64String($sha.ComputeHash($b,0,16)) -cne [Convert]::ToBase64String($b[16..47])){throw 'Invalid/unstable committed archive frontier.'}
            $offset=4096
            while($offset -lt $frontier){
                if($frontier-$offset -lt 60 -or [BitConverter]::ToUInt32($b,$offset) -ne 0x414A5553 -or [BitConverter]::ToInt32($b,$offset+4) -ne 1){throw 'Invalid committed archive frame header.'}
                $length=[BitConverter]::ToInt32($b,$offset+8)
                if($length -le 0 -or $length -gt 131072 -or $length -gt $frontier-$offset-60){throw 'Invalid committed archive payload bound.'}
                $id=[guid]::new([byte[]]$b[($offset+12)..($offset+27)])
                if($id -eq [guid]::Empty -or $seen.ContainsKey($id)){throw 'Empty/duplicate archived transfer identity.'}
                $seen[$id]=$true
                [byte[]]$payload=$b[($offset+60)..($offset+59+$length)]
                [byte[]]$digest=$sha.ComputeHash($payload)
                if([Convert]::ToBase64String($digest) -cne [Convert]::ToBase64String($b[($offset+28)..($offset+59)])){throw 'Completed payload checksum mismatch.'}
                # Logical identity stays the transfer filename across archival.
                # Physical source, frame offset and full container are retained.
                $record=[pscustomobject]@{Path=(Join-Path $Journal ($id.ToString('N')+'.json'));PhysicalPath=$segment.Path;FrameOffset=$offset;
                    Owner=$segment.Owner;Sddl=$segment.Sddl;Artifact=$segment.Artifact;Bytes=$payload;Length=$length;Sha256=([BitConverter]::ToString($digest)).Replace('-','')}
                $json=[Text.UTF8Encoding]::new($false,$true).GetString($payload)
                if(-not (Test-T5JsonDepthBound $json 32)){throw 'Archived JSON exceeds depth bound.'}
                $m=$json | ConvertFrom-Json -ErrorAction Stop
                $errors=@(Get-JournalSchemaErrors $m $record.Path -RequireStateHistory -RequireV20)
                if($errors.Count){throw ('Archived manifest schema: '+($errors -join '; '))}
                if((Get-T5GuidText $m.Transfer.TransferId) -cne $id.ToString('N')){throw 'Archive frame TransferId mismatch.'}
                $parsed=[pscustomobject]@{Entry=$m;StateName=(Get-T5StateName ([int]$m.State))}
                if($parsed.Entry.StageDeleted -isnot [bool] -or $parsed.Entry.StageCleanupStarted -isnot [bool] -or
                    $parsed.Entry.StageCleanupStarted -or $null -ne $parsed.Entry.PendingRename -or $null -ne $parsed.Entry.BoundAllocation -or
                    $null -ne $parsed.Entry.AllocationSecurity -or $null -ne $parsed.Entry.SeedProvenance){throw 'Archived receipt still has unfinished private/bound work.'}
                $m=$parsed.Entry
                $ordinary=$parsed.StateName -ceq 'Released' -and $m.HandbackState -eq 0 -and $m.StageDeleted
                # BlockedCleanupComplete / MatchesBlockedDeletionReceipt: a
                # justified Released receipt carries the same cleanup contract.
                $cleanup=$parsed.StateName -cin @('Blocked','Released') -and $m.StageDeleted -and $m.HandbackState -eq 2 -and
                    $m.JustificationWindowClosed -is [bool] -and $m.JustificationWindowClosed -and
                    $null -ne $m.BlockedDeletionReceipt -and $null -ne $m.StageIdentity
                if($cleanup){
                    $receipt=$m.BlockedDeletionReceipt;$version=$receipt.Version
                    $renames=0;for($name=$m.NamespaceTombstones;$null -ne $name;$name=$name.Previous){$renames++}
                    $cleanup=$null -ne $version -and $null -ne $version.StageIdentity -and
                        [guid]$version.TransferId -eq [guid]$m.Transfer.TransferId -and $version.DestinationGeneration -eq $m.DestinationGeneration -and
                        $null -ne $receipt.CommittedRenames -and $receipt.CommittedRenames -eq $renames -and
                        $null -ne $receipt.Length -and $null -ne $m.SealedLength -and $receipt.Length -ge 0 -and
                        $receipt.Length -eq $m.SealedLength -and $receipt.Sha256Hex -ceq $m.Sha256Hex
                    foreach($value in @($version.DestinationGeneration,$receipt.CommittedRenames,$receipt.Length,$m.SealedLength)){
                        if($null -eq $value -or $value -is [string] -or $value -is [bool] -or $value -is [double] -or $value -is [single] -or
                            [string]$value -notmatch '^\d+$' -or [decimal]$value -gt [long]::MaxValue){$cleanup=$false}
                    }
                    if($receipt.Sha256Hex -isnot [string] -or $receipt.Sha256Hex -cnotmatch '^[0-9a-fA-F]{64}$'){$cleanup=$false}
                    foreach($field in @('VolumeSerialNumber','FileIdHigh','FileIdLow')){
                        foreach($identity in @($version.StageIdentity,$m.StageIdentity)){
                            $value=$identity.$field
                            if($null -eq $value -or $value -is [string] -or $value -is [bool] -or $value -is [double] -or $value -is [single] -or
                                [string]$value -notmatch '^\d+$' -or [decimal]$value -gt [uint64]::MaxValue){$cleanup=$false}
                        }
                        if($version.StageIdentity.$field -ne $m.StageIdentity.$field){$cleanup=$false}
                    }
                }
                # Other terminal workflows stay held for an explicit adapter;
                # archive membership never grants publication or cleanup authority.
                $discard=($m.State -eq 9 -or ($m.State -eq 12 -and $null -ne (Get-T5UtcValue $m.DiscardAcknowledgedAtUtc) -and $null -ne $m.DiscardReservationId))
                $cancel=$null -ne $m.UnboundCancellation -and $m.StageDeleted
                if(-not $ordinary -and -not $cleanup -and -not $discard -and -not $cancel){throw 'Archive terminal shape needs a qualified evidence adapter.'}
                if($rows.Count -ge 1024){throw 'Journal exceeds the 1024-record inspection bound.'}
                $rows+=$record;$offset+=60+$length
            }
        }
    }finally{$sha.Dispose()}
    return ,$rows
}
function Read-T5JournalStorage {
    # A content-addressed copy keeps the actual pack, not just derived JSON. Live
    # inventory changes fail this snapshot; no missing frame becomes approval.
    $script:T5SnapshotBytes=[long]0
    $children=@(Get-StableJournalChildren $journalDir)
    if($children.Count -gt 1026){throw 'Journal exceeds bounded child inventory.'}
    $storage=@(); $archive=@(); $logical=@(); $total=[long]0
    foreach($child in @($children | Sort-Object @{Expression={if($_.Name -ceq 'completed'){0}else{1}}},Name)) {
        if($child.Name -ceq 'completed' -and $child.PSIsContainer) {
            $completed=@(Get-StableJournalChildren $child.FullName)
            if($completed.Count -gt 1025){throw 'Completed inventory exceeds bounded segment count.'}
            foreach($item in $completed) {
                if($item.Name -match '^(?:segments\.state)\.[0-9a-f]{32}\.tmp$'){continue}
                if($item.PSIsContainer -or $item.Name -cnotmatch '^(?:segments\.state|[0-9A-F]{8}\.pack)$'){throw ('Unexpected completed child: '+$item.FullName)}
                $archive+=Read-T5StorageFile $item 4194304
            }
            if((@(Get-StableJournalChildren $child.FullName).Name -join '|') -cne ($completed.Name -join '|')){throw 'Completed inventory changed during collection.'}
        } elseif($child.Name -match '^(?:[0-9a-f]{32}\.json|driver-epoch\.state|segments\.state)\.[0-9a-f]{32}\.tmp$'){continue
        } elseif(-not $child.PSIsContainer -and $child.Name -ceq 'driver-epoch.state') {
            $epoch=Read-T5StorageFile $child 4096
            [void](ConvertFrom-ServiceDriverEpoch $epoch.Bytes); $storage+=$epoch
        } elseif(-not $child.PSIsContainer -and $child.Name -match '^[0-9a-f-]{32,36}\.json$') {
            $logical+=Read-T5StorageFile $child 131072
        } else {throw ('Unexpected journal child: '+$child.FullName)}
    }
    foreach($item in @($storage)+@($archive)+@($logical)){$total+=$item.Length}
    if($total -gt 67108864){throw 'Journal exceeds the 64-MiB inspection bound.'}
    if($archive.Count){$logical+=(ConvertFrom-ServiceArchive $archive $journalDir)}
    $logicalIds=@{}
    foreach($row in $logical){$logicalIds[[IO.Path]::GetFileNameWithoutExtension($row.Path).Replace('-','').ToLowerInvariant()]=$true}
    if($logicalIds.Count -gt 1024){throw 'Journal exceeds the 1024-record inspection bound.'}
    foreach($row in $archive){
        $maximum=if($row.Path.EndsWith('segments.state')){4096}else{4194304}
        $again=Read-T5StorageFile (Get-Item -LiteralPath $row.Path -Force -ErrorAction Stop) $maximum -Recheck
        if([Convert]::ToBase64String($again.Bytes) -cne [Convert]::ToBase64String($row.Bytes)){throw 'Completed bytes changed during hot collection; snapshot incomplete.'}
    }
    if((@(Get-StableJournalChildren $journalDir).Name -join '|') -cne ($children.Name -join '|')){throw 'Journal inventory changed during collection.'}
    return $logical
}
function Read-T5StorageFile($File,[int]$Maximum,[switch]$Recheck) {
    if($File.Length -gt $Maximum){throw ('Storage file exceeds bound: '+$File.FullName)}
    if(-not $Recheck){$script:T5SnapshotBytes+=[long]$File.Length}
    if($script:T5SnapshotBytes -gt 67108864){throw 'Journal exceeds the 64-MiB inspection bound.'}
    $stream=[IO.File]::Open($File.FullName,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::ReadWrite)
    try {
        if($stream.Length -gt $Maximum){throw 'Storage grew beyond bound.'}
        if(-not $Recheck){$script:T5SnapshotBytes+=$stream.Length-$File.Length}
        if($script:T5SnapshotBytes -gt 67108864){throw 'Journal exceeds the 64-MiB inspection bound.'}
        $bytes=New-Object byte[] ([int]$stream.Length);$offset=0
        while($offset -lt $bytes.Length){$n=$stream.Read($bytes,$offset,$bytes.Length-$offset);if($n -le 0){throw 'Short journal storage read.'};$offset+=$n}
        if($stream.Length -ne $bytes.Length){throw 'Storage changed length during read.'}
    }finally{$stream.Dispose()}
    $hash=Sha $bytes
    $artifact=$null
    if($script:T5JournalEvidenceDirectory){
        [void][IO.Directory]::CreateDirectory($script:T5JournalEvidenceDirectory)
        $artifact=Join-Path $script:T5JournalEvidenceDirectory ($hash+'.bin')
        if(-not [IO.File]::Exists($artifact)){[IO.File]::WriteAllBytes($artifact,$bytes)}
    }
    return [pscustomobject]@{Path=$File.FullName;Bytes=$bytes;Length=$bytes.Length;Sha256=$hash;Artifact=$artifact;Owner=$null;Sddl=$null}
}
function Get-JournalFor([string]$Destination, [string[]]$BaselineTransferIds, [switch]$RequireHistoryForNewRecords) {
    $records = @(); $parseErrors = @(); $schemaErrors = @(); $allEntries = @(); $allById = @{}
    try { $files = @(Read-T5JournalStorage) }
    catch {
        $parseErrors += [pscustomobject]@{ Path = $journalDir; Error = $_.Exception.Message }
        return [pscustomobject]@{ Records = $records; ParseErrors = $parseErrors; SchemaErrors = $schemaErrors }
    }
    foreach ($file in $files) {
        try {
            $json = [Text.UTF8Encoding]::new($false,$true).GetString($file.Bytes)
            if (-not (Test-T5JsonDepthBound $json 32)) { throw 'Manifest JSON exceeds depth bound or is unbalanced.' }
            $entry = $json | ConvertFrom-Json -ErrorAction Stop
            $errors=@(Get-JournalSchemaErrors $entry $file.Path -RequireStateHistory:($null -ne $entry.DriverInstanceId))
            if($errors.Count){throw ('Manifest schema: '+($errors -join '; '))}
            $id = Get-T5GuidText $entry.Transfer.TransferId
            if ($null -eq $id -or $id -cne [IO.Path]::GetFileNameWithoutExtension($file.Path).Replace('-','').ToLowerInvariant()) { throw 'TransferId does not bind to manifest filename.' }
            if($allById.ContainsKey($id)){
                $existing=$allById[$id]
                # Product consolidation permits one byte-identical hot/archive
                # pair. Preserve both artifacts; never merge conflicting records.
                if(-not $file.PhysicalPath -or $existing.Storage.PhysicalPath -or
                    [Convert]::ToBase64String($file.Bytes) -cne [Convert]::ToBase64String($existing.Storage.Bytes)){throw ('Conflicting/duplicate transfer storage: '+$id)}
                $existing | Add-Member -NotePropertyName HotStorage -NotePropertyValue $existing.Storage
                $existing.Storage=$file
                continue
            }
            $allById[$id] = [pscustomobject]@{ Entry = $entry; Path = $file.Path; Id = $id; Storage = $file }
        } catch { $parseErrors += [pscustomobject]@{ Path = $file.Path; Error = $_.Exception.Message } }
    }
    # Validate every retained record's lineage, even when querying another leaf.
    $allLineage=@($allById.Values | ForEach-Object {Get-T5Projection $_.Entry $_.Path})
    foreach($error in @(Get-T5JournalLineageErrors $allLineage)){
        $schemaErrors+=[pscustomobject]@{Path=$journalDir;Error=[string]$error.Error}
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
        $projection=Get-T5Projection $entry $item.Path
        if($OfficeBase -and $item.Storage.Artifact){$projection | Add-Member -NotePropertyName JournalArtifact -NotePropertyValue $item.Storage.Artifact}
        if($item.Storage.PhysicalPath){
            $projection | Add-Member -NotePropertyName ArchiveRecord -NotePropertyValue ([pscustomobject]@{
                PhysicalPath=$item.Storage.PhysicalPath; FrameOffset=$item.Storage.FrameOffset; Artifact=$item.Storage.Artifact;
                Length=$item.Storage.Length; Sha256=$item.Storage.Sha256; TransferId=$id; HotArtifact=$(if($item.HotStorage){$item.HotStorage.Artifact}else{$null}) })
        }
        $lineageEntries += $projection
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
function Invoke-T5WorkflowAck($Record,[string]$Op,[string]$Path,[string]$Text,[hashtable]$Codes,[string[]]$BaselineIds) {
    $observe={param($phase) Capture-T5Observation $Record ([string]$phase)}.GetNewClosure()
    $ack=Invoke-Actor $Op $Path $Text $observe $BaselineIds $Record
    $Record.WorkflowAcks+= $ack
    $Record.Ack=$ack
    if($ack.Error){throw ('Actor '+$Op+': '+$ack.Error+' UI='+($ack.Ui | ConvertTo-Json -Depth 8 -Compress))}
    foreach($name in $Codes.Keys){
        $actual=Get-NativeStepCode ([string]$ack.Steps) $name
        if($null -eq $actual -or $actual -ne $Codes[$name]){throw ('Actor '+$Op+' '+$name+' expected='+$Codes[$name]+' actual='+$actual+' steps='+$ack.Steps)}
    }
    return $ack
}
function Wait-T5WorkflowState($Record,[string]$Path,[byte[]]$Expected,[bool]$Absent,[bool]$RequireRelease,[bool]$RequireHandback,[string]$HandbackDirectory,[string[]]$BeforeHandback,[byte[]]$HandbackBytes) {
    $deadline=[Diagnostics.Stopwatch]::GetTimestamp()+90*$frequency
    $image=$null;$journal=$null;$lastTransient=$null
    do {
        $sample=Capture-T5Observation $Record 'WorkflowSettlement'
        $journal=Get-JournalFor -Destination $Path -BaselineTransferIds @() -RequireHistoryForNewRecords
        $Record.Journal=$journal.Records;$Record.JournalParseErrors=$journal.ParseErrors;$Record.JournalSchemaErrors=$journal.SchemaErrors
        if($sample.Status -cne 'OK'){
            # A sample that straddled the agent's publication or cleanup is recorded and retried; only the deadline fails the wait.
            if(-not (Test-T5TransientObservationError $sample)){throw ('Workflow raw observation failed: '+$sample.Error)}
            $lastTransient=$sample.Error;Start-Sleep -Milliseconds 100;continue
        }
        $image=@($sample.CurrentImages | Where-Object {$_.Path -ieq $Path})
        if($image.Count -ne 1){throw 'Workflow target raw image missing or duplicated'}
        $match=if($Absent){$image[0].Absent -eq $true}else{$image[0].Absent -eq $false -and $image[0].Length -eq $Expected.Length -and $image[0].Sha256 -ceq (Sha $Expected)}
        $release=@($journal.Records | Where-Object {$_.State -eq '5' -and $_.SealedLength -eq $Expected.Length -and $_.Sha256Hex -ceq (Sha $Expected) -and $_.StageDeleted -eq $true})
        $blocked=@($journal.Records | Where-Object {$_.State -eq '6' -and $_.HandbackState -eq '2' -and $_.SealedLength -eq $HandbackBytes.Length -and $_.Sha256Hex -ceq (Sha $HandbackBytes)})
        $ok=$match -and @($journal.ParseErrors).Count -eq 0 -and @($journal.SchemaErrors).Count -eq 0
        if($RequireRelease){$ok=$ok -and $release.Count -gt 0}
        if(-not $RequireHandback){
            $unfinished=@($journal.Records | Where-Object {$_.IsV20 -and $_.StageDeleted -ne $true -and $null -eq $_.DiscardAcknowledgedAtUtc})
            $ok=$ok -and $unfinished.Count -eq 0
        }
        if($RequireHandback){
            $pattern=if($Record.HandbackPattern){[string]$Record.HandbackPattern}else{'*.txt'}
            $Record.Handback=Get-Handback $HandbackDirectory $BeforeHandback $HandbackBytes $pattern
            $ok=$ok -and $blocked.Count -gt 0 -and $Record.Handback.Status -ceq 'PASS'
        }
        if($ok){$Record.WorkflowJournalSnapshots+=,@($journal.Records);return $sample}
        Start-Sleep -Milliseconds 100
    }while([Diagnostics.Stopwatch]::GetTimestamp() -lt $deadline)
    throw ('Workflow settlement timed out: path='+$Path+' absent='+$Absent+' release='+$RequireRelease+' handback='+$RequireHandback+' lastTransientSampleError='+$lastTransient+' raw='+($image | ConvertTo-Json -Depth 8 -Compress)+' journal='+($journal | ConvertTo-Json -Depth 12 -Compress))
}
function Set-T5DeleteDenyFixture([string]$Path,[string]$Parent,[string]$Sid,[switch]$ReadDeny) {
    $identity=New-Object Security.Principal.SecurityIdentifier($Sid)
    $fileAcl=Get-Acl -LiteralPath $Path;$parentAcl=Get-Acl -LiteralPath $Parent
    $fixture=[pscustomobject]@{Path=$Path;Parent=$Parent;Sid=$Sid;FileBefore=$fileAcl.Sddl;ParentBefore=$parentAcl.Sddl;FileDenied=$null;ParentDenied=$null;Restored=$false}
    try {
        $right=if($ReadDeny){[Security.AccessControl.FileSystemRights]::ReadData}else{[Security.AccessControl.FileSystemRights]::Delete}
        $fileAcl.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule($identity,$right,[Security.AccessControl.AccessControlType]::Deny)))
        if(-not $ReadDeny){$parentAcl.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule($identity,[Security.AccessControl.FileSystemRights]::DeleteSubdirectoriesAndFiles,[Security.AccessControl.AccessControlType]::Deny)))}
        Set-Acl -LiteralPath $Path -AclObject $fileAcl;Set-Acl -LiteralPath $Parent -AclObject $parentAcl
        $fixture.FileDenied=(Get-Acl -LiteralPath $Path).Sddl;$fixture.ParentDenied=(Get-Acl -LiteralPath $Parent).Sddl
        return $fixture
    }catch{Restore-T5DeleteDenyFixture $fixture;throw}
}
function Restore-T5DeleteDenyFixture($Fixture) {
    $fileAcl=Get-Acl -LiteralPath $Fixture.Path;$fileAcl.SetSecurityDescriptorSddlForm($Fixture.FileBefore);Set-Acl -LiteralPath $Fixture.Path -AclObject $fileAcl
    $parentAcl=Get-Acl -LiteralPath $Fixture.Parent;$parentAcl.SetSecurityDescriptorSddlForm($Fixture.ParentBefore);Set-Acl -LiteralPath $Fixture.Parent -AclObject $parentAcl
    $Fixture.Restored=((Get-Acl -LiteralPath $Fixture.Path).Sddl -ceq $Fixture.FileBefore -and (Get-Acl -LiteralPath $Fixture.Parent).Sddl -ceq $Fixture.ParentBefore)
    if(-not $Fixture.Restored){throw 'Delete-denial fixture SDDL restoration failed'}
}
function Update-T5OfficePublicHashes($Record) {
    # Only inspected journal versions authorize workbook bytes. Actor cell/hash
    # receipts never authorize public bytes. Final host checks require Release.
    # The service replaces manifests atomically while the application saves; a read can land mid-replace (mvpBWdiag7).
    # Retry briefly; a journal that stays unparsable or off-schema is still fatal.
    for($attempt=0;;$attempt++){
        $journal=Get-JournalFor $Record.Path -BaselineTransferIds @() -RequireHistoryForNewRecords
        if(-not (@($journal.ParseErrors).Count -or @($journal.SchemaErrors).Count)){break}
        if($attempt -ge 20){throw ('Office observation journal is invalid: ' + ((@($journal.ParseErrors)+@($journal.SchemaErrors)) -join '; '))}
        Start-Sleep -Milliseconds 50
    }
    $Record.WorkflowJournalSnapshots+=,@($journal.Records)
    $processPattern=if($Record.OfficeApp -ceq 'Word'){'^(?i:winword)(?:\.exe)?$'}else{'^(?i:excel)(?:\.exe)?$'}
    $approved=@($journal.Records | Where-Object {$_.IsV20 -and $_.State -cin @('3','4','5') -and $_.SealedOnce -eq $true -and
        $_.RequestorSid -ceq $result.ActorSid -and $_.ProcessName -match $processPattern -and
        $_.SealedLength -gt 0 -and $_.Sha256Hex -cmatch '^[A-F0-9]{64}$'})
    $script:T5WorkflowPublicHashes[$Record.Path]=@($approved | ForEach-Object Sha256Hex | Sort-Object -Unique)
}
function Wait-T5OfficeVersion($Record,[string[]]$BaselineIds,[bool]$Blocked,[string]$HandbackDirectory,[string[]]$BeforeHandback) {
    $deadline=[Diagnostics.Stopwatch]::GetTimestamp()+90*$frequency
    $empty=New-Object byte[] 0
    do {
        [void](Capture-T5Observation $Record 'WorkflowSettlement')
        $journal=Get-JournalFor $Record.Path -BaselineTransferIds @() -RequireHistoryForNewRecords
        $Record.Journal=$journal.Records;$Record.JournalParseErrors=$journal.ParseErrors;$Record.JournalSchemaErrors=$journal.SchemaErrors
        if(@($journal.ParseErrors).Count -or @($journal.SchemaErrors).Count){throw 'Office settlement journal is invalid'}
        $pidExpected=$Record.WorkflowAcks[-1].Ui.($Record.OfficeApp+'Pid')
        $versions=@($journal.Records | Where-Object {$BaselineIds -notcontains $_.TransferId -and $_.IsV20 -and
            $_.ProcessId -eq $pidExpected -and $_.RequestorSid -ceq $result.ActorSid -and $_.SealedLength -gt 0 -and
            $_.State -ceq $(if($Blocked){'6'}else{'5'}) -and $(if($Blocked){$_.HandbackState -ceq '2'}else{$_.StageDeleted -eq $true})})
        if($versions.Count -gt 0){
            foreach($version in $versions){
                if($Blocked){
                    $files=@(Get-ChildItem -LiteralPath $HandbackDirectory -Filter $Record.HandbackPattern -File -Force -ErrorAction SilentlyContinue | Where-Object {$BeforeHandback -notcontains $_.FullName})
                    if($files.Count -ne 1){continue}
                    $read=Read-Public $files[0].FullName
                }else{$read=Read-Public $Record.Path}
                if($read.Status -cne 'OK' -or $read.Length -ne $version.SealedLength -or $read.Sha256 -cne $version.Sha256Hex){continue}
                $Record.WorkflowJournalSnapshots+=,@($journal.Records)
                if($Blocked){
                    $Record.Handback=Get-Handback $HandbackDirectory $BeforeHandback $read.Bytes $Record.HandbackPattern
                    if($Record.Handback.Status -cne 'PASS'){continue}
                    $Record.ExpectedHandbackLength=$read.Length;$Record.ExpectedHandbackSha256=$read.Sha256
                    [void](Wait-T5WorkflowState $Record $Record.Path $empty $true $false $true $HandbackDirectory $BeforeHandback $read.Bytes)
                }else{
                    $Record.ExpectedLength=$read.Length;$Record.ExpectedSha256=$read.Sha256
                    [void](Wait-T5WorkflowState $Record $Record.Path $read.Bytes $false $true $false '' @() $empty)
                }
                return $version
            }
        }
        Start-Sleep -Milliseconds 100
    }while([Diagnostics.Stopwatch]::GetTimestamp() -lt $deadline)
    throw 'Office version did not reach exact Release or full-content hand-back'
}
function Wait-T5OfficeCleanup($Record) {
    # Retry bookkeeping only. Save/SaveAs and hand-back have already completed.
    $deadline=[Diagnostics.Stopwatch]::GetTimestamp()+90*$frequency
    do {
        [void](Capture-T5Observation $Record 'WorkflowSettlement')
        $journal=Get-JournalFor $Record.Path -BaselineTransferIds @() -RequireHistoryForNewRecords
        $Record.Journal=$journal.Records;$Record.JournalParseErrors=$journal.ParseErrors;$Record.JournalSchemaErrors=$journal.SchemaErrors
        if(@($journal.ParseErrors).Count -or @($journal.SchemaErrors).Count){throw 'Office cleanup journal is invalid'}
        $resolved=@()
        $versionsKey=$Record.OfficeApp+'Versions'
        foreach($version in $Record[$versionsKey]){
            $matches=@($journal.Records | Where-Object {$_.TransferId -ceq $version.TransferId -and $_.Sha256Hex -ceq $version.Sha256Hex -and
                $_.SealedLength -eq $version.SealedLength -and $_.State -ceq $version.State -and
                (Get-T5EntryVersionKey $_) -ceq (Get-T5EntryVersionKey $version) -and $_.StageDeleted -eq $true})
            if($matches.Count -eq 1){$resolved+=$matches[0]}
        }
        if($resolved.Count -eq $Record[$versionsKey].Count -and @($journal.Records | Where-Object {$_.StageDeleted -ne $true}).Count -eq 0){
            $Record[$versionsKey]=$resolved;$Record.WorkflowJournalSnapshots+=,@($journal.Records);return
        }
        Start-Sleep -Milliseconds 100
    }while([Diagnostics.Stopwatch]::GetTimestamp() -lt $deadline)
    throw 'Office completed mutation still has unresolved private cleanup; no save was retried'
}
function Invoke-T5OfficeWorkflow($Spec,$Record,[string]$HandbackDirectory,[string[]]$BeforeHandback) {
    $Record.Workflow=$true;$Record.WorkflowAcks=@();$Record.WorkflowJournalSnapshots=@();$Record.WorkflowOutcome=$false
    $Record.OfficeApp=if($Spec.OfficeApp -ceq 'Word'){'Word'}else{'Excel'}
    $app=$Record.OfficeApp;$opPrefix=$app.ToLowerInvariant();$versionsKey=$app+'Versions'
    $Record.ExpectedPublicAbsent=[bool]$Spec.Sensitive;$Record.HandbackPattern='*'+[IO.Path]::GetExtension([string]$Spec.Leaf)
    $Record[$versionsKey]=@();$Record.Method='Real interactive '+$app+' COM; full-byte journal/NTFS comparison plus application reopen'
    $codes=@{};$codes[$opPrefix]=0
    $baseline=Get-JournalFor $Record.Path
    if(@($baseline.ParseErrors).Count -or @($baseline.SchemaErrors).Count){throw 'Office baseline journal invalid'}
    $Record.WorkflowBaseline=$baseline.Records;$ids=@($baseline.Records | ForEach-Object TransferId)
    [void](Invoke-T5WorkflowAck $Record $Spec.Op $Record.Path $Spec.Kind $codes $ids)
    $first=Wait-T5OfficeVersion $Record $ids ([bool]$Spec.Sensitive) $HandbackDirectory $BeforeHandback
    $Record[$versionsKey]+= $first
    if(-not $Spec.Sensitive){
        $ids=@($Record.Journal | ForEach-Object TransferId)
        $nextOp=if($Spec.Kind -ceq 'WordOverwriteApprove'){'word-overwrite'}else{$opPrefix+'-edit'}
        [void](Invoke-T5WorkflowAck $Record $nextOp $Record.Path $Spec.Kind $codes $ids)
        $newer=Wait-T5OfficeVersion $Record $ids $false '' @()
        if($newer.TransferId -ceq $first.TransferId){throw 'Office edit/overwrite reused the seed Release'}
        $Record[$versionsKey]+=$newer
    }
    $reopen=if($Spec.Sensitive){[string]$Record.Handback.Path}else{[string]$Record.Path}
    $readCodes=$codes.Clone();$readCodes['read-open']=0;$readCodes['read']=0;$readCodes['read-close']=0
    $ack=Invoke-T5WorkflowAck $Record ($opPrefix+'-read') $reopen $Spec.Kind $readCodes @()
    $lastVersion=$Record[$versionsKey][-1]
    if($ack.Read.Code -ne 0 -or $ack.Read.Length -ne $lastVersion.SealedLength -or $ack.Read.Sha256 -cne $lastVersion.Sha256Hex){throw 'Office actor reopen bytes differ from the inspected version'}
    Wait-T5OfficeCleanup $Record
    for($i=0;$i -lt 3;$i++){[void](Capture-T5Observation $Record 'WorkflowFinalBracket')}
    $image=@($Record.RawSamples[-1].CurrentImages | Where-Object {$_.Path -ieq $Record.Path})[0]
    $final=Read-Public $Record.Path
    $Record.FinalRawMatches=if($Spec.Sensitive){$image.Absent -eq $true -and $final.Status -ceq 'ABSENT'}else{
        $image.Absent -eq $false -and $image.Length -eq $Record.ExpectedLength -and $image.Sha256 -ceq $Record.ExpectedSha256 -and
        $final.Status -ceq 'OK' -and $final.Length -eq $Record.ExpectedLength -and $final.Sha256 -ceq $Record.ExpectedSha256}
    $Record.FinalLength=$final.Length;$Record.FinalSha256=$final.Sha256
    $Record.StageEvidence=@($Record.Journal | ForEach-Object {[pscustomobject]@{TransferId=$_.TransferId;Exists=($_.StageDeleted -ne $true);Length=$_.SealedLength}})
    $Record.NoStageLeftover=(@($Record.StageEvidence | Where-Object Exists).Count -eq 0)
    $Record.NoEmptyLeftover=$Record.FinalRawMatches;$Record.HandedBack=([bool]$Spec.Sensitive -and $Record.Handback.Status -ceq 'PASS')
    $Record.NativeStepsChecked=$true;$Record.NativeStepsOk=$true;$Record.NativeStepsReason='Every '+$app+' COM ack and standard-actor byte read checked'
    $Record.FinalJournalOutcomeVerified=$true;$Record.SettlementStatus='PASS';$Record.Published= -not $Spec.Sensitive
    $Record.WorkflowOutcome=($Record.FinalRawMatches -and $Record.NoStageLeftover -and -not $Record.Leaked)
}
function Invoke-T5Workflow($Spec,$Record,[string]$HandbackDirectory,[string[]]$BeforeHandback) {
    if($Spec.Office){Invoke-T5OfficeWorkflow $Spec $Record $HandbackDirectory $BeforeHandback;return}
    $Record.Workflow=$true;$Record.WorkflowAcks=@();$Record.WorkflowJournalSnapshots=@();$Record.Fixtures=@();$Record.WorkflowOutcome=$false
    $Record.ExpectedPublicAbsent=$Spec.Expected -ceq 'Absent';$Record.DeleteBarrierRequired=[bool]$Spec.DeleteBarrier
    $Record.DeleteBarrierVerified=$false;$Record.DeleteBarrierReason=$null
    $prior='T5 '+$Spec.Kind+' published clean prior'
    $newer='T5 '+$Spec.Kind+' inspected newer save'
    $priorBytes=[Text.Encoding]::ASCII.GetBytes($prior);$newerBytes=[Text.Encoding]::ASCII.GetBytes($newer)
    $empty=New-Object byte[] 0;$saveCodes=@{open=0;write=0;close=0}
    $expected=$priorBytes;$handbackBytes=$cpfBytes;$path=$Record.Path
    $seed=$Spec.Op -notin @('explorer-empty','empty-copy','empty-move','shell-copy-in','shell-move-in','shell-move-within')
    if($seed){
        [void](Invoke-T5WorkflowAck $Record 'native-create' $path $prior $saveCodes @())
        [void](Wait-T5WorkflowState $Record $path $priorBytes $false $true $false '' @() $empty)
        $Record.PriorPublication=@($Record.Journal | Where-Object {$_.State -eq '5' -and $_.Sha256Hex -ceq (Sha $priorBytes)})
    }
    $baseline=Get-JournalFor $path
    if(@($baseline.ParseErrors).Count -or @($baseline.SchemaErrors).Count){throw 'Workflow baseline journal is invalid'}
    $ids=@($baseline.Records | ForEach-Object TransferId);$Record.WorkflowBaseline=$baseline.Records
    switch($Spec.Op){
        'notepad-edit' {
            [void](Invoke-T5WorkflowAck $Record 'notepad-edit' $path $newer @{'notepad-edit'=0} $ids)
            $expected=$newerBytes;$Record.Method='Real Notepad existing-file open, replace text, File > Save, prompt-free close'
        }
        {$_ -cin @('shell-copy-in','shell-move-in')} {
            $codes=@{'shell-item-hr'=0;'shell-folder-hr'=0;'shell-flags-hr'=0;'shell-transfer-item-hr'=0;'shell-perform-hr'=0;'shell-abort-hr'=0;'shell-aborted'=0}
            $ack=Invoke-T5WorkflowAck $Record $Spec.Op $path $newer $codes $ids
            if($ack.SourceInActorTemp -ne $true -or $ack.SourceRead.Code -ne 0 -or $ack.SourceRead.Length -ne $newerBytes.Length -or $ack.SourceRead.Sha256 -cne (Sha $newerBytes)){throw 'Shell source bytes differ from the newer payload or source is outside actor TEMP'}
            if($Spec.Op -eq 'shell-move-in' -and ($ack.SourceGone -ne $true -or (Test-Path -LiteralPath $ack.Source))){throw 'Shell move left its TEMP source behind'}
            $Record.SourceGone=$ack.SourceGone;$expected=$newerBytes
        }
        'shell-move-within' {
            $oldPath=Join-Path $root $Spec.AuxiliaryLeaves[0]
            [void](Invoke-T5WorkflowAck $Record 'native-create' $oldPath $prior $saveCodes @())
            [void](Wait-T5WorkflowState $Record $oldPath $priorBytes $false $true $false '' @() $empty)
            $codes=@{'shell-item-hr'=0;'shell-folder-hr'=0;'shell-flags-hr'=0;'shell-transfer-item-hr'=0;'shell-perform-hr'=0;'shell-abort-hr'=0;'shell-aborted'=0}
            $ack=Invoke-T5WorkflowAck $Record 'shell-move-within' $path $oldPath $codes @()
            if($ack.Source -ine $oldPath -or $ack.SourceGone -ne $true -or $ack.SourceRead.Code -ne 0 -or $ack.SourceRead.Length -ne $priorBytes.Length -or $ack.SourceRead.Sha256 -cne (Sha $priorBytes)){throw 'Protected shell move did not consume the exact published prior'}
            $Record.OldPath=$oldPath;$Record.SourceGone=$true
            $Record.Method='IFileOperation MoveItem on published bytes within the same volume; seed Release required, no new Release required for native rename'
        }
        'native-read' {
            $deniedPath=Join-Path $root $Spec.AuxiliaryLeaves[0]
            [void](Invoke-T5WorkflowAck $Record 'native-create' $deniedPath $prior $saveCodes @())
            [void](Wait-T5WorkflowState $Record $deniedPath $priorBytes $false $true $false '' @() $empty)
            $read=Invoke-T5WorkflowAck $Record 'native-read' $path '' @{'read-open'=0;read=0;'read-close'=0} $ids
            if($read.Read.Code -ne 0 -or $read.Read.Length -ne $priorBytes.Length -or $read.Read.Sha256 -cne (Sha $priorBytes)){throw 'Standard actor did not read the exact existing bytes'}
            $fixture=Set-T5DeleteDenyFixture $deniedPath $root $result.ActorSid -ReadDeny;$Record.Fixtures+=$fixture
            try {
                $denied=Invoke-T5WorkflowAck $Record 'native-read' $deniedPath '' @{'read-open'=5} @()
                if($denied.Read.Code -ne 5 -or $denied.Read.Length -ne 0 -or $null -ne $denied.Read.Sha256){throw 'Denied sibling exported bytes or did not return access denied'}
            }finally{Restore-T5DeleteDenyFixture $fixture}
        }
        'explorer-empty' {
            $oldPath=Join-Path $root $Spec.AuxiliaryLeaves[0]
            [void](Invoke-T5WorkflowAck $Record 'native-create' $oldPath '' $saveCodes @())
            [void](Wait-T5WorkflowState $Record $oldPath $empty $false $true $false '' @() $empty)
            [void](Invoke-T5WorkflowAck $Record 'shell-rename-empty' $path $oldPath @{'shell-rename'=0} @())
            $child=Invoke-T5WorkflowAck $Record 'second-open-empty' $path '' @{'second-open'=0} @()
            if($child.Child.Length -ne 0 -or $child.Child.FirstByte -ne -1 -or $child.Child.ReadWrite -ne $true){throw 'Second-process read/write open did not observe the unchanged empty file'}
            $expected=$empty;$Record.OldPath=$oldPath;$Record.SecondProcess=$child.Child
        }
        'empty-copy' {[void](Invoke-T5WorkflowAck $Record 'empty-copy' $path '' @{copy=0} @());$expected=$empty}
        'empty-move' {
            $move=Invoke-T5WorkflowAck $Record 'empty-move' $path '' @{move=0} @()
            if($move.SourceGone -ne $true -or (Test-Path -LiteralPath $move.Source)){throw 'Empty move left its source behind'}
            $Record.SourceGone=$true;$expected=$empty
        }
        'native-clear' {
            $Record.Method='Native TRUNCATE_EXISTING + close; real Notepad clear UI not used'
            [void](Invoke-T5WorkflowAck $Record 'native-clear' $path '' $saveCodes $ids);$expected=$empty
        }
        {$_ -cin @('remove-item','shell-delete')} {
            [void](Invoke-T5WorkflowAck $Record $Spec.Op $path '' $(if($Spec.Op -eq 'remove-item'){@{remove=0}}else{@{'shell-item-hr'=0;'shell-flags-hr'=0;'shell-delete-item-hr'=0;'shell-perform-hr'=0;'shell-abort-hr'=0;'shell-aborted'=0}}) $ids)
        }
        'deny-acl' {
            $nativeParent=Join-Path $control ('native-acl-'+$script:n);[void][IO.Directory]::CreateDirectory($nativeParent)
            $nativePath=Join-Path $nativeParent 'native.txt'
            [void](Invoke-T5WorkflowAck $Record 'native-create' $nativePath $prior $saveCodes @())
            $sid=(New-Object Security.Principal.NTAccount($env:COMPUTERNAME,$ActorUser)).Translate([Security.Principal.SecurityIdentifier]).Value
            foreach($fixturePath in @($nativePath,$path)){
                $fixture=Set-T5DeleteDenyFixture $fixturePath (Split-Path -Parent $fixturePath) $sid;$Record.Fixtures+=$fixture
                try {
                    $denied=Invoke-T5WorkflowAck $Record 'native-delete' $fixturePath '' @{delete=5} $ids
                    if($fixturePath -eq $nativePath){$Record.NativeControlCode=Get-NativeStepCode $denied.Steps 'delete'}else{$Record.ProtectedDeleteCode=Get-NativeStepCode $denied.Steps 'delete'}
                }finally{Restore-T5DeleteDenyFixture $fixture}
            }
        }
        'deny-share' {
            $nativePath=Join-Path $control ('native-share-'+$script:n+'.txt')
            [void](Invoke-T5WorkflowAck $Record 'native-create' $nativePath $prior $saveCodes @())
            foreach($fixturePath in @($nativePath,$path)){
                try {
                    [void](Invoke-T5WorkflowAck $Record 'hold-no-share-delete' $fixturePath '' @{'hold-open'=0} $ids)
                    $denied=Invoke-T5WorkflowAck $Record 'native-delete' $fixturePath '' @{delete=32} $ids
                    if($fixturePath -eq $nativePath){$Record.NativeControlCode=Get-NativeStepCode $denied.Steps 'delete'}else{$Record.ProtectedDeleteCode=Get-NativeStepCode $denied.Steps 'delete'}
                }finally{[void](Invoke-T5WorkflowAck $Record 'close-held' $fixturePath '' @{'hold-close'=0} $ids)}
            }
        }
        {$_ -cin @('inflight-before','inflight-after')} {
            # T5-UX-NAMESPACE-GAP D2/D6 supersedes bound admission wording:
            # an open newer writer refuses public delete (32), leaves P intact,
            # then closing may publish newer clean bytes. Only a completed
            # publication can win the opposite order; its native delete is 0,
            # leaving absence. Pending/blocked saves never supersede a delete
            # (T5-DELETES 1.4 / 4). No gate pauses inside the physical rename.
            $Record.OrderingNote='Deterministic held-writer-before-seal / Released-after-commit boundaries only. Existing probe gates cannot force the interior of the short physical commit turn.'
            if($Spec.Op -eq 'inflight-before'){$Record.GateSha256=Sha $priorBytes;$Record.GateLength=$priorBytes.Length;$code=32;$expected=$newerBytes}
            else{$Record.GateSha256=Sha $newerBytes;$Record.GateLength=$newerBytes.Length;$code=0}
            [void](Invoke-T5WorkflowAck $Record $Spec.Op $path $newer @{'hold-open'=0;'hold-write'=0;'hold-close'=0;delete=$code} $ids)
        }
        'delete-cpf' {
            [void](Invoke-T5WorkflowAck $Record 'native-delete' $path '' @{delete=0} $ids)
            [void](Wait-T5WorkflowState $Record $path $empty $true $false $false '' @() $empty)
            $Record.DeleteObservedBeforeBlockedSave=$true
            [void](Invoke-T5WorkflowAck $Record 'native-create' $path $cpfText $saveCodes $ids)
        }
        'native-append' {
            $line="`r`n"+$cpfText;$handbackBytes=[Text.Encoding]::ASCII.GetBytes($prior+$line)
            [void](Invoke-T5WorkflowAck $Record 'native-append' $path $line @{open=0;seek=0;write=0;close=0} $ids)
        }
        default{throw ('Unknown workflow '+$Spec.Op)}
    }
    $Record.ExpectedLength=$expected.Length;$Record.ExpectedSha256=Sha $expected
    $Record.ExpectedHandbackLength=$handbackBytes.Length;$Record.ExpectedHandbackSha256=Sha $handbackBytes
    $requireRelease=$Spec.Expected -cin @('Empty','Newer') -and $Spec.Op -cne 'explorer-empty'
    [void](Wait-T5WorkflowState $Record $path $expected $Record.ExpectedPublicAbsent $requireRelease ([bool]$Spec.Handback) $HandbackDirectory $BeforeHandback $handbackBytes)
    if($Spec.Op -cin @('deny-acl','deny-share','inflight-before')){
        $canceled=@($Record.Journal | Where-Object {$null -ne $_.UnboundCancellation -or $null -ne $_.DiscardRequestedAtUtc})
        $Record.NoPrivateCancellation=($canceled.Count -eq 0)
        if(-not $Record.NoPrivateCancellation){throw 'Refused public delete recorded private cancellation/discard'}
    }
    for($i=0;$i -lt 3;$i++){[void](Capture-T5Observation $Record 'WorkflowFinalBracket')}
    $last=$Record.RawSamples[-1];$image=@($last.CurrentImages | Where-Object {$_.Path -ieq $path})[0]
    $final=Read-Public $path
    $Record.FinalRawMatches=if($Record.ExpectedPublicAbsent){$image.Absent -eq $true -and $final.Status -ceq 'ABSENT'}else{$image.Absent -eq $false -and $image.Length -eq $expected.Length -and $image.Sha256 -ceq (Sha $expected) -and $final.Status -ceq 'OK' -and (Same $final.Bytes $expected)}
    $Record.FinalLength=$final.Length;$Record.FinalSha256=$final.Sha256
    if($Record.OldPath){
        $old=@($last.CurrentImages | Where-Object {$_.Path -ieq $Record.OldPath})
        $Record.OldNameAbsent=($old.Count -eq 1 -and $old[0].Absent -eq $true -and (Read-Public $Record.OldPath).Status -ceq 'ABSENT')
        if(-not $Record.OldNameAbsent){throw 'Explorer old name survived rename'}
    }
    $Record.NoEmptyLeftover=$Record.FinalRawMatches
    $Record.StageEvidence=@($Record.Journal | ForEach-Object {
        $stage=$null;$guarded=$false
        # The driver hides the private staging namespace from every process but the service: a lookup there is refused (deny ring reason
        # privateNamespace) whether or not the file exists. Then only the service's journal can say; a journal that does not record the
        # stage as deleted counts as an existing stage whose length is the journal's sealed length (a clean case has none, so it fails;
        # a blocked hand-back case may keep it), and the launcher independently lists the staging directory after the run
        # (T5StagingEmptyAfterRun).
        try{$stage=Get-Item -LiteralPath $_.StagePath -Force -ErrorAction Stop}catch{
            if($_.CategoryInfo.Category -eq [Management.Automation.ErrorCategory]::PermissionDenied -or $_.Exception -is [UnauthorizedAccessException]){$guarded=$true}
            elseif($_.CategoryInfo.Category -ne [Management.Automation.ErrorCategory]::ObjectNotFound){throw}}
        [pscustomobject]@{TransferId=$_.TransferId;Path=$_.StagePath;StageDeleted=$_.StageDeleted;Exists=$(if($guarded){$_.StageDeleted -ne $true}else{$null -ne $stage});Length=$(if($stage){$stage.Length}elseif($guarded){$_.SealedLength}else{$null});State=$_.State;Probe=$(if($guarded){'PrivateNamespaceGuard'}else{'Direct'})}
    })
    # Blocked full-content stages may remain for justification. Empty/private
    # leftovers never qualify; successful clean rows require acknowledged cleanup.
    $Record.NoStageLeftover=(@($Record.StageEvidence | Where-Object {$_.Exists -and ($_.Length -eq 0 -or -not $Spec.Handback)}).Count -eq 0)
    if($Spec.DeleteBarrier){
        $barriers=@() # Private discard, ancestry, and Released are not a durable PUBLIC-delete barrier.
        $Record.DeleteBarrierVerified=($barriers.Count -gt 0);$Record.DeleteBarrierRecords=$barriers
        $Record.DeleteBarrierReason='A Released seed is not a delete barrier. Native unbound public deletion may emit no durable barrier; absent exact journal evidence this required assertion stays unproved.'
    }
    $Record.HandedBack=([bool]$Spec.Handback -and $Record.Handback.Status -ceq 'PASS')
    $Record.NativeStepsChecked=$true;$Record.NativeStepsOk=$true;$Record.NativeStepsReason='Every workflow ack checked; Win32 denial compared with an unprotected native control'
    $Record.FinalJournalOutcomeVerified=$true;$Record.SettlementStatus='PASS';$Record.Published= -not $Record.ExpectedPublicAbsent
    $Record.WorkflowOutcome=($Record.FinalRawMatches -and $Record.NoStageLeftover -and $Record.RawCoverageComplete -and $Record.IndependentReadersAgree -and -not $Record.Leaked)
}
function Get-Handback([string]$Directory, [string[]]$BeforePaths, [byte[]]$Expected, [string]$Pattern = '*.txt') {
    $all = @(Get-ChildItem -LiteralPath $Directory -Filter $Pattern -File -Force -ErrorAction SilentlyContinue)
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
    if($allGood){
        $directory=Join-Path $out 'handback-evidence';[void][IO.Directory]::CreateDirectory($directory)
        $artifact=Join-Path $directory ((Sha $direct.Bytes)+'.bin')
        if(-not [IO.File]::Exists($artifact)){[IO.File]::WriteAllBytes($artifact,$direct.Bytes)}
        $receipt.Artifact=$artifact
    }
    if ($allGood) { $receipt.Status = 'PASS' } else { $receipt.Status = 'FAIL'; $receipt.Error = 'Buffered hand-back and both fresh readers must match the exact unapproved fixture.' }
    return [pscustomobject]$receipt
}

# Exact observed-image whitelist for the new workflows. This rejects arbitrary
# clean-looking intermediate bytes as well as CPF; it is not an inspection or
# lower-mutation ledger and cannot promote the canonical INCONCLUSIVE verdict.
foreach($spec in @($cases | Where-Object {$_.Workflow})){
    $hashes=@()
    if($spec.Office){$script:T5WorkflowPublicHashes[(Join-Path $root $spec.Leaf)]=@();continue}
    if($spec.Op -notin @('explorer-empty','empty-copy','empty-move','shell-copy-in','shell-move-in')){$hashes+=Sha ([Text.Encoding]::ASCII.GetBytes('T5 '+$spec.Kind+' published clean prior'))}
    if($spec.Op -cin @('inflight-before','inflight-after','notepad-edit','shell-copy-in','shell-move-in')){$hashes+=Sha ([Text.Encoding]::ASCII.GetBytes('T5 '+$spec.Kind+' inspected newer save'))}
    foreach($leaf in @($spec.Leaf)+@($spec.AuxiliaryLeaves)) {if($leaf){$script:T5WorkflowPublicHashes[(Join-Path $root $leaf)]=$hashes}}
}
$script:n = 0
New-Item -ItemType Directory -Force -Path $out, $control | Out-Null
try {
    Import-Module -Name $ObserverModule -Force -DisableNameChecking -ErrorAction Stop
    $rawContext = Open-InvariantObserver ([StagedInvariant.Native]::ResolveGuid($root)) $root (Join-Path $out 'raw') 'T5'
    if ($rawContext.Status -cne 'OK') { throw ('Raw observer open failed: ' + ($rawContext.Error | ConvertTo-Json -Depth 12 -Compress)) }
    $rawContext | Add-Member -NotePropertyName NamedOpenAttributesOnly -NotePropertyValue $true
    # m2t5ord6: the raw MFT/index copy lags NTFS's cache after the cases' deletes and recreates, and the probe gates sample
    # names that are delete-pending in the filter's view. Both observer behaviours are opt-in for this row only.
    $script:T5FlushVolume = @(Get-Volume -FilePath $root -ErrorAction Stop)
    if ($script:T5FlushVolume.Count -ne 1 -or $script:T5FlushVolume[0].FileSystem -ine 'NTFS' -or $script:T5FlushVolume[0].DriveType -ine 'Fixed') { throw 'The raw flush requires the exact fixed NTFS volume.' }
    $rawContext | Add-Member -NotePropertyName StaleMetadataFlush -NotePropertyValue { $script:T5FlushVolume[0] | Write-VolumeCache -ErrorAction Stop | Out-Null }
    $rawContext | Add-Member -NotePropertyName DeletePendingAbsentByRawIndex -NotePropertyValue $true
    # m2t5ord16: the boot-Verifier boot is slow enough that the on-disk MFT record 0 lags the growth the cases cause; keep the verified map
    # and refresh again instead of ending the observer for the rest of the run (a changed or shrunk prefix stays fatal).
    $rawContext.Volume.RetryStaleMftRefresh = $true
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
    if ($profile.Count -ne 1) {
        # Status flags: 1 temporary, 2 roaming, 4 mandatory, 8 corrupted.
        $seen = @(Get-CimInstance Win32_UserProfile | Where-Object { $_.SID -eq $sid -or $_.LocalPath -match '\\(t5actor|TEMP)' } |
            ForEach-Object { $_.SID + ' ' + $_.LocalPath + ' status=' + $_.Status + ' loaded=' + $_.Loaded + ' special=' + $_.Special })
        throw ('Exactly one actor profile must bind to the actor SID. sid=' + $sid + ' profiles=[' + ($seen -join '; ') + ']')
    }
    $handback = Join-Path $profile[0].LocalPath 'SafeUpload\_bloqueados'
    $result.HandbackDirectory=$handback;$result.ActorSid=$sid
    foreach ($case in $cases) {
        $path = Join-Path $root $case.Leaf
        $text = if ($case.Sensitive) { $cpfText } else { 'T5 ' + $case.Kind + ' clean text' }
        $bytes = [Text.Encoding]::ASCII.GetBytes($text)
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
        try {
        $beforeJournal = Get-JournalFor $path
        if (@($beforeJournal.ParseErrors).Count -gt 0 -or @($beforeJournal.SchemaErrors).Count -gt 0) {
            $record.JournalParseErrors = @($beforeJournal.ParseErrors); $record.JournalSchemaErrors = @($beforeJournal.SchemaErrors)
            throw 'Pre-case journal parsing/schema validation failed; the case cannot bind a trustworthy baseline.'
        }
        $beforeIds = @($beforeJournal.Records | ForEach-Object { $_.TransferId })
        $handbackPattern=if($case.Office){'*'+[IO.Path]::GetExtension([string]$case.Leaf)}else{'*.txt'}
        $beforeHandback = @(Get-ChildItem -LiteralPath $handback -Filter $handbackPattern -File -Force -ErrorAction SilentlyContinue | ForEach-Object { $_.FullName })
        if($case.Workflow) { Invoke-T5Workflow $case $record $handback $beforeHandback; continue }
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
        if (@($record.RawSamples).Count -eq 0 -or @(Get-T5UnresolvedRawSamples $record).Count -gt 0) { $record.RawCoverageComplete = $false }
        if (@($record.RawSamples | Where-Object { -not $_.IndependentReadersAgree -and -not (Test-T5SampleSuperseded $_) }).Count -gt 0) { $record.IndependentReadersAgree = $false }
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
            # The private view refuses with STATUS_DELETE_PENDING (T5-DELETES); Win32 reports it as 5, never 303 (m2t5ord6).
            else { $names += @('open-after-doc-flag', 'open-after-doc-flag-nt'); $expectedCodes['open-after-doc-flag'] = 5; $expectedCodes['open-after-doc-flag-nt'] = -1073741738 }
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
            $names = @('first-create','second-open','first-on-close-delete','open-after-first-flag','open-after-first-flag-nt','second-on-close-delete',
                'first-on-close-clear','open-after-first-clear','open-after-first-clear-nt','second-on-close-clear','open-after-both-clear','save-write','save-close','first-close','second-close')
            # STATUS_DELETE_PENDING (0xC0000056) as a signed Int32, reported by Win32 as 5.
            $expectedCodes = @{ 'first-create' = 0; 'second-open' = 0; 'first-on-close-delete' = 0; 'open-after-first-flag' = 5; 'open-after-first-flag-nt' = -1073741738;
                'second-on-close-delete' = 0; 'first-on-close-clear' = 0; 'open-after-first-clear' = 5; 'open-after-first-clear-nt' = -1073741738; 'second-on-close-clear' = 0;
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
        } catch {
            $record.Error = $_.Exception.ToString() + ' stack=' + $_.ScriptStackTrace
            $record.SettlementStatus = 'FAIL'; $record.RawCoverageComplete = $false
            # A failed gate is never released as if proved. The actor's own bounded
            # gate timeout closes its handles; wait for that ack before the next case.
            $pendingAck = Join-Path $control ('ack-' + $script:n + '.json')
            $pendingCommand = Join-Path $control ('cmd-' + $script:n + '.json')
            $drainDeadline = [Diagnostics.Stopwatch]::GetTimestamp() + 60 * $frequency
            while ((Test-Path -LiteralPath $pendingCommand) -and -not (Test-Path -LiteralPath $pendingAck) -and
                [Diagnostics.Stopwatch]::GetTimestamp() -lt $drainDeadline) { Start-Sleep -Milliseconds 50 }
            if (Test-Path -LiteralPath $pendingAck) {
                try { $record.FailureAck = (Read-ControlText $pendingAck) | ConvertFrom-Json } catch { $record.Error += '; failure ack: ' + $_.Exception.Message }
            }
        } finally { $result.Cases += [pscustomobject]$record }
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
