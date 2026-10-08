#if SAFEUPLOAD_ADMISSION_EVIDENCE
using System.Buffers.Binary;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using SafeUpload.Agent.Minifilter;

namespace SafeUpload.Agent.Service.Diagnostics;

internal static class AdmissionEvidencePolicyFingerprint
{
    internal static byte[] ComputeCanonicalCandidateFingerprint(SafeUploadPolicyMessage candidate)
    {
        // Canonicalize fields which SetPolicy supplies on the wire. The final
        // durable-scope call uses Reserved=1, so this fingerprint identifies
        // the accepted policy candidate and is not a hash of that final call.
        candidate.Control.Version = Contract.Version;
        candidate.Control.StructSize = (uint)Contract.PolicyMessageSize;
        candidate.Control.Command = ControlCommand.SetPolicy;
        candidate.Control.Reserved = 0;
        return SHA256.HashData(MemoryMarshal.AsBytes(
            MemoryMarshal.CreateReadOnlySpan(ref candidate, 1)));
    }
}

internal sealed class AdmissionEvidenceBinding
{
    private readonly object _lifetime = new();
    private bool _accepting = true;
    private int _inFlight;

    private AdmissionEvidenceBinding(
        IAdmissionEvidenceSender sender,
        long generation,
        int policyVersion,
        byte[] canonicalCandidateFingerprint,
        AdmissionEvidenceReply epochReceipt,
        AdmissionEvidenceEpoch? epoch)
    {
        Sender = sender;
        Generation = generation;
        PolicyVersion = policyVersion;
        CanonicalCandidateFingerprint = (byte[])canonicalCandidateFingerprint.Clone();
        EpochReceipt = epochReceipt;
        InitialEpoch = epoch;
    }

    internal IAdmissionEvidenceSender Sender { get; }
    internal long Generation { get; }
    internal int PolicyVersion { get; }
    internal byte[] CanonicalCandidateFingerprint { get; }
    internal AdmissionEvidenceReply EpochReceipt { get; }
    internal AdmissionEvidenceEpoch? InitialEpoch { get; }
    internal bool IsAccepting
    {
        get { lock (_lifetime) return _accepting; }
    }

    internal static AdmissionEvidenceBinding TryCreate(
        IAdmissionEvidenceSender sender,
        long generation,
        int policyVersion,
        ReadOnlySpan<byte> canonicalCandidateFingerprint)
    {
        ArgumentNullException.ThrowIfNull(sender);
        if (generation <= 0 || policyVersion < 0 || canonicalCandidateFingerprint.Length != 32)
            throw new ArgumentException("Invalid admission evidence policy binding.");

        AdmissionEvidenceReply reply = sender.SendAdmissionEvidence(AdmissionEvidenceCommand.EpochStatus);
        AdmissionEvidenceEpoch? epoch = null;
        if (AdmissionEvidenceWire.InputMatches(reply, AdmissionEvidenceCommand.EpochStatus, 0) &&
            reply.IsWirePayloadValid &&
            AdmissionEvidenceWire.TryParseEpoch(reply.RawReply, reply.BytesReturned, out AdmissionEvidenceEpoch parsed))
            epoch = parsed;

        return new AdmissionEvidenceBinding(sender, generation, policyVersion,
            canonicalCandidateFingerprint.ToArray(), reply, epoch);
    }

    internal bool TrySend(AdmissionEvidenceCommand command, uint startIndex, out AdmissionEvidenceReply? reply)
    {
        if (!AdmissionEvidenceWire.IsAllowed(command, startIndex))
            throw new InvalidOperationException("The evidence endpoint only permits controls 19, 20, and 23.");

        lock (_lifetime)
        {
            if (!_accepting)
            {
                reply = null;
                return false;
            }
            _inFlight++;
        }

        try
        {
            reply = Sender.SendAdmissionEvidence(command, startIndex);
            return true;
        }
        finally
        {
            lock (_lifetime)
            {
                _inFlight--;
                if (_inFlight == 0) Monitor.PulseAll(_lifetime);
            }
        }
    }

    internal bool TrySendStagedProof(byte[] request, int outputBytes, out AdmissionEvidenceReply? reply)
    {
        byte[] input = (byte[])request.Clone();
        StagedProofProxyWire.Validate(input, outputBytes);
        lock (_lifetime)
        {
            if (!_accepting || Sender is not IStagedProofSender)
            {
                reply = null;
                return false;
            }
            _inFlight++;
        }
        try
        {
            reply = ((IStagedProofSender)Sender).SendStagedProof(input, outputBytes);
            return true;
        }
        finally
        {
            lock (_lifetime)
            {
                _inFlight--;
                if (_inFlight == 0) Monitor.PulseAll(_lifetime);
            }
        }
    }

    internal void StopAcceptingAndDrain()
    {
        lock (_lifetime)
        {
            _accepting = false;
            while (_inFlight != 0) Monitor.Wait(_lifetime);
        }
    }

    internal void InvalidateAfterEpochDrift()
    {
        lock (_lifetime) _accepting = false;
    }
}

internal readonly record struct AdmissionEvidenceEpoch(
    uint PolicyGeneration,
    uint EpochGeneration,
    uint ActiveCallbacks,
    uint Flags,
    ulong ChangeSequence);

internal sealed record AdmissionEvidenceVolumeSnapshot(byte[] RawBytes, uint MatchCount);

internal readonly record struct AdmissionEvidenceActivatingEntry(
    uint Generation,
    uint State,
    uint H,
    uint S,
    uint C,
    uint T,
    uint W,
    uint UnknownReasons);

internal sealed record AdmissionEvidenceActivatingPage(
    uint TotalEntries,
    uint EntryCount,
    uint StartIndex,
    uint NextIndex,
    uint PolicyGeneration,
    ulong ChangeSequence,
    uint Flags,
    uint Reserved,
    IReadOnlyList<AdmissionEvidenceActivatingEntry> TargetEntries);

internal static class AdmissionEvidenceWire
{
    internal const int ControlBytes = 16;
    internal const int EpochBytes = 32;
    internal const int VolumeStatusBytes = 6672;
    internal const int VolumeEntryBytes = 208;
    internal const int VolumeGuidCharsOffset = 52;
    internal const int VolumeGuidOffset = 76;
    internal const int ActivatingHeaderBytes = 40;
    internal const int ActivatingEntryBytes = 1128;
    internal const int ActivatingPageBytes = ActivatingHeaderBytes +
        AdmissionEvidenceLimits.ActivatingPageEntries * ActivatingEntryBytes;
    private static readonly UnicodeEncoding StrictUtf16 = new(false, false, true);

    internal static bool IsAllowed(AdmissionEvidenceCommand command, uint startIndex) => command switch
    {
        AdmissionEvidenceCommand.ActivatingStatus =>
            startIndex <= AdmissionEvidenceLimits.MaxActivatingEntries &&
            startIndex % AdmissionEvidenceLimits.ActivatingPageEntries == 0,
        AdmissionEvidenceCommand.EpochStatus or AdmissionEvidenceCommand.VolumeObserve => startIndex == 0,
        _ => false,
    };

    internal static bool InputMatches(
        AdmissionEvidenceReply reply,
        AdmissionEvidenceCommand command,
        uint startIndex)
    {
        byte[] input = reply.RawInput;
        return input.Length == ControlBytes &&
            BinaryPrimitives.ReadUInt32LittleEndian(input.AsSpan(0, 4)) == Contract.Version &&
            BinaryPrimitives.ReadUInt32LittleEndian(input.AsSpan(4, 4)) == ControlBytes &&
            BinaryPrimitives.ReadUInt32LittleEndian(input.AsSpan(8, 4)) == (uint)command &&
            BinaryPrimitives.ReadUInt32LittleEndian(input.AsSpan(12, 4)) == startIndex;
    }

    internal static bool TryParseEpoch(
        byte[] raw,
        uint bytesReturned,
        out AdmissionEvidenceEpoch epoch)
    {
        epoch = default;
        if (raw.Length != EpochBytes || bytesReturned != EpochBytes ||
            BinaryPrimitives.ReadUInt32LittleEndian(raw.AsSpan(0, 4)) != EpochBytes ||
            BinaryPrimitives.ReadUInt32LittleEndian(raw.AsSpan(20, 4)) != 0)
            return false;

        epoch = new AdmissionEvidenceEpoch(
            BinaryPrimitives.ReadUInt32LittleEndian(raw.AsSpan(4, 4)),
            BinaryPrimitives.ReadUInt32LittleEndian(raw.AsSpan(8, 4)),
            BinaryPrimitives.ReadUInt32LittleEndian(raw.AsSpan(12, 4)),
            BinaryPrimitives.ReadUInt32LittleEndian(raw.AsSpan(16, 4)),
            BinaryPrimitives.ReadUInt64LittleEndian(raw.AsSpan(24, 8)));
        return true;
    }

    internal static bool TryParseVolumeSnapshot(
        byte[] raw,
        uint bytesReturned,
        string expectedVolumeGuid,
        out AdmissionEvidenceVolumeSnapshot? snapshot)
    {
        snapshot = null;
        if (raw.Length != VolumeStatusBytes || bytesReturned != VolumeStatusBytes ||
            BinaryPrimitives.ReadUInt32LittleEndian(raw.AsSpan(0, 4)) != VolumeStatusBytes)
            return false;

        uint count = BinaryPrimitives.ReadUInt32LittleEndian(raw.AsSpan(4, 4));
        if (count > AdmissionEvidenceLimits.ActivatingPageEntries)
            return false;

        uint matches = 0;
        for (uint index = 0; index < count; index++)
        {
            int offset = checked(16 + (int)index * VolumeEntryBytes);
            uint chars = BinaryPrimitives.ReadUInt32LittleEndian(raw.AsSpan(offset + VolumeGuidCharsOffset, 4));
            if (chars > 63) return false;
            string value = DecodeUtf16(raw.AsSpan(offset + VolumeGuidOffset, checked((int)chars * 2)));
            if (value.IndexOf('\0') >= 0) return false;
            if (string.Equals(value, expectedVolumeGuid, StringComparison.OrdinalIgnoreCase))
                matches++;
        }

        snapshot = new AdmissionEvidenceVolumeSnapshot((byte[])raw.Clone(), matches);
        return true;
    }

    internal static bool TryParseActivatingPage(
        byte[] raw,
        uint bytesReturned,
        uint requestedStart,
        ulong expectedSerial,
        ReadOnlySpan<byte> expectedFileId,
        out AdmissionEvidenceActivatingPage? page)
    {
        page = null;
        if (raw.Length != ActivatingPageBytes || bytesReturned != ActivatingPageBytes ||
            BinaryPrimitives.ReadUInt32LittleEndian(raw.AsSpan(0, 4)) != ActivatingPageBytes)
            return false;

        uint total = BinaryPrimitives.ReadUInt32LittleEndian(raw.AsSpan(4, 4));
        uint entryCount = BinaryPrimitives.ReadUInt32LittleEndian(raw.AsSpan(8, 4));
        uint start = BinaryPrimitives.ReadUInt32LittleEndian(raw.AsSpan(12, 4));
        uint next = BinaryPrimitives.ReadUInt32LittleEndian(raw.AsSpan(16, 4));
        uint generation = BinaryPrimitives.ReadUInt32LittleEndian(raw.AsSpan(20, 4));
        ulong changeSequence = BinaryPrimitives.ReadUInt64LittleEndian(raw.AsSpan(24, 8));
        uint flags = BinaryPrimitives.ReadUInt32LittleEndian(raw.AsSpan(32, 4));
        uint reserved = BinaryPrimitives.ReadUInt32LittleEndian(raw.AsSpan(36, 4));

        if (total > AdmissionEvidenceLimits.MaxActivatingEntries ||
            entryCount > AdmissionEvidenceLimits.ActivatingPageEntries ||
            start != requestedStart || next < start || next > total ||
            entryCount != next - start)
            return false;

        var targetEntries = new List<AdmissionEvidenceActivatingEntry>();
        for (uint index = 0; index < entryCount; index++)
        {
            int offset = checked(ActivatingHeaderBytes + (int)index * ActivatingEntryBytes);
            uint reservedFlags = BinaryPrimitives.ReadUInt32LittleEndian(raw.AsSpan(offset + 56, 4));
            uint openerCount = BinaryPrimitives.ReadUInt32LittleEndian(raw.AsSpan(offset + 60, 4));
            uint nameChars = BinaryPrimitives.ReadUInt32LittleEndian(raw.AsSpan(offset + 96, 4));
            if (reservedFlags != 0 || openerCount > 8 || nameChars > 512) return false;

            bool idMatch = BinaryPrimitives.ReadUInt64LittleEndian(raw.AsSpan(offset, 8)) == expectedSerial &&
                raw.AsSpan(offset + 8, 16).SequenceEqual(expectedFileId);
            if (!idMatch) continue;

            targetEntries.Add(new AdmissionEvidenceActivatingEntry(
                BinaryPrimitives.ReadUInt32LittleEndian(raw.AsSpan(offset + 24, 4)),
                BinaryPrimitives.ReadUInt32LittleEndian(raw.AsSpan(offset + 28, 4)),
                BinaryPrimitives.ReadUInt32LittleEndian(raw.AsSpan(offset + 32, 4)),
                BinaryPrimitives.ReadUInt32LittleEndian(raw.AsSpan(offset + 36, 4)),
                BinaryPrimitives.ReadUInt32LittleEndian(raw.AsSpan(offset + 40, 4)),
                BinaryPrimitives.ReadUInt32LittleEndian(raw.AsSpan(offset + 44, 4)),
                BinaryPrimitives.ReadUInt32LittleEndian(raw.AsSpan(offset + 48, 4)),
                BinaryPrimitives.ReadUInt32LittleEndian(raw.AsSpan(offset + 52, 4))));
        }

        page = new AdmissionEvidenceActivatingPage(total, entryCount, start, next,
            generation, changeSequence, flags, reserved, targetEntries);
        return true;
    }

    internal static bool IsRetryHResult(int hresult) =>
        hresult == unchecked((int)0x800704D5) || hresult == unchecked((int)0xD000022D);

    private static string DecodeUtf16(ReadOnlySpan<byte> bytes)
    {
        if ((bytes.Length & 1) != 0) throw new InvalidDataException("Malformed UTF-16 field in volume observation.");
        try { return StrictUtf16.GetString(bytes); }
        catch (DecoderFallbackException ex)
        {
            throw new InvalidDataException("Malformed UTF-16 field in volume observation.", ex);
        }
    }
}

internal sealed class AdmissionEvidenceCapture
{
    private readonly Func<AdmissionEvidenceBinding, AdmissionEvidenceCommand, uint, AdmissionEvidenceReply?> _send;
    private readonly Func<AdmissionEvidenceBinding, bool> _isCurrent;
    private readonly TimeSpan _frameWriteDeadline;

    internal AdmissionEvidenceCapture(
        Func<AdmissionEvidenceBinding, AdmissionEvidenceCommand, uint, AdmissionEvidenceReply?> send,
        Func<AdmissionEvidenceBinding, bool> isCurrent,
        TimeSpan? frameWriteDeadline = null)
    {
        _send = send ?? throw new ArgumentNullException(nameof(send));
        _isCurrent = isCurrent ?? throw new ArgumentNullException(nameof(isCurrent));
        _frameWriteDeadline = frameWriteDeadline ?? AdmissionEvidenceLimits.FrameWriteDeadline;
        if (_frameWriteDeadline <= TimeSpan.Zero || _frameWriteDeadline == Timeout.InfiniteTimeSpan)
            throw new ArgumentOutOfRangeException(nameof(frameWriteDeadline));
    }

    internal async Task<AdmissionEvidenceCaptureSummary> CaptureAsync(
        Stream output,
        AdmissionEvidenceRequest request,
        AdmissionEvidenceBinding binding,
        AdmissionEvidenceCaller caller,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(output);
        ArgumentNullException.ThrowIfNull(request);
        ArgumentNullException.ThrowIfNull(binding);
        ArgumentNullException.ThrowIfNull(caller);

        // This is the retained bind-time receipt, not a new native send. Its
        // distinct BindingReceipt frame kind and original timestamps preserve
        // that distinction while making each hook stream independently useful.
        AdmissionEvidenceReply initialEpochReceipt = binding.EpochReceipt;
        await AdmissionEvidenceFrames.WriteCallAsync(output,
            AdmissionEvidenceFrameKind.BindingReceipt, null, binding,
            AdmissionEvidenceCommand.EpochStatus, initialEpochReceipt, 0, 0,
            cancellationToken, _frameWriteDeadline).ConfigureAwait(false);

        string reason = "EvidenceCaptured";
        bool failed = false;
        bool stableSnapshot = false;
        uint targetMatchCount = 0;
        AdmissionEvidenceActivatingEntry? target = null;
        uint volumeBeforeCount = 0;
        uint volumeAfterCount = 0;
        bool volumeSnapshotsEqual = false;
        AdmissionEvidenceEpoch? beforeEpoch = null;
        AdmissionEvidenceEpoch? afterEpoch = null;
        uint? activatingGeneration = null;
        ulong? activatingChangeSequence = null;
        long rawPageBytes = 0;

        if (binding.InitialEpoch is null)
        {
            failed = true;
            reason = "BindingEpochReceiptInvalid";
        }

        AdmissionEvidenceReply? beforeEpochReply = await SendAndWriteAsync(
            output, request, binding, AdmissionEvidenceCommand.EpochStatus, 0, 0,
            cancellationToken).ConfigureAwait(false);
        if (beforeEpochReply is null || !TryEpoch(beforeEpochReply, out AdmissionEvidenceEpoch parsedBefore))
        {
            failed = true;
            reason = beforeEpochReply is null ? "PortUnbound" : "EpochBeforeInvalid";
        }
        else
        {
            beforeEpoch = parsedBefore;
        }

        AdmissionEvidenceReply? volumeBeforeReply = await SendAndWriteAsync(
            output, request, binding, AdmissionEvidenceCommand.VolumeObserve, 0, 0,
            cancellationToken).ConfigureAwait(false);
        AdmissionEvidenceVolumeSnapshot? volumeBefore = null;
        if (volumeBeforeReply is null || !volumeBeforeReply.IsWirePayloadValid ||
            !AdmissionEvidenceWire.InputMatches(volumeBeforeReply, AdmissionEvidenceCommand.VolumeObserve, 0) ||
            !AdmissionEvidenceWire.TryParseVolumeSnapshot(volumeBeforeReply.RawReply,
                volumeBeforeReply.BytesReturned, request.VolumeGuid, out volumeBefore))
        {
            failed = true;
            reason = FirstFailure(reason, volumeBeforeReply is null ? "PortUnbound" : "VolumeBeforeInvalid");
        }
        else
        {
            volumeBeforeCount = volumeBefore!.MatchCount;
        }

        (bool stable, bool walkFailed, string walkReason, uint matches,
            AdmissionEvidenceActivatingEntry? matched, uint? pageGeneration, ulong? pageSequence,
            long pageBytes) = await WalkActivatingSnapshotAsync(output, request, binding, cancellationToken)
                .ConfigureAwait(false);
        stableSnapshot = stable;
        targetMatchCount = matches;
        target = matched;
        activatingGeneration = pageGeneration;
        activatingChangeSequence = pageSequence;
        rawPageBytes = pageBytes;
        if (!stable || walkFailed)
        {
            failed = true;
            reason = FirstFailure(reason, walkReason);
        }
        AdmissionEvidenceReply? volumeAfterReply = await SendAndWriteAsync(
            output, request, binding, AdmissionEvidenceCommand.VolumeObserve, 0, 0,
            cancellationToken).ConfigureAwait(false);
        AdmissionEvidenceVolumeSnapshot? volumeAfter = null;
        if (volumeAfterReply is null || !volumeAfterReply.IsWirePayloadValid ||
            !AdmissionEvidenceWire.InputMatches(volumeAfterReply, AdmissionEvidenceCommand.VolumeObserve, 0) ||
            !AdmissionEvidenceWire.TryParseVolumeSnapshot(volumeAfterReply.RawReply,
                volumeAfterReply.BytesReturned, request.VolumeGuid, out volumeAfter))
        {
            failed = true;
            reason = FirstFailure(reason, volumeAfterReply is null ? "PortUnbound" : "VolumeAfterInvalid");
        }
        else
        {
            volumeAfterCount = volumeAfter!.MatchCount;
        }

        if (volumeBefore is not null && volumeAfter is not null)
            volumeSnapshotsEqual = volumeBefore.RawBytes.AsSpan().SequenceEqual(volumeAfter.RawBytes);
        if (volumeBefore is not null && volumeAfter is not null && !volumeSnapshotsEqual)
        {
            failed = true;
            reason = FirstFailure(reason, "VolumeObservationChanged");
        }

        AdmissionEvidenceReply? afterEpochReply = await SendAndWriteAsync(
            output, request, binding, AdmissionEvidenceCommand.EpochStatus, 0, 0,
            cancellationToken).ConfigureAwait(false);
        if (afterEpochReply is null || !TryEpoch(afterEpochReply, out AdmissionEvidenceEpoch parsedAfter))
        {
            failed = true;
            reason = FirstFailure(reason, afterEpochReply is null ? "PortUnbound" : "EpochAfterInvalid");
        }
        else
        {
            afterEpoch = parsedAfter;
        }

        bool generationStable = binding.InitialEpoch is { } initialEpoch &&
            beforeEpoch is not null && afterEpoch is not null &&
            beforeEpoch.Value.PolicyGeneration == afterEpoch.Value.PolicyGeneration &&
            beforeEpoch.Value.EpochGeneration == afterEpoch.Value.EpochGeneration &&
            beforeEpoch.Value.PolicyGeneration == initialEpoch.PolicyGeneration &&
            beforeEpoch.Value.EpochGeneration == initialEpoch.EpochGeneration &&
            (!stableSnapshot || activatingGeneration == beforeEpoch.Value.PolicyGeneration);
        if (!generationStable)
        {
            failed = true;
            reason = FirstFailure(reason, "BackendGenerationChangedOrUnmatched");
            if (binding.InitialEpoch is not null && beforeEpoch is not null && afterEpoch is not null)
                binding.InvalidateAfterEpochDrift();
        }

        string outcome = failed ? "EvidenceIncomplete" : "EvidenceCaptured";
        string targetAssessment = stableSnapshot ? AssessCount(targetMatchCount) : "Unavailable";
        AdmissionEvidenceActivatingEntry? uniqueTarget =
            stableSnapshot && targetMatchCount == 1 ? target : null;
        byte[] fileId = request.FileId;
        var summary = new AdmissionEvidenceCaptureSummary(
            request.RunId,
            request.RequestId,
            (byte)request.Hook,
            request.VolumeGuid,
            request.VolumeSerial,
            Convert.ToHexString(fileId),
            outcome,
            rawPageBytes > AdmissionEvidenceLimits.MaxPageBytesPerCapture ? "RawPageBudgetExceeded" : reason,
            stableSnapshot,
            rawPageBytes,
            targetMatchCount,
            targetAssessment,
            uniqueTarget?.State,
            uniqueTarget?.Generation,
            uniqueTarget?.H,
            uniqueTarget?.S,
            uniqueTarget?.C,
            uniqueTarget?.T,
            uniqueTarget?.W,
            uniqueTarget?.UnknownReasons,
            volumeBeforeCount,
            volumeAfterCount,
            AssessVolume(volumeBefore),
            AssessVolume(volumeAfter),
            volumeSnapshotsEqual,
            beforeEpoch?.PolicyGeneration,
            beforeEpoch?.EpochGeneration,
            afterEpoch?.PolicyGeneration,
            afterEpoch?.EpochGeneration,
            activatingGeneration,
            activatingChangeSequence,
            generationStable,
            binding.Generation,
            binding.PolicyVersion,
            Convert.ToHexString(binding.CanonicalCandidateFingerprint),
            binding.InitialEpoch?.PolicyGeneration,
            binding.InitialEpoch?.EpochGeneration,
            binding.InitialEpoch?.Flags,
            binding.InitialEpoch?.ChangeSequence,
            Environment.ProcessId,
            System.Security.Principal.WindowsIdentity.GetCurrent().User?.Value ?? string.Empty,
            caller.ProcessId,
            caller.Sid,
            BindingReceiptIncluded: true,
            ReadyClaim: false);

        await AdmissionEvidenceFrames.WriteSummaryAsync(output, summary, cancellationToken,
            _frameWriteDeadline).ConfigureAwait(false);
        return summary;
    }

    private async Task<(bool Stable, bool Failed, string Reason, uint Matches,
        AdmissionEvidenceActivatingEntry? Target, uint? PolicyGeneration, ulong? ChangeSequence, long RawBytes)>
        WalkActivatingSnapshotAsync(
            Stream output,
            AdmissionEvidenceRequest request,
            AdmissionEvidenceBinding binding,
            CancellationToken cancellationToken)
    {
        long rawBytes = 0;
        string reason = "EvidenceCaptured";

        for (uint attempt = 0; attempt < AdmissionEvidenceLimits.MaxSnapshotAttempts; attempt++)
        {
            uint start = 0;
            uint? total = null;
            uint? generation = null;
            ulong? changeSequence = null;
            uint matches = 0;
            AdmissionEvidenceActivatingEntry? target = null;
            bool retrySnapshot = false;

            for (int pageIndex = 0; pageIndex < AdmissionEvidenceLimits.MaxActivatingPagesPerAttempt; pageIndex++)
            {
                if (rawBytes + AdmissionEvidenceWire.ActivatingPageBytes >
                    AdmissionEvidenceLimits.MaxPageBytesPerCapture)
                {
                    return (false, true, "RawPageBudgetExceeded", matches, target,
                        generation, changeSequence, rawBytes);
                }

                AdmissionEvidenceReply? reply = await SendAndWriteAsync(
                    output, request, binding, AdmissionEvidenceCommand.ActivatingStatus,
                    start, attempt + 1, cancellationToken).ConfigureAwait(false);
                if (reply is null)
                {
                    return (false, true, "PortUnbound", matches, target, generation, changeSequence, rawBytes);
                }

                rawBytes += reply.RawReply.Length;
                if (rawBytes > AdmissionEvidenceLimits.MaxPageBytesPerCapture)
                    return (false, true, "RawPageBudgetExceeded", matches, target, generation, changeSequence, rawBytes);

                if (!AdmissionEvidenceWire.InputMatches(reply, AdmissionEvidenceCommand.ActivatingStatus, start))
                    return (false, true, "ActivatingStatusInputMismatch", matches, target, generation, changeSequence, rawBytes);

                if (reply.HResult != 0)
                {
                    if (AdmissionEvidenceWire.IsRetryHResult(reply.HResult))
                    {
                        retrySnapshot = true;
                        break;
                    }
                    return (false, true, "ActivatingStatusSendFailed", matches, target, generation, changeSequence, rawBytes);
                }

                if (!reply.IsWirePayloadValid ||
                    !AdmissionEvidenceWire.TryParseActivatingPage(reply.RawReply, reply.BytesReturned,
                        start, request.VolumeSerial, request.FileId, out AdmissionEvidenceActivatingPage? page))
                {
                    return (false, true, "ActivatingStatusPageInvalid", matches, target, generation, changeSequence, rawBytes);
                }

                if (start == 0)
                {
                    total = page!.TotalEntries;
                    generation = page.PolicyGeneration;
                    changeSequence = page.ChangeSequence;
                }
                else if (page!.TotalEntries != total ||
                    page.PolicyGeneration != generation || page.ChangeSequence != changeSequence)
                {
                    retrySnapshot = true;
                    break;
                }

                if (page!.Flags != 0 || page.Reserved != 0)
                    return (false, true, "ActivatingStatusUnknownPageFlags", matches, target, generation, changeSequence, rawBytes);

                foreach (AdmissionEvidenceActivatingEntry entry in page.TargetEntries)
                {
                    matches++;
                    target ??= entry;
                }

                if (page.NextIndex <= start && start < page.TotalEntries)
                {
                    retrySnapshot = true;
                    break;
                }

                start = page.NextIndex;
                if (start >= total)
                {
                    return (true, false, reason, matches, target, generation, changeSequence, rawBytes);
                }
            }

            if (!retrySnapshot)
                return (false, true, "ActivatingStatusPageLimitExceeded", matches, target, generation, changeSequence, rawBytes);
        }

        return (false, true, "ActivatingStatusUnstableAfterFiveAttempts", 0, null, null, null, rawBytes);
    }

    private async Task<AdmissionEvidenceReply?> SendAndWriteAsync(
        Stream output,
        AdmissionEvidenceRequest request,
        AdmissionEvidenceBinding binding,
        AdmissionEvidenceCommand command,
        uint startIndex,
        uint attempt,
        CancellationToken cancellationToken)
    {
        if (!_isCurrent(binding)) return null;
        AdmissionEvidenceReply? reply = _send(binding, command, startIndex);
        if (reply is not null)
        {
            await AdmissionEvidenceFrames.WriteCallAsync(output,
                AdmissionEvidenceFrameKind.RawCall, request, binding, command,
                reply, attempt, startIndex, cancellationToken, _frameWriteDeadline).ConfigureAwait(false);
        }
        return reply;
    }

    private static bool TryEpoch(AdmissionEvidenceReply reply, out AdmissionEvidenceEpoch epoch)
    {
        epoch = default;
        return AdmissionEvidenceWire.InputMatches(reply, AdmissionEvidenceCommand.EpochStatus, 0) &&
            reply.IsWirePayloadValid &&
            AdmissionEvidenceWire.TryParseEpoch(reply.RawReply, reply.BytesReturned, out epoch);
    }

    private static string AssessCount(uint count) => count switch
    {
        0 => "Absent",
        1 => "Unique",
        _ => "Ambiguous",
    };

    private static string AssessVolume(AdmissionEvidenceVolumeSnapshot? snapshot) =>
        snapshot is null ? "Unavailable" : AssessCount(snapshot.MatchCount);

    private static string FirstFailure(string current, string next) =>
        string.Equals(current, "EvidenceCaptured", StringComparison.Ordinal) ? next : current;
}
#endif
