#if SAFEUPLOAD_ADMISSION_EVIDENCE
using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;
using SafeUpload.Agent.Minifilter;

namespace SafeUpload.Agent.Service.Diagnostics;

internal enum AdmissionEvidenceHook : byte
{
    BeforeExpandedLaunch = 1,
    ExpandedPolicyPostAck = 2,
    ExpansionPrewrite = 3,
    ExpansionPostflush = 4,
    BeforeRetainedMapView = 5,
    AfterRetainedViewBeforeWrite = 6,
    RetainedSectionPostflush = 7,
}

internal sealed class AdmissionEvidenceRequest
{
    private AdmissionEvidenceRequest(
        Guid runId,
        Guid requestId,
        AdmissionEvidenceHook hook,
        string volumeGuid,
        ulong volumeSerial,
        byte[] fileId)
    {
        RunId = runId;
        RequestId = requestId;
        Hook = hook;
        VolumeGuid = volumeGuid;
        VolumeSerial = volumeSerial;
        FileId = fileId;
    }

    internal Guid RunId { get; }
    internal Guid RequestId { get; }
    internal AdmissionEvidenceHook Hook { get; }
    internal string VolumeGuid { get; }
    internal ulong VolumeSerial { get; }
    internal byte[] FileId { get; }

    internal static AdmissionEvidenceRequest Parse(ReadOnlySpan<byte> bytes)
    {
        const int fixedBytes = 65;
        if (bytes.Length < fixedBytes || bytes.Length > AdmissionEvidenceLimits.MaxRequestBytes)
            throw new InvalidDataException("Invalid admission evidence request length.");

        if (!bytes[..4].SequenceEqual("SAER"u8))
            throw new InvalidDataException("Invalid admission evidence request magic.");
        if (BinaryPrimitives.ReadUInt16LittleEndian(bytes.Slice(4, 2)) != 1)
            throw new InvalidDataException("Unsupported admission evidence request version.");

        byte rawHook = bytes[6];
        if (rawHook is < (byte)AdmissionEvidenceHook.BeforeExpandedLaunch or > (byte)AdmissionEvidenceHook.RetainedSectionPostflush)
            throw new InvalidDataException("Invalid admission evidence hook ordinal.");
        if (bytes[7] != 0)
            throw new InvalidDataException("Unknown admission evidence request flags.");

        Guid runId = new(bytes.Slice(8, 16));
        Guid requestId = new(bytes.Slice(24, 16));
        if (runId == Guid.Empty || requestId == Guid.Empty)
            throw new InvalidDataException("Admission evidence run and request identifiers are required.");

        ulong serial = BinaryPrimitives.ReadUInt64LittleEndian(bytes.Slice(40, 8));
        byte[] fileId = bytes.Slice(48, 16).ToArray();
        byte volumeGuidLength = bytes[64];
        if (volumeGuidLength is 0 or > AdmissionEvidenceLimits.MaxVolumeGuidChars ||
            bytes.Length != fixedBytes + volumeGuidLength)
            throw new InvalidDataException("Invalid admission evidence volume identity length.");

        string volumeGuid;
        try
        {
            volumeGuid = AdmissionEvidenceLimits.StrictUtf8.GetString(bytes.Slice(fixedBytes, volumeGuidLength));
        }
        catch (DecoderFallbackException ex)
        {
            throw new InvalidDataException("Admission evidence volume GUID is not strict UTF-8.", ex);
        }

        AdmissionEvidenceLimits.ValidateNativeVolumeGuid(volumeGuid);
        return new AdmissionEvidenceRequest(
            runId, requestId, (AdmissionEvidenceHook)rawHook, volumeGuid, serial, fileId);
    }

    internal static byte[] EncodeForTest(
        Guid runId,
        Guid requestId,
        AdmissionEvidenceHook hook,
        string volumeGuid,
        ulong volumeSerial,
        ReadOnlySpan<byte> fileId)
    {
        ArgumentNullException.ThrowIfNull(volumeGuid);
        AdmissionEvidenceLimits.ValidateNativeVolumeGuid(volumeGuid);
        if (runId == Guid.Empty || requestId == Guid.Empty || fileId.Length != 16)
            throw new ArgumentException("Invalid test request identity.");
        byte[] volumeBytes = AdmissionEvidenceLimits.StrictUtf8.GetBytes(volumeGuid);
        if (volumeBytes.Length > AdmissionEvidenceLimits.MaxVolumeGuidChars)
            throw new ArgumentException("Volume GUID exceeds the protocol bound.", nameof(volumeGuid));

        byte[] request = new byte[65 + volumeBytes.Length];
        "SAER"u8.CopyTo(request);
        BinaryPrimitives.WriteUInt16LittleEndian(request.AsSpan(4, 2), 1);
        request[6] = (byte)hook;
        runId.TryWriteBytes(request.AsSpan(8, 16));
        requestId.TryWriteBytes(request.AsSpan(24, 16));
        BinaryPrimitives.WriteUInt64LittleEndian(request.AsSpan(40, 8), volumeSerial);
        fileId.CopyTo(request.AsSpan(48, 16));
        request[64] = checked((byte)volumeBytes.Length);
        volumeBytes.CopyTo(request.AsSpan(65));
        return request;
    }
}

internal static class AdmissionEvidenceLimits
{
    internal const int MaxRequestBytes = 4096;
    internal const int MaxVolumeGuidChars = 63;
    internal const int MaxFrameBytes = 64 * 1024;
    internal const int MaxPageBytesPerCapture = 128 * 1024 * 1024;
    internal const int MaxActivatingEntries = 20_480;
    internal const int ActivatingPageEntries = 32;
    internal const int MaxActivatingPagesPerAttempt = MaxActivatingEntries / ActivatingPageEntries;
    internal const int MaxSnapshotAttempts = 5;
    internal static readonly TimeSpan MaxCaptureDuration = TimeSpan.FromMinutes(5);
    internal static readonly TimeSpan FrameWriteDeadline = TimeSpan.FromSeconds(10);

    internal static readonly UTF8Encoding StrictUtf8 = new(encoderShouldEmitUTF8Identifier: false, throwOnInvalidBytes: true);

    internal static void ValidateNativeVolumeGuid(string value)
    {
        const string prefix = @"\??\Volume{";
        if (value.Length != 48 ||
            !value.StartsWith(prefix, StringComparison.OrdinalIgnoreCase) ||
            value[^1] != '}' ||
            !Guid.TryParseExact(value.AsSpan(prefix.Length, 36), "D", out _))
        {
            throw new InvalidDataException(@"Volume GUID must use the native \??\Volume{GUID} form.");
        }
    }
}

internal enum AdmissionEvidenceFrameKind : byte
{
    BindingReceipt = 1,
    RawCall = 2,
    Summary = 3,
    Error = 4,
}

internal sealed record AdmissionEvidenceCaller(uint ProcessId, string Sid);

internal sealed record AdmissionEvidenceCaptureSummary(
    Guid RunId,
    Guid RequestId,
    byte HookOrdinal,
    string VolumeGuid,
    ulong VolumeSerial,
    string FileIdHex,
    string Outcome,
    string Reason,
    bool StableActivatingSnapshot,
    long RawActivatingBytes,
    uint TargetEntryMatches,
    string TargetAssessment,
    uint? TargetState,
    uint? TargetGeneration,
    uint? TargetH,
    uint? TargetS,
    uint? TargetC,
    uint? TargetT,
    uint? TargetW,
    uint? TargetUnknownReasons,
    uint VolumeGuidMatchesBefore,
    uint VolumeGuidMatchesAfter,
    string VolumeGuidAssessmentBefore,
    string VolumeGuidAssessmentAfter,
    bool VolumeSnapshotsByteIdentical,
    uint? PolicyGenerationBefore,
    uint? EpochGenerationBefore,
    uint? PolicyGenerationAfter,
    uint? EpochGenerationAfter,
    uint? ActivatingPolicyGeneration,
    ulong? ActivatingChangeSequence,
    bool BindingGenerationStable,
    long BindingGeneration,
    int AcceptedPolicyVersion,
    string CanonicalCandidatePolicyFingerprint,
    uint? BindingPolicyGeneration,
    uint? BindingEpochGeneration,
    uint? BindingEpochFlags,
    ulong? BindingChangeSequence,
    int ServiceProcessId,
    string ServiceSid,
    uint CallerProcessId,
    string CallerSid,
    bool BindingReceiptIncluded,
    bool ReadyClaim);

/// <summary>Length-prefixed, streaming receipts. Frame bodies stay below 64 KiB.</summary>
internal static class AdmissionEvidenceFrames
{
    // Fixed raw-call header length. RawInput and RawReply follow this header.
    internal const int RawCallHeaderBytes = 292;
    private const int RawHeaderBytes = RawCallHeaderBytes;
    private const byte RawReplyPresentFlag = 0x01;
    private const byte ReturnedLengthAvailableFlag = 0x02;
    private const byte KnownCallFlags = RawReplyPresentFlag | ReturnedLengthAvailableFlag;
    private static readonly byte[] EmptyHash = new byte[32];

    internal static async Task WriteCallAsync(
        Stream destination,
        AdmissionEvidenceFrameKind kind,
        AdmissionEvidenceRequest? request,
        AdmissionEvidenceBinding binding,
        AdmissionEvidenceCommand command,
        AdmissionEvidenceReply reply,
        uint attempt,
        uint startIndex,
        CancellationToken cancellationToken,
        TimeSpan? writeDeadline = null)
    {
        ArgumentNullException.ThrowIfNull(destination);
        ArgumentNullException.ThrowIfNull(binding);
        ArgumentNullException.ThrowIfNull(reply);

        byte[] frame = BuildCallFrame(kind, request, binding, command, reply, attempt, startIndex);
        await WriteBoundedAsync(destination, frame, cancellationToken,
            writeDeadline ?? AdmissionEvidenceLimits.FrameWriteDeadline).ConfigureAwait(false);
    }

    internal static async Task WriteBoundedAsync(
        Stream destination,
        ReadOnlyMemory<byte> bytes,
        CancellationToken cancellationToken,
        TimeSpan writeDeadline)
    {
        ArgumentNullException.ThrowIfNull(destination);
        if (writeDeadline <= TimeSpan.Zero || writeDeadline == Timeout.InfiniteTimeSpan)
            throw new ArgumentOutOfRangeException(nameof(writeDeadline));

        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        deadline.CancelAfter(writeDeadline);
        // Named pipes are unbuffered. Do not call Flush/FlushAsync after the
        // write: native pipe flush waits for the client to consume buffered
        // data and does not provide the same cancellable async boundary.
        await destination.WriteAsync(bytes, deadline.Token).ConfigureAwait(false);
    }

    private static byte[] BuildCallFrame(
        AdmissionEvidenceFrameKind kind,
        AdmissionEvidenceRequest? request,
        AdmissionEvidenceBinding binding,
        AdmissionEvidenceCommand command,
        AdmissionEvidenceReply reply,
        uint attempt,
        uint startIndex)
    {
        byte[] rawInput = reply.RawInput;
        byte[] rawReply = reply.RawReply;
        byte[] validationError = reply.ResponseValidationError is null
            ? Array.Empty<byte>()
            : AdmissionEvidenceLimits.StrictUtf8.GetBytes(reply.ResponseValidationError);
        if (rawInput.Length > AdmissionEvidenceLimits.MaxRequestBytes ||
            validationError.Length > 1024 ||
            rawReply.Length >= AdmissionEvidenceLimits.MaxFrameBytes)
        {
            throw new InvalidDataException("Admission evidence sender returned an invalid raw receipt.");
        }

        int bodyLength = checked(RawHeaderBytes + validationError.Length + rawInput.Length + rawReply.Length);
        if (bodyLength > AdmissionEvidenceLimits.MaxFrameBytes)
            throw new InvalidDataException("Admission evidence receipt exceeds the frame bound.");

        byte[] frame = new byte[4 + bodyLength];
        Span<byte> span = frame;
        BinaryPrimitives.WriteUInt32LittleEndian(span, checked((uint)bodyLength));
        span[4..8].Clear();
        "SAEF"u8.CopyTo(span[4..8]);
        BinaryPrimitives.WriteUInt16LittleEndian(span.Slice(8, 2), 1);
        span[10] = (byte)kind;
        span[11] = request is null ? (byte)0 : (byte)request.Hook;
        // Bit 0 reports bytes actually captured in RawReply. Bit 1 says the
        // native BytesReturned field is defined by FilterSendMessage: only a
        // successful HRESULT carries a meaningful returned length. Preserve
        // the numeric field even on failure, but consumers must ignore it
        // unless bit 1 is set. Unknown bits are reserved and must be rejected.
        byte callFlags = rawReply.Length == 0 ? (byte)0 : RawReplyPresentFlag;
        if (reply.HResult == 0)
            callFlags |= ReturnedLengthAvailableFlag;
        if ((callFlags & ~KnownCallFlags) != 0)
            throw new InvalidDataException("Admission evidence call flags are invalid.");
        span[12] = callFlags;
        span[13] = reply.IsWirePayloadValid ? (byte)1 : (byte)0;
        BinaryPrimitives.WriteUInt16LittleEndian(span.Slice(14, 2), checked((ushort)validationError.Length));
        if (request is not null)
        {
            request.RunId.TryWriteBytes(span.Slice(16, 16));
            request.RequestId.TryWriteBytes(span.Slice(32, 16));
        }
        BinaryPrimitives.WriteUInt32LittleEndian(span.Slice(48, 4), (uint)command);
        BinaryPrimitives.WriteUInt32LittleEndian(span.Slice(52, 4), attempt);
        BinaryPrimitives.WriteUInt32LittleEndian(span.Slice(56, 4), startIndex);
        BinaryPrimitives.WriteInt32LittleEndian(span.Slice(60, 4), reply.HResult);
        BinaryPrimitives.WriteUInt32LittleEndian(span.Slice(64, 4), reply.BytesReturned);
        BinaryPrimitives.WriteUInt32LittleEndian(span.Slice(68, 4), checked((uint)rawInput.Length));
        BinaryPrimitives.WriteUInt32LittleEndian(span.Slice(72, 4), checked((uint)rawReply.Length));
        BinaryPrimitives.WriteInt64LittleEndian(span.Slice(76, 8), reply.StartedUtc.UtcDateTime.Ticks);
        BinaryPrimitives.WriteInt64LittleEndian(span.Slice(84, 8), reply.FinishedUtc.UtcDateTime.Ticks);
        BinaryPrimitives.WriteInt64LittleEndian(span.Slice(92, 8), reply.StartedTimestamp);
        BinaryPrimitives.WriteInt64LittleEndian(span.Slice(100, 8), reply.FinishedTimestamp);
        BinaryPrimitives.WriteInt64LittleEndian(span.Slice(108, 8), System.Diagnostics.Stopwatch.Frequency);
        BinaryPrimitives.WriteInt64LittleEndian(span.Slice(116, 8), binding.Generation);
        BinaryPrimitives.WriteInt32LittleEndian(span.Slice(124, 4), binding.PolicyVersion);
        binding.CanonicalCandidateFingerprint.CopyTo(span.Slice(128, 32));
        SHA256.HashData(rawInput).CopyTo(span.Slice(160, 32));
        if (rawReply.Length != 0)
            SHA256.HashData(rawReply).CopyTo(span.Slice(192, 32));
        else
            EmptyHash.CopyTo(span.Slice(192, 32));
        if (request is not null)
        {
            BinaryPrimitives.WriteUInt64LittleEndian(span.Slice(224, 8), request.VolumeSerial);
            request.FileId.CopyTo(span.Slice(232, 16));
            byte[] volumeGuid = Encoding.ASCII.GetBytes(request.VolumeGuid);
            if (volumeGuid.Length != 48)
                throw new InvalidDataException("Validated native volume GUID changed length.");
            volumeGuid.CopyTo(span.Slice(248, 48));
        }
        validationError.CopyTo(span.Slice(4 + RawHeaderBytes));
        rawInput.CopyTo(span.Slice(4 + RawHeaderBytes + validationError.Length));
        rawReply.CopyTo(span.Slice(4 + RawHeaderBytes + validationError.Length + rawInput.Length));

        return frame;
    }

    internal static async Task WriteSummaryAsync<T>(
        Stream destination,
        T summary,
        CancellationToken cancellationToken,
        TimeSpan? writeDeadline = null)
    {
        byte[] payload = System.Text.Json.JsonSerializer.SerializeToUtf8Bytes(summary);
        const int headerBytes = 8;
        int bodyLength = checked(headerBytes + payload.Length);
        if (bodyLength > AdmissionEvidenceLimits.MaxFrameBytes)
            throw new InvalidDataException("Admission evidence summary exceeds the frame bound.");
        byte[] frame = new byte[4 + bodyLength];
        BinaryPrimitives.WriteUInt32LittleEndian(frame.AsSpan(0, 4), checked((uint)bodyLength));
        "SAEF"u8.CopyTo(frame.AsSpan(4, 4));
        BinaryPrimitives.WriteUInt16LittleEndian(frame.AsSpan(8, 2), 1);
        frame[10] = (byte)AdmissionEvidenceFrameKind.Summary;
        frame[11] = 0;
        payload.CopyTo(frame.AsSpan(12));
        await WriteBoundedAsync(destination, frame, cancellationToken,
            writeDeadline ?? AdmissionEvidenceLimits.FrameWriteDeadline).ConfigureAwait(false);
    }

    internal static async Task WriteErrorAsync(
        Stream destination,
        string code,
        CancellationToken cancellationToken)
    {
        // Fixed protocol error text only. Never include request bytes or target paths.
        byte[] payload = StrictError(code);
        const int headerBytes = 8;
        int bodyLength = checked(headerBytes + payload.Length);
        byte[] frame = new byte[4 + bodyLength];
        BinaryPrimitives.WriteUInt32LittleEndian(frame.AsSpan(0, 4), checked((uint)bodyLength));
        "SAEF"u8.CopyTo(frame.AsSpan(4, 4));
        BinaryPrimitives.WriteUInt16LittleEndian(frame.AsSpan(8, 2), 1);
        frame[10] = (byte)AdmissionEvidenceFrameKind.Error;
        frame[11] = 0;
        payload.CopyTo(frame.AsSpan(12));
        await WriteBoundedAsync(destination, frame, cancellationToken,
            AdmissionEvidenceLimits.FrameWriteDeadline).ConfigureAwait(false);
    }

    private static byte[] StrictError(string code) => Encoding.ASCII.GetBytes(code);
}
#endif
