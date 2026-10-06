#if SAFEUPLOAD_ADMISSION_EVIDENCE
using System.Buffers.Binary;
using System.Diagnostics;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

namespace SafeUpload.Agent.Minifilter;

/// <summary>
/// The only raw admission-status controls exposed by the feature build.
/// Numeric values match Protocol.h; this enum intentionally excludes every
/// mutating control and the legacy volume-status control that advances a
/// canary deadline.
/// </summary>
public enum AdmissionEvidenceCommand : uint
{
    ActivatingStatus = 19,
    EpochStatus = 20,
    VolumeObserve = 23,
}

/// <summary>Read-only raw status sender on the service-owned FilterPort.</summary>
public interface IAdmissionEvidenceSender
{
    AdmissionEvidenceReply SendAdmissionEvidence(
        AdmissionEvidenceCommand command, uint startIndex = 0);
}

/// <summary>
/// One native FilterSendMessage receipt. Raw arrays are defensively copied on
/// construction and access. Stopwatch timestamps use Stopwatch.Frequency and
/// bracket the native call (not time waiting for the per-port send gate).
/// ResponseValidationError reports malformed or incomplete wire output;
/// an overreported successful reply retains only its bounded buffer bytes and
/// is marked truncated. This receipt makes no Ready or privacy claim.
/// </summary>
public sealed record AdmissionEvidenceReply
{
    private readonly byte[] _rawInput;
    private readonly byte[] _rawReply;

    public byte[] RawInput => (byte[])_rawInput.Clone();
    public byte[] RawReply => (byte[])_rawReply.Clone();
    public int HResult { get; }
    public uint BytesReturned { get; }
    public DateTimeOffset StartedUtc { get; }
    public DateTimeOffset FinishedUtc { get; }
    public long StartedTimestamp { get; }
    public long FinishedTimestamp { get; }
    public string? ResponseValidationError { get; }
    public bool IsWirePayloadValid => HResult == 0 && ResponseValidationError is null;

    internal AdmissionEvidenceReply(
        byte[] rawInput,
        byte[] rawReply,
        int hResult,
        uint bytesReturned,
        DateTimeOffset startedUtc,
        DateTimeOffset finishedUtc,
        long startedTimestamp,
        long finishedTimestamp,
        string? responseValidationError)
    {
        _rawInput = (byte[])rawInput.Clone();
        _rawReply = (byte[])rawReply.Clone();
        HResult = hResult;
        BytesReturned = bytesReturned;
        StartedUtc = startedUtc;
        FinishedUtc = finishedUtc;
        StartedTimestamp = startedTimestamp;
        FinishedTimestamp = finishedTimestamp;
        ResponseValidationError = responseValidationError;
    }
}

// Injection seam for tests. Production instances use FilterSendMessage on
// the existing SafeFileHandle; this seam never opens or connects a port.
internal interface IAdmissionEvidenceNativeSender
{
    int Send(SafeFileHandle handle, ReadOnlyMemory<byte> input,
        Memory<byte> output, out uint bytesReturned);
}

[StructLayout(LayoutKind.Sequential, Pack = 8, CharSet = CharSet.Unicode)]
internal unsafe struct AdmissionEvidenceVolumeEntryWire
{
    public ulong Instance;
    public uint VolumeKind;
    public uint FileSystemType;
    public uint FileSystemStatus;
    public uint SetupFlags;
    public uint CanaryState;
    public uint CanaryStatus;
    public uint CanaryChecks;
    public uint CanaryCleanupStatus;
    public uint InstanceWritersUntracked;
    public uint ContextStatus;
    public uint VolumeGuidStatus;
    public uint VolumeGuidChars;
    public uint VolumeInfoStatus;
    public uint VolumeFlags;
    public uint InstanceRegistryUnknownReasons;
    public uint FirstUnknownReason;
    public uint FirstUnknownSite;
    public fixed char VolumeGuid[64];
}

[StructLayout(LayoutKind.Sequential, Pack = 8)]
internal unsafe struct AdmissionEvidenceVolumeStatusWire
{
    public uint StructSize;
    public uint EntryCount;
    public uint WriterGlobalUnknown;
    public uint BootPolicyState;
    public fixed byte Entries[AdmissionEvidenceWire.VolumeEntrySize * AdmissionEvidenceWire.VolumeMaxEntries];
}

[StructLayout(LayoutKind.Sequential, Pack = 8, CharSet = CharSet.Unicode)]
internal unsafe struct AdmissionEvidenceActivatingEntryWire
{
    public ulong VolumeSerialNumber;
    public fixed byte FileId[16];
    public uint Generation;
    public uint State;
    public uint H;
    public uint S;
    public uint C;
    public uint T;
    public uint W;
    public uint UnknownReasons;
    public uint ReservedFlags;
    public uint OpenerPidCount;
    public fixed uint OpenerPids[8];
    public uint NameChars;
    public fixed char Name[512];
}

[StructLayout(LayoutKind.Sequential, Pack = 8)]
internal unsafe struct AdmissionEvidenceActivatingPageWire
{
    public uint StructSize;
    public uint TotalEntries;
    public uint EntryCount;
    public uint StartIndex;
    public uint NextIndex;
    public uint PolicyGeneration;
    public ulong ChangeSequence;
    public uint Flags;
    public uint Reserved;
    public fixed byte Entries[AdmissionEvidenceWire.ActivatingEntrySize * AdmissionEvidenceWire.ActivatingPageEntries];
}

[StructLayout(LayoutKind.Sequential, Pack = 8)]
internal struct AdmissionEvidenceEpochStatusWire
{
    public uint StructSize;
    public uint PolicyGeneration;
    public uint EpochGeneration;
    public uint ActiveCallbacks;
    public uint Flags;
    public uint Reserved;
    public ulong ChangeSequence;
}

/// <summary>
/// Exact little-endian control encoders and bounded wire checks for the
/// feature-only replies. This reads only structural fields; the full raw
/// payload remains the evidence and no readiness state is inferred.
/// </summary>
internal static class AdmissionEvidenceWire
{
    internal const int ControlSize = 16;
    internal const int EpochStatusSize = 32;
    internal const int VolumeMaxEntries = 32;
    internal const int VolumeEntrySize = 208;
    internal const int VolumeStatusSize = 6672;
    internal const int ActivatingPageEntries = 32;
    internal const int ActivatingEntrySize = 1128;
    internal const int ActivatingPageSize = 36136;
    internal const uint MaximumActivatingStartIndex = 20480; // SAFEUPLOAD_WRITER_REGISTRY_ALL_LIMIT
    private const int VolumeStatusEntryCountOffset = 4;
    private const int VolumeStatusEntriesOffset = 16;
    private const int VolumeEntryGuidCharsOffset = 52;
    private const int ActivatingPageTotalEntriesOffset = 4;
    private const int ActivatingPageEntryCountOffset = 8;
    private const int ActivatingPageStartIndexOffset = 12;
    private const int ActivatingPageNextIndexOffset = 16;
    private const int ActivatingPageEntriesOffset = 40;
    private const int ActivatingPageReservedOffset = 36;
    private const int ActivatingEntryOpenerPidCountOffset = 60;
    private const int ActivatingEntryNameCharsOffset = 96;

    internal static byte[] CreateInput(AdmissionEvidenceCommand command, uint startIndex)
    {
        uint rawCommand = (uint)command;
        uint reserved;
        switch (command)
        {
            case AdmissionEvidenceCommand.ActivatingStatus:
                if (startIndex > MaximumActivatingStartIndex)
                {
                    throw new ArgumentOutOfRangeException(nameof(startIndex),
                        $"Control 19 start index exceeds {MaximumActivatingStartIndex}.");
                }
                reserved = startIndex;
                break;
            case AdmissionEvidenceCommand.EpochStatus:
            case AdmissionEvidenceCommand.VolumeObserve:
                if (startIndex != 0)
                {
                    throw new ArgumentOutOfRangeException(nameof(startIndex),
                        "Only Control 19 accepts a nonzero start index.");
                }
                reserved = 0;
                break;
            default:
                throw new ArgumentOutOfRangeException(nameof(command),
                    "Only read-only admission status controls are available.");
        }

        byte[] input = new byte[ControlSize];
        BinaryPrimitives.WriteUInt32LittleEndian(input.AsSpan(0, 4), Contract.Version);
        BinaryPrimitives.WriteUInt32LittleEndian(input.AsSpan(4, 4), ControlSize);
        BinaryPrimitives.WriteUInt32LittleEndian(input.AsSpan(8, 4), rawCommand);
        BinaryPrimitives.WriteUInt32LittleEndian(input.AsSpan(12, 4), reserved);
        return input;
    }

    internal static int ExpectedReplySize(AdmissionEvidenceCommand command) => command switch
    {
        AdmissionEvidenceCommand.ActivatingStatus => ActivatingPageSize,
        AdmissionEvidenceCommand.EpochStatus => EpochStatusSize,
        AdmissionEvidenceCommand.VolumeObserve => VolumeStatusSize,
        _ => throw new ArgumentOutOfRangeException(nameof(command),
            "Only read-only admission status controls are available."),
    };

    internal static string? ValidateReply(AdmissionEvidenceCommand command,
        uint requestedStartIndex, ReadOnlySpan<byte> reply)
    {
        int expected = ExpectedReplySize(command);
        if (reply.Length != expected)
        {
            return $"Reply length {reply.Length} differs from expected {expected}.";
        }

        uint structSize = BinaryPrimitives.ReadUInt32LittleEndian(reply[..4]);
        if (structSize != expected)
        {
            return $"Wire StructSize {structSize} differs from expected {expected}.";
        }

        switch (command)
        {
            case AdmissionEvidenceCommand.EpochStatus:
                if (BinaryPrimitives.ReadUInt32LittleEndian(reply.Slice(20, 4)) != 0)
                {
                    return "Control 20 Reserved field is nonzero.";
                }
                return null;

            case AdmissionEvidenceCommand.VolumeObserve:
            {
                uint entryCount = BinaryPrimitives.ReadUInt32LittleEndian(
                    reply.Slice(VolumeStatusEntryCountOffset, 4));
                if (entryCount > VolumeMaxEntries)
                {
                    return $"Control 23 EntryCount {entryCount} exceeds {VolumeMaxEntries}.";
                }
                for (uint i = 0; i < entryCount; i++)
                {
                    int offset = VolumeStatusEntriesOffset + checked((int)i * VolumeEntrySize) +
                        VolumeEntryGuidCharsOffset;
                    uint chars = BinaryPrimitives.ReadUInt32LittleEndian(reply.Slice(offset, 4));
                    if (chars > 63)
                    {
                        return $"Control 23 entry {i} VolumeGuidChars {chars} exceeds 63.";
                    }
                }
                return null;
            }

            case AdmissionEvidenceCommand.ActivatingStatus:
            {
                uint reserved = BinaryPrimitives.ReadUInt32LittleEndian(
                    reply.Slice(ActivatingPageReservedOffset, 4));
                if (reserved != 0)
                {
                    return "Control 19 Reserved field is nonzero.";
                }
                uint total = BinaryPrimitives.ReadUInt32LittleEndian(
                    reply.Slice(ActivatingPageTotalEntriesOffset, 4));
                uint count = BinaryPrimitives.ReadUInt32LittleEndian(
                    reply.Slice(ActivatingPageEntryCountOffset, 4));
                uint start = BinaryPrimitives.ReadUInt32LittleEndian(
                    reply.Slice(ActivatingPageStartIndexOffset, 4));
                uint next = BinaryPrimitives.ReadUInt32LittleEndian(
                    reply.Slice(ActivatingPageNextIndexOffset, 4));
                if (total > MaximumActivatingStartIndex)
                {
                    return $"Control 19 TotalEntries {total} exceeds {MaximumActivatingStartIndex}.";
                }
                if (count > ActivatingPageEntries)
                {
                    return $"Control 19 EntryCount {count} exceeds {ActivatingPageEntries}.";
                }
                uint entriesRemaining = requestedStartIndex >= total ? 0 : total - requestedStartIndex;
                if (count > entriesRemaining)
                {
                    return $"Control 19 EntryCount {count} exceeds the {entriesRemaining} entries remaining.";
                }
                if (start != requestedStartIndex)
                {
                    return $"Control 19 StartIndex {start} differs from requested {requestedStartIndex}.";
                }
                ulong requestedNext = (ulong)requestedStartIndex + count;
                ulong expectedNext = requestedNext < total ? requestedNext : total;
                if (next != expectedNext || next > total)
                {
                    return $"Control 19 NextIndex {next} is inconsistent with page bounds.";
                }
                for (uint i = 0; i < count; i++)
                {
                    int entryOffset = ActivatingPageEntriesOffset + checked((int)i * ActivatingEntrySize);
                    uint pidCount = BinaryPrimitives.ReadUInt32LittleEndian(
                        reply.Slice(entryOffset + ActivatingEntryOpenerPidCountOffset, 4));
                    uint nameChars = BinaryPrimitives.ReadUInt32LittleEndian(
                        reply.Slice(entryOffset + ActivatingEntryNameCharsOffset, 4));
                    if (pidCount > 8 || nameChars > 512)
                    {
                        return $"Control 19 entry {i} has invalid bounded field lengths.";
                    }
                }
                return null;
            }

            default:
                return "Unsupported read-only admission status command.";
        }
    }

    internal static unsafe void VerifyLayout()
    {
        CheckSize<SafeUploadControl>(ControlSize);
        CheckOffset<SafeUploadControl>(nameof(SafeUploadControl.Version), 0);
        CheckOffset<SafeUploadControl>(nameof(SafeUploadControl.StructSize), 4);
        CheckOffset<SafeUploadControl>(nameof(SafeUploadControl.Command), 8);
        CheckOffset<SafeUploadControl>(nameof(SafeUploadControl.Reserved), 12);

        CheckSize<AdmissionEvidenceEpochStatusWire>(EpochStatusSize);
        CheckOffset<AdmissionEvidenceEpochStatusWire>(nameof(AdmissionEvidenceEpochStatusWire.ChangeSequence), 24);
        CheckSize<AdmissionEvidenceVolumeEntryWire>(VolumeEntrySize);
        CheckOffset<AdmissionEvidenceVolumeEntryWire>(nameof(AdmissionEvidenceVolumeEntryWire.VolumeGuidChars), 52);
        CheckOffset<AdmissionEvidenceVolumeEntryWire>(nameof(AdmissionEvidenceVolumeEntryWire.VolumeGuid), 76);
        CheckSize<AdmissionEvidenceVolumeStatusWire>(VolumeStatusSize);
        CheckOffset<AdmissionEvidenceVolumeStatusWire>(nameof(AdmissionEvidenceVolumeStatusWire.Entries), 16);

        CheckSize<AdmissionEvidenceActivatingEntryWire>(ActivatingEntrySize);
        CheckOffset<AdmissionEvidenceActivatingEntryWire>(nameof(AdmissionEvidenceActivatingEntryWire.FileId), 8);
        CheckOffset<AdmissionEvidenceActivatingEntryWire>(nameof(AdmissionEvidenceActivatingEntryWire.Generation), 24);
        CheckOffset<AdmissionEvidenceActivatingEntryWire>(nameof(AdmissionEvidenceActivatingEntryWire.OpenerPidCount), 60);
        CheckOffset<AdmissionEvidenceActivatingEntryWire>(nameof(AdmissionEvidenceActivatingEntryWire.OpenerPids), 64);
        CheckOffset<AdmissionEvidenceActivatingEntryWire>(nameof(AdmissionEvidenceActivatingEntryWire.NameChars), 96);
        CheckOffset<AdmissionEvidenceActivatingEntryWire>(nameof(AdmissionEvidenceActivatingEntryWire.Name), 100);
        CheckSize<AdmissionEvidenceActivatingPageWire>(ActivatingPageSize);
        CheckOffset<AdmissionEvidenceActivatingPageWire>(nameof(AdmissionEvidenceActivatingPageWire.TotalEntries), 4);
        CheckOffset<AdmissionEvidenceActivatingPageWire>(nameof(AdmissionEvidenceActivatingPageWire.EntryCount), 8);
        CheckOffset<AdmissionEvidenceActivatingPageWire>(nameof(AdmissionEvidenceActivatingPageWire.StartIndex), 12);
        CheckOffset<AdmissionEvidenceActivatingPageWire>(nameof(AdmissionEvidenceActivatingPageWire.NextIndex), 16);
        CheckOffset<AdmissionEvidenceActivatingPageWire>(nameof(AdmissionEvidenceActivatingPageWire.ChangeSequence), 24);
        CheckOffset<AdmissionEvidenceActivatingPageWire>(nameof(AdmissionEvidenceActivatingPageWire.Flags), 32);
        CheckOffset<AdmissionEvidenceActivatingPageWire>(nameof(AdmissionEvidenceActivatingPageWire.Reserved), 36);
        CheckOffset<AdmissionEvidenceActivatingPageWire>(nameof(AdmissionEvidenceActivatingPageWire.Entries), 40);
    }

    private static void CheckSize<T>(int expected) where T : struct
    {
        int actual = Marshal.SizeOf<T>();
        if (actual != expected)
        {
            throw new InvalidOperationException(
                $"{typeof(T).Name} has {actual} bytes; Protocol.h expects {expected}.");
        }
    }

    private static void CheckOffset<T>(string field, int expected) where T : struct
    {
        int actual = (int)Marshal.OffsetOf<T>(field);
        if (actual != expected)
        {
            throw new InvalidOperationException(
                $"{typeof(T).Name}.{field} is at {actual}; Protocol.h expects {expected}.");
        }
    }
}

public sealed partial class FilterPort
{
    internal FilterPort(SafeFileHandle handle, IAdmissionEvidenceNativeSender nativeSender)
        : this(handle, Contract.PortName)
    {
        _admissionEvidenceNativeSender = nativeSender ?? throw new ArgumentNullException(nameof(nativeSender));
    }

    internal static FilterPort CreateForTesting(SafeFileHandle handle,
        IAdmissionEvidenceNativeSender nativeSender) => new(handle, nativeSender);

    public AdmissionEvidenceReply SendAdmissionEvidence(
        AdmissionEvidenceCommand command, uint startIndex = 0)
    {
        byte[] input = AdmissionEvidenceWire.CreateInput(command, startIndex);
        byte[] rawInput = (byte[])input.Clone();
        byte[] output = new byte[AdmissionEvidenceWire.ExpectedReplySize(command)];
        uint bytesReturned = 0;
        int hResult;
        DateTimeOffset startedUtc;
        DateTimeOffset finishedUtc;
        long startedTimestamp;
        long finishedTimestamp;

        using SendLease send = EnterSend();
        startedUtc = DateTimeOffset.UtcNow;
        startedTimestamp = Stopwatch.GetTimestamp();
        if (_admissionEvidenceNativeSender is { } nativeSender)
        {
            hResult = nativeSender.Send(send.Handle, input, output, out bytesReturned);
        }
        else
        {
            unsafe
            {
                fixed (byte* inputPointer = input)
                fixed (byte* outputPointer = output)
                {
                    hResult = FilterSendMessage(send.Handle, (IntPtr)inputPointer,
                        (uint)input.Length, (IntPtr)outputPointer, (uint)output.Length,
                        out bytesReturned);
                }
            }
        }
        finishedTimestamp = Stopwatch.GetTimestamp();
        finishedUtc = DateTimeOffset.UtcNow;

        byte[] rawReply = Array.Empty<byte>();
        string? validationError = null;
        if (hResult == 0)
        {
            if (bytesReturned > (uint)output.Length)
            {
                rawReply = (byte[])output.Clone();
                validationError = $"Driver reported {bytesReturned} reply bytes for a {output.Length}-byte buffer; captured output is truncated to buffer capacity.";
            }
            else
            {
                rawReply = output.AsSpan(0, (int)bytesReturned).ToArray();
                validationError = AdmissionEvidenceWire.ValidateReply(command, startIndex, rawReply);
            }
        }

        return new AdmissionEvidenceReply(rawInput, rawReply, hResult, bytesReturned,
            startedUtc, finishedUtc, startedTimestamp, finishedTimestamp, validationError);
    }
}
#endif
