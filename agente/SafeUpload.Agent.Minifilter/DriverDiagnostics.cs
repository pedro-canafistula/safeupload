using System.ComponentModel;
using System.Runtime.InteropServices;

namespace SafeUpload.Agent.Minifilter;

// Mirrors the field-diagnostics part of Protocol.h (SAFEUPLOAD_CONTROL_DENY_RING_READ / DIAG_COUNTERS /
// WRITER_STATE_STATUS). These are read-only queries; the driver answers them to the connected service.

public static class DiagnosticsCommand
{
    public const uint WriterStateStatus = 12;
    public const uint DenyRingRead = 27;
    public const uint DiagCounters = 28;
}

public static class DiagnosticsContract
{
    public const int DenyRingBatchEntries = 16;
    public const int DenyNameChars = 64;
    public const int DenyRecordSize = 192;
    public const int DenyRingRequestSize = 24;
    public const int DenyRingBatchSize = 32 + DenyRingBatchEntries * DenyRecordSize;
    public const int DiagCountersSize = 112;
    public const int WriterStateStatusSize = 288;

    // Deny record flags (SAFEUPLOAD_DENY_FLAG_*).
    public const uint FlagTopLevelIrp = 0x001;
    public const uint FlagTransaction = 0x002;
    public const uint FlagPagingIo = 0x004;
    public const uint FlagFastIo = 0x008;
    public const uint FlagPostOperation = 0x010;
    public const uint FlagNameIsRenameTarget = 0x020;
    public const uint FlagNameIsCreateName = 0x040;
    public const uint FlagServiceProcess = 0x080;
    public const uint FlagKernelMode = 0x100;
    public const uint FlagNameTruncated = 0x200;
    public const uint BatchFlagGap = 0x1;

    /// <summary>
    /// Same idea as <see cref="Contract.Verify"/>: a layout mismatch with the driver is reported by name.
    /// </summary>
    public static unsafe void Verify()
    {
        Check(sizeof(SafeUploadDenyRecord), DenyRecordSize, nameof(SafeUploadDenyRecord));
        Check(sizeof(SafeUploadDenyRingRequest), DenyRingRequestSize, nameof(SafeUploadDenyRingRequest));
        Check(sizeof(SafeUploadDenyRingBatch), DenyRingBatchSize, nameof(SafeUploadDenyRingBatch));
        Check(sizeof(SafeUploadDiagCounters), DiagCountersSize, nameof(SafeUploadDiagCounters));
        Check(sizeof(SafeUploadWriterStateStatus), WriterStateStatusSize, nameof(SafeUploadWriterStateStatus));
    }

    private static void Check(int actual, int expected, string name)
    {
        if (actual != expected)
            throw new InvalidOperationException(
                $"{name} is {actual} bytes here but Protocol.h expects {expected}.");
    }
}

[StructLayout(LayoutKind.Sequential, Pack = 8)]
public unsafe struct SafeUploadDenyRecord
{
    public ulong Sequence;
    public ulong SystemTime;
    public uint Status;
    public uint SiteOffset;
    public uint ProcessId;
    public uint ThreadId;
    public uint MajorFunction;
    public uint MinorFunction;
    public uint Irql;
    public uint Flags;
    public uint Access;
    public uint Options;
    public uint NameChars;
    public uint Reserved;
    public fixed char Name[DiagnosticsContract.DenyNameChars];

    public string ReadName()
    {
        uint chars = Math.Min(NameChars, (uint)DiagnosticsContract.DenyNameChars);
        fixed (char* value = Name) return new string(value, 0, (int)chars);
    }
}

[StructLayout(LayoutKind.Sequential, Pack = 8)]
public struct SafeUploadDenyRingRequest
{
    public SafeUploadControl Control;
    public ulong AfterSequence;
}

[StructLayout(LayoutKind.Sequential, Pack = 8)]
public unsafe struct SafeUploadDenyRingBatch
{
    public uint StructSize;
    public uint ProtocolVersion;
    public uint Count;
    public uint Flags;
    public ulong NextSequence;
    public ulong ImageBase;
    public fixed byte Entries[DiagnosticsContract.DenyRingBatchEntries * DiagnosticsContract.DenyRecordSize];
}

[StructLayout(LayoutKind.Sequential, Pack = 8)]
public struct SafeUploadDiagCounters
{
    public uint StructSize;
    public uint ProtocolVersion;
    public ulong DenyRecorded;
    public ulong DenyAccessDenied;
    public ulong DenyRetry;
    public ulong DenyOtherStatus;
    public ulong DenyBenignIgnored;
    public ulong DenyNotRecorded;
    public ulong VolumeWideQueries;
    public ulong VolumeWideAnswers;
    public ulong NextDenySequence;
    public ulong ImageBase;
    public ulong ReclaimPasses;
    public ulong ReclaimParkedPasses;
    public ulong ReclaimMoreWorkRequeues;
}

/// <summary>SAFEUPLOAD_WRITER_STATE_STATUS of the staging build (288 bytes).</summary>
[StructLayout(LayoutKind.Sequential, Pack = 8)]
public struct SafeUploadWriterStateStatus
{
    public uint StructSize;
    public uint SectionInFlightNow;
    public ulong PostCreateRuns;
    public ulong WriteObjectsCounted;
    public ulong WriteObjectsReleased;
    public ulong UntrackedCreates;
    public ulong CleanupUnmatched;
    public ulong DirectoryCreatesSkipped;
    public ulong SectionInFlightInserted;
    public ulong SectionInFlightReleased;
    public ulong RetiredSectionOverflow;
    public ulong SectionInFlightStuck;
    public ulong SectionInFlightRemovedOnFailure;
    public uint SectionInFlightMaxDepth;
    public uint CleanupDirectoriesSkipped;
    public ulong PagingCreatesSkipped;
    public ulong VolumeCreatesSkipped;
    public uint StageStreams;
    public uint StageFileObjects;
    public uint LastUnloadVeto;
    public uint LastUnloadStatus;
    public ulong WritersDroppedAtTeardown;
    public ulong WritersDroppedWhileMounted;
    public ulong InstanceTeardownsDismount;
    public ulong InstanceTeardownsOther;
    public ulong TxfRefused;
    public ulong RegistryCapacityFailures;
    public ulong RegistryAllocationFailures;
    public ulong RegistryIdentityFailures;
    public ulong RegistryTransactionFailures;
    public ulong RegistryRenameFailures;
    public ulong RegistryDroppedAtDismount;
    public ulong RegistryDroppedWhileMounted;
    public uint RegistryEntries;
    public uint RegistryReservations;
    public uint RegistryOverflow;
    public uint RegistryUnknownReasons;
    public uint RegistryInstanceUnknown;
    public uint RegistryCapacity;
    public uint TransactionAssociations;
    public uint Reserved2;
    public ulong RegistryPruned;
    public ulong RegistryReclaimPasses;
    public uint RegistryNameTierEntries;
    public uint RegistryCompactTierEntries;
}

/// <summary>One refusal recorded by the driver's choke point.</summary>
public sealed record DenyRecord(
    ulong Sequence,
    DateTime TimeUtc,
    uint Status,
    uint SiteOffset,
    uint ProcessId,
    uint ThreadId,
    uint MajorFunction,
    uint MinorFunction,
    uint Irql,
    uint Flags,
    uint Access,
    uint Options,
    string Name);

/// <summary>A page of the deny ring. <see cref="NextSequence"/> is the cursor for the next request.</summary>
public sealed record DenyRingPage(
    IReadOnlyList<DenyRecord> Records,
    ulong NextSequence,
    ulong ImageBase,
    bool Gap);

public sealed partial class FilterPort
{
    /// <summary>
    /// Reads refusals with a sequence greater than <paramref name="afterSequence"/>. A cursor ahead of the driver's
    /// (a driver that was reloaded) returns no records and a smaller <see cref="DenyRingPage.NextSequence"/>.
    /// </summary>
    public unsafe DenyRingPage ReadDenyRing(ulong afterSequence)
    {
        SafeUploadDenyRingRequest request = new()
        {
            Control = new SafeUploadControl
            {
                Version = Contract.Version,
                StructSize = (uint)sizeof(SafeUploadDenyRingRequest),
                Command = DiagnosticsCommand.DenyRingRead,
                Reserved = 0
            },
            AfterSequence = afterSequence
        };
        SafeUploadDenyRingBatch batch = default;

        using var send = EnterSend();
        int hr = FilterSendMessage(send.Handle, (IntPtr)(&request), (uint)sizeof(SafeUploadDenyRingRequest),
            (IntPtr)(&batch), (uint)sizeof(SafeUploadDenyRingBatch), out uint returned);
        if (hr != 0) throw new Win32Exception(hr, $"Deny ring query failed: 0x{hr:X8}");
        if (returned != sizeof(SafeUploadDenyRingBatch) || batch.StructSize != sizeof(SafeUploadDenyRingBatch) ||
            batch.ProtocolVersion != Contract.Version ||
            batch.Count > DiagnosticsContract.DenyRingBatchEntries)
            throw new InvalidDataException("Deny ring response does not match Protocol.h.");

        var records = new List<DenyRecord>((int)batch.Count);
        SafeUploadDenyRecord* entries = (SafeUploadDenyRecord*)batch.Entries;
        for (int index = 0; index < batch.Count; ++index)
        {
            SafeUploadDenyRecord* entry = &entries[index];
            records.Add(new DenyRecord(entry->Sequence, FromFileTimeOrMin(entry->SystemTime), entry->Status,
                entry->SiteOffset, entry->ProcessId, entry->ThreadId, entry->MajorFunction,
                entry->MinorFunction, entry->Irql, entry->Flags, entry->Access, entry->Options,
                entry->ReadName()));
        }
        return new DenyRingPage(records, batch.NextSequence, batch.ImageBase,
            (batch.Flags & DiagnosticsContract.BatchFlagGap) != 0);
    }

    public unsafe SafeUploadDiagCounters ReadDiagnosticCounters()
    {
        SafeUploadDiagCounters counters = default;
        QueryControl(DiagnosticsCommand.DiagCounters, (IntPtr)(&counters), (uint)sizeof(SafeUploadDiagCounters));
        if (counters.StructSize != sizeof(SafeUploadDiagCounters) || counters.ProtocolVersion != Contract.Version)
            throw new InvalidDataException("Diagnostic counters response does not match Protocol.h.");
        return counters;
    }

    public unsafe SafeUploadWriterStateStatus ReadWriterStateStatus()
    {
        SafeUploadWriterStateStatus status = default;
        QueryControl(DiagnosticsCommand.WriterStateStatus, (IntPtr)(&status), (uint)sizeof(SafeUploadWriterStateStatus));
        if (status.StructSize != sizeof(SafeUploadWriterStateStatus))
            throw new InvalidDataException("Writer state response does not match Protocol.h.");
        return status;
    }

    private unsafe void QueryControl(uint command, IntPtr output, uint outputSize)
    {
        SafeUploadControl control = new()
        {
            Version = Contract.Version,
            StructSize = (uint)sizeof(SafeUploadControl),
            Command = command,
            Reserved = 0
        };
        using var send = EnterSend();
        int hr = FilterSendMessage(send.Handle, (IntPtr)(&control), (uint)sizeof(SafeUploadControl),
            output, outputSize, out uint returned);
        if (hr != 0) throw new Win32Exception(hr, $"Driver query {command} failed: 0x{hr:X8}");
        if (returned != outputSize)
            throw new InvalidDataException($"Driver query {command} returned {returned} bytes, expected {outputSize}.");
    }

    private static DateTime FromFileTimeOrMin(ulong fileTime) =>
        fileTime is > 0 and < long.MaxValue ? DateTime.FromFileTimeUtc((long)fileTime) : DateTime.MinValue;
}
