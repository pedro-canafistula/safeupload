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
    public const uint StageStreams = 29;
}

public static class DiagnosticsContract
{
    public const int DenyRingBatchEntries = 16;
    public const int DenyNameChars = 62;
    public const int DenyRecordSize = 192;
    public const int DenyRingRequestSize = 24;
    public const int DenyRingBatchSize = 32 + DenyRingBatchEntries * DenyRecordSize;
    public const int DiagCountersSize = 296;
    public const int StageLifetimeCountersSize = 176;
    public const int WriterStateStatusSize = 304;
    public const int StageStreamEntries = 16;
    public const int StageStreamNameChars = 48;
    public const int StageStreamRecordSize = 160;
    public const int StageStreamsSize = 16 + StageStreamEntries * StageStreamRecordSize;

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
    public const uint FlagNameIsImage = 0x400;
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
        Check(sizeof(SafeUploadStageLifetimeCounters), StageLifetimeCountersSize, nameof(SafeUploadStageLifetimeCounters));
        Check(sizeof(SafeUploadWriterStateStatus), WriterStateStatusSize, nameof(SafeUploadWriterStateStatus));
        Check(sizeof(SafeUploadStageStreamRecord), StageStreamRecordSize, nameof(SafeUploadStageStreamRecord));
        Check(sizeof(SafeUploadStageStreams), StageStreamsSize, nameof(SafeUploadStageStreams));
        Check(Marshal.OffsetOf<SafeUploadStageStreamRecord>(nameof(SafeUploadStageStreamRecord.DestinationGeneration)).ToInt32(), 48,
            $"{nameof(SafeUploadStageStreamRecord)}.{nameof(SafeUploadStageStreamRecord.DestinationGeneration)} offset");
        CheckWriterOffset(nameof(SafeUploadWriterStateStatus.Reserved2), 260);
        CheckWriterOffset(nameof(SafeUploadWriterStateStatus.WriterGlobalFirstUnknown), 288);
        CheckWriterOffset(nameof(SafeUploadWriterStateStatus.WriterEntryFirstUnknown), 292);
        CheckWriterOffset(nameof(SafeUploadWriterStateStatus.WriterSopFirstUnknown), 296);
        CheckWriterOffset(nameof(SafeUploadWriterStateStatus.WriterSopUnknownCount), 300);
    }

    private static void CheckWriterOffset(string field, int expected) =>
        Check(Marshal.OffsetOf<SafeUploadWriterStateStatus>(field).ToInt32(), expected,
            $"{nameof(SafeUploadWriterStateStatus)}.{field} offset");

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
    public uint AuxStatus;
    public uint Reason;
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
    public ulong ReclaimWakeupsSkipped;
    public SafeUploadStageLifetimeCounters Stage;
}

/// <summary>SAFEUPLOAD_STAGE_STREAM_RECORD (160 bytes): one live stage version in the read-only snapshot (T8 increment 0).</summary>
[StructLayout(LayoutKind.Sequential, Pack = 8)]
public unsafe struct SafeUploadStageStreamRecord
{
    public Guid TransferId;
    public uint Flags;
    public uint FileObjects;
    public uint ShareOpenCount;
    public uint RpcReferences;
    public uint OwnerProcessId;
    public uint Wait;
    public uint SectionBits;
    public uint Reserved0;
    public ulong DestinationGeneration;
    public uint NameChars;
    public uint Reserved1;
    public fixed char Name[DiagnosticsContract.StageStreamNameChars];

    public string ReadName()
    {
        uint chars = Math.Min(NameChars, (uint)DiagnosticsContract.StageStreamNameChars);
        fixed (char* value = Name) return new string(value, 0, (int)chars);
    }
}

[StructLayout(LayoutKind.Sequential, Pack = 8)]
public unsafe struct SafeUploadStageStreams
{
    public uint StructSize;
    public uint ProtocolVersion;
    public uint Count;
    public uint Total;
    public fixed byte Entries[DiagnosticsContract.StageStreamEntries * DiagnosticsContract.StageStreamRecordSize];
}

public sealed record StageStreamRecord(Guid TransferId, uint Flags, uint FileObjects, uint ShareOpenCount, uint RpcReferences,
    uint OwnerProcessId, uint Wait, uint SectionBits, ulong DestinationGeneration, string Name);

public sealed record StageStreamSnapshot(IReadOnlyList<StageStreamRecord> Streams, uint Total);

/// <summary>SAFEUPLOAD_STAGE_LIFETIME_COUNTERS (176 bytes): stage-version lifetime and stage-worker wakes (T4).</summary>
[StructLayout(LayoutKind.Sequential, Pack = 8)]
public struct SafeUploadStageLifetimeCounters
{
    public uint LiveVersions;
    public uint LiveViews;
    public uint Tombstones;
    public uint WaitingVersions;
    public ulong VersionsCreated;
    public ulong VersionsReleased;
    public ulong ViewsReleased;
    public ulong CapRefusals;
    public ulong TombstoneRefusals;
    public ulong WorkerPasses;
    public ulong WakeCleanup;
    public ulong WakeClose;
    public ulong WakeDispose;
    public ulong WakeConnect;
    public ulong WakeExit;
    public ulong WakeTimer;
    public ulong WakeInline;
    public ulong TimerArms;
    public ulong DisposeHeld;
    public ulong DisposeNotHeld;
    public ulong DisposeStale;
    public ulong DisposeDeferred;
    public ulong StageDeletes;
    public ulong StageDeleteFailures;
}

/// <summary>SAFEUPLOAD_WRITER_STATE_STATUS of the staging build (304 bytes).</summary>
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
    // Diagnostic first CAS: reason low 16, delivered-source line high 16; zero = not recorded.
    public uint WriterGlobalFirstUnknown;
    public uint WriterEntryFirstUnknown;
    public uint WriterSopFirstUnknown;
    public uint WriterSopUnknownCount;
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
    uint AuxStatus,
    uint Reason,
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
                entry->AuxStatus, entry->Reason, entry->ReadName()));
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

    /// <summary>Read-only snapshot of up to 16 live stage versions: flags, counts and section pointers (T8 increment 0).</summary>
    public unsafe StageStreamSnapshot ReadStageStreams()
    {
        SafeUploadStageStreams batch = default;
        QueryControl(DiagnosticsCommand.StageStreams, (IntPtr)(&batch), (uint)sizeof(SafeUploadStageStreams));
        if (batch.StructSize != sizeof(SafeUploadStageStreams) || batch.ProtocolVersion != Contract.Version ||
            batch.Count > DiagnosticsContract.StageStreamEntries || batch.Count > batch.Total)
            throw new InvalidDataException("Stage streams response does not match Protocol.h.");
        var records = new List<StageStreamRecord>((int)batch.Count);
        SafeUploadStageStreamRecord* entries = (SafeUploadStageStreamRecord*)batch.Entries;
        for (int index = 0; index < batch.Count; ++index)
        {
            SafeUploadStageStreamRecord* e = &entries[index];
            records.Add(new StageStreamRecord(e->TransferId, e->Flags, e->FileObjects, e->ShareOpenCount, e->RpcReferences,
                e->OwnerProcessId, e->Wait, e->SectionBits, e->DestinationGeneration, e->ReadName()));
        }
        return new StageStreamSnapshot(records, batch.Total);
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
