using System.Buffers.Binary;
using System.Runtime.InteropServices;

namespace SafeUpload.Agent.Minifilter;

/// <summary>Read-only commands, explicitly selected for driver e0df8d1c's M2 layout.</summary>
public enum M2DiagnosticQuery : uint { WriterState = 12, Counters = 28, StageStreams = 29 }

/// <summary>One synchronous control exchange; returns the actual byte count, not buffer capacity.</summary>
public interface IM2DiagnosticTransport
{
    int Query(M2DiagnosticQuery query, Span<byte> response);
}

public static class M2DiagnosticContract
{
    public const uint ProtocolVersion = 18;
    public const int CountersBytes = 296;
    public const int WriterStateBytes = 304;
    public const int StageLifetimeBytes = 176;

    public static int ResponseBytes(M2DiagnosticQuery query) => query switch
    {
        M2DiagnosticQuery.Counters => CountersBytes,
        M2DiagnosticQuery.WriterState => WriterStateBytes,
        M2DiagnosticQuery.StageStreams => StageStreamDiagnosticsContract.SnapshotBytes,
        _ => throw new ArgumentOutOfRangeException(nameof(query), "Unsupported M2 diagnostic command.")
    };

    public static void Verify()
    {
        if (!BitConverter.IsLittleEndian || Contract.Version != ProtocolVersion ||
            StageStreamDiagnosticsContract.ProtocolVersion != ProtocolVersion ||
            StageStreamDiagnosticsContract.Command != 29 || StageStreamDiagnosticsContract.SnapshotBytes != 2576 ||
            Marshal.SizeOf<SafeUploadControl>() != 16 ||
            Marshal.SizeOf<SafeUploadDiagCounters>() != 120 ||
            Marshal.SizeOf<SafeUploadWriterStateStatus>() != 288 ||
            Marshal.SizeOf<M2StageLifetimeCounters>() != StageLifetimeBytes ||
            Marshal.SizeOf<M2DiagnosticCounters>() != CountersBytes ||
            Marshal.SizeOf<M2WriterStateStatus>() != WriterStateBytes ||
            Marshal.OffsetOf<M2DiagnosticCounters>(nameof(M2DiagnosticCounters.Stage)).ToInt32() != 120 ||
            Marshal.OffsetOf<M2WriterStateStatus>(nameof(M2WriterStateStatus.WriterGlobalFirstUnknown)).ToInt32() != 288)
            throw new InvalidOperationException("M2 diagnostic layout requires review against its pinned Protocol.h.");
    }
}

/// <summary>
/// Explicit M2 profile. Not registered in the service, not capability negotiation,
/// and never an automatic fallback from legacy diagnostics. Each snapshot can be
/// momentarily inconsistent; a successful query does not grant protection/readiness.
/// </summary>
public sealed class M2DiagnosticClient
{
    private readonly IM2DiagnosticTransport _transport;
    public M2DiagnosticClient(IM2DiagnosticTransport transport)
    {
        _transport = transport ?? throw new ArgumentNullException(nameof(transport));
        M2DiagnosticContract.Verify();
    }

    public M2CounterSnapshot ReadCounters()
    {
        var counters = Query(M2DiagnosticQuery.Counters);
        ValidateHeader(counters, hasVersion: true);
        var writer = Query(M2DiagnosticQuery.WriterState);
        // Writer-state has StructSize followed by SectionInFlightNow, not a version field.
        ValidateHeader(writer, hasVersion: false);
        return new(MemoryMarshal.Read<M2DiagnosticCounters>(counters), MemoryMarshal.Read<M2WriterStateStatus>(writer));
    }

    public StageStreamDiagnosticSnapshot ReadStageStreams() =>
        StageStreamDiagnosticsContract.Decode(Query(M2DiagnosticQuery.StageStreams));

    private byte[] Query(M2DiagnosticQuery query)
    {
        M2DiagnosticContract.Verify();
        var response = new byte[M2DiagnosticContract.ResponseBytes(query)];
        int returned = _transport.Query(query, response);
        if (returned != response.Length)
            throw new InvalidDataException("M2 diagnostic transport returned an unexpected byte count.");
        return response;
    }

    private static void ValidateHeader(ReadOnlySpan<byte> response, bool hasVersion)
    {
        if (BinaryPrimitives.ReadUInt32LittleEndian(response) != response.Length ||
            (hasVersion && BinaryPrimitives.ReadUInt32LittleEndian(response[4..]) != M2DiagnosticContract.ProtocolVersion))
            throw new InvalidDataException("M2 diagnostic response has an unsupported size or protocol.");
    }
}

// Prefixes remain the unmodified legacy structures; M2 only appends these fields.
[StructLayout(LayoutKind.Sequential, Pack = 8)]
public struct M2DiagnosticCounters
{
    public SafeUploadDiagCounters Prefix;
    public M2StageLifetimeCounters Stage;
}

[StructLayout(LayoutKind.Sequential, Pack = 8)]
public struct M2WriterStateStatus
{
    public SafeUploadWriterStateStatus Prefix;
    public uint WriterGlobalFirstUnknown;
    public uint WriterEntryFirstUnknown;
    public uint WriterSopFirstUnknown;
    public uint WriterSopUnknownCount;
}

[StructLayout(LayoutKind.Sequential, Pack = 8)]
public struct M2StageLifetimeCounters
{
    public uint LiveVersions, LiveViews, Tombstones, WaitingVersions;
    public ulong VersionsCreated, VersionsReleased, ViewsReleased, CapRefusals, TombstoneRefusals;
    public ulong WorkerPasses, WakeCleanup, WakeClose, WakeDispose, WakeConnect, WakeExit;
    public ulong WakeTimer, WakeInline, TimerArms, DisposeHeld, DisposeNotHeld, DisposeStale;
    public ulong DisposeDeferred, StageDeletes, StageDeleteFailures;
}

/// <summary>Two sequential replies, not an atomic snapshot or a qualified driver pair.</summary>
public sealed record M2CounterSnapshot(M2DiagnosticCounters Counters, M2WriterStateStatus WriterState);
