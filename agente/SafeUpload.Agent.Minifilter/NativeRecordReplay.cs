#if SAFEUPLOAD_ADMISSION_EVIDENCE
using System.Buffers.Binary;
using System.ComponentModel;
using System.Security.Principal;
using System.Text;
using Microsoft.Win32.SafeHandles;

namespace SafeUpload.Agent.Minifilter;

[Flags]
public enum NativeRecordFacts : uint
{
    Forwarded = 1, CreateOutcomeKnown = 2, CreateAccepted = 4, IdentityChecked = 8,
    LastHandleCleanedUp = 16, CancelledBeforeHandle = 32, CancelledCloseObserved = 64,
    CleanupCoverageLost = 128
}

// Immutable transport facts, never a DELETE grant, publication permit or
// physical-cleanup ACK. The service must reconcile them with durable intents.
public sealed record NativeRecordReplayRow(Guid DriverInstanceId, Guid TransferId,
    Guid RequestNonce, Guid OperationId, ulong OriginalConnectionEpoch, ulong JournalGeneration,
    long CallerProcessCreationTime, SafeUploadStageIdentityV19 VolumeRootIdentity,
    SafeUploadStageIdentityV19 ParentIdentity, SafeUploadStageIdentityV19 PublicIdentity,
    uint OsBootSequence, uint CreateOptions, uint OriginalDesiredAccess, uint OriginalShareAccess,
    uint CallerProcessId, uint CallerSessionId, string CallerSid, bool ParentCaseSensitive,
    string CanonicalLeaf, NativeRecordFacts Facts, int CreateStatus, int IdentityStatus, uint TeardownReason,
    Guid MountManagerVolumeId);

public sealed record NativeRecordReplay(Guid DriverInstanceId, ulong ConnectionEpoch,
    ulong Revision, uint OsBootSequence, IReadOnlyList<NativeRecordReplayRow> Records);

internal interface INativeRecordReplayNativeSender
{
    int Send(SafeFileHandle handle, ReadOnlyMemory<byte> input, Memory<byte> output, out uint returned);
}

internal sealed record NativeRecordReplayPage(Guid DriverInstanceId, ulong ConnectionEpoch,
    ulong Revision, uint OsBootSequence, uint StartIndex, bool Complete, NativeRecordReplayRow[] Rows);

internal static class NativeRecordReplayWire
{
    internal const uint Command = 30, ExtensionVersion = 22;
    internal const int RequestBytes = 64, HeaderBytes = 64, RowBytes = 816, PageRows = 16;
    internal const int PageBytes = HeaderBytes + RowBytes * PageRows, MaximumRecords = 1024;
    private static readonly Encoding StrictUtf16 = new UnicodeEncoding(false, false, true);

    internal static byte[] CreateRequest(uint startIndex, Guid driver = default, ulong epoch = 0, ulong revision = 0)
    {
        if (startIndex > MaximumRecords ||
            (revision == 0 ? startIndex != 0 || driver != Guid.Empty || epoch != 0 : driver == Guid.Empty || epoch == 0))
            throw new ArgumentException("Native replay requires one exact driver/connection/revision.");
        byte[] request = new byte[RequestBytes];
        Write(request, 0, Contract.Version); Write(request, 4, RequestBytes); Write(request, 8, Command);
        Write(request, 16, ExtensionVersion); Write(request, 20, startIndex);
        driver.TryWriteBytes(request.AsSpan(24, 16));
        BinaryPrimitives.WriteUInt64LittleEndian(request.AsSpan(40), epoch);
        BinaryPrimitives.WriteUInt64LittleEndian(request.AsSpan(48), revision);
        return request;
    }

    internal static NativeRecordReplayPage DecodePage(ReadOnlySpan<byte> bytes, uint startIndex,
        Guid expectedDriver = default, ulong expectedEpoch = 0, ulong expectedRevision = 0)
    {
        if (bytes.Length != PageBytes || U32(bytes, 0) != ExtensionVersion || U32(bytes, 4) != PageBytes ||
            U32(bytes, 44) != startIndex || U32(bytes, 52) > 1 || U64(bytes, 56) != 0)
            throw Bad("Invalid native replay header or length.");
        Guid driver = new(bytes.Slice(8, 16));
        ulong epoch = U64(bytes, 24), revision = U64(bytes, 32);
        uint boot = U32(bytes, 40), count = U32(bytes, 48);
        bool complete = U32(bytes, 52) == 1;
        if (driver == Guid.Empty || epoch == 0 || revision == 0 || startIndex > MaximumRecords ||
            count > PageRows || startIndex + count > MaximumRecords || (!complete && count != PageRows) ||
            (expectedRevision != 0 && (driver != expectedDriver || epoch != expectedEpoch || revision != expectedRevision)))
            throw Bad("Native replay is stale, incomplete or exceeds its bound.");
        var rows = new NativeRecordReplayRow[count];
        for (int i = 0; i < rows.Length; i++) rows[i] = DecodeRow(bytes.Slice(HeaderBytes + i * RowBytes, RowBytes), driver, epoch, boot);
        if (!IsZero(bytes[(HeaderBytes + rows.Length * RowBytes)..]))
            throw Bad("Unused native replay rows are not zero.");
        return new(driver, epoch, revision, boot, startIndex, complete, rows);
    }

    internal static NativeRecordReplayRow DecodeRow(ReadOnlySpan<byte> b, Guid driver, ulong epoch, uint boot,
        bool ordinary = false)
    {
        Guid rowDriver = new(b[..16]), transfer = new(b.Slice(16, 16)), nonce = new(b.Slice(32, 16)), operation = new(b.Slice(48, 16));
        Guid mountVolumeId = new(b.Slice(800, 16));
        ulong originalEpoch = U64(b, 64), generation = U64(b, 72);
        long creationTime = BinaryPrimitives.ReadInt64LittleEndian(b[80..]);
        var root = Identity(b, 88); var parent = Identity(b, 112); var file = Identity(b, 136);
        uint options = U32(b, 164), desired = U32(b, 168), share = U32(b, 172), pid = U32(b, 176);
        uint sidBytes = U32(b, 184), caseMode = U32(b, 188), leafBytes = U32(b, 192);
        var facts = (NativeRecordFacts)U32(b, 196);
        if (rowDriver != driver || transfer == Guid.Empty || nonce == Guid.Empty || operation == Guid.Empty || mountVolumeId == Guid.Empty ||
            originalEpoch == 0 || originalEpoch > epoch || U32(b, 160) != boot || creationTime <= 0 ||
            !root.HasNonzeroFileId || !parent.HasNonzeroFileId || !file.HasNonzeroFileId ||
            root.VolumeSerialNumber != parent.VolumeSerialNumber || parent.VolumeSerialNumber != file.VolumeSerialNumber ||
            (options >> 24) != 1 || (options & (0x01 | 0x2000 | 0x200000)) != 0 ||
            (ordinary ? (options & 0x1000) != 0 : (options & 0x1000) == 0) ||
            (desired & (ordinary ? 0x52000056u : 0x52000156u)) != 0 ||
            (desired & 0x10000) == 0 || (share & ~7u) != 0 ||
            pid == 0 || pid > int.MaxValue || sidBytes < 8 || sidBytes > 68 || caseMode > 1 ||
            leafBytes == 0 || leafBytes >= 512 || (leafBytes & 1) != 0 || (facts & ~(NativeRecordFacts)255) != 0 ||
            U32(b, 212) != 0 || U32(b, 796) != 0 ||
            (ordinary ? generation != 0 :
                ((!facts.HasFlag(NativeRecordFacts.Forwarded) && generation != 0) ||
                 (facts.HasFlag(NativeRecordFacts.Forwarded) && (generation == 0 || generation > long.MaxValue)))) ||
            (facts.HasFlag(NativeRecordFacts.CreateAccepted) && !facts.HasFlag(NativeRecordFacts.CreateOutcomeKnown)) ||
            (facts.HasFlag(NativeRecordFacts.IdentityChecked) && !facts.HasFlag(NativeRecordFacts.CreateAccepted)) ||
            !IsZero(b.Slice(216 + (int)sidBytes, 68 - (int)sidBytes)) ||
            !IsZero(b.Slice(284 + (int)leafBytes, 512 - (int)leafBytes)))
            throw Bad("Native replay contains an invalid or unbound original-object record.");
        ReadOnlySpan<byte> sid = b.Slice(216, (int)sidBytes);
        if (sid[0] != 1 || sid[1] > 15 || sidBytes != 8 + 4 * sid[1]) throw Bad("Native replay SID length is invalid.");
        string ownerSid;
        string leaf;
        try
        {
            ownerSid = new SecurityIdentifier(sid.ToArray(), 0).Value;
            leaf = StrictUtf16.GetString(b.Slice(284, (int)leafBytes));
        }
        catch (ArgumentException ex) { throw new IOException("Invalid native replay SID/name encoding.", ex); }
        if (leaf is "." or ".." || leaf.Any(c => c == 0 || c is '\\' or '/' or ':')) throw Bad("Invalid native canonical leaf.");
        return new(driver, transfer, nonce, operation, originalEpoch, generation, creationTime, root, parent, file,
            boot, options, desired, share, pid, U32(b, 180), ownerSid, caseMode == 1, leaf, facts,
            BinaryPrimitives.ReadInt32LittleEndian(b[200..]), BinaryPrimitives.ReadInt32LittleEndian(b[204..]), U32(b, 208), mountVolumeId);
    }

    private static SafeUploadStageIdentityV19 Identity(ReadOnlySpan<byte> b, int offset) => new()
        { VolumeSerialNumber = U64(b, offset), FileIdLow = U64(b, offset + 8), FileIdHigh = U64(b, offset + 16) };
    private static uint U32(ReadOnlySpan<byte> b, int offset) => BinaryPrimitives.ReadUInt32LittleEndian(b[offset..]);
    private static ulong U64(ReadOnlySpan<byte> b, int offset) => BinaryPrimitives.ReadUInt64LittleEndian(b[offset..]);
    private static void Write(Span<byte> b, int offset, uint value) => BinaryPrimitives.WriteUInt32LittleEndian(b[offset..], value);
    private static bool IsZero(ReadOnlySpan<byte> b) { foreach (byte value in b) if (value != 0) return false; return true; }
    private static IOException Bad(string message) => new(message);
}

public sealed partial class FilterPort
{
    private readonly INativeRecordReplayNativeSender? _nativeRecordReplaySender;

    internal static FilterPort CreateForNativeReplayTesting(SafeFileHandle handle, INativeRecordReplayNativeSender sender)
        => new(handle, sender);

    private FilterPort(SafeFileHandle handle, INativeRecordReplayNativeSender sender) : this(handle, Contract.PortName)
        => _nativeRecordReplaySender = sender ?? throw new ArgumentNullException(nameof(sender));

    // One send lease covers all pages and the final revision check. Dispose
    // cannot close/replace this handle halfway through a complete replay.
    public NativeRecordReplay ReadNativeRecordReplay()
    {
        using SendLease lease = EnterSend();
        var records = new List<NativeRecordReplayRow>();
        var transfers = new HashSet<Guid>(); var nonces = new HashSet<Guid>(); var operations = new HashSet<Guid>();
        NativeRecordReplayPage page = SendNativeReplayPage(lease.Handle, 0);
        Guid driver = page.DriverInstanceId;
        ulong epoch = page.ConnectionEpoch, revision = page.Revision;
        uint boot = page.OsBootSequence;
        while (true)
        {
            if (page.OsBootSequence != boot) throw new IOException("Native boot evidence changed between replay pages.");
            foreach (var row in page.Rows)
            {
                if (!transfers.Add(row.TransferId) || !nonces.Add(row.RequestNonce) || !operations.Add(row.OperationId))
                    throw new IOException("Native replay repeats an immutable operation/transfer/nonce.");
                records.Add(row);
            }
            if (page.Complete) break;
            page = SendNativeReplayPage(lease.Handle, (uint)records.Count, driver, epoch, revision);
        }
        var final = SendNativeReplayPage(lease.Handle, (uint)records.Count, driver, epoch, revision);
        if (!final.Complete || final.Rows.Length != 0 || final.OsBootSequence != boot)
            throw new IOException("Native replay changed before its final completion check.");
        return new(driver, epoch, revision, boot, records.AsReadOnly());
    }

    private NativeRecordReplayPage SendNativeReplayPage(SafeFileHandle handle, uint startIndex,
        Guid driver = default, ulong epoch = 0, ulong revision = 0)
    {
        byte[] input = NativeRecordReplayWire.CreateRequest(startIndex, driver, epoch, revision);
        byte[] output = new byte[NativeRecordReplayWire.PageBytes];
        uint returned;
        int hr;
        if (_nativeRecordReplaySender is { } sender) hr = sender.Send(handle, input, output, out returned);
        else
        {
            unsafe
            {
                fixed (byte* i = input)
                fixed (byte* o = output)
                    hr = FilterSendMessage(handle, (IntPtr)i, (uint)input.Length, (IntPtr)o, (uint)output.Length, out returned);
            }
        }
        if (hr != 0) throw new Win32Exception(hr, $"Native-record replay failed: 0x{hr:X8}");
        if (returned != output.Length) throw new IOException("Incomplete native-record replay receipt.");
        return NativeRecordReplayWire.DecodePage(output, startIndex, driver, epoch, revision);
    }
}
#endif
