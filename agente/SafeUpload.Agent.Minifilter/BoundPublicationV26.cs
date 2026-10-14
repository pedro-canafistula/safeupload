#if SAFEUPLOAD_ADMISSION_EVIDENCE
using System.Buffers.Binary;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;

namespace SafeUpload.Agent.Minifilter;

public enum BoundPublicationPhase : uint { Create = 1, Rename = 2, Revoke = 3, Facts = 4, CleanupAck = 5 }
public enum BoundPublicationResult : uint
{ Prepared = 1, Consumed = 2, Revoked = 3, Acknowledged = 4, Unknown = 5, Rejected = 6, NotReady = 7 }

[Flags]
public enum BoundPublicationFacts : ulong
{
    CreateConsumed = 1ul << 0, CreateForwarded = 1ul << 1, CreateNotForwarded = 1ul << 2,
    CreateResultKnown = 1ul << 3, CreateAccepted = 1ul << 4, TemporaryIdentityKnown = 1ul << 5,
    DataFenced = 1ul << 6, DataDrained = 1ul << 7, FlushResultKnown = 1ul << 8, FlushSucceeded = 1ul << 9,
    RenameArmed = 1ul << 10, RenameConsumed = 1ul << 11, RenameForwarded = 1ul << 12,
    RenameNotForwarded = 1ul << 13, RenameResultKnown = 1ul << 14, RenameAccepted = 1ul << 15,
    TargetObservationKnown = 1ul << 16, TargetAbsent = 1ul << 17, CleanupArmed = 1ul << 18,
    CleanupForwarded = 1ul << 19, CleanupNotForwarded = 1ul << 20, CleanupResultKnown = 1ul << 21,
    CleanupAccepted = 1ul << 22, LastCleanup = 1ul << 23, CoverageLost = 1ul << 24, CallbackOwned = 1ul << 25
}

[StructLayout(LayoutKind.Sequential, Pack = 4)]
public unsafe struct BoundPublicationRequestV26
{
    public SafeUploadControl Control;
    public uint ExtensionVersion;
    public BoundPublicationPhase Phase;
    public Guid TransferId, DriverInstanceId, PermitNonce, CreateNonce, OperationId;
    public long DestinationGeneration;
    public Guid MountManagerVolumeId;
    public SafeUploadStageIdentityV19 VolumeRootIdentity, ParentIdentity, StageIdentity, TemporaryIdentity, ExpectedPublicIdentity;
    public long MeasuredLength, ExpectedLatestPublished, ExpectedCommittedDelete, ExpectedMaxAllocated;
    public ushort Flags, ParentCaseSensitive, DestinationLeafBytes, TemporaryLeafBytes;
    public fixed byte InspectedDigest[32];
    public fixed char DestinationLeaf[256], TemporaryLeaf[64];

    public string GetDestinationLeaf()
    {
        if ((DestinationLeafBytes & 1) != 0 || DestinationLeafBytes == 0 || DestinationLeafBytes >= 512)
            throw new InvalidOperationException("Invalid destination leaf length.");
        fixed (char* p = DestinationLeaf) return new(p, 0, DestinationLeafBytes / 2);
    }
    public string GetTemporaryLeaf()
    {
        if ((TemporaryLeafBytes & 1) != 0 || TemporaryLeafBytes == 0 || TemporaryLeafBytes >= 128)
            throw new InvalidOperationException("Invalid temporary leaf length.");
        fixed (char* p = TemporaryLeaf) return new(p, 0, TemporaryLeafBytes / 2);
    }
    public byte[] GetDigest() { fixed (byte* p = InspectedDigest) return new ReadOnlySpan<byte>(p, 32).ToArray(); }
}

[StructLayout(LayoutKind.Sequential, Pack = 4)]
public struct BoundPublicationReplyV26
{
    public uint ExtensionVersion, StructSize;
    public BoundPublicationPhase Phase;
    public uint Reserved;
    public Guid TransferId, DriverInstanceId, PermitNonce, CreateNonce, OperationId;
    public long DestinationGeneration;
    public ulong ConnectionEpoch, AuthorityRevision;
    public BoundPublicationResult Result;
    public uint ReservedEnd;
}

[StructLayout(LayoutKind.Sequential, Pack = 4)]
public unsafe struct BoundPublicationFactsRowV26
{
    public BoundPublicationRequestV26 Create, Rename;
    public uint OriginalProcessId, OriginalSessionId;
    public long OriginalProcessCreationTime;
    public ulong OriginalConnectionEpoch;
    public SafeUploadStageIdentityV19 TemporaryIdentity, ObservedPublicIdentity;
    public long ObservedEof;
    public ulong CreateInformation;
    public BoundPublicationFacts Flags;
    public int CreateStatus, IdentityStatus, FlushStatus, RenameStatus, TargetStatus, CleanupStatus;
    public uint TeardownReason, InFlightWrites, InFlightMutators, OsBootSequence;
    public Guid CleanupOperationId, CleanupNonce;
    public fixed byte Reserved[24];
}

public sealed record BoundPublicationReplayRow(BoundPublicationFactsRowV26 Facts)
{
    // This is local lifetime evidence only. The caller must separately persist
    // and reconcile the exact journal outcome before requesting an ACK.
    public bool HasTerminalLocalProof
    {
        get
        {
            var f = Facts; var bits = f.Flags;
            if ((bits & (BoundPublicationFacts.CallbackOwned | BoundPublicationFacts.CoverageLost)) != 0 ||
                f.InFlightWrites != 0 || f.InFlightMutators != 0) return false;
            if (bits.HasFlag(BoundPublicationFacts.CreateNotForwarded))
                return !bits.HasFlag(BoundPublicationFacts.TemporaryIdentityKnown);
            if (bits.HasFlag(BoundPublicationFacts.CreateResultKnown) && !bits.HasFlag(BoundPublicationFacts.CreateAccepted))
                return f.CreateStatus < 0 && (f.CreateInformation == 0 ||
                    f.CreateStatus == unchecked((int)0xc0000035) && f.CreateInformation == 4 ||
                    (f.CreateStatus is unchecked((int)0xc0000034) or unchecked((int)0xc000003a)) && f.CreateInformation == 5) &&
                    !bits.HasFlag(BoundPublicationFacts.TemporaryIdentityKnown);
            return bits.HasFlag(BoundPublicationFacts.LastCleanup) &&
                (!bits.HasFlag(BoundPublicationFacts.RenameForwarded) || bits.HasFlag(BoundPublicationFacts.RenameResultKnown) && f.RenameStatus <= 0) &&
                (!bits.HasFlag(BoundPublicationFacts.CleanupForwarded) || bits.HasFlag(BoundPublicationFacts.CleanupResultKnown) && f.CleanupStatus <= 0);
        }
    }
}

public sealed record BoundPublicationReplay(Guid DriverInstanceId, ulong ConnectionEpoch, ulong Revision,
    uint OsBootSequence, IReadOnlyList<BoundPublicationReplayRow> Records);
internal sealed record BoundPublicationReplayPage(Guid DriverInstanceId, ulong ConnectionEpoch, ulong Revision,
    uint OsBootSequence, uint StartIndex, bool Complete, BoundPublicationReplayRow[] Rows);

public static unsafe class BoundPublicationV26
{
    public const uint Control = 33, Version = 26;
    public const int RequestBytes = 960, ReplyBytes = 128, QueryBytes = 64, RowBytes = 2112,
        HeaderBytes = 64, PageRows = 8, PageBytes = 16960, MaximumRecords = 1024;
    private static readonly Encoding StrictUtf16 = new UnicodeEncoding(false, false, true);
    private static readonly byte[] EmptyDigest = SHA256.HashData([]);

    public static void Verify()
    {
        if (sizeof(BoundPublicationRequestV26) != RequestBytes || sizeof(BoundPublicationReplyV26) != ReplyBytes ||
            sizeof(BoundPublicationFactsRowV26) != RowBytes ||
            Marshal.OffsetOf<BoundPublicationRequestV26>(nameof(BoundPublicationRequestV26.DestinationLeaf)).ToInt32() != 320 ||
            Marshal.OffsetOf<BoundPublicationFactsRowV26>(nameof(BoundPublicationFactsRowV26.Flags)).ToInt32() != 2008 ||
            Marshal.OffsetOf<BoundPublicationFactsRowV26>(nameof(BoundPublicationFactsRowV26.Reserved)).ToInt32() != 2088)
            throw new InvalidOperationException("Bound publication ABI mismatch.");
    }

    public static BoundPublicationRequestV26 WithPayload(BoundPublicationRequestV26 value,
        string destinationLeaf, string temporaryLeaf, ReadOnlySpan<byte> digest)
    {
        RequireLeaf(destinationLeaf, 255); RequireLeaf(temporaryLeaf, 63);
        if (digest.Length != 32) throw new ArgumentException("Publication requires a SHA-256 digest.", nameof(digest));
        value.Control = new() { Version = Contract.Version, StructSize = RequestBytes, Command = Control };
        value.ExtensionVersion = Version;
        value.DestinationLeafBytes = checked((ushort)(destinationLeaf.Length * 2));
        value.TemporaryLeafBytes = checked((ushort)(temporaryLeaf.Length * 2));
        new Span<char>(value.DestinationLeaf, 256).Clear(); destinationLeaf.AsSpan().CopyTo(new(value.DestinationLeaf, 256));
        new Span<char>(value.TemporaryLeaf, 64).Clear(); temporaryLeaf.AsSpan().CopyTo(new(value.TemporaryLeaf, 64));
        digest.CopyTo(new(value.InspectedDigest, 32));
        if (!Valid(value)) throw new ArgumentException("Invalid bound publication request.", nameof(value));
        return value;
    }

    internal static bool Zero(ReadOnlySpan<byte> bytes)
    { foreach (byte b in bytes) if (b != 0) return false; return true; }
    internal static bool Same(SafeUploadStageIdentityV19 a, SafeUploadStageIdentityV19 b) =>
        a.VolumeSerialNumber == b.VolumeSerialNumber && a.FileIdLow == b.FileIdLow && a.FileIdHigh == b.FileIdHigh;
    internal static bool Absent(SafeUploadStageIdentityV19 value) => Same(value, default);
    private static bool OnVolume(SafeUploadStageIdentityV19 value, ulong serial) =>
        value.HasNonzeroFileId && value.VolumeSerialNumber == serial;
    private static void RequireLeaf(string value, int limit)
    {
        if (value.Length is 0 || value.Length > limit || value is "." or ".." ||
            value.IndexOfAny(['\\', '/', ':', '*', '?', '\0']) >= 0)
            throw new ArgumentException("A bounded single canonical leaf is required.");
        _ = StrictUtf16.GetByteCount(value);
    }
    private static bool ValidLeaf(char* buffer, ushort bytes, int capacity)
    {
        if ((bytes & 1) != 0 || bytes == 0 || bytes >= capacity * 2 ||
            !Zero(new ReadOnlySpan<byte>((byte*)buffer + bytes, capacity * 2 - bytes))) return false;
        try { RequireLeaf(new string(buffer, 0, bytes / 2), capacity - 1); return true; }
        catch (ArgumentException) { return false; }
    }

    public static bool Valid(BoundPublicationRequestV26 v)
    {
        ulong serial = v.VolumeRootIdentity.VolumeSerialNumber;
        if (v.Control.Version != Contract.Version || v.Control.StructSize != RequestBytes ||
            v.Control.Command != Control || v.Control.Reserved != 0 || v.ExtensionVersion != Version ||
            v.Phase is not (BoundPublicationPhase.Create or BoundPublicationPhase.Rename or BoundPublicationPhase.Revoke) ||
            v.TransferId == Guid.Empty || v.DriverInstanceId == Guid.Empty || v.CreateNonce == Guid.Empty ||
            v.PermitNonce == Guid.Empty || v.OperationId == Guid.Empty || v.MountManagerVolumeId == Guid.Empty ||
            v.TransferId == v.CreateNonce || v.OperationId == v.CreateNonce || v.OperationId == v.TransferId ||
            v.OperationId == v.PermitNonce || v.DestinationGeneration <= 0 || v.MeasuredLength < 0 ||
            v.ExpectedLatestPublished < 0 || v.ExpectedCommittedDelete < 0 ||
            v.ExpectedMaxAllocated < v.DestinationGeneration || v.ExpectedMaxAllocated < v.ExpectedLatestPublished ||
            v.ExpectedMaxAllocated < v.ExpectedCommittedDelete || v.Flags > 1 || v.ParentCaseSensitive > 1 ||
            !v.VolumeRootIdentity.HasNonzeroFileId || !OnVolume(v.ParentIdentity, serial) || !OnVolume(v.StageIdentity, serial) ||
            (v.Flags == 0 ? !Absent(v.ExpectedPublicIdentity) : !OnVolume(v.ExpectedPublicIdentity, serial)) ||
            !ValidLeaf(v.DestinationLeaf, v.DestinationLeafBytes, 256) || !ValidLeaf(v.TemporaryLeaf, v.TemporaryLeafBytes, 64) ||
            string.Equals(v.GetDestinationLeaf(), v.GetTemporaryLeaf(), StringComparison.OrdinalIgnoreCase)) return false;
        if (v.Phase == BoundPublicationPhase.Create && (!Absent(v.TemporaryIdentity) || v.PermitNonce != v.CreateNonce)) return false;
        if (v.Phase == BoundPublicationPhase.Rename && (!OnVolume(v.TemporaryIdentity, serial) || v.PermitNonce == v.CreateNonce)) return false;
        if (v.Phase == BoundPublicationPhase.Revoke && (v.PermitNonce != v.CreateNonce ||
            (!Absent(v.TemporaryIdentity) && !OnVolume(v.TemporaryIdentity, serial)))) return false;
        var digest = new ReadOnlySpan<byte>(v.InspectedDigest, 32);
        return !Zero(digest) && (v.MeasuredLength != 0 || digest.SequenceEqual(EmptyDigest));
    }

    internal static byte[] Encode(BoundPublicationRequestV26 request)
    {
        if (!Valid(request)) throw new ArgumentException("Invalid bound publication request.", nameof(request));
        byte[] bytes = new byte[RequestBytes]; MemoryMarshal.Write(bytes, in request); return bytes;
    }

    internal static BoundPublicationReplyV26 DecodeReply(ReadOnlySpan<byte> bytes, BoundPublicationRequestV26 request)
    {
        if (bytes.Length != ReplyBytes || !Valid(request)) throw new IOException("Invalid bound publication reply size/request.");
        var r = MemoryMarshal.Read<BoundPublicationReplyV26>(bytes);
        if (r.ExtensionVersion != Version || r.StructSize != ReplyBytes || r.Phase != request.Phase || r.Reserved != 0 ||
            r.ReservedEnd != 0 || r.TransferId != request.TransferId || r.DriverInstanceId != request.DriverInstanceId ||
            r.PermitNonce != request.PermitNonce || r.CreateNonce != request.CreateNonce || r.OperationId != request.OperationId ||
            r.DestinationGeneration != request.DestinationGeneration || r.ConnectionEpoch == 0 || r.AuthorityRevision == 0 ||
            r.Result is not (BoundPublicationResult.Prepared or BoundPublicationResult.Consumed or BoundPublicationResult.Revoked or
                BoundPublicationResult.Unknown or BoundPublicationResult.Rejected or BoundPublicationResult.NotReady) ||
            (request.Phase == BoundPublicationPhase.Revoke ? r.Result == BoundPublicationResult.Prepared : r.Result == BoundPublicationResult.Revoked))
            throw new IOException("Bound publication reply changed authority or result kind.");
        return r;
    }

    internal static byte[] FactsRequest(uint startIndex, Guid driver = default, ulong epoch = 0, ulong revision = 0)
    {
        if (startIndex > MaximumRecords || (revision == 0 ? startIndex != 0 || driver != Guid.Empty || epoch != 0 :
            driver == Guid.Empty || epoch == 0)) throw new ArgumentException("Facts require an exact replay tuple.");
        byte[] b = ControlRequest(BoundPublicationPhase.Facts);
        driver.TryWriteBytes(b.AsSpan(24)); BinaryPrimitives.WriteUInt64LittleEndian(b.AsSpan(40), epoch);
        BinaryPrimitives.WriteUInt64LittleEndian(b.AsSpan(48), revision); BinaryPrimitives.WriteUInt32LittleEndian(b.AsSpan(56), startIndex);
        return b;
    }

    private static byte[] ControlRequest(BoundPublicationPhase phase)
    {
        byte[] b = new byte[QueryBytes];
        BinaryPrimitives.WriteUInt32LittleEndian(b, Contract.Version);
        BinaryPrimitives.WriteUInt32LittleEndian(b.AsSpan(4), QueryBytes);
        BinaryPrimitives.WriteUInt32LittleEndian(b.AsSpan(8), Control);
        BinaryPrimitives.WriteUInt32LittleEndian(b.AsSpan(16), Version);
        BinaryPrimitives.WriteUInt32LittleEndian(b.AsSpan(20), (uint)phase); return b;
    }

    internal static byte[] AckRequest(BoundPublicationReplay replay, BoundPublicationReplayRow row)
    {
        if (replay.DriverInstanceId == Guid.Empty || replay.ConnectionEpoch == 0 || replay.Revision == 0 ||
            row.Facts.Create.DriverInstanceId != replay.DriverInstanceId || !row.HasTerminalLocalProof ||
            !replay.Records.Any(candidate => ReferenceEquals(candidate, row))) throw new ArgumentException("ACK requires retained exact terminal facts.");
        byte[] b = ControlRequest(BoundPublicationPhase.CleanupAck);
        replay.DriverInstanceId.TryWriteBytes(b.AsSpan(24)); row.Facts.Create.CreateNonce.TryWriteBytes(b.AsSpan(40));
        BinaryPrimitives.WriteUInt64LittleEndian(b.AsSpan(56), replay.Revision); return b;
    }

    internal static BoundPublicationReplayPage DecodePage(ReadOnlySpan<byte> b, uint startIndex,
        Guid driver = default, ulong epoch = 0, ulong revision = 0)
    {
        if (b.Length != PageBytes || U32(b, 0) != Version || U32(b, 4) != PageBytes ||
            U32(b, 44) != startIndex || U32(b, 52) > 1 || !Zero(b.Slice(56, 8))) throw new IOException("Invalid publication Facts page.");
        Guid actualDriver = new(b.Slice(8, 16)); ulong actualEpoch = U64(b, 24), actualRevision = U64(b, 32);
        uint count = U32(b, 48), boot = U32(b, 40); bool complete = U32(b, 52) == 1;
        if (actualDriver == Guid.Empty || actualEpoch == 0 || actualRevision == 0 || startIndex > MaximumRecords ||
            count > PageRows || count > MaximumRecords - startIndex || (!complete && count != PageRows) ||
            (revision != 0 && (driver != actualDriver || epoch != actualEpoch || revision != actualRevision)))
            throw new IOException("Publication Facts are stale, incomplete or exceed bounds.");
        var rows = new BoundPublicationReplayRow[count];
        for (int i = 0; i < rows.Length; i++) rows[i] = DecodeRow(b.Slice(HeaderBytes + i * RowBytes, RowBytes), actualDriver, actualEpoch, boot);
        if (!Zero(b[(HeaderBytes + rows.Length * RowBytes)..])) throw new IOException("Unused publication rows are not zero.");
        return new(actualDriver, actualEpoch, actualRevision, boot, startIndex, complete, rows);
    }

    // Durable service receipts store exactly the validated native row, not a
    // lossy Boolean projection. This parser confers no execution authority.
    public static BoundPublicationReplayRow DecodeFactRow(ReadOnlySpan<byte> bytes, Guid driver, ulong epoch, uint boot)
    {
        if (bytes.Length != RowBytes || driver == Guid.Empty || epoch == 0)
            throw new IOException("Invalid durable publication facts scope/size.");
        return DecodeRow(bytes, driver, epoch, boot);
    }

    public static byte[] EncodeFactRow(BoundPublicationReplay replay, BoundPublicationReplayRow row)
    {
        if (replay.Revision == 0 || !replay.Records.Any(candidate => ReferenceEquals(candidate, row)))
            throw new ArgumentException("Publication facts must belong to one retained complete replay.");
        byte[] bytes = new byte[RowBytes]; var facts = row.Facts;
        MemoryMarshal.Write(bytes, in facts);
        _ = DecodeFactRow(bytes, replay.DriverInstanceId, replay.ConnectionEpoch, replay.OsBootSequence);
        return bytes;
    }

    private static BoundPublicationReplayRow DecodeRow(ReadOnlySpan<byte> bytes, Guid driver, ulong epoch, uint boot)
    {
        var r = MemoryMarshal.Read<BoundPublicationFactsRowV26>(bytes); var f = r.Flags;
        bool Has(BoundPublicationFacts bit) => (f & bit) == bit;
        bool NativeSuccess(int status) => status == 0;
        bool Outcome(BoundPublicationFacts forward, BoundPublicationFacts noForward, BoundPublicationFacts known,
            BoundPublicationFacts accepted, int status) =>
            !(Has(forward) && Has(noForward)) && (!Has(known) || (Has(forward) || Has(noForward)) && status != 259) &&
            (!Has(accepted) || Has(forward) && Has(known) && NativeSuccess(status)) && (Has(known) || status == 0);
        if (!Valid(r.Create) || r.Create.Phase != BoundPublicationPhase.Create || r.Create.DriverInstanceId != driver ||
            r.OriginalProcessId is 0 or > int.MaxValue || r.OriginalSessionId > int.MaxValue ||
            r.OriginalProcessCreationTime <= 0 || r.OriginalConnectionEpoch == 0 || r.OriginalConnectionEpoch > epoch ||
            r.OsBootSequence != boot || ((ulong)f >> 26) != 0 || !Zero(bytes[2088..]) ||
            !Outcome(BoundPublicationFacts.CreateForwarded, BoundPublicationFacts.CreateNotForwarded,
                BoundPublicationFacts.CreateResultKnown, BoundPublicationFacts.CreateAccepted, r.CreateStatus) ||
            ((Has(BoundPublicationFacts.CreateForwarded) || Has(BoundPublicationFacts.CreateNotForwarded)) && !Has(BoundPublicationFacts.CreateConsumed)) ||
            (!Has(BoundPublicationFacts.CreateResultKnown) && r.CreateInformation != 0) ||
            (Has(BoundPublicationFacts.CreateAccepted) && r.CreateInformation != 2) ||
            (Has(BoundPublicationFacts.TemporaryIdentityKnown) ? !Has(BoundPublicationFacts.CreateAccepted) ||
                !NativeSuccess(r.IdentityStatus) || !OnVolume(r.TemporaryIdentity, r.Create.VolumeRootIdentity.VolumeSerialNumber) :
                !Absent(r.TemporaryIdentity)) ||
            r.ObservedEof < 0 || (Has(BoundPublicationFacts.DataDrained) && (!Has(BoundPublicationFacts.DataFenced) ||
                r.InFlightWrites != 0 || r.InFlightMutators != 0)) ||
            (Has(BoundPublicationFacts.FlushResultKnown) ? !Has(BoundPublicationFacts.DataDrained) ||
                !Has(BoundPublicationFacts.TemporaryIdentityKnown) || r.FlushStatus == 259 : r.FlushStatus != 0) ||
            (Has(BoundPublicationFacts.FlushSucceeded) && (!Has(BoundPublicationFacts.FlushResultKnown) ||
                !NativeSuccess(r.FlushStatus) || r.ObservedEof != r.Create.MeasuredLength)) ||
            (Has(BoundPublicationFacts.LastCleanup) && (!Has(BoundPublicationFacts.TemporaryIdentityKnown) || Has(BoundPublicationFacts.CoverageLost))))
            throw new IOException("Publication CREATE/fence facts are inconsistent.");

        if (Has(BoundPublicationFacts.RenameArmed))
        {
            if (!Valid(r.Rename) || r.Rename.Phase != BoundPublicationPhase.Rename ||
                !SameAuthority(r.Create, r.Rename) || !Same(r.TemporaryIdentity, r.Rename.TemporaryIdentity) ||
                !Has(BoundPublicationFacts.TemporaryIdentityKnown) || r.Rename.OperationId == r.Create.OperationId)
                throw new IOException("Publication rename changed its linked CREATE authority.");
        }
        else if (!Zero(bytes.Slice(RequestBytes, RequestBytes)) ||
            (f & (BoundPublicationFacts.RenameConsumed | BoundPublicationFacts.RenameForwarded | BoundPublicationFacts.RenameNotForwarded |
                BoundPublicationFacts.RenameResultKnown | BoundPublicationFacts.RenameAccepted | BoundPublicationFacts.TargetObservationKnown)) != 0)
            throw new IOException("Unarmed publication has rename facts.");
        if (!Outcome(BoundPublicationFacts.RenameForwarded, BoundPublicationFacts.RenameNotForwarded,
                BoundPublicationFacts.RenameResultKnown, BoundPublicationFacts.RenameAccepted, r.RenameStatus) ||
            ((Has(BoundPublicationFacts.RenameForwarded) || Has(BoundPublicationFacts.RenameNotForwarded)) && !Has(BoundPublicationFacts.RenameConsumed)) ||
            // Complete anchored enumeration ends with native STATUS_NO_MORE_FILES.
            (Has(BoundPublicationFacts.TargetObservationKnown) ? (r.TargetStatus != 0 && r.TargetStatus != unchecked((int)0x80000006)) ||
                (Has(BoundPublicationFacts.TargetAbsent) ? !Absent(r.ObservedPublicIdentity) :
                    !OnVolume(r.ObservedPublicIdentity, r.Create.VolumeRootIdentity.VolumeSerialNumber)) :
                !Absent(r.ObservedPublicIdentity) || Has(BoundPublicationFacts.TargetAbsent)) ||
            (Has(BoundPublicationFacts.RenameForwarded) && (!Has(BoundPublicationFacts.DataFenced | BoundPublicationFacts.DataDrained |
                BoundPublicationFacts.FlushSucceeded | BoundPublicationFacts.TargetObservationKnown) ||
                !Same(r.ObservedPublicIdentity, r.Rename.ExpectedPublicIdentity))))
            throw new IOException("Publication rename/target facts are inconsistent.");

        if (Has(BoundPublicationFacts.CleanupArmed))
        {
            if (r.CleanupOperationId == Guid.Empty || r.CleanupNonce == Guid.Empty || r.CleanupOperationId == r.CleanupNonce ||
                r.CleanupOperationId == r.Create.OperationId || r.CleanupNonce == r.Create.CreateNonce ||
                !Has(BoundPublicationFacts.TemporaryIdentityKnown | BoundPublicationFacts.DataFenced | BoundPublicationFacts.DataDrained) ||
                Has(BoundPublicationFacts.RenameAccepted) || (Has(BoundPublicationFacts.RenameForwarded) && (!Has(BoundPublicationFacts.RenameResultKnown) || r.RenameStatus >= 0)))
                throw new IOException("Cleanup has no exact proven uncommitted temporary.");
        }
        else if (r.CleanupOperationId != Guid.Empty || r.CleanupNonce != Guid.Empty ||
            (f & (BoundPublicationFacts.CleanupForwarded | BoundPublicationFacts.CleanupNotForwarded | BoundPublicationFacts.CleanupResultKnown |
                BoundPublicationFacts.CleanupAccepted)) != 0) throw new IOException("Unarmed temporary cleanup has execution facts.");
        if (!Outcome(BoundPublicationFacts.CleanupForwarded, BoundPublicationFacts.CleanupNotForwarded,
            BoundPublicationFacts.CleanupResultKnown, BoundPublicationFacts.CleanupAccepted, r.CleanupStatus))
            throw new IOException("Temporary cleanup completion is inconsistent.");
        return new(r);
    }

    private static bool SameAuthority(BoundPublicationRequestV26 a, BoundPublicationRequestV26 b) =>
        a.TransferId == b.TransferId && a.DriverInstanceId == b.DriverInstanceId && a.CreateNonce == b.CreateNonce &&
        a.DestinationGeneration == b.DestinationGeneration && a.MountManagerVolumeId == b.MountManagerVolumeId &&
        Same(a.VolumeRootIdentity, b.VolumeRootIdentity) && Same(a.ParentIdentity, b.ParentIdentity) && Same(a.StageIdentity, b.StageIdentity) &&
        a.MeasuredLength == b.MeasuredLength && a.ParentCaseSensitive == b.ParentCaseSensitive &&
        a.GetDestinationLeaf() == b.GetDestinationLeaf() && a.GetTemporaryLeaf() == b.GetTemporaryLeaf() && a.GetDigest().AsSpan().SequenceEqual(b.GetDigest());
    private static uint U32(ReadOnlySpan<byte> b, int o) => BinaryPrimitives.ReadUInt32LittleEndian(b[o..]);
    private static ulong U64(ReadOnlySpan<byte> b, int o) => BinaryPrimitives.ReadUInt64LittleEndian(b[o..]);
}
#endif
