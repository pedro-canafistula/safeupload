#if SAFEUPLOAD_ADMISSION_EVIDENCE
using System.Buffers.Binary;
using System.ComponentModel;
using System.Security.Principal;
using Microsoft.Win32.SafeHandles;

namespace SafeUpload.Agent.Minifilter;

[Flags]
public enum PublicOperationFacts : uint
{
    Captured = 1, Forwarded = 2, ResultKnown = 4, NotForwarded = 8, CoverageLost = 16, CleanupOutstanding = 32
}

public sealed record PublicOpenReplayRow(NativeRecordReplayRow Open, ulong PublishedGeneration,
    SafeUploadStageIdentityV19 PublishedIdentity, ulong OperationSequence,
    Guid MutationTransferId, Guid MutationNonce, Guid MutationOperationId, uint GrantedAccess,
    uint InformationClass, uint DispositionFlags, uint RequestorMode, PublicOperationFacts OperationFacts,
    int OperationStatus, ulong MutationGeneration, long ActorProcessCreationTime,
    uint ActorProcessId, uint ActorSessionId, string? ActorSid);

public sealed record PublicOpenReplay(Guid DriverInstanceId, ulong ConnectionEpoch,
    ulong Revision, uint OsBootSequence, IReadOnlyList<PublicOpenReplayRow> Records);

internal sealed record PublicOpenReplayPage(Guid DriverInstanceId, ulong ConnectionEpoch,
    ulong Revision, uint OsBootSequence, uint StartIndex, bool Complete, PublicOpenReplayRow[] Rows);

internal static class PublicOpenReplayWireV25
{
    private static uint U32(ReadOnlySpan<byte> value, int offset) => BinaryPrimitives.ReadUInt32LittleEndian(value[offset..]);
    private static ulong U64(ReadOnlySpan<byte> value, int offset) => BinaryPrimitives.ReadUInt64LittleEndian(value[offset..]);
    private static bool Zero(ReadOnlySpan<byte> value)
    { foreach (byte item in value) if (item != 0) return false; return true; }
    private static SafeUploadStageIdentityV19 Identity(ReadOnlySpan<byte> value, int offset) =>
        new() { VolumeSerialNumber = U64(value, offset), FileIdHigh = U64(value, offset + 16), FileIdLow = U64(value, offset + 8) };

    internal static byte[] CreateRequest(uint startIndex, Guid driver = default, ulong epoch = 0, ulong revision = 0)
    {
        byte[] request = NativeRecordReplayWire.CreateRequest(startIndex, driver, epoch, revision);
        BinaryPrimitives.WriteUInt32LittleEndian(request.AsSpan(8), PublicDispositionV25.ReplayControl);
        BinaryPrimitives.WriteUInt32LittleEndian(request.AsSpan(16), PublicDispositionV25.Version);
        return request;
    }

    internal static PublicOpenReplayPage DecodePage(ReadOnlySpan<byte> bytes, uint startIndex,
        Guid expectedDriver = default, ulong expectedEpoch = 0, ulong expectedRevision = 0)
    {
        if (bytes.Length != PublicDispositionV25.ReplayPageBytes || U32(bytes, 0) != PublicDispositionV25.Version ||
            U32(bytes, 4) != PublicDispositionV25.ReplayPageBytes || U32(bytes, 44) != startIndex ||
            U32(bytes, 52) > 1 || U64(bytes, 56) != 0)
            throw new IOException("Invalid ordinary-open replay header/length.");
        Guid driver = new(bytes.Slice(8, 16));
        ulong epoch = U64(bytes, 24), revision = U64(bytes, 32);
        uint boot = U32(bytes, 40), count = U32(bytes, 48);
        bool complete = U32(bytes, 52) == 1;
        if (driver == Guid.Empty || epoch == 0 || revision == 0 || startIndex > NativeRecordReplayWire.MaximumRecords ||
            count > NativeRecordReplayWire.PageRows || startIndex + count > NativeRecordReplayWire.MaximumRecords ||
            (!complete && count != NativeRecordReplayWire.PageRows) ||
            (expectedRevision != 0 && (driver != expectedDriver || epoch != expectedEpoch || revision != expectedRevision)))
            throw new IOException("Ordinary-open replay is stale, partial or exceeds its bound.");
        var rows = new PublicOpenReplayRow[count];
        for (int i = 0; i < rows.Length; i++)
            rows[i] = DecodeRow(bytes.Slice(64 + i * PublicDispositionV25.ReplayRowBytes,
                PublicDispositionV25.ReplayRowBytes), driver, epoch, boot);
        if (!Zero(bytes[(64 + rows.Length * PublicDispositionV25.ReplayRowBytes)..]))
            throw new IOException("Unused ordinary-open rows are not zero.");
        return new(driver, epoch, revision, boot, startIndex, complete, rows);
    }

    private static PublicOpenReplayRow DecodeRow(ReadOnlySpan<byte> b, Guid driver, ulong epoch, uint boot)
    {
        var opened = NativeRecordReplayWire.DecodeRow(b[..816], driver, epoch, boot, ordinary: true);
        ulong published = U64(b, 816), sequence = U64(b, 848), generation = U64(b, 928);
        var publishedIdentity = Identity(b, 824);
        Guid transfer = new(b.Slice(856, 16)), nonce = new(b.Slice(872, 16)), operation = new(b.Slice(888, 16));
        uint granted = U32(b, 904), information = U32(b, 908), flags = U32(b, 912), mode = U32(b, 916);
        var facts = (PublicOperationFacts)U32(b, 920);
        int status = BinaryPrimitives.ReadInt32LittleEndian(b[924..]);
        long actorCreation = BinaryPrimitives.ReadInt64LittleEndian(b[936..]);
        uint actor = U32(b, 944), session = U32(b, 948), sidBytes = U32(b, 952);
        uint requested = opened.OriginalDesiredAccess;
        uint mapped = requested & ~0xa0000000u;
        if ((requested & 0x80000000) != 0) mapped |= 0x120089;
        if ((requested & 0x20000000) != 0) mapped |= 0x1200a0;
        if (published > long.MaxValue || generation > long.MaxValue ||
            (published == 0 ? publishedIdentity.HasNonzeroFileId || publishedIdentity.VolumeSerialNumber != 0 :
                !publishedIdentity.HasNonzeroFileId || publishedIdentity.VolumeSerialNumber != opened.PublicIdentity.VolumeSerialNumber) ||
            granted != (opened.Facts.HasFlag(NativeRecordFacts.IdentityChecked) ? mapped : 0) ||
            (facts & ~(PublicOperationFacts)63) != 0 ||
            (facts.HasFlag(PublicOperationFacts.CleanupOutstanding) && !opened.Facts.HasFlag(NativeRecordFacts.IdentityChecked)) ||
            (sequence == 0 ? !Zero(b.Slice(856, 48)) || !Zero(b.Slice(908, 12)) || !Zero(b[924..]) ||
                (facts & ~PublicOperationFacts.CleanupOutstanding) != 0 :
                (transfer == Guid.Empty || nonce == Guid.Empty || operation == Guid.Empty ||
                 transfer == opened.TransferId || nonce == opened.RequestNonce || operation == opened.OperationId ||
                 !facts.HasFlag(PublicOperationFacts.Captured) || !opened.Facts.HasFlag(NativeRecordFacts.IdentityChecked) ||
                 information is not (13 or 64) || (information == 13 ? flags > 1 : (flags & ~0x1fu) != 0) || mode > 1 ||
                 actor == 0 || actor > int.MaxValue || actorCreation <= 0 || sidBytes < 8 || sidBytes > 68 ||
                 !Zero(b.Slice(956 + (int)sidBytes, 68 - (int)sidBytes)) ||
                 (facts.HasFlag(PublicOperationFacts.Forwarded) && facts.HasFlag(PublicOperationFacts.NotForwarded)) ||
                 (facts.HasFlag(PublicOperationFacts.ResultKnown) && !facts.HasFlag(PublicOperationFacts.Forwarded)) ||
                 (facts.HasFlag(PublicOperationFacts.ResultKnown) && status == 259))))
            throw new IOException("Ordinary-open replay contains an unbound grant or operation.");
        string? sid = null;
        if (sequence != 0)
        {
            var bytes = b.Slice(956, (int)sidBytes);
            if (bytes[0] != 1 || bytes[1] > 15 || sidBytes != 8 + 4 * bytes[1])
                throw new IOException("Invalid ordinary-operation actor SID.");
            sid = new SecurityIdentifier(bytes.ToArray(), 0).Value;
        }
        return new(opened, published, publishedIdentity, sequence, transfer, nonce, operation, granted,
            information, flags, mode, facts, status, generation, actorCreation, actor, session, sid);
    }
}

public sealed partial class FilterPort
{
    public PublicOpenReplay ReadPublicOpenReplayV25()
    {
        using SendLease lease = EnterSend();
        var records = new List<PublicOpenReplayRow>();
        var transfers = new HashSet<Guid>(); var nonces = new HashSet<Guid>(); var operations = new HashSet<Guid>();
        var page = SendPublicOpenReplayPage(lease.Handle, 0);
        Guid driver = page.DriverInstanceId;
        ulong epoch = page.ConnectionEpoch, revision = page.Revision;
        uint boot = page.OsBootSequence;
        while (true)
        {
            if (page.OsBootSequence != boot) throw new IOException("Ordinary-open boot evidence changed.");
            foreach (var row in page.Rows)
            {
                if (!transfers.Add(row.Open.TransferId) || !nonces.Add(row.Open.RequestNonce) || !operations.Add(row.Open.OperationId))
                    throw new IOException("Ordinary-open replay repeats its immutable binding.");
                records.Add(row);
            }
            if (page.Complete) break;
            page = SendPublicOpenReplayPage(lease.Handle, (uint)records.Count, driver, epoch, revision);
        }
        var final = SendPublicOpenReplayPage(lease.Handle, (uint)records.Count, driver, epoch, revision);
        if (!final.Complete || final.Rows.Length != 0 || final.OsBootSequence != boot)
            throw new IOException("Ordinary-open replay changed before its final check.");
        return new(driver, epoch, revision, boot, records.AsReadOnly());
    }

    private PublicOpenReplayPage SendPublicOpenReplayPage(SafeFileHandle handle, uint offset,
        Guid driver = default, ulong epoch = 0, ulong revision = 0)
    {
        byte[] input = PublicOpenReplayWireV25.CreateRequest(offset, driver, epoch, revision);
        byte[] output = new byte[PublicDispositionV25.ReplayPageBytes];
        uint returned; int hr;
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
        if (hr != 0) throw new Win32Exception(hr, $"Ordinary-open replay failed: 0x{hr:X8}");
        if (returned != output.Length) throw new IOException("Incomplete ordinary-open replay receipt.");
        return PublicOpenReplayWireV25.DecodePage(output, offset, driver, epoch, revision);
    }
}
#endif
