#if SAFEUPLOAD_ADMISSION_EVIDENCE
using System.ComponentModel;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

namespace SafeUpload.Agent.Minifilter;

public sealed partial class FilterPort
{
    // These calls provide no application authority and advertise no capability.
    // Older/unintegrated drivers refuse control 33; that cannot become Prepared.
    public BoundPublicationReplyV26 SendBoundPublication(BoundPublicationRequestV26 request)
    {
        using var lease = EnterSend();
        byte[] output = SendBoundPublicationControl(lease.Handle, BoundPublicationV26.Encode(request), BoundPublicationV26.ReplyBytes);
        return BoundPublicationV26.DecodeReply(output, request);
    }

    public BoundPublicationReplay ReadBoundPublicationFacts()
    {
        using var lease = EnterSend();
        var page = SendBoundPublicationPage(lease.Handle, 0);
        Guid driver = page.DriverInstanceId; ulong epoch = page.ConnectionEpoch, revision = page.Revision;
        uint boot = page.OsBootSequence;
        var rows = new List<BoundPublicationReplayRow>();
        var nonces = new HashSet<Guid>(); var operations = new HashSet<Guid>();
        while (true)
        {
            if (page.OsBootSequence != boot) throw new IOException("Publication Facts changed boot lifetime.");
            foreach (var row in page.Rows)
            {
                var r = row.Facts;
                if (!nonces.Add(r.Create.CreateNonce) || !operations.Add(r.Create.OperationId) ||
                    (r.Flags.HasFlag(BoundPublicationFacts.RenameArmed) && (!nonces.Add(r.Rename.PermitNonce) || !operations.Add(r.Rename.OperationId))) ||
                    (r.Flags.HasFlag(BoundPublicationFacts.CleanupArmed) && (!nonces.Add(r.CleanupNonce) || !operations.Add(r.CleanupOperationId))))
                    throw new IOException("Publication Facts contain duplicate attempt/nonces/operations.");
                rows.Add(row);
            }
            if (page.Complete) break;
            page = SendBoundPublicationPage(lease.Handle, (uint)rows.Count, driver, epoch, revision);
        }
        var final = SendBoundPublicationPage(lease.Handle, (uint)rows.Count, driver, epoch, revision);
        if (!final.Complete || final.Rows.Length != 0 || final.OsBootSequence != boot)
            throw new IOException("Publication Facts changed before the final complete check.");
        return new(driver, epoch, revision, boot, rows.AsReadOnly());
    }

    public BoundPublicationReplyV26 AcknowledgeBoundPublication(BoundPublicationReplay replay, BoundPublicationReplayRow row)
    {
        byte[] input = BoundPublicationV26.AckRequest(replay, row);
        using var lease = EnterSend();
        byte[] output = SendBoundPublicationControl(lease.Handle, input, BoundPublicationV26.ReplyBytes);
        var r = MemoryMarshal.Read<BoundPublicationReplyV26>(output); var c = row.Facts.Create;
        if (r.ExtensionVersion != BoundPublicationV26.Version || r.StructSize != BoundPublicationV26.ReplyBytes ||
            r.Phase != BoundPublicationPhase.CleanupAck || r.Reserved != 0 || r.ReservedEnd != 0 ||
            r.TransferId != c.TransferId || r.DriverInstanceId != c.DriverInstanceId || r.PermitNonce != c.PermitNonce ||
            r.CreateNonce != c.CreateNonce || r.OperationId != c.OperationId || r.DestinationGeneration != c.DestinationGeneration ||
            r.ConnectionEpoch != replay.ConnectionEpoch || r.AuthorityRevision == 0 ||
            r.Result is not (BoundPublicationResult.Acknowledged or BoundPublicationResult.Unknown or BoundPublicationResult.Rejected or BoundPublicationResult.NotReady))
            throw new IOException("Publication ACK changed its exact record/connection.");
        return r;
    }

    private BoundPublicationReplayPage SendBoundPublicationPage(SafeFileHandle handle, uint cursor,
        Guid driver = default, ulong epoch = 0, ulong revision = 0) => BoundPublicationV26.DecodePage(
            SendBoundPublicationControl(handle, BoundPublicationV26.FactsRequest(cursor, driver, epoch, revision), BoundPublicationV26.PageBytes),
            cursor, driver, epoch, revision);

    private byte[] SendBoundPublicationControl(SafeFileHandle handle, byte[] input, int outputBytes)
    {
        byte[] output = new byte[outputBytes]; uint returned; int hr;
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
        if (hr != 0) throw new Win32Exception(hr, $"Bound publication control failed: 0x{hr:X8}");
        if (returned != outputBytes) throw new IOException("Incomplete bound publication control receipt.");
        return output;
    }
}
#endif
