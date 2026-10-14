using System.Runtime.InteropServices;
using System.Security.AccessControl;
using SafeUpload.Agent.Core.Domain;
using SafeUpload.Agent.Minifilter;

namespace SafeUpload.Agent.Service.Interception;

public sealed partial class StagedTransferAllocator
{
    internal static bool AllocationOwnerMatches(long expectedCreationTime, long? observedCreationTime) =>
        expectedCreationTime > 0 && observedCreationTime == expectedCreationTime;

    private string RejectionPath(Guid id) => Path.Combine(_root, id.ToString("N") + ".allocation-refused");

    private async Task<TransferJournalEntry?> ReadAllocationManifestAsync(Guid id, CancellationToken token)
    {
        try { return await _journal.ReadAsync(id, token).ConfigureAwait(false); }
        catch (FileNotFoundException) { return null; }
        catch (DirectoryNotFoundException) { return null; }
    }

    // Serialized with allocation, including backing creation and manifest
    // replacement. The exact negative receipt survives restart and prevents a
    // future policy/owner change from reviving this failed CREATE reservation.
    // A null prepare result is a definitive refusal BEFORE backing creation;
    // exceptions remain uncertain. Generic DENY never carries release authority.
    internal async Task<StagedAllocationReply?> ResolveAllocationRequestV20Async(
        SafeUploadRequest request, string destination, DestinationKind kind,
        Func<Task<StagedAllocationReply?>> prepare, CancellationToken token)
    {
        if (!request.TryReadStagePayload<SafeUploadStageAllocateV20>(Operation.StageAllocate, out var source) ||
            source.RequestorCreationTime <= 0 || request.RequestorProcessId == 0 || request.RequestId == 0 ||
            source.Intent.AllocationReservationId == Guid.Empty || source.Intent.DriverInstanceId == Guid.Empty ||
            source.Intent.Disposition > 5 || source.Intent.ReferenceKind > 2 ||
            (source.Intent.ReferenceKind == 0) != (source.Intent.ParentTransferId == Guid.Empty))
            throw StagedRequestRefusal.Create("Invalid allocation resolution tuple.");
        var intent = source.Intent;
        byte[] bytes = new byte[Contract.RequestSize];
        MemoryMarshal.Write(bytes, in request);
        await _v19AllocationGate.WaitAsync(token).ConfigureAwait(false);
        try
        {
            string receiptPath = RejectionPath(intent.AllocationReservationId);
            TransferJournalEntry? existing = await ReadAllocationManifestAsync(intent.AllocationReservationId, token)
                .ConfigureAwait(false);
            if (File.Exists(receiptPath))
            {
                if (existing is not null)
                    throw StagedRequestRefusal.Create("Conflicting committed and refused allocation evidence; retain the reservation.");
                using var receipt = StagedJournalFile.Open(receiptPath, maximumBytes: Contract.RequestSize);
                byte[] saved = new byte[Contract.RequestSize];
                await receipt.ReadExactlyAsync(saved, token).ConfigureAwait(false);
                if (receipt.Length != saved.Length || !saved.AsSpan().SequenceEqual(bytes))
                    throw StagedRequestRefusal.Create("The refused allocation receipt belongs to a different exact request.");
                return null;
            }
            if (existing is not null)
            {
                if (!MinifilterInterceptor.MatchesV19AllocationReplay(existing, destination, kind,
                        checked((int)request.RequestorProcessId), intent) ||
                    existing.Transfer.RequestorProcessCreationTime != source.RequestorCreationTime)
                    throw StagedRequestRefusal.Create("The committed allocation belongs to a different requester or tuple.");
                // No live process lookup, parent seeding, generation allocation,
                // attachment or public mutation on a committed replay.
                using var stage = StagedStageFile.Open(existing.Transfer.StagePath);
                if (stage.Identity != existing.StageIdentity)
                    throw StagedRequestRefusal.Create("The committed allocation backing identity changed.");
                return new(existing.Transfer, existing.DestinationGeneration, existing.StageIdentity!, stage.Stream.Length);
            }
            StagedAllocationReply? allocated = await prepare().ConfigureAwait(false);
            if (allocated is not null) return allocated;
            // A missing manifest alone is insufficient: a crashed pre-commit
            // backing must first be identity-qualified, deleted and absent.
            if (await ReadAllocationManifestAsync(intent.AllocationReservationId, token).ConfigureAwait(false) is not null)
                throw StagedRequestRefusal.Create("Allocation committed while preparing a terminal refusal.");
            string extension = Path.GetExtension(Path.GetFullPath(destination));
            if (extension.Length > 16 || extension.IndexOfAny(['\\', '/', ':']) >= 0)
                throw StagedRequestRefusal.Create("Invalid allocation backing extension.");
            string stagePath = Path.Combine(_root, intent.AllocationReservationId.ToString("N") + extension);
            if (!StagedStageFile.TryDeleteUnjournaled(stagePath, out var failure))
            {
                if (failure is not null && StagedRequestRefusal.IsPermanent(failure))
                    throw StagedRequestRefusal.Create("Unjournaled backing is structurally invalid; no terminal release is authorized.");
                throw new IOException("Unjournaled backing cleanup is unresolved; refusal is not terminal.", failure);
            }
            string temporary = receiptPath + "." + Guid.NewGuid().ToString("N") + ".tmp";
            try
            {
                using (var output = new FileStream(temporary, FileMode.CreateNew, FileAccess.Write,
                           FileShare.None, 4096, FileOptions.WriteThrough))
                {
                    if (_fileSecurity is not null) new FileInfo(temporary).SetAccessControl(_fileSecurity);
                    await output.WriteAsync(bytes, token).ConfigureAwait(false);
                    output.Flush(flushToDisk: true);
                }
                File.Move(temporary, receiptPath);
            }
            finally { if (File.Exists(temporary)) File.Delete(temporary); }
            return null;
        }
        finally { _v19AllocationGate.Release(); }
    }
}
