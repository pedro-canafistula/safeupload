using System.Runtime.InteropServices;
using SafeUpload.Agent.Minifilter;

namespace SafeUpload.Agent.Service.Interception;

public sealed partial class StagedTransferAllocator
{
    private IEnumerator<string>? _negativeRecovery;

    // Startup drains the existing population; background callers take a bounded
    // pass. The same gate excludes allocation/manifest creation during each proof.
    internal async Task RecoverFailedAllocationsAsync(CancellationToken token,
        int maximumItems = 16, Action<Guid, Exception>? held = null)
    {
        if (maximumItems < 1) throw new ArgumentOutOfRangeException(nameof(maximumItems));
        await _v19AllocationGate.WaitAsync(token).ConfigureAwait(false);
        try
        {
            _negativeRecovery ??= Directory.EnumerateFiles(_root, "*.allocation-refused*").GetEnumerator();
            for (int count = 0; count < maximumItems; count++)
            {
                token.ThrowIfCancellationRequested();
                if (!_negativeRecovery.MoveNext()) { _negativeRecovery.Dispose(); _negativeRecovery = null; break; }
                string path = _negativeRecovery.Current;
                Guid id = Guid.Empty;
                try
                {
                    if (!StagedSpaceBudget.IsNegativeReceiptPath(path))
                        throw new IOException("Unrecognized legacy refusal metadata; retained.");
                    id = Guid.ParseExact(Path.GetFileName(path)[..32], "N");
                    await RetireNegativeReceiptAsync(path, id, token).ConfigureAwait(false);
                }
                catch (Exception error) when (error is IOException or UnauthorizedAccessException)
                {
                    held?.Invoke(id, error); // One unresolved nonce never stops another.
                }
            }
            if (_spaceBudget is not null)
                await _spaceBudget.ReconcileAsync(_journal, token, maximumItems, held).ConfigureAwait(false);
        }
        finally { _v19AllocationGate.Release(); }
    }

    private async Task RetireNegativeReceiptAsync(string path, Guid id, CancellationToken token)
    {
        StagedStageIdentity metadataIdentity;
        SafeUploadRequest request;
        using (var input = StagedStageFile.Open(path))
        {
            if (input.Stream.Length != Contract.RequestSize)
                throw new IOException("Partial legacy refusal metadata; retain this nonce.");
            byte[] bytes = new byte[Contract.RequestSize];
            await input.Stream.ReadExactlyAsync(bytes, token).ConfigureAwait(false);
            request = MemoryMarshal.Read<SafeUploadRequest>(bytes);
            if (!request.TryReadStagePayload<SafeUploadStageAllocateV20>(Operation.StageAllocate, out var source) ||
                request.RequestId == 0 || request.RequestorProcessId == 0 || source.RequestorCreationTime <= 0 ||
                source.Intent.AllocationReservationId != id || source.Intent.DriverInstanceId == Guid.Empty ||
                source.Intent.Disposition > 5 || source.Intent.ReferenceKind > 2 ||
                (source.Intent.ReferenceKind == 0) != (source.Intent.ParentTransferId == Guid.Empty))
                throw new IOException("Invalid legacy refusal request; retain this nonce.");
            metadataIdentity = input.Identity;
        }
        if (await ReadAllocationManifestAsync(id, token).ConfigureAwait(false) is not null)
            throw new IOException("Conflicting allocation/refusal evidence; retain this nonce.");
        string extension = Path.GetExtension(request.GetPath());
        if (extension.Length > 16 || extension.IndexOfAny(['\\', '/', ':']) >= 0)
            throw new IOException("Invalid legacy refusal backing extension.");
        string stage = Path.Combine(_root, id.ToString("N") + extension);
        if (_spaceBudget is not null)
        {
            _spaceBudget.RequireFailedAllocationAbsent(id, stage);
            if (!_spaceBudget.RetireUnissuedMetadata(id))
                throw new IOException("Failed allocation custody remains unresolved.");
        }
        else if (!StagedStageFile.TryConfirmAbsent(stage, out var absence))
            throw new IOException("Legacy refusal has unresolved private backing; retained.", absence);
        if (!StagedStageFile.TryConfirmAbsent(stage + ".space", out var grantFailure))
            throw new IOException("Legacy refusal has unresolved capacity grant; retained.", grantFailure);
        if (!StagedStageFile.TryDeleteExactAndConfirmAbsent(path, metadataIdentity, out var failure,
                expectedLength: Contract.RequestSize))
            throw new IOException("Exact refusal metadata retirement is unresolved.", failure);
        _spaceBudget?.RetiredNegativeReceipt(Contract.RequestSize);
    }
}
