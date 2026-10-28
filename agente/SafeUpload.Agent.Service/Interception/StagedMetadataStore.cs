#if SAFEUPLOAD_ADMISSION_EVIDENCE
using Microsoft.Win32.SafeHandles;
using SafeUpload.Agent.Minifilter;

namespace SafeUpload.Agent.Service.Interception;

internal readonly record struct MetadataNativeResult(int Status, ulong Information)
{
    internal bool Success => Status == 0;
    internal void Require() { if (!Success) throw new MetadataNativeException(this); }
}
internal sealed class MetadataNativeException(MetadataNativeResult result) : IOException($"Metadata native status 0x{result.Status:X8}, information {result.Information}.")
{ internal MetadataNativeResult Result { get; } = result; }
internal sealed record MetadataNativeObservation(StagedStageIdentity Identity, long EndOfFile, long AllocationSize,
    uint Links, bool DeletePending);
internal sealed record MetadataOperationReceipt(MetadataStoreStep Step, MetadataNativeResult Native,
    MetadataNativeObservation? Observation, long RetainedCharge = 0);
internal interface IStagedMetadataNative : IDisposable
{
    // The adapter uses this sharing for every Create/Open handle retained by the store.
    uint HeldHandleShare { get; }
    long Alignment { get; }
    long AllocationUnit { get; }
    StagedStageIdentity ParentIdentity { get; }
    void ValidateParent();
    SafeFileHandle Create(string leaf, MetadataRoleV32 role, out MetadataNativeResult result);
    SafeFileHandle Open(string leaf, MetadataRoleV32 role, StagedStageIdentity expected);
    MetadataNativeObservation Query(SafeFileHandle handle);
    MetadataNativeResult Write(SafeFileHandle handle, long offset, ReadOnlySpan<byte> bytes);
    MetadataNativeResult Read(SafeFileHandle handle, long offset, Span<byte> bytes);
    MetadataNativeResult Flush(SafeFileHandle handle);
    MetadataNativeResult Allocation(SafeFileHandle handle, long length);
    MetadataNativeResult EndOfFile(SafeFileHandle handle, long length);
    MetadataNativeResult Rename(SafeFileHandle handle, string leaf, bool replace);
    MetadataNativeResult Delete(SafeFileHandle handle);
}

// Claims are process-local namespace exclusion for registered writers, not OS
// exclusion of privileged administrators. No native I/O runs under the map lock.
internal sealed class StagedMetadataStore : IDisposable
{
    private readonly IStagedMetadataNative _native;
    private readonly StagedMetadataStoreAccounting _accounting;
    private readonly object _claimsGate = new();
    private readonly HashSet<string> _claims = new(StringComparer.OrdinalIgnoreCase);
    private int _transactions, _growthTransactions;
    private bool _disposed;
    internal StagedMetadataStore(IStagedMetadataNative native, StagedMetadataStoreAccounting accounting) =>
        (_native, _accounting) = (native, accounting);

    internal sealed class Transaction : IDisposable
    {
        private StagedMetadataStore? _owner;
        internal BoundedOutputPlan Plan { get; set; }
        internal string OutputLeaf { get; }
        internal string TargetLeaf { get; }
        internal SafeFileHandle? Output, Predecessor;
        internal IDisposable? OutputPin, PredecessorPin;
        internal MetadataNativeObservation? PredecessorObservation;
        internal byte[] Bytes { get; }
        internal List<MetadataOperationReceipt> Receipts { get; } = new();
        private readonly object _operationGate = new();
        private bool _operationActive;
        internal bool Issued;
        internal bool Growth;
        internal bool MutationSucceeded, Completed, Failed, RecoveryBlocked;
        internal MetadataStoreStep? LostBookkeeping;
        internal RawAppend? PendingAppend;
        internal sealed record RawAppend(long Offset, byte[] Frame, int SlotIndex, byte[] Slot, long End)
        { internal bool SlotWritten, EofSet; }
        internal Transaction(StagedMetadataStore owner, BoundedOutputPlan plan, string output, string target, byte[] bytes) =>
            (_owner, Plan, OutputLeaf, TargetLeaf, Bytes) = (owner, plan, output, target, bytes);
        internal bool BelongsTo(StagedMetadataStore owner) => ReferenceEquals(_owner, owner);
        internal IDisposable EnterOperation(StagedMetadataStore owner)
        {
            lock (_operationGate)
            {
                if (!BelongsTo(owner)) throw new InvalidOperationException("Stale store transaction incarnation.");
                if (_operationActive) throw new IOException("Metadata transaction is locally busy.");
                _operationActive = true;
                return new OperationLease(this);
            }
        }
        private sealed class OperationLease(Transaction transaction) : IDisposable
        {
            public void Dispose()
            { lock (transaction._operationGate) { transaction._operationActive = false; Monitor.PulseAll(transaction._operationGate); } }
        }
        public void Dispose()
        {
            StagedMetadataStore? owner;
            lock (_operationGate)
            {
                owner = Interlocked.Exchange(ref _owner, null);
                if (owner is null) return;
                while (_operationActive) Monitor.Wait(_operationGate);
            }
            Output?.Dispose(); Predecessor?.Dispose();
            OutputPin?.Dispose(); PredecessorPin?.Dispose();
            lock (owner._claimsGate)
            {
                owner._claims.Remove(OutputLeaf); owner._claims.Remove(TargetLeaf);
                owner._transactions--; if (Growth) owner._growthTransactions--; Monitor.PulseAll(owner._claimsGate);
            }
        }
    }
    internal sealed record Result(MetadataStoreDisposition Disposition, Transaction Transaction,
        IReadOnlyList<MetadataOperationReceipt> Receipts, Exception? Failure);

    internal Transaction? TryClaim(BoundedOutputPlan plan, string outputLeaf, string targetLeaf,
        ReadOnlySpan<byte> bytes, MetadataPhysicalClass physicalClass, bool growth = false)
    {
        if (!ResourceControlWireV32.LeafValid(outputLeaf) || !ResourceControlWireV32.LeafValid(targetLeaf) ||
            bytes.Length != plan.LogicalLength || plan.Alignment != _native.Alignment || plan.AllocationUnit != _native.AllocationUnit ||
            (plan.ExpectedPredecessor is not null && string.Equals(outputLeaf, targetLeaf, StringComparison.OrdinalIgnoreCase)) ||
            (!MetadataStoreRoles.CanReplace(plan.Role) && outputLeaf != targetLeaf))
            throw new ArgumentException("Invalid exact metadata claim or verified units.");
        if (plan.ExpectedPredecessor is not null && (_native.HeldHandleShare & 4) == 0)
            throw new ArgumentException("Held predecessor handles must include FILE_SHARE_DELETE.");
        lock (_claimsGate)
        {
            ObjectDisposedException.ThrowIf(_disposed, this);
            if (_transactions >= 16 || (growth ? _growthTransactions : _transactions - _growthTransactions) >= 8 ||
                _claims.Contains(outputLeaf) || _claims.Contains(targetLeaf)) return null;
            if (plan.ExpectedPredecessor is { } predecessor && !_accounting.Retains(predecessor))
                throw new IOException("Expected predecessor lacks its independent retained physical charge.");
            if (!_accounting.TryReserve(plan, physicalClass)) return null;
            // Reserve before retaining bytes, opening a child or issuing a write.
            _claims.Add(outputLeaf); _claims.Add(targetLeaf); _transactions++; if (growth) _growthTransactions++;
            try { return new Transaction(this, plan, outputLeaf, targetLeaf, bytes.ToArray()) { Growth = growth }; }
            catch { _claims.Remove(outputLeaf); _claims.Remove(targetLeaf); _transactions--; if (growth) _growthTransactions--; throw; }
        }
    }

    internal Result Execute(Transaction tx, Action<MetadataStoreStep>? afterNative = null)
    {
        using var operation = tx.EnterOperation(this);
        if (tx.Issued || tx.Completed || tx.MutationSucceeded || tx.Receipts.Count != 0 || tx.Failed)
            throw new InvalidOperationException("An issued transaction cannot be executed again.");
        tx.Issued = true;
        try
        {
            if (tx.Plan.ExpectedPredecessor is not null && (_native.HeldHandleShare & 4) == 0)
                throw new IOException("Held predecessor sharing changed after claim; no native work is permitted.");
            _native.ValidateParent();
            if (tx.Plan.ExpectedPredecessor is { } expected)
            {
                tx.PredecessorPin = _accounting.Pin(expected);
                tx.Predecessor = _native.Open(tx.TargetLeaf, CurrentRole(tx.Plan.Role), expected);
            }
            EnsureReceiptSpace(tx, 2);
            tx.Output = _native.Create(tx.OutputLeaf, tx.Plan.Role, out var created);
            Record(tx, MetadataStoreStep.Create, created);
            created.Require();
            if (created.Information != 2) throw new IOException("Relative FILE_CREATE did not return FILE_CREATED.");
            var initial = _native.Query(tx.Output);
            _accounting.Bind(tx.Plan.Object, initial.Identity);
            tx.OutputPin = _accounting.Pin(initial.Identity);
            Observe(tx, MetadataStoreStep.Create, created, initial);
            Notify(tx, MetadataStoreStep.Create, afterNative);
            Call(tx, MetadataStoreStep.Allocation, () => _native.Allocation(tx.Output, tx.Plan.PaddedExtent), afterNative);
            WritePadded(tx, 0, tx.Bytes, MetadataStoreStep.Write);
            Notify(tx, MetadataStoreStep.Write, afterNative);
            Call(tx, MetadataStoreStep.F1, () => _native.Flush(tx.Output), afterNative);
            Call(tx, MetadataStoreStep.EndOfFile, () => _native.EndOfFile(tx.Output, tx.Plan.LogicalLength), afterNative);
            Call(tx, MetadataStoreStep.F2, () => _native.Flush(tx.Output), afterNative);
            Verify(tx, tx.Bytes, 0, tx.Plan.LogicalLength);
            if (tx.OutputLeaf != tx.TargetLeaf)
            {
                _native.ValidateParent();
                if (tx.Predecessor is not null)
                {
                    var predecessor = _native.Query(tx.Predecessor);
                    if (predecessor.Identity != tx.Plan.ExpectedPredecessor || predecessor.DeletePending || predecessor.Links != 1)
                        throw new IOException("Held predecessor changed identity or became delete-pending.");
                    using var current = _native.Open(tx.TargetLeaf, CurrentRole(tx.Plan.Role), predecessor.Identity);
                    if (_native.Query(current).Identity != predecessor.Identity) throw new IOException("Replacement target name changed identity.");
                }
                EnsureReceiptSpace(tx, 3);
                var renamed = _native.Rename(tx.Output, tx.TargetLeaf, tx.Predecessor is not null);
                // Record the native result before any wrapper/observer can fail.
                Record(tx, MetadataStoreStep.Replace, renamed);
                if (renamed.Success) tx.MutationSucceeded = true;
                ObservePredecessor(tx);
                renamed.Require();
                Observe(tx, MetadataStoreStep.Replace, renamed, _native.Query(tx.Output));
                Notify(tx, MetadataStoreStep.Replace, afterNative);
            }
            Call(tx, MetadataStoreStep.F3, () => _native.Flush(tx.Output), afterNative);
            VerifyCurrent(tx);
            tx.Completed = true;
            return Finish(tx, MetadataStoreDisposition.Committed);
        }
        catch (Exception error) when (error is IOException or UnauthorizedAccessException)
        {
            tx.Failed = true;
            if (tx.MutationSucceeded && error is not MetadataNativeException) tx.LostBookkeeping ??= MetadataStoreStep.Replace;
            if (error is MetadataNativeException) tx.RecoveryBlocked = true;
            return Finish(tx, MetadataStoreDisposition.Held, error);
        }
    }

    // Only known-success replacement/append may enter bookkeeping recovery.
    // A second interruption preserves the same receipt and performs no mutation.
    internal Result RecoverBookkeeping(Transaction tx, Action<MetadataStoreStep>? afterNative = null)
    {
        using var operation = tx.EnterOperation(this);
        if (!tx.MutationSucceeded || tx.LostBookkeeping is null || tx.RecoveryBlocked)
            return Finish(tx, MetadataStoreDisposition.Held, new IOException("No known native mutation receipt."));
        try
        {
            if (tx.PendingAppend is { } append)
            {
                Call(tx, MetadataStoreStep.F1, () => _native.Flush(tx.Output!), afterNative);
                if (!append.EofSet) Call(tx, MetadataStoreStep.EndOfFile, () => _native.EndOfFile(tx.Output!, append.End), afterNative);
                Call(tx, MetadataStoreStep.F2, () => _native.Flush(tx.Output!), afterNative);
                Verify(tx, append.Frame, append.Offset, append.End);
                if (!append.SlotWritten)
                {
                    WriteSlot(tx, append);
                    Notify(tx, MetadataStoreStep.Slot, afterNative);
                }
                Call(tx, MetadataStoreStep.F3, () => _native.Flush(tx.Output!), afterNative);
                Verify(tx, append.Slot, append.SlotIndex * tx.Plan.Alignment, append.End);
            }
            else
            {
                Call(tx, MetadataStoreStep.F3, () => _native.Flush(tx.Output!), afterNative);
                VerifyCurrent(tx);
            }
            tx.Completed = true; tx.Failed = false;
            return Finish(tx, MetadataStoreDisposition.RecoverableBookkeeping);
        }
        catch (Exception error) when (error is IOException or UnauthorizedAccessException)
        { if (error is MetadataNativeException) tx.RecoveryBlocked = true; return Finish(tx, MetadataStoreDisposition.Held, error); }
    }

    internal Result Append(Transaction tx, BoundedOutputPlan extension, long expectedFrontier, ReadOnlySpan<byte> frame,
        int inactiveSlot, ReadOnlySpan<byte> slot, Action<MetadataStoreStep>? afterNative = null)
    {
        using var operation = tx.EnterOperation(this);
        long alignment = tx.Plan.Alignment;
        if (tx.Plan.Role != MetadataRoleV32.Segment || tx.Output is null || tx.Failed || !tx.Completed ||
            expectedFrontier < 2 * alignment || expectedFrontier % alignment != 0 ||
            frame.Length == 0 || frame.Length % alignment != 0 || inactiveSlot is < 0 or > 1 || slot.Length != alignment ||
            extension.Object != tx.Plan.Object || extension.ExpectedPredecessor is not null ||
            extension.LogicalLength != checked(expectedFrontier + frame.Length) ||
            extension.LogicalLength % alignment != 0)
            throw new ArgumentException("Invalid bounded aligned append claim.");
        if (!_accounting.TryExtend(extension)) return Finish(tx, MetadataStoreDisposition.Held, new IOException("Segment peak admission refused before issue."));
        tx.Plan = extension;
        byte[] frameBytes = frame.ToArray(), slotBytes = slot.ToArray();
        tx.PendingAppend = new(expectedFrontier, frameBytes, inactiveSlot, slotBytes, extension.LogicalLength);
        tx.MutationSucceeded = false; tx.LostBookkeeping = null;
        tx.Completed = false;
        try
        {
            if (_native.Query(tx.Output).EndOfFile != expectedFrontier) throw new IOException("Append frontier changed.");
            Call(tx, MetadataStoreStep.Allocation, () => _native.Allocation(tx.Output, extension.PaddedExtent), afterNative);
            EnsureReceiptSpace(tx, 2);
            var appended = _native.Write(tx.Output, expectedFrontier, frameBytes);
            Record(tx, MetadataStoreStep.Append, appended);
            if (appended.Success && appended.Information == (ulong)frameBytes.Length) tx.MutationSucceeded = true;
            Observe(tx, MetadataStoreStep.Append, appended, _native.Query(tx.Output));
            appended.Require();
            if (appended.Information != (ulong)frameBytes.Length) throw new IOException("Short raw frame remains held.");
            Notify(tx, MetadataStoreStep.Append, afterNative);
            Call(tx, MetadataStoreStep.F1, () => _native.Flush(tx.Output), afterNative);
            long end = checked(expectedFrontier + frame.Length);
            Call(tx, MetadataStoreStep.EndOfFile, () => _native.EndOfFile(tx.Output, end), afterNative);
            Call(tx, MetadataStoreStep.F2, () => _native.Flush(tx.Output), afterNative);
            Verify(tx, frameBytes, expectedFrontier, end);
            WriteSlot(tx, tx.PendingAppend);
            Notify(tx, MetadataStoreStep.Slot, afterNative);
            Call(tx, MetadataStoreStep.F3, () => _native.Flush(tx.Output), afterNative);
            Verify(tx, slotBytes, inactiveSlot * alignment, end);
            tx.Completed = true;
            return Finish(tx, MetadataStoreDisposition.Committed);
        }
        catch (Exception error) when (error is IOException or UnauthorizedAccessException)
        {
            tx.Failed = true;
            if (tx.MutationSucceeded && error is not MetadataNativeException) tx.LostBookkeeping ??= MetadataStoreStep.Append;
            if (error is MetadataNativeException) tx.RecoveryBlocked = true;
            return Finish(tx, MetadataStoreDisposition.Held, error);
        }
    }

    internal Result Delete(Transaction tx)
    {
        using var operation = tx.EnterOperation(this);
        if (tx.Output is null || !MetadataStoreRoles.CanDelete(tx.Plan.Role) || tx.Plan.Role == MetadataRoleV32.MarkerNew ||
            tx.Receipts.Any(r => r.Step == MetadataStoreStep.Delete))
            throw new InvalidOperationException("No unused exact delete claim.");
        try
        {
            _native.ValidateParent();
            var observation = _native.Query(tx.Output);
            _accounting.Observe(tx.Plan.Object, observation.Identity, observation.AllocationSize);
            EnsureReceiptSpace(tx, 2);
            var deleted = _native.Delete(tx.Output);
            Record(tx, MetadataStoreStep.Delete, deleted); deleted.Require();
            Observe(tx, MetadataStoreStep.Delete, deleted, _native.Query(tx.Output));
            // Delete-pending is not storage release. The charge remains.
            return Finish(tx, MetadataStoreDisposition.Committed);
        }
        catch (Exception error) when (error is IOException or UnauthorizedAccessException)
        { return Finish(tx, MetadataStoreDisposition.Held, error); }
    }

    private static MetadataRoleV32 CurrentRole(MetadataRoleV32 role) => role switch
    {
        MetadataRoleV32.LedgerNew => MetadataRoleV32.LedgerCurrent, MetadataRoleV32.CompanionNew => MetadataRoleV32.CompanionCurrent,
        MetadataRoleV32.ManifestNew => MetadataRoleV32.ManifestCurrent, MetadataRoleV32.InventoryNew => MetadataRoleV32.InventoryCurrent,
        MetadataRoleV32.MarkerNew => MetadataRoleV32.MarkerCurrent, MetadataRoleV32.EpochNew => MetadataRoleV32.EpochCurrent,
        MetadataRoleV32.AppendIntentNew => MetadataRoleV32.AppendIntentCurrent,
        MetadataRoleV32.CompactionIntentNew => MetadataRoleV32.CompactionIntentCurrent,
        _ => throw new ArgumentOutOfRangeException(nameof(role))
    };
    private static void EnsureReceiptSpace(Transaction tx, int count)
    { if (tx.Receipts.Count > 32768 - count) throw new IOException("Bounded operation receipt storage exhausted; retain custody."); }
    private void Record(Transaction tx, MetadataStoreStep step, MetadataNativeResult result) =>
        tx.Receipts.Add(new(step, result, null, _accounting.Charge(tx.Plan.Object)));
    private void ObservePredecessor(Transaction tx)
    {
        if (tx.Predecessor is null) return;
        EnsureReceiptSpace(tx, 1);
        var observation = _native.Query(tx.Predecessor);
        tx.PredecessorObservation = observation;
        try { _accounting.Observe(observation.Identity, observation.AllocationSize, observation.Links); }
        catch { tx.RecoveryBlocked = true; throw; }
        finally { tx.Receipts.Add(new(MetadataStoreStep.Predecessor, new(0, 0), observation, _accounting.Charge(observation.Identity))); }
    }
    private void Observe(Transaction tx, MetadataStoreStep step, MetadataNativeResult result, MetadataNativeObservation observation)
    {
        try { _accounting.Observe(tx.Plan.Object, observation.Identity, observation.AllocationSize, observation.Links); }
        catch { tx.RecoveryBlocked = true; throw; }
        finally { tx.Receipts.Add(new(step, result, observation, _accounting.Charge(tx.Plan.Object))); }
        if ((observation.DeletePending || observation.Links == 0) && step != MetadataStoreStep.Delete)
            throw new IOException("Metadata output unexpectedly became delete-pending.");
    }
    private static void Notify(Transaction tx, MetadataStoreStep step, Action<MetadataStoreStep>? observer)
    {
        try { observer?.Invoke(step); }
        catch (IOException) { tx.LostBookkeeping = step; throw; }
    }
    private void Call(Transaction tx, MetadataStoreStep step, Func<MetadataNativeResult> action, Action<MetadataStoreStep>? observer)
    {
        EnsureReceiptSpace(tx, 2);
        var result = action(); Record(tx, step, result);
        if (result.Success && step == MetadataStoreStep.EndOfFile && tx.PendingAppend is { } append) append.EofSet = true;
        Observe(tx, step, result, _native.Query(tx.Output!));
        result.Require(); Notify(tx, step, observer);
    }
    private void WriteSlot(Transaction tx, Transaction.RawAppend append)
    {
        EnsureReceiptSpace(tx, 2);
        var result = _native.Write(tx.Output!, append.SlotIndex * tx.Plan.Alignment, append.Slot);
        Record(tx, MetadataStoreStep.Slot, result);
        if (result.Success && result.Information == (ulong)append.Slot.Length) append.SlotWritten = true;
        Observe(tx, MetadataStoreStep.Slot, result, _native.Query(tx.Output!));
        result.Require();
        if (result.Information != (ulong)append.Slot.Length) { tx.RecoveryBlocked = true; throw new IOException("Short raw slot remains held."); }
    }
    private void WritePadded(Transaction tx, long offset, ReadOnlySpan<byte> bytes, MetadataStoreStep step)
    {
        int alignment = checked((int)tx.Plan.Alignment);
        byte[] chunk = new byte[alignment];
        long padded = BoundedOutputPlan.Round(bytes.Length, alignment);
        if (offset % alignment != 0 || checked(offset + padded) > tx.Plan.PaddedExtent)
            throw new IOException("Write exceeds admitted padded extent.");
        for (int cursor = 0; cursor < padded; cursor += alignment)
        {
            chunk.AsSpan().Clear();
            bytes.Slice(cursor, Math.Min(alignment, bytes.Length - cursor)).CopyTo(chunk);
            EnsureReceiptSpace(tx, 2);
            var result = _native.Write(tx.Output!, offset + cursor, chunk);
            Record(tx, step, result);
            Observe(tx, step, result, _native.Query(tx.Output!));
            result.Require();
            if (result.Information != (ulong)alignment) throw new IOException("Short metadata write remains held.");
        }
    }
    private void Verify(Transaction tx, ReadOnlySpan<byte> expected, long offset, long eof)
    {
        EnsureReceiptSpace(tx, 1);
        var observation = _native.Query(tx.Output!);
        Observe(tx, MetadataStoreStep.Verify, new(0, 0), observation);
        if (observation.EndOfFile != eof) throw new IOException("Metadata EOF changed.");
        byte[] chunk = new byte[checked((int)tx.Plan.Alignment)];
        for (int cursor = 0; cursor < expected.Length; cursor += chunk.Length)
        {
            EnsureReceiptSpace(tx, 1);
            var read = _native.Read(tx.Output!, offset + cursor, chunk);
            Record(tx, MetadataStoreStep.Verify, read); read.Require();
            int length = Math.Min(chunk.Length, expected.Length - cursor);
            if (read.Information < (ulong)length || read.Information > (ulong)chunk.Length ||
                !expected.Slice(cursor, length).SequenceEqual(chunk.AsSpan(0, length)))
                throw new IOException("Metadata bytes changed.");
        }
        _native.ValidateParent();
    }
    private void VerifyCurrent(Transaction tx)
    {
        Verify(tx, tx.Bytes, 0, tx.Plan.LogicalLength);
        if (tx.OutputLeaf != tx.TargetLeaf)
        {
            var exact = _native.Query(tx.Output!).Identity;
            using var current = _native.Open(tx.TargetLeaf, CurrentRole(tx.Plan.Role), exact);
            if (_native.Query(current).Identity != exact) throw new IOException("Replacement current changed.");
        }
    }
    private static Result Finish(Transaction tx, MetadataStoreDisposition disposition, Exception? error = null) =>
        new(disposition, tx, tx.Receipts.ToArray(), error);
    public void Dispose()
    {
        lock (_claimsGate)
        {
            _disposed = true;
            while (_transactions != 0) Monitor.Wait(_claimsGate);
        }
        _native.Dispose();
    }
}
#endif
