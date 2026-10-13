namespace SafeUpload.Agent.Service.Interception;

public sealed partial class StagedTransferJournal
{
    // Runs on the validated manifest snapshot under _gate. File/state/time
    // eligibility stays in CompactAsync; this only indexes durable claims and
    // their references. C claims cost O(C log D), where D is bound destinations;
    // reference closure visits each retained manifest once instead of rescanning
    // the journal for every step in an ancestry chain.
    internal static HashSet<Guid> FindCompactionProtectedTransfers(IReadOnlyList<TransferJournalEntry> entries,
        IReadOnlySet<Guid> finished, CancellationToken token)
    {
        token.ThrowIfCancellationRequested();
        var legacyClaims = new Dictionary<string, (long Generation, HashSet<Guid> Transfers)>(StringComparer.OrdinalIgnoreCase);
        var boundClaims = new SortedDictionary<StagedDestinationIdentity, (long Generation, HashSet<Guid> Transfers)>(
            Comparer<StagedDestinationIdentity>.Create(CompareDestinations));
        var byId = new Dictionary<Guid, TransferJournalEntry>(entries.Count);
        var protectedIds = new HashSet<Guid>();
        foreach (var entry in entries)
        {
            token.ThrowIfCancellationRequested();
            Guid id = entry.Transfer.TransferId;
            byId.Add(id, entry);
            if (!finished.Contains(id)) protectedIds.Add(id);
            AddClaim(entry.Transfer.DestinationPath, entry.BoundAllocation, entry.DestinationGeneration, id);
            for (var name = entry.NamespaceTombstones; name is not null; name = name.Previous)
                AddClaim(name.DestinationPath, name.AllocationBindingV23, name.Generation, id);
        }
        // Keep every maximum-generation tie. Legacy locators and identity-bound
        // destinations are separate authorities, even when their paths agree.
        foreach (var claim in legacyClaims.Values.Concat(boundClaims.Values))
            protectedIds.UnionWith(claim.Transfers);

        var pending = new Queue<Guid>(protectedIds);
        while (pending.TryDequeue(out Guid id))
        {
            token.ThrowIfCancellationRequested();
            if (!byId.TryGetValue(id, out var entry)) continue;
            if (entry.ParentVersionIdentity is { } parent) Retain(parent.TransferId);
            if (entry.DeleteVersionIdentity is { } deleted) Retain(deleted.TransferId);
            if (entry.AllocationReferenceId is { } owner) Retain(owner);
        }
        return protectedIds;

        void Retain(Guid id)
        {
            if (protectedIds.Add(id)) pending.Enqueue(id);
        }

        void AddClaim(string locator, StagedAllocationBindingV23? binding, long generation, Guid transfer)
        {
            if (binding is null) AddMaximum(legacyClaims, locator, generation, transfer);
            else AddMaximum(boundClaims, binding.Destination, generation, transfer);
        }
    }

    private static void AddMaximum<TKey>(IDictionary<TKey, (long Generation, HashSet<Guid> Transfers)> claims,
        TKey destination, long generation, Guid transfer) where TKey : notnull
    {
        if (!claims.TryGetValue(destination, out var maximum) || generation > maximum.Generation)
            claims[destination] = (generation, [transfer]);
        else if (generation == maximum.Generation) maximum.Transfers.Add(transfer);
    }

    private static int CompareDestinations(StagedDestinationIdentity left, StagedDestinationIdentity right)
    {
        // Parent serials equal their volume-root serials by construction. Order
        // every other identity field before the leaf, using precisely the same
        // Windows comparator as destination equality. No leaf hash is needed.
        var leftIdentity = (left.VolumeRoot.VolumeSerialNumber, left.VolumeRoot.FileIdHigh, left.VolumeRoot.FileIdLow,
            left.Parent.FileIdHigh, left.Parent.FileIdLow, left.CaseSensitive, left.MountManagerVolumeId);
        var rightIdentity = (right.VolumeRoot.VolumeSerialNumber, right.VolumeRoot.FileIdHigh, right.VolumeRoot.FileIdLow,
            right.Parent.FileIdHigh, right.Parent.FileIdLow, right.CaseSensitive, right.MountManagerVolumeId);
        int order = leftIdentity.CompareTo(rightIdentity);
        return order != 0 ? order : StagedDestinationLeafComparer.Compare(left.CanonicalLeaf, right.CanonicalLeaf,
            left.CaseSensitive);
    }
}
