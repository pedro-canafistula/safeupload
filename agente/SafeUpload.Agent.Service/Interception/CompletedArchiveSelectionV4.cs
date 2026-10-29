#if SAFEUPLOAD_ADMISSION_EVIDENCE
using System.Collections.Immutable;

namespace SafeUpload.Agent.Service.Interception;

internal enum ArchiveRecoveryDecisionV4 { Held = 0, IssueOnce = 1, FrontierOnly = 2, BookkeepingOnly = 3 }
internal sealed record ArchiveProjectionV4(StagedJournalEnvelopeV3 Base, StagedJournalEnvelopeV3? Delta, int InitialPendingCount);
internal sealed record ArchiveSelectionV4(ImmutableDictionary<Guid, byte[]> Records, ImmutableDictionary<Guid, ArchiveProjectionV4> Transfers);
internal sealed record ArchiveSegmentObservationV4(StagedStageIdentity Identity, bool SecurityMatches, bool SingleLink, bool ReparsePoint, byte[] Bytes);

// Selection never truncates a tail or performs native recovery. Its caller must
// persist/revalidate the exact decision against held objects before any adapter.
internal static class CompletedArchiveSelectionV4
{
    internal static ResourceFrontierV4 SelectFrontier(ReadOnlySpan<byte> slot0, ReadOnlySpan<byte> slot1, int alignment)
    {
        var first = ResourceStorageCodecV4.ReadFrontier(slot0, alignment, 0);
        if (slot1.IndexOfAnyExcept((byte)0) < 0)
        {
            EvidenceBinaryV1.Need(slot1.Length == alignment && first.Sequence == 1 && first.End == 2 * alignment,
                "Only the initial inactive frontier can be zero."); return first;
        }
        var second = ResourceStorageCodecV4.ReadFrontier(slot1, alignment, 1);
        Pair(first, second); return first.Sequence > second.Sequence ? first : second;
    }
    internal static ArchiveRecoveryDecisionV4 Recover(CompletedAppendIntentV4 intent, ArchiveSegmentObservationV4 observed,
        ArchiveCandidateObservationV4 candidate, EvidenceCatalogV1 evidence, bool oldNativeIssuersDrained)
    {
        try { return RecoverCore(intent, observed, candidate, evidence, oldNativeIssuersDrained); }
        catch (Exception error) when (error is InvalidDataException or ArgumentException or OverflowException)
        { return ArchiveRecoveryDecisionV4.Held; }
    }
    private static ArchiveRecoveryDecisionV4 RecoverCore(CompletedAppendIntentV4 intent, ArchiveSegmentObservationV4 observed,
        ArchiveCandidateObservationV4 candidate, EvidenceCatalogV1 evidence, bool drained)
    {
        _ = CompletedArchiveV4Codec.ReadCandidate(intent, candidate, evidence); var plan = intent.Location; int alignment = checked((int)plan.Alignment);
        EvidenceBinaryV1.Need(observed.Identity == plan.SegmentIdentity && observed.SecurityMatches && observed.SingleLink && !observed.ReparsePoint &&
            observed.Bytes.Length >= plan.ExpectedFrontier && observed.Bytes.Length <= 4194304 && observed.Bytes.Length % alignment == 0,
            "Observed segment binding/EOF differs.");
        var bytes = observed.Bytes; var slots = new ResourceFrontierV4?[2]; bool[] zero = new bool[2];
        for (int index = 0; index < 2; index++)
        {
            var slot = bytes.AsSpan(index * alignment, alignment); zero[index] = slot.IndexOfAnyExcept((byte)0) < 0;
            try { slots[index] = ResourceStorageCodecV4.ReadFrontier(slot, alignment, index); }
            catch (InvalidDataException) { }
        }
        if (slots[0] is { } a && slots[1] is { } b) Pair(a, b);
        int expectedIndex = (int)((plan.ExpectedFrontierSequence - 1) % 2), targetIndex = 1 - expectedIndex;
        var expected = slots[expectedIndex];
        EvidenceBinaryV1.Need(expected is not null && expected.Sequence == plan.ExpectedFrontierSequence && expected.End == plan.ExpectedFrontier &&
            expected.SegmentIdentity == observed.Identity && expected.InstallationId == plan.InstallationId &&
            expected.LastAppendTransactionId != plan.TransactionId, "Expected frontier/fresh transaction differs.");
        ValidatePrefix(bytes, 2 * alignment, expected.End, alignment, evidence);
        var target = slots[targetIndex]; bool committed = target?.Sequence == plan.TargetFrontierSequence;
        if (committed)
        {
            EvidenceBinaryV1.Need(target!.End == plan.TargetFrontier && target.LastAppendTransactionId == plan.TransactionId &&
                observed.Bytes.Length == target.End, "Selected target frontier differs.");
            ValidatePrefix(bytes, 2 * alignment, target.End, alignment, evidence);
            ExactTarget(bytes, plan, candidate.Bytes, alignment); return ArchiveRecoveryDecisionV4.BookkeepingOnly;
        }
        if (target is not null) EvidenceBinaryV1.Need(target.Sequence + 1 == expected.Sequence, "Inactive frontier is not the expected predecessor.");
        if (bytes.Length == plan.ExpectedFrontier)
        {
            EvidenceBinaryV1.Need(drained && (target is not null || zero[targetIndex] && expected.Sequence == 1), "Uncertain/torn no-write append.");
            return ArchiveRecoveryDecisionV4.IssueOnce;
        }
        EvidenceBinaryV1.Need(bytes.Length == plan.TargetFrontier, "Unknown/partial tail remains charged.");
        ExactTarget(bytes, plan, candidate.Bytes, alignment); return ArchiveRecoveryDecisionV4.FrontierOnly;
    }
    private static void Pair(ResourceFrontierV4 first, ResourceFrontierV4 second)
    {
        var old = first.Sequence < second.Sequence ? first : second; var next = old == first ? second : first;
        EvidenceBinaryV1.Need(first.InstallationId == second.InstallationId && first.SegmentIdentity == second.SegmentIdentity && first.Alignment == second.Alignment &&
            old.Sequence != ulong.MaxValue && next.Sequence == old.Sequence + 1 && next.End > old.End &&
            next.LastAppendTransactionId != Guid.Empty && next.LastAppendTransactionId != old.LastAppendTransactionId, "Frontier fork/gap/binding differs.");
    }
    private static void ExactTarget(byte[] bytes, ResourceHistoryHandoffV3 plan, byte[] candidate, int alignment)
    {
        var frame = ResourceStorageCodecV4.Serialize(new(plan.RecordId, candidate), alignment);
        EvidenceBinaryV1.Need(frame.Length == plan.FrameStride && bytes.AsSpan(checked((int)plan.FrameOffset), frame.Length).SequenceEqual(frame),
            "Independently observed frame differs from candidate.");
    }
    internal static ImmutableArray<byte[]> ValidatePrefix(byte[] bytes, long start, long end, int alignment, EvidenceCatalogV1 evidence)
    {
        EvidenceBinaryV1.Need(start >= 2 * alignment && start % alignment == 0 && end <= bytes.Length && end <= 4194304 && end % alignment == 0,
            "Selected range exceeds observed segment.");
        var payloads = ImmutableArray.CreateBuilder<byte[]>();
        while (start < end)
        {
            EvidenceBinaryV1.Need(end - start >= 60, "Truncated selected frame header.");
            uint length = EvidenceBinaryV1.U32(bytes, checked((int)start + 8));
            EvidenceBinaryV1.Need(length is > 0 and <= 131072, "Invalid selected payload length.");
            int stride = checked((60 + (int)length + alignment - 1) / alignment * alignment);
            EvidenceBinaryV1.Need(stride <= end - start, "Selected frame crosses frontier.");
            var frame = ResourceStorageCodecV4.ReadFrame(bytes.AsSpan((int)start, stride), alignment);
            var envelope = StagedJournalEnvelopeV3Codec.Deserialize(frame.Payload, evidence);
            EvidenceBinaryV1.Need(frame.RecordId == envelope.RecordId && envelope.ResourceClosure is not null ||
                frame.RecordId == envelope.RecordId && envelope.RecordKind is JournalRecordKindV4.InitialResolutionDelta or JournalRecordKindV4.LegacyHistory,
                "Selected frame is not a completed record.");
            payloads.Add(frame.Payload); start += stride;
        }
        EvidenceBinaryV1.Need(start == end, "Frame walk did not reach exact frontier."); return payloads.ToImmutable();
    }
    internal static ArchiveSelectionV4 SelectRecords(IEnumerable<byte[]> records, EvidenceCatalogV1 evidence)
    {
        var bytesById = new Dictionary<Guid, byte[]>(); var recordsById = new Dictionary<Guid, StagedJournalEnvelopeV3>();
        foreach (byte[] bytes in records)
        {
            var record = StagedJournalEnvelopeV3Codec.Deserialize(bytes, evidence);
            if (bytesById.TryGetValue(record.RecordId, out var prior))
            { EvidenceBinaryV1.Need(prior.AsSpan().SequenceEqual(bytes), "Changed duplicate RecordId."); continue; }
            bytesById.Add(record.RecordId, bytes.ToArray()); recordsById.Add(record.RecordId, record);
        }
        var transfers = ImmutableDictionary.CreateBuilder<Guid, ArchiveProjectionV4>();
        foreach (var group in recordsById.Values.GroupBy(x => x.TransferId))
        {
            var bases = group.Where(x => x.RecordKind != JournalRecordKindV4.InitialResolutionDelta).ToArray();
            var deltas = group.Where(x => x.RecordKind == JournalRecordKindV4.InitialResolutionDelta).ToArray();
            EvidenceBinaryV1.Need(bases.Length == 1 && deltas.Length <= 1, "Orphan delta/forked transfer base.");
            var basis = bases[0]; var delta = deltas.SingleOrDefault();
            var initial = basis.ResourceClosure?.InitialResolution;
            if (delta is not null)
            {
                EvidenceBinaryV1.Need(initial is { State: ResourceInitialPhaseV3.CleanupComplete } &&
                    delta.PreviousRecordId == basis.RecordId && basis.RecordRevision < long.MaxValue && delta.RecordRevision == basis.RecordRevision + 1 &&
                    delta.ResolutionDelta!.OriginalRequest == initial.OriginalRequest && delta.ResolutionDelta.FenceId == initial.FenceId &&
                    delta.ResolutionDelta.OriginCookie == initial.OriginCookie && delta.ResolutionDelta.ResolutionRevision > initial.ResolutionRevision,
                    "ACK delta does not extend the exact cleanup base.");
            }
            transfers.Add(group.Key, new(basis, delta, initial?.State == ResourceInitialPhaseV3.CleanupComplete && delta is null ? 1 : 0));
        }
        return new(bytesById.ToImmutableDictionary(), transfers.ToImmutable());
    }
    internal static void RequireEquivalent(ArchiveSelectionV4 before, ArchiveSelectionV4 after)
    {
        EvidenceBinaryV1.Need(before.Records.Count == after.Records.Count && before.Records.All(pair =>
            after.Records.TryGetValue(pair.Key, out var bytes) && bytes.AsSpan().SequenceEqual(pair.Value)), "Compaction lost/changed a complete witness.");
        EvidenceBinaryV1.Need(before.Transfers.Count == after.Transfers.Count && before.Transfers.All(pair =>
            after.Transfers.TryGetValue(pair.Key, out var state) && state.InitialPendingCount == pair.Value.InitialPendingCount &&
            state.Base.RecordId == pair.Value.Base.RecordId && state.Delta?.RecordId == pair.Value.Delta?.RecordId), "Compaction changed replay/debt projection.");
    }
}
#endif
