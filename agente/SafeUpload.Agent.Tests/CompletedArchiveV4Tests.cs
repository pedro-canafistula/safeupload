#if SAFEUPLOAD_ADMISSION_EVIDENCE
using System.Collections.Immutable;
using System.Security.Cryptography;
using SafeUpload.Agent.Service.Interception;

namespace SafeUpload.Agent.Tests;

public sealed class CompletedArchiveV4Tests
{
    [Fact]
    public void Complete_manifest_closure_and_hot_completion_state_round_trip_with_all_references()
    {
        var x = Build(); byte[] bytes = StagedJournalEnvelopeV3Codec.Serialize(x.Envelope, x.Catalog);
        Assert.Equal(bytes, StagedJournalEnvelopeV3Codec.Serialize(StagedJournalEnvelopeV3Codec.Deserialize(bytes, x.Catalog), x.Catalog));
        var hot = x.Envelope with { ResourceClosure = null,
            CompletionState = new(x.State.CustodyTransfers.Select(c => c?.Completion).ToImmutableArray()) };
        byte[] hotBytes = StagedJournalEnvelopeV3Codec.Serialize(hot, x.Catalog);
        Assert.Equal(hotBytes, StagedJournalEnvelopeV3Codec.Serialize(StagedJournalEnvelopeV3Codec.Deserialize(hotBytes, x.Catalog), x.Catalog));
        Assert.Throws<InvalidDataException>(() => StagedJournalEnvelopeV3Codec.Serialize(hot with { ResourceClosure = x.State }, x.Catalog));
        Console.WriteLine($"Rev9Manifest closure={bytes.Length} hot={hotBytes.Length} limit=131072");
    }

    [Theory]
    [InlineData(1)] [InlineData(2)]
    public void Independent_segment_candidate_and_both_parities_require_fresh_transaction_and_validate_every_frame(int sequence)
    {
        var x = Recovery(sequence); var expected = ArchiveRecoveryDecisionV4.FrontierOnly;
        Assert.Equal(expected, CompletedArchiveSelectionV4.Recover(x.Intent, x.Segment, x.Candidate, x.Catalog, true));
        var selected = x.Segment.Bytes.ToArray(); var location = x.Intent.Location;
        byte[] target = ResourceStorageCodecV4.Serialize(new ResourceFrontierV4(location.InstallationId, x.Segment.Identity, 4096,
            (int)((location.TargetFrontierSequence - 1) % 2), location.TargetFrontierSequence, location.TargetFrontier, location.TransactionId));
        target.CopyTo(selected, (int)((location.TargetFrontierSequence - 1) % 2) * 4096);
        for (int retry = 0; retry < 2; retry++) Assert.Equal(ArchiveRecoveryDecisionV4.BookkeepingOnly,
            CompletedArchiveSelectionV4.Recover(x.Intent, x.Segment with { Bytes = selected }, x.Candidate, x.Catalog, true));
        Assert.Equal(location.TargetFrontierSequence, CompletedArchiveSelectionV4.SelectFrontier(selected.AsSpan(0, 4096), selected.AsSpan(4096, 4096), 4096).Sequence);
        var corrupt = selected.ToArray(); corrupt[(int)location.FrameOffset + 60] ^= 1;
        Assert.Equal(ArchiveRecoveryDecisionV4.Held, CompletedArchiveSelectionV4.Recover(x.Intent, x.Segment with { Bytes = corrupt }, x.Candidate, x.Catalog, true));
        if (sequence == 2)
        {
            var reused = x.Intent with { Location = location with { TransactionId = PriorTransaction } };
            Assert.Equal(ArchiveRecoveryDecisionV4.Held, CompletedArchiveSelectionV4.Recover(reused, x.Segment, x.Candidate, x.Catalog, true));
            Assert.Equal(ArchiveRecoveryDecisionV4.Held, CompletedArchiveSelectionV4.Recover(reused,
                x.Segment with { Bytes = x.Segment.Bytes[..(int)location.ExpectedFrontier] }, x.Candidate, x.Catalog, true));
        }
    }

    [Theory]
    [InlineData("candidate-zero")] [InlineData("candidate-identity")] [InlineData("candidate-length")]
    [InlineData("selected-prefix")] [InlineData("padding")] [InlineData("extra-tail")] [InlineData("partial-tail")]
    [InlineData("slot-identity")] [InlineData("candidate-evidence-missing")]
    public void Recovery_holds_unknown_or_partial_bytes_without_truncation_or_mutation(string mutation)
    {
        var x = Recovery(2); var segment = x.Segment; var candidate = x.Candidate; var catalog = x.Catalog;
        byte[] bytes = segment.Bytes.ToArray();
        switch (mutation)
        {
            case "candidate-zero": candidate = candidate with { Bytes = new byte[candidate.Bytes.Length] }; break;
            case "candidate-identity": candidate = candidate with { Identity = segment.Identity }; break;
            case "candidate-length": candidate = candidate with { Bytes = candidate.Bytes[..^1] }; break;
            case "selected-prefix": bytes[8192 + 60] ^= 1; break;
            case "padding": bytes[^1] = 1; break;
            case "extra-tail": bytes = [.. bytes, .. new byte[4096]]; break;
            case "partial-tail": bytes = bytes[..^4096]; break;
            case "slot-identity": bytes[4096 + 32] ^= 1; break;
            case "candidate-evidence-missing": catalog = EvidenceCatalogV1.Empty; break;
        }
        Assert.Equal(ArchiveRecoveryDecisionV4.Held, CompletedArchiveSelectionV4.Recover(x.Intent, segment with { Bytes = bytes }, candidate, catalog, true));
        Assert.Equal(x.Segment.Bytes, segment.Bytes);
    }

    [Fact]
    public void Exact_record_mapping_coalesces_duplicates_and_compaction_preserves_all_witnesses()
    {
        var x = Build(); byte[] bytes = StagedJournalEnvelopeV3Codec.Serialize(x.Envelope, x.Catalog);
        var selected = CompletedArchiveSelectionV4.SelectRecords([bytes, bytes], x.Catalog);
        Assert.Single(selected.Records); Assert.Equal(0, Assert.Single(selected.Transfers).Value.InitialPendingCount);
        CompletedArchiveSelectionV4.RequireEquivalent(selected, CompletedArchiveSelectionV4.SelectRecords([bytes], x.Catalog));
        byte[] changed = StagedJournalEnvelopeV3Codec.Serialize(x.Envelope with { RecordRevision = 11 }, x.Catalog);
        Assert.Throws<InvalidDataException>(() => CompletedArchiveSelectionV4.SelectRecords([bytes, changed], x.Catalog));
        Assert.Throws<InvalidDataException>(() => CompletedArchiveSelectionV4.RequireEquivalent(selected,
            CompletedArchiveSelectionV4.SelectRecords([], x.Catalog)));
    }

    [Theory]
    [InlineData(1)] [InlineData(32)]
    public void Full_source_target_compaction_inventories_serialize_and_preserve_creation_cursor(int count)
    {
        var x = Build(); var inventory = new ResourceInventoryV4(x.State.InstallationId, SegmentIdentity, (uint)count, 1, Guid.Empty, 1, Guid.Empty, 0);
        var sources = Enumerable.Range(0, count).Select(i => new ArchiveSourceV4((uint)i + 1, new(ulong.MaxValue, (ulong)i + 1000, (ulong)i + 2000), 1, 8192, 3)).ToImmutableArray();
        var targets = Enumerable.Range(0, count).Select(i => new ArchiveTargetV4((uint)(count + i + 1), ArchiveCreationPhaseV4.IdentityCaptured,
            new(ulong.MaxValue, (ulong)i + 3000, (ulong)i + 4000), 1, 8192)).ToImmutableArray();
        var intent = new CompletedCompactionIntentV4(3, Transaction, x.State.InstallationId, SegmentIdentity,
            Convert.ToBase64String(ResourceStorageCodecV4.Serialize(inventory)), CompactionPhaseV4.Prepared, sources, targets,
            (uint)count + 1, (uint)(2 * count), 16777216, 3, null, null);
        byte[] bytes = CompletedArchiveV4Codec.Serialize(intent);
        Assert.Equal(bytes, CompletedArchiveV4Codec.Serialize(CompletedArchiveV4Codec.ReadCompactionIntent(bytes)));
        Assert.Throws<InvalidDataException>(() => CompletedArchiveV4Codec.Serialize(intent with { Sources = sources.Add(sources[0]) }));
        var legacy = intent with { SourceInventoryFormat = 1, ExpectedInventoryBytes = null,
            ExpectedLegacyInventory = new(SegmentIdentity, 128, ResourceSerializationLimitsV3Tests.Hash, 1, (uint)count),
            Sources = sources.Select(s => s with { Format = 1, FrontierSequence = null }).ToImmutableArray(),
            MigrationCursor = new(0, 4096, x.Envelope.RecordId, 0, MigrationPhaseV4.Prepared) };
        byte[] legacyBytes = CompletedArchiveV4Codec.Serialize(legacy);
        Assert.Equal(legacyBytes, CompletedArchiveV4Codec.Serialize(CompletedArchiveV4Codec.ReadCompactionIntent(legacyBytes)));
        Console.WriteLine($"Rev9Compaction count={count} modern={bytes.Length} legacy={legacyBytes.Length} limit=65536");
    }

    internal static readonly Guid Transaction = Guid.Parse("20000000-1111-2222-3333-444444444444");
    private static readonly Guid PriorTransaction = Guid.Parse("20000001-1111-2222-3333-444444444444");
    internal static readonly StagedStageIdentity SegmentIdentity = new(ulong.MaxValue, 700, 701);
    internal sealed record ArchiveFixture(ResourceStateV4 State, StagedJournalEnvelopeV3 Envelope, EvidenceCatalogV1 Catalog, ImmutableArray<EvidenceHeldImageV1> Images);
    internal static ArchiveFixture Build()
    {
        var f = EvidencePackV1Tests.Fixture(); var x = ResourceStateV4Tests.Build(f);
        var core = f.Entry with { State = TransferJournalState.Released };
        var owner = f.Owner with { RecordId = Guid.Parse("10000002-1111-2222-3333-444444444444"), Kind = EvidenceKindV1.EntryCore };
        var image = EvidencePackCodecV1.Serialize(EvidencePackCodecV1.Preflight(owner, 4096, core, null), new(ulong.MaxValue, 502, 602));
        var images = x.Images.Add(new(image.Reference, new(image.Reference.Identity, true, true, false), 4096, image.Bytes));
        var first = x.State.EvidenceClaims[0]!;
        var claim = first with { RecordId = owner.RecordId, Kind = EvidenceKindV1.EntryCore, Identity = image.Reference.Identity,
            Length = image.Bytes.Length, Sha256 = image.Reference.Sha256, ReservedMax = image.Bytes.Length, MeasuredAllocation = image.Bytes.Length };
        var state = x.State with { EvidenceClaims = x.State.EvidenceClaims.SetItem(2, claim), ChargeBytes = x.State.ChargeBytes + image.Bytes.Length };
        var envelope = new StagedJournalEnvelopeV3(3, 4, state.InstallationId, JournalRecordKindV4.TransferClosure,
            Guid.Parse("30000000-1111-2222-3333-444444444444"), state.TransferId, state.Revision, null,
            Convert.ToBase64String(EvidenceReferenceCodecV1.Serialize(image.Reference)), state, null, null, null, null);
        return new(state, envelope, new(images), images);
    }
    private sealed record RecoveryFixture(CompletedAppendIntentV4 Intent, ArchiveSegmentObservationV4 Segment,
        ArchiveCandidateObservationV4 Candidate, EvidenceCatalogV1 Catalog);
    private static RecoveryFixture Recovery(int sequence)
    {
        var x = Build(); byte[] candidate = StagedJournalEnvelopeV3Codec.Serialize(x.Envelope, x.Catalog);
        byte[] frame = ResourceStorageCodecV4.Serialize(new(x.Envelope.RecordId, candidate), 4096);
        long expectedEnd = 8192 + (sequence == 1 ? 0 : frame.Length); long targetEnd = expectedEnd + frame.Length;
        var location = new ResourceHistoryHandoffV3(Transaction, x.Envelope.RecordId, 1, x.State.InstallationId, x.State.Revision,
            ResourceHandoffPhaseV3.Prepared, new(ulong.MaxValue, 800, 801), x.Envelope.RecordId.ToString("N") + ".resource", candidate.Length,
            Convert.ToHexString(SHA256.HashData(candidate)), 1, SegmentIdentity, 4096, expectedEnd, (ulong)sequence,
            expectedEnd, frame.Length, targetEnd, (ulong)sequence + 1, 0, targetEnd);
        var intent = new CompletedAppendIntentV4(3, location, null, x.Envelope.RecordRevision, null, null);
        byte[] bytes = new byte[(int)targetEnd];
        ResourceStorageCodecV4.Serialize(new ResourceFrontierV4(x.State.InstallationId, SegmentIdentity, 4096, 0, 1, 8192, Guid.Empty)).CopyTo(bytes, 0);
        if (sequence == 2)
        {
            frame.CopyTo(bytes, 8192);
            ResourceStorageCodecV4.Serialize(new ResourceFrontierV4(x.State.InstallationId, SegmentIdentity, 4096, 1, 2, expectedEnd, PriorTransaction)).CopyTo(bytes, 4096);
        }
        frame.CopyTo(bytes, (int)expectedEnd);
        return new(intent, new(SegmentIdentity, true, true, false, bytes), new(location.CandidateIdentity!, true, true, false, candidate), x.Catalog);
    }
}
#endif
