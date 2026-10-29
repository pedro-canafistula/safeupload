#if SAFEUPLOAD_ADMISSION_EVIDENCE
using System.Collections.Immutable;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json.Nodes;

namespace SafeUpload.Agent.Service.Interception;

internal sealed record CompletedAppendIntentV4(int Version, ResourceHistoryHandoffV3 Location,
    Guid? ExpectedPreviousRecordId, long ExpectedRecordRevision, Guid? CompactionTransactionId, LegacySourceV4? LegacySource);
internal enum CompactionPhaseV4 { Prepared = 1, Copied = 2, Selected = 3, CleanupComplete = 4 }
internal enum ArchiveCreationPhaseV4 { ReservedNotIssued = 1, CreationMayHaveStarted = 2, IdentityCaptured = 3, Committed = 4 }
internal sealed record ArchiveSourceV4(uint Number, StagedStageIdentity Identity, ulong? FrontierSequence, long End, uint Format);
internal sealed record ArchiveTargetV4(uint Number, ArchiveCreationPhaseV4 CreationPhase, StagedStageIdentity? Identity, ulong FrontierSequence, long End);
internal sealed record LegacyInventoryV4(StagedStageIdentity Identity, long EndOfFile, string Sha256, uint Version, uint SegmentCount);
internal enum MigrationPhaseV4 { Prepared = 1, FrameCommitted = 2 }
internal sealed record ArchiveMigrationCursorV4(uint SourceIndex, long FrameOffset, Guid RecordId, uint TargetIndex, MigrationPhaseV4 Phase);
internal sealed record CompletedCompactionIntentV4(int Version, Guid TransactionId, Guid InstallationId, StagedStageIdentity ExpectedInventoryIdentity,
    string? ExpectedInventoryBytes, CompactionPhaseV4 Phase, ImmutableArray<ArchiveSourceV4> Sources, ImmutableArray<ArchiveTargetV4> Targets,
    uint NewFirstSelected, uint NewRangeEnd, long ReservedPhysicalGrowth, uint SourceInventoryFormat,
    LegacyInventoryV4? ExpectedLegacyInventory, ArchiveMigrationCursorV4? MigrationCursor);
internal sealed record ArchiveCandidateObservationV4(StagedStageIdentity Identity, bool SecurityMatches, bool SingleLink, bool ReparsePoint, byte[] Bytes);

internal static class CompletedArchiveV4Codec
{
    internal const int ControlMaximumBytes = 65536;
    internal static byte[] Serialize(CompletedAppendIntentV4 intent)
    {
        Validate(intent);
        var location = JsonNode.Parse(ResourceJsonV3.Serialize(intent.Location, ControlMaximumBytes))!.AsObject();
        var root = new JsonObject { ["Version"] = intent.Version };
        foreach (var property in location) root.Add(property.Key, property.Value?.DeepClone());
        root.Add("ExpectedPreviousRecordId", JsonNode.Parse(ResourceJsonV3.Serialize(intent.ExpectedPreviousRecordId, ControlMaximumBytes)));
        root.Add("ExpectedRecordRevision", intent.ExpectedRecordRevision);
        root.Add("CompactionTransactionId", JsonNode.Parse(ResourceJsonV3.Serialize(intent.CompactionTransactionId, ControlMaximumBytes)));
        root.Add("LegacySource", JsonNode.Parse(ResourceJsonV3.Serialize(intent.LegacySource, ControlMaximumBytes)));
        return ResourceJsonV3.Serialize(root, ControlMaximumBytes);
    }
    internal static CompletedAppendIntentV4 ReadAppendIntent(ReadOnlySpan<byte> bytes)
    {
        EvidenceBinaryV1.Need(bytes.Length is > 0 and <= ControlMaximumBytes, "Append intent byte bound exceeded.");
        try
        {
            ResourceJsonV3.CheckTokens(bytes); var root = JsonNode.Parse(bytes)!.AsObject();
            int version = Take<int>(root, "Version");
            Guid? previous = Take<Guid?>(root, "ExpectedPreviousRecordId");
            long revision = Take<long>(root, "ExpectedRecordRevision");
            Guid? compaction = Take<Guid?>(root, "CompactionTransactionId");
            LegacySourceV4? legacy = Take<LegacySourceV4?>(root, "LegacySource");
            var location = ResourceJsonV4.Deserialize<ResourceHistoryHandoffV3>(Encoding.UTF8.GetBytes(root.ToJsonString()), ControlMaximumBytes);
            var value = new CompletedAppendIntentV4(version, location, previous, revision, compaction, legacy);
            EvidenceBinaryV1.Need(bytes.SequenceEqual(Serialize(value)), "Noncanonical append intent."); return value;
        }
        catch (Exception error) when (error is System.Text.Json.JsonException or ArgumentException or InvalidOperationException or OverflowException)
        { throw new InvalidDataException("Malformed append intent.", error); }
    }
    private static T Take<T>(JsonObject root, string name)
    {
        EvidenceBinaryV1.Need(root.TryGetPropertyValue(name, out var node), "Missing append intent property.");
        root.Remove(name);
        if (node is null)
        {
            EvidenceBinaryV1.Need(default(T) is null, "Required append intent property is null."); return default!;
        }
        return ResourceJsonV4.Deserialize<T>(Encoding.UTF8.GetBytes(node.ToJsonString()), ControlMaximumBytes);
    }
    internal static void Validate(CompletedAppendIntentV4 value)
    {
        var location = value.Location;
        EvidenceBinaryV1.Need(value.Version == 3 && value.ExpectedRecordRevision > 0 && location.ExpectedLedgerRevision > 0 &&
            value.ExpectedPreviousRecordId != Guid.Empty && value.CompactionTransactionId != Guid.Empty, "Append owner/revision differs.");
        ValidateLocation(location);
        if (value.LegacySource is { } legacy)
        { StagedJournalEnvelopeV3Codec.ValidateLegacy(legacy); EvidenceBinaryV1.Need(value.CompactionTransactionId.HasValue && location.RecordKind == 4, "Unowned legacy append."); }
        else EvidenceBinaryV1.Need(location.RecordKind != 4, "Legacy append lost its source assignment.");
        EvidenceBinaryV1.Need((location.RecordKind == 3) == value.ExpectedPreviousRecordId.HasValue, "Append base/delta null rules differ.");
    }
    internal static byte[] Serialize(CompletedCompactionIntentV4 intent)
    { Validate(intent); return ResourceJsonV3.Serialize(intent, ControlMaximumBytes); }
    internal static CompletedCompactionIntentV4 ReadCompactionIntent(ReadOnlySpan<byte> bytes)
    {
        var value = ResourceJsonV4.Deserialize<CompletedCompactionIntentV4>(bytes, ControlMaximumBytes);
        EvidenceBinaryV1.Need(bytes.SequenceEqual(Serialize(value)), "Noncanonical compaction intent."); return value;
    }
    internal static void Validate(CompletedCompactionIntentV4 value)
    {
        EvidenceBinaryV1.Need(value.Version == 3 && Enum.IsDefined(value.Phase) && value.ReservedPhysicalGrowth > 0 &&
            !value.Sources.IsDefault && value.Sources.Length is > 0 and <= 32 && !value.Targets.IsDefault && value.Targets.Length is > 0 and <= 32,
            "Compaction dimensions/phase differ.");
        ResourceJsonV3.Id(value.TransactionId); ResourceJsonV3.Id(value.InstallationId); ResourceJsonV3.Identity(value.ExpectedInventoryIdentity);
        uint first, oldEnd;
        if (value.SourceInventoryFormat == 3)
        {
            EvidenceBinaryV1.Need(value.ExpectedInventoryBytes is not null && value.ExpectedLegacyInventory is null, "Modern inventory null rules differ.");
            var inventory = ResourceStorageCodecV4.ReadInventory(ResourceJsonV3.Base64(value.ExpectedInventoryBytes!, 128));
            EvidenceBinaryV1.Need(inventory.InstallationId == value.InstallationId && inventory.RangeEnd != 0, "Compaction installation/selected inventory differs.");
            first = inventory.FirstSelectedSegment; oldEnd = inventory.RangeEnd;
        }
        else
        {
            EvidenceBinaryV1.Need(value.SourceInventoryFormat == 1 && value.ExpectedInventoryBytes is null && value.ExpectedLegacyInventory is not null,
                "Legacy inventory null rules differ.");
            var legacy = value.ExpectedLegacyInventory!; ResourceJsonV3.Identity(legacy.Identity); ResourceJsonV3.Hex(legacy.Sha256);
            EvidenceBinaryV1.Need(legacy.Identity == value.ExpectedInventoryIdentity && legacy.Version == 1 && legacy.EndOfFile > 0 &&
                legacy.SegmentCount is > 0 and <= int.MaxValue, "Legacy inventory differs.");
            first = 1; oldEnd = legacy.SegmentCount;
        }
        var identities = new HashSet<StagedStageIdentity>();
        for (int index = 0; index < value.Sources.Length; index++)
        {
            var source = value.Sources[index]; ResourceJsonV3.Identity(source.Identity);
            EvidenceBinaryV1.Need(source.Number == checked(first + index) && source.Number <= oldEnd && identities.Add(source.Identity) &&
                source.Format is 1 or 3 && source.End is >= 4096 and <= 4194304 &&
                (source.Format == 1 ? source.FrontierSequence is null : source.FrontierSequence is > 0), "Compaction source prefix differs.");
        }
        for (int index = 0; index < value.Targets.Length; index++)
        {
            var target = value.Targets[index];
            EvidenceBinaryV1.Need(target.Number == checked(oldEnd + 1 + index) && Enum.IsDefined(target.CreationPhase) &&
                target.FrontierSequence > 0 && target.End is >= 8192 and <= 4194304 &&
                (target.CreationPhase is ArchiveCreationPhaseV4.IdentityCaptured or ArchiveCreationPhaseV4.Committed) == (target.Identity is not null),
                "Compaction target number/phase differs.");
            if (target.Identity is { } identity) { ResourceJsonV3.Identity(identity); EvidenceBinaryV1.Need(identities.Add(identity), "Target aliases retained storage."); }
            if (value.Phase != CompactionPhaseV4.Prepared) EvidenceBinaryV1.Need(target.CreationPhase == ArchiveCreationPhaseV4.Committed, "Selected incomplete target.");
        }
        uint afterPrefix = checked(value.Sources[^1].Number + 1);
        uint expectedFirst = afterPrefix <= oldEnd ? afterPrefix : value.Targets[0].Number;
        EvidenceBinaryV1.Need(value.NewFirstSelected == expectedFirst && value.NewRangeEnd == value.Targets[^1].Number, "Compaction selection skips retained segments.");
        if (value.MigrationCursor is { } cursor)
        {
            ResourceJsonV3.Id(cursor.RecordId);
            EvidenceBinaryV1.Need(cursor.SourceIndex < value.Sources.Length && cursor.TargetIndex < value.Targets.Length &&
                value.Sources[(int)cursor.SourceIndex].Format == 1 && cursor.FrameOffset >= 4096 &&
                cursor.FrameOffset < value.Sources[(int)cursor.SourceIndex].End && Enum.IsDefined(cursor.Phase), "Migration cursor differs.");
        }
    }
    internal static void ValidateLocation(ResourceHistoryHandoffV3 value)
    {
        ResourceJsonV3.Id(value.TransactionId); ResourceJsonV3.Id(value.RecordId); ResourceJsonV3.Id(value.InstallationId);
        EvidenceBinaryV1.Alignment(checked((int)value.Alignment)); ResourceJsonV3.Hex(value.CandidateSha256);
        EvidenceBinaryV1.Need(value.RecordKind is >= 1 and <= 4 && Enum.IsDefined(value.Phase) && value.CandidateLeaf == value.RecordId.ToString("N") + ".resource" &&
            value.CandidateBytes is > 0 and <= 131072 && value.SegmentNumber > 0 && value.ExpectedFrontierSequence > 0 &&
            value.ExpectedFrontierSequence != ulong.MaxValue && value.ExpectedFrontier >= 2 * value.Alignment && value.ExpectedFrontier % value.Alignment == 0 &&
            value.FrameOffset == value.ExpectedFrontier && value.FrameStride == (60 + value.CandidateBytes + value.Alignment - 1) / value.Alignment * value.Alignment &&
            value.TargetFrontier == checked(value.FrameOffset + value.FrameStride) && value.TargetFrontier <= 4194304 &&
            value.TargetFrontierSequence == value.ExpectedFrontierSequence + 1 && value.SharedPhysicalBefore >= 0 && value.ReservedPhysicalGrowth >= 0,
            "Append frame/location differs.");
        bool captured = value.Phase is not (ResourceHandoffPhaseV3.ReservedNotIssued or ResourceHandoffPhaseV3.CreationMayHaveStarted);
        EvidenceBinaryV1.Need(captured == (value.CandidateIdentity is not null), "Candidate capture phase differs.");
        if (captured) ResourceJsonV3.Identity(value.CandidateIdentity);
        if (value.Phase is ResourceHandoffPhaseV3.Prepared or ResourceHandoffPhaseV3.FrameDurable or ResourceHandoffPhaseV3.SharedCommitted)
            ResourceJsonV3.Identity(value.SegmentIdentity);
    }
    internal static StagedJournalEnvelopeV3 ReadCandidate(CompletedAppendIntentV4 intent, ArchiveCandidateObservationV4 observed, EvidenceCatalogV1 evidence)
    {
        Validate(intent); var location = intent.Location;
        EvidenceBinaryV1.Need(location.Phase is ResourceHandoffPhaseV3.Prepared or ResourceHandoffPhaseV3.FrameDurable or ResourceHandoffPhaseV3.SharedCommitted &&
            observed.Identity == location.CandidateIdentity && observed.SecurityMatches && observed.SingleLink && !observed.ReparsePoint &&
            observed.Bytes.Length == location.CandidateBytes && Convert.ToHexString(SHA256.HashData(observed.Bytes)) == location.CandidateSha256,
            "Candidate is not a complete captured immutable object.");
        var envelope = StagedJournalEnvelopeV3Codec.Deserialize(observed.Bytes, evidence);
        EvidenceBinaryV1.Need(envelope.RecordId == location.RecordId && envelope.InstallationId == location.InstallationId &&
            (uint)envelope.RecordKind == location.RecordKind && envelope.RecordRevision == intent.ExpectedRecordRevision &&
            envelope.PreviousRecordId == intent.ExpectedPreviousRecordId && envelope.LegacySource == intent.LegacySource,
            "Candidate differs from append intent."); return envelope;
    }
}
#endif
