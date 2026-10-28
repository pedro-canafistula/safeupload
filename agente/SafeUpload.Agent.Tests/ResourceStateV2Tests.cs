#if SAFEUPLOAD_ADMISSION_EVIDENCE
using System.Buffers.Binary;
using System.Collections.Immutable;
using System.Text;
using System.Text.Json.Nodes;
using SafeUpload.Agent.Service.Interception;

namespace SafeUpload.Agent.Tests;

public sealed class ResourceStateV2Tests
{
    private const long MiB = 1024 * 1024, Capacity = 16 * MiB, Meta = MiB, Unit = 65536;
    private static readonly Guid Transfer = new("11223344-5566-7788-99aa-bbccddeeff00");
    private static readonly Guid Driver = new("ffeeddcc-bbaa-9988-7766-554433221100");
    private static readonly StagedStageIdentity Stage = new(ulong.MaxValue, 0x123456789abcdef0, 0xfedcba9876543210);
    private static readonly StagedStageIdentity Companion = new(ulong.MaxValue, 11, 12);
    private static readonly StagedStageIdentity Snapshot = new(ulong.MaxValue, 21, 22);

    [Fact]
    public void Complete_historical_intent_and_unsigned_identity_words_round_trip_without_renewing_time()
    {
        var state = Retired();
        byte[] bytes = ResourceStateCodecV2.Serialize(state, 4096);
        var loaded = ResourceStateCodecV2.Deserialize(bytes, 4096);
        Assert.Equal(bytes, ResourceStateCodecV2.Serialize(loaded, 4096));
        Assert.Equal(ulong.MaxValue, loaded.AcceptedRetirement!.ConnectionCookie);
        Assert.Equal(ulong.MaxValue, loaded.AcceptedRetirement.Sequence);
        Assert.Equal(ulong.MaxValue, loaded.Binding!.Identity.VolumeSerialNumber);
        Assert.Equal(Stage.FileIdHigh, loaded.Binding.Identity.FileIdHigh);
        Assert.Equal(Stage.FileIdLow, loaded.Binding.Identity.FileIdLow);
        Assert.Equal(state.OriginalRequest, loaded.OriginalRequest);
        Assert.Equal(4 * Unit + Meta, loaded.ChargeBytes);
    }

    [Theory]
    [InlineData("GrowthClosed")]
    [InlineData("GrantMayHaveEscaped")]
    [InlineData("FullDebitHeld")]
    [InlineData("Binding")]
    [InlineData("AcceptedRetirement")]
    [InlineData("StageRelease")]
    [InlineData("PendingCompanion")]
    [InlineData("ChargeBytes")]
    [InlineData("OriginalRequest")]
    public void Even_false_or_null_properties_are_required(string property)
    {
        var json = Node(Preparing()); json.Remove(property);
        Assert.Throws<InvalidDataException>(() => Read(json));
    }

    [Theory]
    [InlineData("unknown")]
    [InlineData("duplicate")]
    [InlineData("nested-duplicate")]
    [InlineData("identity-word-missing")]
    [InlineData("identity-word-string")]
    [InlineData("numeric-string")]
    [InlineData("unknown-phase")]
    [InlineData("unknown-slot")]
    [InlineData("extra-slot")]
    [InlineData("negative-measurement")]
    [InlineData("partial-measurement")]
    public void Corrupt_encodings_and_incomplete_custody_return_no_record(string mutation)
    {
        var json = Node(Retired());
        if (mutation == "duplicate")
        {
            string text = json.ToJsonString().Replace("\"Version\":2", "\"Version\":2,\"Version\":2", StringComparison.Ordinal);
            Assert.Throws<InvalidDataException>(() => ResourceStateCodecV2.Deserialize(Encoding.UTF8.GetBytes(text), 4096)); return;
        }
        if (mutation == "nested-duplicate")
        {
            string text = json.ToJsonString().Replace("\"FileIdLow\":", "\"FileIdLow\":0,\"FileIdLow\":", StringComparison.Ordinal);
            Assert.Throws<InvalidDataException>(() => ResourceStateCodecV2.Deserialize(Encoding.UTF8.GetBytes(text), 4096)); return;
        }
        switch (mutation)
        {
            case "unknown": json["IgnoreMe"] = true; break;
            case "identity-word-missing": json["Binding"]!["Identity"]!.AsObject().Remove("FileIdHigh"); break;
            case "identity-word-string": json["Binding"]!["Identity"]!["FileIdHigh"] = "0"; break;
            case "numeric-string": json["ChargeBytes"] = "1310720"; break;
            case "unknown-phase": json["Phase"] = 99; break;
            case "unknown-slot": json["Slots"]![0]!["Phase"] = 99; break;
            case "extra-slot": json["Slots"]!.AsArray().Add((JsonNode?)null); break;
            case "negative-measurement": json["Slots"]![0]!["AllocationSize"] = -1; break;
            case "partial-measurement": json["Slots"]![0]!["AllocationSize"] = null; break;
            default: throw new ArgumentOutOfRangeException(nameof(mutation));
        }
        Assert.Throws<InvalidDataException>(() => Read(json));
    }

    [Theory]
    [InlineData(1)]
    [InlineData(2)]
    [InlineData(3)]
    [InlineData(5)]
    public void Zero_allocation_or_unresolved_copy_never_reduces_the_reserved_envelope(int phaseCode)
    {
        var phase = (ResourceSlotPhaseV2)phaseCode;
        var state = Retired();
        var copy = Slot(1, ResourceSlotRoleV2.Snapshot, phase, phase == ResourceSlotPhaseV2.Mutable ? Snapshot : null);
        state = state with { Slots = state.Slots.SetItem(1, copy), ChargeBytes = 4 * Capacity + Meta };
        Assert.Equal(4 * Capacity + Meta, RoundTrip(state).ChargeBytes);
        Assert.Throws<InvalidDataException>(() => ResourceStateCodecV2.Serialize(state with { ChargeBytes = 4 * Unit + Meta }, 4096));
        Assert.Throws<InvalidDataException>(() => ResourceStateCodecV2.Serialize(state with
        { Slots = state.Slots.SetItem(1, copy with { EndOfFile = 0, AllocationSize = 0 }) }, 4096));
    }

    [Fact]
    public void Immutable_reader_keeps_measured_allocation_without_reinflating_or_claiming_metadata_only()
    {
        var state = Retired();
        var reader = Slot(1, ResourceSlotRoleV2.Snapshot, ResourceSlotPhaseV2.ImmutableReleasePending, Snapshot) with
        { ExpectedLength = 1, EndOfFile = 1, AllocationSize = 4096 };
        state = state with { Slots = state.Slots.SetItem(1, reader) };
        Assert.Equal(4 * Unit + Meta, RoundTrip(state).ChargeBytes);
        Assert.Throws<InvalidDataException>(() => ResourceStateCodecV2.Serialize(state with
        { Phase = ResourceStatePhaseV2.MetadataOnly, ChargeBytes = Meta }, 4096));
    }

    [Fact]
    public void Retirement_large_preallocation_must_match_the_original_stage_even_at_zero_eof()
    {
        var state = Retired(); var slot = state.Slots[0]!;
        state = state with
        {
            Slots = state.Slots.SetItem(0, slot with { ExpectedLength = 0, EndOfFile = 0, AllocationSize = Capacity }),
            AcceptedRetirement = state.AcceptedRetirement! with { EndOfFile = 0, AllocationSize = Capacity },
            ChargeBytes = 4 * Capacity + Meta
        };
        Assert.Equal(4 * Capacity + Meta, RoundTrip(state).ChargeBytes);
        Assert.Throws<InvalidDataException>(() => ResourceStateCodecV2.Serialize(state with
        { Slots = state.Slots.SetItem(0, state.Slots[0]! with { AllocationSize = 0 }), ChargeBytes = Meta }, 4096));
    }

    [Fact]
    public void Growth_closure_and_uncertain_custody_retain_full_debit_until_explicit_retirement()
    {
        var state = Writable() with { GrowthClosed = true, Phase = ResourceStatePhaseV2.Closing };
        Assert.Equal(4 * Capacity + Meta, RoundTrip(state).ChargeBytes);
        Assert.Throws<InvalidDataException>(() => ResourceStateCodecV2.Serialize(state with { ChargeBytes = Meta }, 4096));
        var retired = Retired() with { FullDebitHeld = true, ChargeBytes = 4 * Capacity + Meta };
        Assert.Equal(4 * Capacity + Meta, RoundTrip(retired).ChargeBytes);
    }

    [Fact]
    public void Released_original_stage_retains_its_witness_when_a_slot_is_reused()
    {
        var state = MetadataOnly();
        Assert.Equal(Meta, RoundTrip(state).ChargeBytes);
        var successor = Slot(0, ResourceSlotRoleV2.Snapshot, ResourceSlotPhaseV2.Immutable, Snapshot) with
        { Incarnation = 2, ExpectedLength = 1, EndOfFile = 1, AllocationSize = 4096 };
        state = state with { Phase = ResourceStatePhaseV2.WriteRetired, Slots = state.Slots.SetItem(0, successor), ChargeBytes = 4 * Unit + Meta };
        Assert.Equal(4 * Unit + Meta, RoundTrip(state).ChargeBytes);
        Assert.Throws<InvalidDataException>(() => ResourceStateCodecV2.Serialize(state with { StageRelease = null }, 4096));
        Assert.Throws<InvalidDataException>(() => ResourceStateCodecV2.Serialize(state with
        { StageRelease = state.StageRelease! with { Incarnation = 2 } }, 4096));
        Assert.Throws<InvalidDataException>(() => ResourceStateCodecV2.Serialize(state with
        { Slots = state.Slots.SetItem(0, successor with { Phase = ResourceSlotPhaseV2.Released, Release = state.StageRelease }) }, 4096));
    }

    [Fact]
    public void Metadata_only_needs_resolved_slots_and_an_irreversible_closure()
    {
        var state = MetadataOnly();
        Assert.Throws<InvalidDataException>(() => ResourceStateCodecV2.Serialize(state with { FullDebitHeld = true }, 4096));
        Assert.Throws<InvalidDataException>(() => ResourceStateCodecV2.Serialize(state with { ClosureKind = ResourceClosureV2.None }, 4096));
        var unissued = Preparing() with { GrowthClosed = true, Phase = ResourceStatePhaseV2.ClosedUnissued, ClosureKind = ResourceClosureV2.UnissuedClosed };
        var proof = new ResourceReleaseStateV2
        { Kind = ResourceReleaseKindV2.NeverIssued, Slot = 0, Incarnation = 1, Identity = null, WitnessId = Guid.NewGuid(), ClaimRevision = 1 };
        unissued = unissued with { Slots = unissued.Slots.SetItem(0, unissued.Slots[0]! with { Phase = ResourceSlotPhaseV2.Released, Release = proof }) };
        Assert.Equal(4 * Capacity + Meta, RoundTrip(unissued).ChargeBytes); // explicit phase still holds full
        Assert.Equal(Meta, RoundTrip(unissued with { Phase = ResourceStatePhaseV2.MetadataOnly, ChargeBytes = Meta }).ChargeBytes);
        Assert.Throws<InvalidDataException>(() => ResourceStateCodecV2.Serialize(unissued with { GrantMayHaveEscaped = true }, 4096));
    }

    [Fact]
    public void Pending_companion_keeps_full_debit_and_its_target_revision_survives_later_closure()
    {
        var state = Writable();
        var pending = new ResourcePendingCompanionV2
        {
            OperationId = Guid.NewGuid(), Predecessor = state.Companion, TargetCapacity = 2 * Capacity,
            TargetRevision = 4, ReplacementIncarnation = 1, ReplacementIdentity = new(ulong.MaxValue, 31, 32),
            Phase = ResourceCompanionPhaseV2.Prepared
        };
        state = state with
        {
            AuthorizedCapacity = 2 * Capacity, Revision = 5, GrantRevision = 4, PendingCompanion = pending,
            Slots = state.Slots.SetItem(0, state.Slots[0]! with { ReservedMax = 2 * Capacity }),
            Phase = ResourceStatePhaseV2.Closing, GrowthClosed = true, ChargeBytes = 8 * Capacity + Meta
        };
        Assert.Equal(8 * Capacity + Meta, RoundTrip(state).ChargeBytes);
        Assert.Throws<InvalidDataException>(() => ResourceStateCodecV2.Serialize(state with
        { PendingCompanion = pending with { TargetRevision = 5 } }, 4096));
        Assert.Throws<InvalidDataException>(() => ResourceStateCodecV2.Serialize(state with
        { PendingCompanion = pending with { ReplacementIdentity = null } }, 4096));
        Assert.Throws<InvalidDataException>(() => ResourceStateCodecV2.Serialize(state with { PendingCompanion = null }, 4096));
        var retired = Retired();
        state = state with
        {
            Revision = 6, Phase = ResourceStatePhaseV2.WriteRetired, ClosureKind = ResourceClosureV2.DriverWriteRetired,
            AcceptedRetirement = retired.AcceptedRetirement! with { AcceptedRevision = 6 },
            Slots = state.Slots.SetItem(0, retired.Slots[0]! with { ReservedMax = 2 * Capacity })
        };
        Assert.Equal(8 * Capacity + Meta, RoundTrip(state).ChargeBytes); // driver never adopted the larger service grant
        state = state with
        {
            Revision = 7, PendingCompanion = null, Companion = new()
            { Identity = pending.ReplacementIdentity!, Capacity = 2 * Capacity, GrantRevision = 4 }, ChargeBytes = 4 * Unit + Meta
        };
        Assert.Equal(4 * Unit + Meta, RoundTrip(state).ChargeBytes);
    }

    [Fact]
    public void Content_alignment_does_not_inflate_metadata_defaults_and_overflow_fails_closed()
    {
        var state = Preparing() with { Alignment = MiB };
        Assert.Equal(Meta, RoundTrip(state).MetadataDebit);
        Assert.Throws<InvalidDataException>(() => ResourceStateCodecV2.Serialize(state with { MetadataDebit = 16 * MiB }, 4096));
        Assert.Throws<InvalidDataException>(() => ResourceStateCodecV2.Serialize(state, 8192));
        long huge = long.MaxValue / MiB * MiB;
        state = state with { AuthorizedCapacity = huge, Slots = state.Slots.SetItem(0, state.Slots[0]! with { ReservedMax = huge }) };
        Assert.Throws<InvalidDataException>(() => ResourceStateCodecV2.Serialize(state, 4096));
    }

    [Fact]
    public void Original_intent_mutations_and_parser_storage_bounds_refuse()
    {
        var state = Preparing(); byte[] raw = Convert.FromBase64String(state.OriginalRequest); raw[^1] = 1;
        Assert.Throws<InvalidDataException>(() => ResourceStateCodecV2.Serialize(state with { OriginalRequest = Convert.ToBase64String(raw) }, 4096));
        Assert.Throws<InvalidDataException>(() => ResourceStateCodecV2.Serialize(state with { TransferId = Guid.NewGuid() }, 4096));
        Assert.Throws<InvalidDataException>(() => ResourceStateCodecV2.Deserialize(new byte[65537], 4096));
        byte[] invalidUtf8 = ResourceStateCodecV2.Serialize(state, 4096); invalidUtf8[1] = 0xff;
        Assert.Throws<InvalidDataException>(() => ResourceStateCodecV2.Deserialize(invalidUtf8, 4096));
    }

    private static ResourceStateV2 RoundTrip(ResourceStateV2 state) => ResourceStateCodecV2.Deserialize(ResourceStateCodecV2.Serialize(state, 4096), 4096);
    private static JsonObject Node(ResourceStateV2 state) => JsonNode.Parse(ResourceStateCodecV2.Serialize(state, 4096))!.AsObject();
    private static ResourceStateV2 Read(JsonObject json) => ResourceStateCodecV2.Deserialize(Encoding.UTF8.GetBytes(json.ToJsonString()), 4096);
    private static ResourceStateV2 Preparing() => new()
    {
        Version = 2, TransferId = Transfer, DriverInstanceId = Driver, Sid = "S-1-5-21-11-22-33-1000", OriginalRequest = Original(),
        Alignment = Unit, MetadataGranularity = 4096, AuthorizedCapacity = Capacity, MetadataDebit = Meta, Revision = 1, GrantRevision = 0,
        GrowthClosed = false, GrantMayHaveEscaped = false, Phase = ResourceStatePhaseV2.Preparing, ClosureKind = ResourceClosureV2.None,
        Binding = null, CurrentDestinationGeneration = null, Slots = ImmutableArray.Create<ResourceSlotStateV2?>(
            Slot(0, ResourceSlotRoleV2.Stage, ResourceSlotPhaseV2.ReservedNotIssued, null), null, null, null),
        AcceptedRetirement = null, StageRelease = null, Companion = null, PendingCompanion = null, FullDebitHeld = false, ChargeBytes = 4 * Capacity + Meta
    };
    private static ResourceStateV2 Writable()
    {
        var state = Preparing();
        return state with
        {
            Revision = 3, GrantRevision = 2, GrantMayHaveEscaped = true, Phase = ResourceStatePhaseV2.Writable,
            Binding = new() { Identity = Stage, AllocationGeneration = 11, InitialDestinationGeneration = 13, StageSlot = 0, StageIncarnation = 1 },
            CurrentDestinationGeneration = 13, Companion = new() { Identity = Companion, Capacity = Capacity, GrantRevision = 2 },
            Slots = state.Slots.SetItem(0, Slot(0, ResourceSlotRoleV2.Stage, ResourceSlotPhaseV2.Mutable, Stage))
        };
    }
    private static ResourceStateV2 Retired()
    {
        var state = Writable();
        return state with
        {
            Revision = 5, GrowthClosed = true, Phase = ResourceStatePhaseV2.WriteRetired, ClosureKind = ResourceClosureV2.DriverWriteRetired,
            AcceptedRetirement = new()
            {
                DriverInstanceId = Driver, TransferId = Transfer, AllocationGeneration = 11, DestinationGeneration = 13, Identity = Stage,
                ConnectionCookie = ulong.MaxValue, Sequence = ulong.MaxValue, AuthorizedCapacity = Capacity,
                EndOfFile = 1, AllocationSize = 4096, AcceptedRevision = 4
            },
            Slots = state.Slots.SetItem(0, state.Slots[0]! with { Phase = ResourceSlotPhaseV2.Immutable, ExpectedLength = 1, EndOfFile = 1, AllocationSize = 4096 }),
            ChargeBytes = 4 * Unit + Meta
        };
    }
    private static ResourceStateV2 MetadataOnly()
    {
        var state = Retired();
        var proof = new ResourceReleaseStateV2
        { Kind = ResourceReleaseKindV2.FinalStorageRelease, Slot = 0, Incarnation = 1, Identity = Stage, WitnessId = Guid.NewGuid(), ClaimRevision = 6 };
        return state with
        {
            Revision = 6, Phase = ResourceStatePhaseV2.MetadataOnly, StageRelease = proof,
            Slots = state.Slots.SetItem(0, state.Slots[0]! with { Phase = ResourceSlotPhaseV2.Released, Release = proof }), ChargeBytes = Meta
        };
    }
    private static ResourceSlotStateV2 Slot(int index, ResourceSlotRoleV2 role, ResourceSlotPhaseV2 phase, StagedStageIdentity? identity) => new()
    {
        Index = index, Incarnation = 1, Role = role, Phase = phase, ReservedMax = Capacity, ExpectedLength = 0,
        Identity = identity, Locator = null, EndOfFile = null, AllocationSize = null, Release = null
    };
    private static string Original()
    {
        var bytes = new byte[1192]; U32(bytes, 0, 18); U32(bytes, 4, 1192); U64(bytes, 8, 7);
        U32(bytes, 16, 3); U32(bytes, 20, 42); U32(bytes, 24, 0x200); U32(bytes, 32, 104); U32(bytes, 36, 32);
        byte[] name = Encoding.Unicode.GetBytes(@"\Device\HarddiskVolume3\Docs\fixture.txt"); U32(bytes, 28, (uint)name.Length); name.CopyTo(bytes.AsSpan(40));
        U32(bytes, 1064, 32); U32(bytes, 1068, 104); Transfer.TryWriteBytes(bytes.AsSpan(1072)); U32(bytes, 1104, 3);
        Driver.TryWriteBytes(bytes.AsSpan(1112)); U64(bytes, 1128, 1234); U64(bytes, 1136, ulong.MaxValue);
        U64(bytes, 1144, 100); U64(bytes, 1152, 1_200_000_100); U32(bytes, 1160, 1);
        return Convert.ToBase64String(bytes);
    }
    private static void U32(byte[] bytes, int offset, uint value) => BinaryPrimitives.WriteUInt32LittleEndian(bytes.AsSpan(offset), value);
    private static void U64(byte[] bytes, int offset, ulong value) => BinaryPrimitives.WriteUInt64LittleEndian(bytes.AsSpan(offset), value);
}
#endif
