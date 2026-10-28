#if SAFEUPLOAD_ADMISSION_EVIDENCE
using System.Runtime.InteropServices;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using SafeUpload.Agent.Minifilter;

namespace SafeUpload.Agent.Service.Interception;

// Bounded data validation only: this class performs no I/O, authenticates no
// receipt and changes no budget. Native custody/store adapters remain gated.
internal static class ResourceStateCodecV2
{
    internal const int MaximumBytes = 64 * 1024;
    private static readonly UTF8Encoding StrictUtf8 = new(false, true);
    private static readonly UnicodeEncoding StrictUtf16 = new(false, false, true);
    private static readonly JsonSerializerOptions Json = new()
    {
        MaxDepth = 16,
        UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow,
        RespectRequiredConstructorParameters = true,
        Converters = { new IdentityConverter() }
    };

    internal static byte[] Serialize(ResourceStateV2 state, long metadataGranularity)
    {
        Validate(state, metadataGranularity);
        byte[] bytes = JsonSerializer.SerializeToUtf8Bytes(state, Json);
        Require(bytes.Length <= MaximumBytes, "Modern reservation exceeds its storage bound.");
        return bytes;
    }

    internal static ResourceStateV2 Deserialize(ReadOnlySpan<byte> bytes, long metadataGranularity)
    {
        Require(bytes.Length is > 0 and <= MaximumBytes, "Modern reservation size is invalid.");
        try
        {
            StrictUtf8.GetCharCount(bytes);
            RejectDuplicateProperties(bytes);
            var state = JsonSerializer.Deserialize<ResourceStateV2>(bytes, Json)
                ?? throw new InvalidDataException("Modern reservation is missing.");
            Validate(state, metadataGranularity);
            return state;
        }
        catch (Exception error) when (error is JsonException or ArgumentException or FormatException or OverflowException)
        {
            throw new InvalidDataException("Modern reservation encoding is invalid.", error);
        }
    }

    internal static void Validate(ResourceStateV2 state, long metadataGranularity)
    {
        try
        {
            long charge = ValidateAndMeasure(state, metadataGranularity);
            Require(state.ChargeBytes == charge, "Persisted modern debit differs from its custody state.");
        }
        catch (OverflowException error)
        {
            throw new InvalidDataException("Modern reservation arithmetic overflowed.", error);
        }
    }

    private static long ValidateAndMeasure(ResourceStateV2 state, long metadataGranularity)
    {
        Require(state.Version == 2 && state.TransferId != Guid.Empty && state.DriverInstanceId != Guid.Empty,
            "Modern reservation identity/version is invalid.");
        Require(!string.IsNullOrWhiteSpace(state.Sid) && state.Sid.Length <= 184 && !state.Sid.Contains('\0'),
            "Modern reservation owner is invalid.");
        Require(PowerOfTwo(metadataGranularity) && metadataGranularity >= 512 &&
            state.MetadataGranularity == metadataGranularity, "Modern metadata unit is not the verified unit.");
        Require(PowerOfTwo(state.Alignment) && state.Alignment >= Math.Max(65536, metadataGranularity),
            "Modern content alignment is invalid.");
        Require(state.MetadataDebit == Math.Max(1024 * 1024, checked(metadataGranularity * 16)),
            "Modern metadata envelope differs from the existing default.");
        Require(Capacity(state.AuthorizedCapacity, state.Alignment) && state.Revision > 0 &&
            Enum.IsDefined(state.Phase) && Enum.IsDefined(state.ClosureKind), "Modern capacity/revision/phase is invalid.");
        long fullDebit = checked(state.AuthorizedCapacity * 4 + state.MetadataDebit);
        ValidateOriginalRequest(state);
        Require(!state.Slots.IsDefault && state.Slots.Length == 4, "Modern custody must have four indexed slots.");
        var liveIdentities = new HashSet<StagedStageIdentity>();
        long extent = 0;
        for (int index = 0; index < state.Slots.Length; index++)
        {
            if (state.Slots[index] is not { } slot) continue;
            long charged = ValidateSlot(state, slot, index);
            extent = Math.Max(extent, charged);
            if (slot.Phase != ResourceSlotPhaseV2.Released && slot.Identity is { } identity)
                Require(liveIdentities.Add(identity), "One content object appears in two live custody slots.");
        }
        ValidateBinding(state);
        ValidateRetirement(state);
        ValidateCompanion(state, liveIdentities);
        ValidatePhase(state);
        if (state.FullDebitHeld || state.PendingCompanion is not null || state.Phase is
            ResourceStatePhaseV2.Preparing or ResourceStatePhaseV2.Writable or ResourceStatePhaseV2.Closing or ResourceStatePhaseV2.ClosedUnissued)
            return fullDebit;
        return state.Phase == ResourceStatePhaseV2.MetadataOnly ? state.MetadataDebit :
            checked(extent * 4 + state.MetadataDebit);
    }

    private static long ValidateSlot(ResourceStateV2 state, ResourceSlotStateV2 slot, int index)
    {
        Require(slot.Index == index && slot.Incarnation > 0 && Enum.IsDefined(slot.Role) && Enum.IsDefined(slot.Phase),
            "Modern custody position/incarnation/role is invalid.");
        Require(Aligned(slot.ReservedMax, state.Alignment) && slot.ReservedMax <= state.AuthorizedCapacity &&
            slot.ExpectedLength >= 0 && slot.ExpectedLength <= slot.ReservedMax, "Modern custody ceiling is invalid.");
        Require(slot.Locator is null || slot.Locator.Length is > 0 and <= 512 && !slot.Locator.Contains('\0'),
            "Modern custody locator exceeds its bound.");
        Require(slot.Identity is null || IdentityValid(slot.Identity), "Modern custody identity is invalid.");
        Require(slot.EndOfFile.HasValue == slot.AllocationSize.HasValue, "Partial custody measurement is invalid.");
        bool measured = slot.EndOfFile.HasValue;
        if (measured)
        {
            Require(slot.EndOfFile >= 0 && slot.AllocationSize >= 0 && slot.EndOfFile <= slot.ReservedMax &&
                slot.AllocationSize <= slot.ReservedMax, "Custody measurement exceeds its admitted ceiling.");
            Require(slot.Role == ResourceSlotRoleV2.Stage || slot.EndOfFile == slot.ExpectedLength,
                "Completed copy length differs from its admitted version.");
        }
        Require(slot.Role != ResourceSlotRoleV2.Stage || slot.ReservedMax == state.AuthorizedCapacity,
            "Original stage does not retain the full authorized ceiling.");
        if (slot.Phase == ResourceSlotPhaseV2.Released)
        {
            Require(slot.Release is not null, "Released custody lacks its exact evidence.");
            ValidateRelease(state, slot.Release!);
            Require(slot.Release!.Slot == index && slot.Release.Incarnation == slot.Incarnation &&
                slot.Release.Identity == slot.Identity, "Release evidence belongs to another custody incarnation.");
            if (NonCreation(slot.Release.Kind)) Require(slot.Identity is null && !measured, "Non-creation cannot release a created object.");
            else Require(IdentityValid(slot.Identity), "Storage release lacks an exact object.");
            return 0;
        }
        Require(slot.Release is null, "Live custody cannot carry completed release evidence.");
        switch (slot.Phase)
        {
            case ResourceSlotPhaseV2.ReservedNotIssued:
            case ResourceSlotPhaseV2.CreationMayHaveStarted:
                Require(slot.Identity is null && !measured, "Pre-identity creation has invented object measurements.");
                return slot.ReservedMax;
            case ResourceSlotPhaseV2.Mutable:
                Require(IdentityValid(slot.Identity) && !measured, "Mutable custody cannot use final measurements.");
                return slot.ReservedMax;
            case ResourceSlotPhaseV2.ReleasePending:
                Require(!measured, "Abandoned copying cannot substitute partial allocation for its reserved maximum.");
                return slot.ReservedMax;
            case ResourceSlotPhaseV2.Immutable:
            case ResourceSlotPhaseV2.ImmutableReleasePending:
                Require(IdentityValid(slot.Identity) && measured, "Immutable custody lacks closed-lease measurements.");
                return Round(slot.AllocationSize!.Value, state.Alignment);
            default: throw new InvalidDataException("Unknown custody state.");
        }
    }

    private static void ValidateBinding(ResourceStateV2 state)
    {
        if (state.Binding is not { } binding)
        {
            Require(state.GrantRevision == 0 && state.CurrentDestinationGeneration is null && state.Companion is null &&
                state.PendingCompanion is null && state.AcceptedRetirement is null && state.StageRelease is null,
                "Unbound modern custody carries bound authority.");
            Require(!state.GrantMayHaveEscaped, "An unbound modern grant may have escaped.");
            return;
        }
        Require(IdentityValid(binding.Identity) && binding.AllocationGeneration > 0 && binding.InitialDestinationGeneration > 0 &&
            binding.StageSlot is >= 0 and < 4 && binding.StageIncarnation > 0 &&
            state.CurrentDestinationGeneration >= binding.InitialDestinationGeneration &&
            state.GrantRevision > 0 && state.GrantRevision <= state.Revision, "Modern binding is invalid.");
        var original = state.Slots[binding.StageSlot];
        Require(original is not null && original.Incarnation >= binding.StageIncarnation, "The original stage incarnation was lost.");
        bool originalPresent = original!.Incarnation == binding.StageIncarnation;
        if (originalPresent)
            Require(original.Role == ResourceSlotRoleV2.Stage && original.Identity == binding.Identity,
                "The original stage slot changed identity or role.");
        foreach (var slot in state.Slots)
            if (slot?.Role == ResourceSlotRoleV2.Stage)
                Require(slot.Index == binding.StageSlot && slot.Incarnation == binding.StageIncarnation,
                    "Another original stage appears under one allocation.");
        bool released = !originalPresent || original.Phase == ResourceSlotPhaseV2.Released;
        if (released)
        {
            Require(state.StageRelease is not null, "Released/reused stage lacks retained release evidence.");
            var proof = state.StageRelease!;
            ValidateRelease(state, proof);
            Require(!NonCreation(proof.Kind) && proof.Identity == binding.Identity && proof.Slot == binding.StageSlot &&
                proof.Incarnation == binding.StageIncarnation, "Stage release evidence belongs to a different object/incarnation.");
            if (originalPresent) Require(proof == original.Release, "Original stage release witnesses disagree.");
        }
        else Require(state.StageRelease is null, "A live original stage carries a release claim.");
    }

    private static void ValidateRetirement(ResourceStateV2 state)
    {
        if (state.AcceptedRetirement is not { } receipt) return;
        Require(state.Binding is not null && state.GrowthClosed && state.ClosureKind == ResourceClosureV2.DriverWriteRetired,
            "Retirement evidence is not joined to closed bound custody.");
        var binding = state.Binding!;
        Require(receipt.DriverInstanceId == state.DriverInstanceId && receipt.TransferId == state.TransferId &&
            receipt.AllocationGeneration == binding.AllocationGeneration && receipt.Identity == binding.Identity &&
            receipt.DestinationGeneration >= binding.InitialDestinationGeneration &&
            receipt.DestinationGeneration <= state.CurrentDestinationGeneration && receipt.ConnectionCookie != 0 && receipt.Sequence != 0 &&
            Capacity(receipt.AuthorizedCapacity, state.Alignment) && receipt.AuthorizedCapacity <= state.AuthorizedCapacity &&
            receipt.EndOfFile >= 0 && receipt.AllocationSize >= 0 && receipt.EndOfFile <= receipt.AuthorizedCapacity &&
            receipt.AllocationSize <= receipt.AuthorizedCapacity && receipt.AcceptedRevision > 0 &&
            receipt.AcceptedRevision <= state.Revision && state.GrantRevision <= receipt.AcceptedRevision,
            "Retirement evidence conflicts with the allocation binding.");
        var original = state.Slots[binding.StageSlot]!;
        if (original.Incarnation == binding.StageIncarnation && original.Phase is
            ResourceSlotPhaseV2.Immutable or ResourceSlotPhaseV2.ImmutableReleasePending)
            Require(original.EndOfFile == receipt.EndOfFile && original.AllocationSize == receipt.AllocationSize,
                "Original stage measurements differ from the accepted retirement receipt.");
        else if (original.Incarnation == binding.StageIncarnation && original.Phase != ResourceSlotPhaseV2.Released)
            Require(original.Phase == ResourceSlotPhaseV2.ReleasePending,
                "Retirement cannot leave an original mutable/creation lease open.");
    }

    private static void ValidateCompanion(ResourceStateV2 state, HashSet<StagedStageIdentity> content)
    {
        if (state.Companion is { } companion)
        {
            Require(IdentityValid(companion.Identity) && !content.Contains(companion.Identity) &&
                Capacity(companion.Capacity, state.Alignment) && companion.Capacity <= state.AuthorizedCapacity &&
                companion.GrantRevision > 0 && companion.GrantRevision <= state.GrantRevision,
                "Current companion is not an exact charged metadata object.");
            if (state.PendingCompanion is null)
                Require(companion.Capacity == state.AuthorizedCapacity && companion.GrantRevision == state.GrantRevision,
                    "A synchronized companion disagrees with committed capacity.");
        }
        if (state.PendingCompanion is not { } pending) return;
        Require(state.Binding is not null && pending.OperationId != Guid.Empty && Enum.IsDefined(pending.Phase) &&
            pending.ReplacementIncarnation > 0 && pending.TargetCapacity == state.AuthorizedCapacity &&
            Capacity(pending.TargetCapacity, state.Alignment) && pending.TargetRevision == state.GrantRevision &&
            pending.TargetRevision > 0 && pending.TargetRevision <= state.Revision,
            "Pending companion target is invalid.");
        if (pending.Predecessor is null)
            Require(state.Companion is null && !state.GrantMayHaveEscaped, "An issued grant lost its exact companion predecessor.");
        else
            Require(pending.Predecessor == state.Companion && pending.Predecessor.Capacity <= pending.TargetCapacity,
                "Pending companion predecessor is not current.");
        bool captured = pending.Phase is ResourceCompanionPhaseV2.Prepared or ResourceCompanionPhaseV2.NativeReplacementCommitted;
        Require(captured ? IdentityValid(pending.ReplacementIdentity) : pending.ReplacementIdentity is null,
            "Companion replacement identity is missing or premature.");
        if (pending.ReplacementIdentity is { } replacement)
            Require(!content.Contains(replacement) && replacement != state.Companion?.Identity,
                "Companion replacement aliases an existing object.");
    }

    private static void ValidatePhase(ResourceStateV2 state)
    {
        bool noContent = state.Slots.All(slot => slot is null || slot.Phase == ResourceSlotPhaseV2.Released);
        var stages = state.Slots.Where(slot => slot?.Role == ResourceSlotRoleV2.Stage && slot.Phase != ResourceSlotPhaseV2.Released).ToArray();
        Require(stages.Length <= 1, "One allocation has multiple live original stages.");
        var stage = stages.FirstOrDefault();
        switch (state.Phase)
        {
            case ResourceStatePhaseV2.Preparing:
                Require(!state.GrowthClosed && !state.GrantMayHaveEscaped && state.ClosureKind == ResourceClosureV2.None &&
                    state.AcceptedRetirement is null && stage is not null, "Preparing reservation claims completed authority."); break;
            case ResourceStatePhaseV2.Writable:
                Require(state.Binding is not null && state.Companion is not null && !state.GrowthClosed &&
                    state.ClosureKind == ResourceClosureV2.None && state.AcceptedRetirement is null &&
                    stage?.Phase == ResourceSlotPhaseV2.Mutable, "Writable reservation is not fully bound mutable custody."); break;
            case ResourceStatePhaseV2.Closing:
                Require(state.Binding is not null && state.GrowthClosed && state.ClosureKind == ResourceClosureV2.None &&
                    state.AcceptedRetirement is null, "Closing reservation has invalid proof/closure state."); break;
            case ResourceStatePhaseV2.ClosedUnissued:
                Require(state.GrowthClosed && !state.GrantMayHaveEscaped && state.ClosureKind == ResourceClosureV2.UnissuedClosed &&
                    state.AcceptedRetirement is null, "Unissued closure may have issued authority."); break;
            case ResourceStatePhaseV2.WriteRetired:
                Require(state.GrowthClosed && state.Binding is not null && state.ClosureKind == ResourceClosureV2.DriverWriteRetired &&
                    state.AcceptedRetirement is not null, "Write retirement lacks accepted driver evidence."); break;
            case ResourceStatePhaseV2.MetadataOnly:
                Require(state.GrowthClosed && !state.FullDebitHeld && noContent && state.PendingCompanion is null &&
                    (state.ClosureKind == ResourceClosureV2.UnissuedClosed && !state.GrantMayHaveEscaped && state.AcceptedRetirement is null ||
                     state.ClosureKind == ResourceClosureV2.DriverWriteRetired && state.AcceptedRetirement is not null),
                    "Metadata-only reservation still carries unresolved content authority."); break;
            default: throw new InvalidDataException("Unknown modern reservation phase.");
        }
    }

    private static void ValidateRelease(ResourceStateV2 state, ResourceReleaseStateV2 proof) =>
        Require(Enum.IsDefined(proof.Kind) && proof.Slot is >= 0 and < 4 && proof.Incarnation > 0 &&
            proof.WitnessId != Guid.Empty && proof.ClaimRevision > 0 && proof.ClaimRevision <= state.Revision &&
            (NonCreation(proof.Kind) ? proof.Identity is null : IdentityValid(proof.Identity)), "Custody release representation is invalid.");

    private static unsafe void ValidateOriginalRequest(ResourceStateV2 state)
    {
        Require(state.OriginalRequest is { Length: 1592 }, "Original allocation request has the wrong encoded length.");
        byte[] bytes = Convert.FromBase64String(state.OriginalRequest);
        Require(bytes.Length == Contract.RequestSize && Convert.ToBase64String(bytes) == state.OriginalRequest,
            "Original allocation request is not canonical complete bytes.");
        var original = MemoryMarshal.Read<SafeUploadRequest>(bytes);
        Require(original.Version == Contract.Version && original.StructSize == Contract.RequestSize && original.RequestId != 0 &&
            original.Operation == Operation.StageAllocate && original.Reserved == ResourceWireV32.Version &&
            original.Flags == Contract.StageV19ReplyFlag && original.RequestorProcessId is > 0 and <= int.MaxValue &&
            original.ImageNameLength == ResourceWireV32.IntentBytes && original.PathLength is > 0 and <= 1022 &&
            (original.PathLength & 1) == 0, "Original allocation envelope is invalid.");
        var image = new ReadOnlySpan<byte>(original.ImageName, 128);
        var path = new ReadOnlySpan<byte>(original.Path, 1024);
        Require(Zero(image[104..]) && Zero(path[(int)original.PathLength..]), "Original allocation unused bytes are invalid.");
        Require(ResourceWireV32.TryReadAllocation(image[..104], out var intent), "Original allocation payload is invalid.");
        Require(intent.Intent.Intent.AllocationReservationId == state.TransferId && intent.Intent.Intent.DriverInstanceId == state.DriverInstanceId,
            "Original allocation intent belongs to another reservation.");
        string name = StrictUtf16.GetString(path[..(int)original.PathLength]);
        Require(name[0] == '\\' && !name.Contains('\0') && name[^1] != '\\', "Original allocation destination is malformed.");
    }

    private static void RejectDuplicateProperties(ReadOnlySpan<byte> bytes)
    {
        var reader = new Utf8JsonReader(bytes, new JsonReaderOptions { MaxDepth = 16 });
        var objects = new Stack<HashSet<string>>();
        while (reader.Read())
        {
            if (reader.TokenType == JsonTokenType.StartObject) objects.Push(new(StringComparer.Ordinal));
            else if (reader.TokenType == JsonTokenType.EndObject) objects.Pop();
            else if (reader.TokenType == JsonTokenType.PropertyName)
                Require(objects.Peek().Add(reader.GetString()!), "Duplicate modern reservation property.");
        }
    }

    private static bool IdentityValid(StagedStageIdentity? identity) => identity is not null && (identity.FileIdLow | identity.FileIdHigh) != 0;
    private static bool NonCreation(ResourceReleaseKindV2 kind) => kind is ResourceReleaseKindV2.NeverIssued or ResourceReleaseKindV2.DefinitiveNonCreation;
    private static bool PowerOfTwo(long value) => value > 0 && (value & (value - 1)) == 0;
    private static bool Aligned(long value, long alignment) => value >= 0 && value % alignment == 0;
    private static bool Capacity(long value, long alignment) => value >= 16 * 1024 * 1024 && Aligned(value, alignment);
    private static long Round(long value, long alignment) => checked((value + alignment - 1) / alignment * alignment);
    private static bool Zero(ReadOnlySpan<byte> bytes) { foreach (byte value in bytes) if (value != 0) return false; return true; }
    private static void Require(bool condition, string message) { if (!condition) throw new InvalidDataException(message); }

    private sealed class IdentityConverter : JsonConverter<StagedStageIdentity>
    {
        public override StagedStageIdentity Read(ref Utf8JsonReader reader, Type type, JsonSerializerOptions options)
        {
            using var document = JsonDocument.ParseValue(ref reader);
            var root = document.RootElement;
            Require(root.ValueKind == JsonValueKind.Object && root.EnumerateObject().Count() == 3 &&
                root.EnumerateObject().All(p => p.Name is "VolumeSerialNumber" or "FileIdHigh" or "FileIdLow"),
                "Complete object identity fields are required.");
            return new(ReadWord(root, "VolumeSerialNumber"), ReadWord(root, "FileIdHigh"), ReadWord(root, "FileIdLow"));
        }
        private static ulong ReadWord(JsonElement root, string name)
        {
            var property = root.GetProperty(name);
            Require(property.ValueKind == JsonValueKind.Number, "Identity words must be unsigned integers.");
            Require(property.TryGetUInt64(out ulong value), "Identity word is out of range.");
            return value;
        }
        public override void Write(Utf8JsonWriter writer, StagedStageIdentity value, JsonSerializerOptions options)
        {
            writer.WriteStartObject(); writer.WriteNumber("VolumeSerialNumber", value.VolumeSerialNumber);
            writer.WriteNumber("FileIdHigh", value.FileIdHigh); writer.WriteNumber("FileIdLow", value.FileIdLow); writer.WriteEndObject();
        }
    }
}
#endif
