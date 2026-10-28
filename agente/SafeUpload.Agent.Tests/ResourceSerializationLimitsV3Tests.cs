#if SAFEUPLOAD_ADMISSION_EVIDENCE
using System.Buffers.Binary;
using System.Collections.Immutable;
using System.IO.Compression;
using System.Reflection;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using SafeUpload.Agent.Core.Domain;
using SafeUpload.Agent.Core.Infrastructure;
using SafeUpload.Agent.Core.Infrastructure.Extraction;
using SafeUpload.Agent.Service.Interception;

namespace SafeUpload.Agent.Tests;

// These controls deliberately keep the format blocker visible. They are not a
// strict ledger-reader/transition/archive qualification receipt.
public sealed class ResourceSerializationLimitsV3Tests
{
    internal static readonly Guid Transfer = new("11223344-5566-7788-99aa-bbccddeeff00");
    internal static readonly Guid Driver = new("ffeeddcc-bbaa-9988-7766-554433221100");
    internal static readonly Guid Installation = new("12345678-1111-2222-3333-abcdefabcdef");
    internal static readonly StagedStageIdentity Stage = new(ulong.MaxValue, ulong.MaxValue, ulong.MaxValue);
    internal static readonly StagedStageIdentity Snapshot = new(ulong.MaxValue, ulong.MaxValue, ulong.MaxValue - 1);
    internal const string Sid = "S-1-5-21-11-22-33-1000";
    internal const string Hash = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    private static readonly string DestinationPath = Path.Combine(Path.GetTempPath(), "docs", "a.zip");
    private static readonly string StagePath = Path.Combine(Path.GetTempPath(), "private", "a.stage");
    private const long Capacity = 16 * 1024 * 1024;

    [Fact]
    public async Task Supported_archive_findings_overflow_the_actual_composed_ledger_before_any_candidate_exists()
    {
        var (approval, archiveBytes) = await ArchiveApproval(128, 'a');
        PublicationApprovalCodecV1.Validate(approval);
        byte[] approvalBytes = PublicationApprovalCodecV1.Serialize(approval);
        Assert.Equal(approvalBytes, PublicationApprovalCodecV1.Serialize(PublicationApprovalCodecV1.Deserialize(approvalBytes)));
        var ledger = Ledger(approval);
        ValidateSourceEntries(ledger);
        // Actual complete typed JSON, including both full retained completions;
        // the higher diagnostic bound measures the refused record, not a format change.
        byte[] composed = ResourceJsonV3.Serialize(ledger, 1024 * 1024);
        Assert.True(composed.Length > ResourceSerializationPreflightV3.LedgerMaximumBytes);
        Assert.True(approvalBytes.Length < 131072);
        Assert.Throws<InvalidDataException>(() => ResourceSerializationPreflightV3.Serialize(ledger));
        Assert.Equal(1048576, ledger.ChargeBytes);
        Assert.Equal(2, ledger.CustodyTransfers.Length);
        Assert.Equal(128, approval.Inspection.Findings.Length);
        Console.WriteLine($"T9Fit ordinary archive={archiveBytes} approval={approvalBytes.Length} ledger={composed.Length} ledgerLimit=65536 depth={Depth(composed)} findings=128 memberUtf16=512");
    }

    [Theory]
    [InlineData('a')]
    [InlineData('é')]
    public async Task Complete_supported_shapes_measure_default_escapes_without_omitting_findings(char memberCharacter)
    {
        var (approval, archiveBytes) = await ArchiveApproval(128, memberCharacter);
        var state = Ledger(approval);
        ValidateSourceEntries(state);
        byte[] bytes = ResourceJsonV3.Serialize(state, 1024 * 1024);
        using var json = JsonDocument.Parse(bytes);
        var findings = json.RootElement.GetProperty("CustodyTransfers")[0].GetProperty("Completion")
            .GetProperty("Authorization").GetProperty("PublicationApproval").GetProperty("Inspection").GetProperty("Findings");
        Assert.Equal(128, findings.GetArrayLength());
        Assert.Equal(512, findings[127].GetProperty("MemberName").GetString()!.Length);
        Assert.Equal(Hash, json.RootElement.GetProperty("CustodyTransfers")[0].GetProperty("Completion")
            .GetProperty("Authorization").GetProperty("PublicationApproval").GetProperty("Inspection").GetProperty("PolicyContentFingerprint").GetString());
        Assert.Throws<InvalidDataException>(() => ResourceSerializationPreflightV3.Serialize(state));
        Console.WriteLine($"T9Fit member={(int)memberCharacter} archive={archiveBytes} ledger={bytes.Length} depth={Depth(bytes)} limit=65536");
    }

    [Fact]
    public void Small_complete_shape_serializes_but_is_not_an_accepting_ledger_reader()
    {
        var state = Ledger(Approval());
        ValidateSourceEntries(state);
        byte[] bytes = ResourceSerializationPreflightV3.Serialize(state);
        using var json = JsonDocument.Parse(bytes);
        Assert.Equal(3, json.RootElement.GetProperty("Version").GetInt32());
        Assert.Equal(JsonValueKind.Null, json.RootElement.GetProperty("PendingCompanion").ValueKind);
        Assert.Equal(JsonValueKind.Null, json.RootElement.GetProperty("CustodyTransfers")[1].GetProperty("Completion")
            .GetProperty("Authorization").GetProperty("PublicationApproval").ValueKind);
        Assert.Equal(64, json.RootElement.GetProperty("CustodyTransfers")[0].GetProperty("Completion")
            .GetProperty("Authorization").GetProperty("PublicationApproval").GetProperty("Inspection").GetProperty("PolicyContentFingerprint").GetString()!.Length);
        Assert.Throws<InvalidDataException>(() => ResourceStateCodecV2.Deserialize(bytes, 4096));
        Console.WriteLine($"T9Fit smallLedger={bytes.Length} depth={Depth(bytes)} limit=65536");
    }

    [Theory]
    [InlineData(65536)]
    [InlineData(131072)]
    public void Actual_writer_includes_quotes_and_refuses_at_limit_plus_one(int limit)
    {
        // Byte-bound controls for the shared writer; these alone are not full-shape proof.
        Assert.Equal(limit, ResourceJsonV3.Serialize(new string('a', limit - 2), limit).Length);
        Assert.Throws<InvalidDataException>(() => ResourceJsonV3.Serialize(new string('a', limit - 1), limit));
    }

    internal static PublicationApprovalV1 Approval()
    {
        var binding = new PublicationApprovalBindingV1(Guid.Parse("00000001-1111-2222-3333-444444444444"), Transfer,
            1, 1, Stage, Snapshot, 1, Hash, Sid, 1);
        var operation = new PublicationApprovalOperationV1(DestinationPath, "a.zip", ".zip", 1, 1, "notepad.exe", 42, DestinationPath, 2);
        return new(1, binding, operation, new(1, [], null, 1, false, 7, true, Hash),
            new(operation, 7, Hash, false, true, true, true), true,
            new(Guid.Parse("00000002-1111-2222-3333-444444444444"), binding, 7, Hash, 7, Hash, 1, 2));
    }

    private static async Task<(PublicationApprovalV1 Approval, int ArchiveBytes)> ArchiveApproval(int count, char memberCharacter)
    {
        using var content = new MemoryStream();
        using (var zip = new ZipArchive(content, ZipArchiveMode.Create, leaveOpen: true))
        {
            var member = zip.CreateEntry(new string(memberCharacter, 508) + ".txt", CompressionLevel.NoCompression);
            using var writer = new StreamWriter(member.Open(), new UTF8Encoding(false));
            for (int index = 0; index < count; index++) await writer.WriteLineAsync("529.982.247-25");
        }
        content.Position = 0;
        var policy = LocalPolicyStore.CreateDefault() with { ActiveCategories = new HashSet<Category> { Category.Cpf } };
        var findings = await new ZipArchiveExtractor().InspectAsync(content, ExtractorRegistry.CreateDefault(), policy, CancellationToken.None);
        Assert.Equal(count, findings.Count);
        Assert.All(findings, finding => Assert.Equal(512, finding.MemberName!.Length));
        var initial = Approval();
        string hash = Convert.ToHexString(SHA256.HashData(content.ToArray()));
        var binding = initial.Binding with { Length = content.Length, Sha256 = hash };
        var operation = initial.Operation with { SizeBytes = content.Length };
        var inspection = new InspectionResult(Verdict.Blocked, findings, null, 1, false, 7, true) { PolicyContentFingerprint = Hash };
        return (initial with { Binding = binding, Operation = operation, Inspection = PublicationApprovalInspectionV1.Capture(inspection),
            PolicyCheck = initial.PolicyCheck with { Operation = operation }, Justification = initial.Justification! with { Binding = binding } },
            checked((int)content.Length));
    }

    internal static PublicCustodyReceiptV3 Receipt(bool handback = false)
    {
        var destination = new PublicCustodyDestinationV3(new(ulong.MaxValue, 10, 11), new(ulong.MaxValue, 12, 13), Installation, false, "a.zip");
        return new(Guid.Parse(handback ? "00000004-1111-2222-3333-444444444444" : "00000003-1111-2222-3333-444444444444"),
            Installation, Driver, Transfer, 1, 1, Stage, handback ? 3u : 2u,
            handback ? ResourceSlotRoleV2.Handback : ResourceSlotRoleV2.PublicationTemporary, 1,
            Guid.Parse(handback ? "00000006-1111-2222-3333-444444444444" : "00000005-1111-2222-3333-444444444444"),
            5, 0, new(ulong.MaxValue, 14, handback ? 16ul : 15ul), destination, handback ? 2u : 1u,
            Guid.Parse(handback ? "00000008-1111-2222-3333-444444444444" : "00000007-1111-2222-3333-444444444444"),
            7, handback ? 3u : 2u, Sid, Guid.Parse("00000001-1111-2222-3333-444444444444"), null,
            Installation, Installation, destination, Installation);
    }

    internal static ResourceStateV3 Ledger(PublicationApprovalV1 approval)
    {
        var cells = new List<ResourceCustodyTransferV3?>(); var slots = new List<ResourceSlotStateV3?>();
        var stageRelease = new ResourceReleaseStateV3 { Kind = ResourceReleaseKindV3.FinalStorageRelease, Slot = 0,
            Incarnation = 1, Identity = Stage, WitnessId = Installation, CustodyTransferReceiptId = null, ClaimRevision = 5 };
        for (int index = 0; index < 4; index++)
        {
            bool promotion = index >= 2;
            var receipt = Receipt(index == 3);
            var identity = index == 0 ? Stage : index == 1 ? Snapshot : receipt.DeliveredObjectIdentity;
            var claim = new ResourceCustodyClaimV3(promotion ? receipt.ClaimId : Guid.Parse($"{index + 9:X8}-1111-2222-3333-444444444444"),
                Installation, (uint)index, 1, 5, promotion ? ResourceClaimKindV3.Promote : ResourceClaimKindV3.Dispose,
                ResourceClaimPhaseV3.Drained, identity, index == 0 ? Installation : null, Installation);
            ResourceReleaseStateV3 release = index == 0 ? stageRelease : stageRelease with { Slot = index, Identity = identity,
                Kind = promotion ? ResourceReleaseKindV3.PublicCustodyTransferred : ResourceReleaseKindV3.FinalStorageRelease,
                CustodyTransferReceiptId = promotion ? receipt.ReceiptId : null };
            slots.Add(new() { Index = index, Incarnation = 1, Role = (ResourceSlotRoleV2)(index + 1), Phase = ResourceSlotPhaseV2.Released,
                ReservedMax = Capacity, ExpectedLength = approval.Binding.Length, Identity = identity, Locator = null,
                EndOfFile = approval.Binding.Length, AllocationSize = (approval.Binding.Length + 4095) / 4096 * 4096, Release = release, CustodyClaim = claim });
            if (!promotion) continue;
            var transfer = new StagedTransfer(Transfer, StagePath, DestinationPath, DestinationKind.Cloud, "notepad.exe", 42, 1)
            { RequestorSid = Sid, RequestorProcessCreationTime = 1 };
            var entry = new TransferJournalEntry(transfer, index == 2 ? TransferJournalState.Publishing : TransferJournalState.Blocked,
                approval.Binding.Sha256, new DateTimeOffset(2026, 10, 28, 0, 0, 0, TimeSpan.Zero))
            { SealedOnce = true, StageIdentity = Stage, SealedLength = approval.Binding.Length, DestinationGeneration = 1,
                DriverInstanceId = Driver, AllocationReferenceKind = 0, CreateReservationId = Transfer, BlockedPolicyVersion = 7, BlockedPolicyFingerprint = Hash,
                JustificationExpiresAtUtc = new DateTimeOffset(2026, 10, 29, 0, 0, 0, TimeSpan.Zero),
                HandbackState = index == 3 ? StagedHandbackState.Copying : StagedHandbackState.NotAttempted };
            var completion = new PublicCustodyCompletionV3(1, Convert.ToBase64String(PublicCustodyReceiptCodecV3.Serialize(receipt, true)),
                null, claim, new(Installation, entry, index == 2 ? approval : null));
            cells.Add(new(Convert.ToBase64String(PublicCustodyReceiptCodecV3.Serialize(receipt with { AcceptedBudgetRevision = index + 6 }, false)), completion));
        }
        string original = Original();
        return new()
        {
            Version = 3, InstallationId = Installation, InitialCapacity = Capacity, RetirementWitnessId = Installation,
            InitialResolution = new(original, ulong.MaxValue, Installation, Sid, 1, ResourceInitialPhaseV3.InitialResolved,
                Installation, 5, FenceReceipt(), null, 3, null, null),
            GrowthReplay = new(0, null), HistoryHandoff = null, CustodyTransfers = cells.ToImmutableArray(), TransferId = Transfer,
            DriverInstanceId = Driver, Sid = Sid, OriginalRequest = original, Alignment = 65536, MetadataGranularity = 4096,
            AuthorizedCapacity = Capacity, MetadataDebit = 1048576, Revision = 10, GrantRevision = 2, GrowthClosed = true,
            GrantMayHaveEscaped = true, Phase = ResourceStatePhaseV2.MetadataOnly, ClosureKind = ResourceClosureV2.DriverWriteRetired,
            Binding = new() { Identity = Stage, AllocationGeneration = 1, InitialDestinationGeneration = 1, StageSlot = 0, StageIncarnation = 1 },
            CurrentDestinationGeneration = 1, Slots = slots.ToImmutableArray(), AcceptedRetirement = new()
            { DriverInstanceId = Driver, TransferId = Transfer, AllocationGeneration = 1, DestinationGeneration = 1, Identity = Stage,
                ConnectionCookie = ulong.MaxValue, Sequence = 1, AuthorizedCapacity = Capacity, EndOfFile = approval.Binding.Length,
                AllocationSize = (approval.Binding.Length + 4095) / 4096 * 4096, AcceptedRevision = 4 }, StageRelease = stageRelease,
            Companion = new() { Identity = new(ulong.MaxValue, 17, 18), Capacity = Capacity, GrantRevision = 2 },
            PendingCompanion = null, FullDebitHeld = false, ChargeBytes = 1048576
        };
    }

    private static void ValidateSourceEntries(ResourceStateV3 state)
    {
        // Reuse the unchanged shipped source-entry validator; do not weaken its
        // existing assertions merely to get a large serialized specimen.
        var method = typeof(StagedTransferJournal).GetMethod("ValidateEntry", BindingFlags.NonPublic | BindingFlags.Static)!;
        foreach (var cell in state.CustodyTransfers)
            method.Invoke(null, [cell!.Completion.Authorization.Entry, Transfer]);
    }
    private static int Depth(byte[] bytes)
    {
        var reader = new Utf8JsonReader(bytes, new JsonReaderOptions { MaxDepth = 64 }); int depth = 0;
        while (reader.Read()) if (reader.TokenType is JsonTokenType.StartArray or JsonTokenType.StartObject) depth = Math.Max(depth, reader.CurrentDepth + 1);
        return depth;
    }
    private static string FenceReceipt()
    {
        var bytes = new byte[192];
        void U32(int at, uint value) => BinaryPrimitives.WriteUInt32LittleEndian(bytes.AsSpan(at), value);
        void U64(int at, ulong value) => BinaryPrimitives.WriteUInt64LittleEndian(bytes.AsSpan(at), value);
        U32(0, 18); U32(4, 192); U32(8, 36); U32(16, 32); U32(20, 5); U64(24, 1); U64(32, ulong.MaxValue);
        Driver.TryWriteBytes(bytes.AsSpan(40)); U32(56, 128); U32(64, 2);
        Installation.TryWriteBytes(bytes.AsSpan(72)); Installation.TryWriteBytes(bytes.AsSpan(88));
        U64(104, ulong.MaxValue); U64(112, 1); U64(120, 1); U64(128, 1);
        U64(136, Stage.VolumeSerialNumber); U64(144, Stage.FileIdLow); U64(152, Stage.FileIdHigh);
        return Convert.ToBase64String(bytes);
    }
    private static string Original()
    {
        var bytes = new byte[1192]; U32(0, 18); U32(4, 1192); U64(8, 7); U32(16, 3); U32(20, 42);
        U32(24, 0x200); byte[] path = Encoding.Unicode.GetBytes(@"\Device\HarddiskVolume3\docs\a.zip");
        U32(28, (uint)path.Length); U32(32, 104); U32(36, 32); path.CopyTo(bytes, 40);
        U32(1064, 32); U32(1068, 104); Transfer.TryWriteBytes(bytes.AsSpan(1072)); U32(1104, 3);
        Driver.TryWriteBytes(bytes.AsSpan(1112)); U64(1128, 1234); U64(1136, ulong.MaxValue); U64(1144, 100); U64(1152, 1200000100); U32(1160, 1);
        return Convert.ToBase64String(bytes);
        void U32(int offset, uint value) => BinaryPrimitives.WriteUInt32LittleEndian(bytes.AsSpan(offset), value);
        void U64(int offset, ulong value) => BinaryPrimitives.WriteUInt64LittleEndian(bytes.AsSpan(offset), value);
    }
}
#endif
