#if SAFEUPLOAD_ADMISSION_EVIDENCE
using System.Collections.Immutable;
using System.Text;
using System.Text.Json.Nodes;
using SafeUpload.Agent.Service.Interception;

namespace SafeUpload.Agent.Tests;

public sealed class ResourceStateV4Tests
{
    [Theory]
    [InlineData('a')]
    [InlineData('é')]
    public async Task Both_full_two_completion_ZIP_ledgers_now_progress_and_keep_every_finding(char character)
    {
        var f = await EvidencePackV1Tests.ZipFixture(character); var x = Build(f);
        byte[] bytes = ResourceStateCodecV4.Serialize(x.State, x.Catalog);
        Assert.Equal(bytes, ResourceStateCodecV4.Serialize(ResourceStateCodecV4.Deserialize(bytes, x.Catalog), x.Catalog));
        Assert.Equal(2, x.State.CustodyTransfers.Count(c => c is not null));
        Assert.Throws<InvalidDataException>(() => ResourceStateCodecV4.Deserialize(bytes, EvidenceCatalogV1.Empty));
        Console.WriteLine($"Rev9Ledger character={(int)character} bytes={bytes.Length} limit=65536 evidencePhysical={x.State.ChargeBytes - 1048576}");
    }

    [Theory]
    [InlineData("version")] [InlineData("debit")] [InlineData("phase")] [InlineData("unknown")] [InlineData("missing-null")]
    [InlineData("duplicate")] [InlineData("claim-generation")] [InlineData("claim-identity")] [InlineData("claim-drain")]
    [InlineData("acceptance")] [InlineData("source-byte")] [InlineData("reference")] [InlineData("numeric-string")]
    [InlineData("reordered")] [InlineData("truncated")] [InlineData("oversize")]
    public void Strict_composed_reader_rejects_corruption_without_returning_a_state(string mutation)
    {
        var x = Build(EvidencePackV1Tests.Fixture()); byte[] bytes = ResourceStateCodecV4.Serialize(x.State, x.Catalog);
        var node = JsonNode.Parse(bytes)!.AsObject(); string? raw = null;
        switch (mutation)
        {
            case "version": node["Version"] = 3; break;
            case "debit": node["ChargeBytes"] = x.State.ChargeBytes - 1; break;
            case "phase": node["Phase"] = 99; break;
            case "unknown": node["Unknown"] = null; break;
            case "missing-null": node.Remove("HistoryHandoff"); break;
            case "duplicate": raw = Encoding.UTF8.GetString(bytes).Replace("\"Version\":4", "\"Version\":4,\"Version\":4", StringComparison.Ordinal); break;
            case "claim-generation": node["EvidenceClaims"]![0]!["Generation"] = 2; break;
            case "claim-identity": node["EvidenceClaims"]![0]!["Identity"]!["FileIdLow"] = 42; break;
            case "claim-drain": node["Slots"]![0]!["CustodyClaim"]!["DrainWitnessId"] = null; break;
            case "acceptance": node["CustodyTransfers"]![0]!["ReceiptBase64"] = node["CustodyTransfers"]![0]!["Completion"]!["CompletionBase64"]!.GetValue<string>(); break;
            case "source-byte": node["CustodyTransfers"]![0]!["Completion"]!["CompletionBase64"] = Convert.ToBase64String(new byte[2048]); break;
            case "reference": node["CustodyTransfers"]![0]!["Completion"]!["Authorization"]!["EvidenceReferenceBase64"] = Convert.ToBase64String(new byte[192]); break;
            case "numeric-string": node["ChargeBytes"] = x.State.ChargeBytes.ToString(); break;
            case "reordered":
                var reversed = new JsonObject(); foreach (var property in node.Reverse()) reversed.Add(property.Key, property.Value?.DeepClone()); raw = reversed.ToJsonString(); break;
            case "truncated": Assert.Throws<InvalidDataException>(() => ResourceStateCodecV4.Deserialize(bytes.AsSpan(0, bytes.Length - 1), x.Catalog)); return;
            case "oversize": Assert.Throws<InvalidDataException>(() => ResourceStateCodecV4.Deserialize(new byte[65537], x.Catalog)); return;
        }
        Assert.Throws<InvalidDataException>(() => ResourceStateCodecV4.Deserialize(Encoding.UTF8.GetBytes(raw ?? node.ToJsonString()), x.Catalog));
    }

    [Fact]
    public void Four_evidence_cells_and_maximum_locator_escapes_fit_with_both_full_completions()
    {
        var x = Build(EvidencePackV1Tests.Fixture());
        var claims = x.State.EvidenceClaims;
        for (int index = 2; index < 4; index++) claims = claims.SetItem(index, claims[0]! with
        { RecordId = Guid.Parse($"{index:X8}-aaaa-bbbb-cccc-dddddddddddd"), Identity = null, Phase = EvidencePhaseV1.CreationMayHaveStarted,
            Length = null, Sha256 = null, MeasuredAllocation = null, DrainWitnessId = null });
        var state = x.State with { EvidenceClaims = claims, ChargeBytes = x.State.ChargeBytes + 2 * claims[0]!.ReservedMax,
            Slots = x.State.Slots.Select(slot => slot! with { Locator = new string('\u0001', 512) }).Cast<ResourceSlotStateV3?>().ToImmutableArray() };
        byte[] bytes = ResourceStateCodecV4.Serialize(state, x.Catalog);
        Assert.Equal(bytes, ResourceStateCodecV4.Serialize(ResourceStateCodecV4.Deserialize(bytes, x.Catalog), x.Catalog));
        Console.WriteLine($"Rev9FourClaims bytes={bytes.Length} limit=65536");
    }

    internal sealed record StateFixture(ResourceStateV4 State, EvidenceCatalogV1 Catalog, ImmutableArray<EvidenceHeldImageV1> Images);
    internal static StateFixture Build(EvidencePackV1Tests.PackFixture fixture)
    {
        var old = ResourceSerializationLimitsV3Tests.Ledger(fixture.Approval);
        var cells = ImmutableArray.CreateBuilder<ResourceCustodyTransferV4?>(); var images = ImmutableArray.CreateBuilder<EvidenceHeldImageV1>();
        var claims = ImmutableArray.CreateBuilder<EvidenceClaimV1?>();
        for (int index = 0; index < 2; index++)
        {
            var source = old.CustodyTransfers[index]!.Completion;
            var receipt = PublicCustodyReceiptCodecV3.Deserialize(Convert.FromBase64String(source.CompletionBase64), true);
            var owner = fixture.Owner with { RecordId = Guid.Parse($"1000000{index}-1111-2222-3333-444444444444"), OperationId = receipt.PromotionOperationId,
                AuthorizationWitnessId = receipt.AuthorizationWitnessId };
            var image = EvidencePackCodecV1.Serialize(EvidencePackCodecV1.Preflight(owner, 4096, source.Authorization.Entry,
                source.Authorization.PublicationApproval), new(ulong.MaxValue, (ulong)(500 + index), (ulong)(600 + index)));
            images.Add(new(image.Reference, new(image.Reference.Identity, true, true, false), 4096, image.Bytes));
            var completion = new PublicCustodyCompletionV4(1, source.CompletionBase64, source.PublicationNativeReceipt, source.Claim,
                new(source.Authorization.WitnessId, Convert.ToBase64String(EvidenceReferenceCodecV1.Serialize(image.Reference))));
            cells.Add(new(old.CustodyTransfers[index]!.ReceiptBase64, completion));
            claims.Add(new(owner.RecordId, 1, owner.Kind, owner.OperationId, owner.AuthorizationWitnessId, owner.AllocationGeneration,
                owner.DestinationGeneration, old.InstallationId, EvidencePhaseV1.Referenced, image.Reference.Identity, image.Bytes.Length,
                image.Reference.Sha256, image.Bytes.Length, image.Bytes.Length, old.InstallationId, null, null, EvidenceAccountingOwnerV1.Transfer, null));
        }
        claims.Add(null); claims.Add(null);
        var state = new ResourceStateV4
        {
            Version = 4, InstallationId = old.InstallationId, InitialCapacity = old.InitialCapacity, RetirementWitnessId = old.RetirementWitnessId,
            InitialResolution = old.InitialResolution, GrowthReplay = old.GrowthReplay, HistoryHandoff = old.HistoryHandoff,
            CustodyTransfers = cells.ToImmutable(), EvidenceClaims = claims.ToImmutable(), TransferId = old.TransferId,
            DriverInstanceId = old.DriverInstanceId, Sid = old.Sid, OriginalRequest = old.OriginalRequest, Alignment = old.Alignment,
            MetadataGranularity = old.MetadataGranularity, AuthorizedCapacity = old.AuthorizedCapacity, MetadataDebit = old.MetadataDebit,
            Revision = old.Revision, GrantRevision = old.GrantRevision, GrowthClosed = old.GrowthClosed, GrantMayHaveEscaped = old.GrantMayHaveEscaped,
            Phase = old.Phase, ClosureKind = old.ClosureKind, Binding = old.Binding, CurrentDestinationGeneration = old.CurrentDestinationGeneration,
            Slots = old.Slots, AcceptedRetirement = old.AcceptedRetirement, StageRelease = old.StageRelease, Companion = old.Companion,
            PendingCompanion = old.PendingCompanion, FullDebitHeld = old.FullDebitHeld,
            ChargeBytes = old.ChargeBytes + images.Sum(image => image.Bytes.Length)
        };
        return new(state, new(images), images.ToImmutable());
    }
}
#endif
