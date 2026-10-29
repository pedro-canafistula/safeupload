#if SAFEUPLOAD_ADMISSION_EVIDENCE
using System.Collections.Immutable;
using System.IO.Compression;
using System.Security.Cryptography;
using System.Text;
using SafeUpload.Agent.Core.Domain;
using SafeUpload.Agent.Core.Infrastructure;
using SafeUpload.Agent.Core.Infrastructure.Extraction;
using SafeUpload.Agent.Service.Interception;

namespace SafeUpload.Agent.Tests;

public sealed class EvidencePackV1Tests
{
    [Theory]
    [InlineData('a')]
    [InlineData('é')]
    public async Task Both_real_ZIP_regressions_progress_with_lossless_out_of_line_evidence(char character)
    {
        var fixture = await ZipFixture(character);
        var plan = EvidencePackCodecV1.Preflight(fixture.Owner, 4096, fixture.Entry, fixture.Approval);
        var image = EvidencePackCodecV1.Serialize(plan, ObjectIdentity);
        var loaded = Read(image);
        Assert.Equal(StagedEntryCoreCodecV1.Serialize(fixture.Entry), StagedEntryCoreCodecV1.Serialize(loaded.Entry));
        Assert.Equal(fixture.Approval.Inspection.Findings.ToArray(), loaded.Approval!.Inspection.Findings.ToArray());
        Assert.Equal(ResourceJsonV3.Serialize(fixture.Approval, 1048576), ResourceJsonV3.Serialize(loaded.Approval, 1048576));
        Assert.Equal(image.Bytes, EvidencePackCodecV1.Serialize(EvidencePackCodecV1.Preflight(fixture.Owner, 4096, loaded.Entry, loaded.Approval), ObjectIdentity).Bytes);
        Assert.Equal(192, EvidenceReferenceCodecV1.Serialize(image.Reference).Length);
        Assert.Equal(256, Convert.ToBase64String(EvidenceReferenceCodecV1.Serialize(image.Reference)).Length);
        Console.WriteLine($"Rev9Zip character={(int)character} findings=128 member=512 entry={plan.EntryBytes} metadata={plan.MetadataBytes} payload={plan.Payload.Length} file={image.Bytes.Length} chunks={plan.ChunkCount} reference=192");
    }

    [Fact]
    public void Independently_specified_finding_vector_fixes_category_member_length_at_offsets_0_4_8()
    {
        var f = Fixture(); var approval = f.Approval with { Inspection = f.Approval.Inspection with { Findings = [new(1, "A", "a"), new(0, "B", "b")] } };
        var plan = EvidencePackCodecV1.Preflight(f.Owner, 4096, f.Entry, approval);
        byte[] vector = Convert.FromHexString("010000000000000001000000410000000000010000000100000042000000000001000000610000000000010000006200");
        Assert.Equal(vector, plan.Payload[(plan.EntryBytes + plan.MetadataBytes)..]);
        byte[] independent = [.. plan.Payload[..(plan.EntryBytes + plan.MetadataBytes)], .. vector];
        var loaded = EvidencePackCodecV1.DecodePayload(independent, plan.EntryBytes, plan.MetadataBytes, 2, 2, 2, f.Owner).Approval!;
        Assert.Equal(new PublicationApprovalFindingV1(1, "A", "a"), loaded.Inspection.Findings[0]);
        Assert.Equal(new PublicationApprovalFindingV1(0, "B", "b"), loaded.Inspection.Findings[1]);
    }

    [Theory]
    [InlineData(0)] [InlineData(8)] [InlineData(12)] [InlineData(16)] [InlineData(32)] [InlineData(48)]
    [InlineData(64)] [InlineData(80)] [InlineData(88)] [InlineData(112)] [InlineData(116)] [InlineData(120)]
    [InlineData(124)] [InlineData(128)] [InlineData(132)] [InlineData(136)] [InlineData(144)] [InlineData(152)]
    [InlineData(160)] [InlineData(168)] [InlineData(176)] [InlineData(192)] [InlineData(255)] [InlineData(4095)]
    [InlineData(4096)] [InlineData(4104)] [InlineData(4108)] [InlineData(4112)] [InlineData(4128)]
    [InlineData(4136)] [InlineData(4144)] [InlineData(4152)] [InlineData(4160)] [InlineData(4164)]
    [InlineData(4168)] [InlineData(4200)] [InlineData(4232)] [InlineData(4351)] [InlineData(135167)]
    public void Matching_whole_digest_cannot_hide_malformed_header_chunk_or_padding(int at)
    {
        var f = Fixture(); var image = Image(f); var mutated = image.Bytes.ToArray(); mutated[at] ^= 1;
        var reference = image.Reference with { Sha256 = Convert.ToHexString(SHA256.HashData(mutated)) };
        Assert.Throws<InvalidDataException>(() => Read(new(reference, mutated)));
    }

    [Fact]
    public void Every_reference_byte_and_length_is_bound_to_the_persisted_owner_or_held_object()
    {
        var image = Image(Fixture()); byte[] reference = EvidenceReferenceCodecV1.Serialize(image.Reference);
        for (int index = 0; index < reference.Length; index++)
        {
            var changed = reference.ToArray(); changed[index] ^= 1;
            Assert.Throws<InvalidDataException>(() =>
            {
                var parsed = EvidenceReferenceCodecV1.Deserialize(changed);
                EvidencePackCodecV1.Deserialize(parsed, image.Reference.Owner, Observation, 4096, image.Bytes);
            });
        }
        for (int length = 0; length < 192; length++)
            Assert.Throws<InvalidDataException>(() => EvidenceReferenceCodecV1.Deserialize(reference.AsSpan(0, length)));
        Assert.Throws<InvalidDataException>(() => EvidenceReferenceCodecV1.Deserialize([.. reference, 0]));
    }

    [Theory]
    [InlineData("substitution")] [InlineData("missing")] [InlineData("security")] [InlineData("link")] [InlineData("reparse")]
    [InlineData("generation")] [InlineData("witness")] [InlineData("kind")] [InlineData("operation")] [InlineData("duplicate")]
    public void Exact_referenced_identity_and_every_owner_field_are_required(string mutation)
    {
        var image = Image(Fixture()); var observed = Observation; var owner = image.Reference.Owner;
        switch (mutation)
        {
            case "substitution": observed = observed with { Identity = ObjectIdentity with { FileIdLow = 100 } }; break;
            case "security": observed = observed with { SecurityMatches = false }; break;
            case "link": observed = observed with { SingleLink = false }; break;
            case "reparse": observed = observed with { ReparsePoint = true }; break;
            case "generation": owner = owner with { Generation = 2 }; break;
            case "witness": owner = owner with { AuthorizationWitnessId = Guid.NewGuid() }; break;
            case "operation": owner = owner with { OperationId = Guid.NewGuid() }; break;
            case "kind": owner = owner with { Kind = EvidenceKindV1.EntryCore }; break;
            case "missing": Assert.Throws<InvalidDataException>(() => EvidenceCatalogV1.Empty.Resolve(image.Reference)); return;
            case "duplicate":
                var held = new EvidenceHeldImageV1(image.Reference, observed, 4096, image.Bytes);
                Assert.Throws<InvalidDataException>(() => new EvidenceCatalogV1([held, held]).Resolve(image.Reference)); return;
        }
        Assert.Throws<InvalidDataException>(() => EvidencePackCodecV1.Deserialize(image.Reference, owner, observed, 4096, image.Bytes));
    }

    [Theory]
    [InlineData("count")] [InlineData("snippet")] [InlineData("name")] [InlineData("surrogate")]
    public void Producer_limit_plus_one_refuses_before_the_adapter_boundary(string mutation)
    {
        var f = Fixture(); var finding = new PublicationApprovalFindingV1(0, "***", "member");
        var findings = mutation switch
        {
            "count" => Enumerable.Repeat(finding, 16385).ToImmutableArray(),
            "snippet" => ImmutableArray.Create(finding with { MaskedSnippet = new('x', 33) }),
            "name" => ImmutableArray.Create(finding with { MemberName = new('x', 1179635) }),
            "surrogate" => ImmutableArray.Create(finding with { MemberName = "\ud800" }),
            _ => throw new ArgumentOutOfRangeException(nameof(mutation))
        };
        int issues = 0;
        Assert.Throws<InvalidDataException>(() => EvidencePackAdmissionV1.PreflightThenIssue(f.Owner, 4096, f.Entry,
            f.Approval with { Inspection = f.Approval.Inspection with { Findings = findings } }, _ => issues++));
        Assert.Equal(0, issues);
    }

    [Fact]
    public void Maximum_finding_count_and_long_supplementary_names_round_trip_without_new_product_caps()
    {
        var f = Fixture();
        var findings = Enumerable.Repeat(new PublicationApprovalFindingV1(0, "***", "😃" + new string('a', 1024)), 16384).ToImmutableArray();
        var approval = f.Approval with { Inspection = f.Approval.Inspection with { Findings = findings } };
        var plan = EvidencePackCodecV1.Preflight(f.Owner, 65536, f.Entry, approval);
        var image = EvidencePackCodecV1.Serialize(plan, ObjectIdentity);
        var loaded = EvidencePackCodecV1.Deserialize(image.Reference, f.Owner, Observation, 65536, image.Bytes);
        Assert.Equal(findings.ToArray(), loaded.Approval!.Inspection.Findings.ToArray());
        Assert.True(plan.ChunkCount > 1);
        Console.WriteLine($"Rev9MaxFindings count=16384 payload={plan.Payload.Length} file={image.Bytes.Length} chunks={plan.ChunkCount}");
    }

    internal static readonly StagedStageIdentity ObjectIdentity = new(ulong.MaxValue, 500, 501);
    internal static EvidenceObservationV1 Observation => new(ObjectIdentity, true, true, false);
    internal sealed record PackFixture(EvidenceOwnerV1 Owner, TransferJournalEntry Entry, PublicationApprovalV1 Approval);
    internal static PackFixture Fixture(PublicationApprovalV1? approval = null)
    {
        approval ??= ResourceSerializationLimitsV3Tests.Approval();
        var ledger = ResourceSerializationLimitsV3Tests.Ledger(approval);
        return new(new(ledger.InstallationId, ledger.TransferId, approval.Binding.OperationId,
            Guid.Parse("10000000-1111-2222-3333-444444444444"), 1, EvidenceKindV1.Authorization,
            approval.Binding.AllocationGeneration, approval.Binding.DestinationGeneration, ledger.InstallationId),
            ledger.CustodyTransfers[0]!.Completion.Authorization.Entry, approval);
    }
    internal static EvidencePackImageV1 Image(PackFixture fixture) => EvidencePackCodecV1.Serialize(
        EvidencePackCodecV1.Preflight(fixture.Owner, 4096, fixture.Entry, fixture.Approval), ObjectIdentity);
    private static EvidencePackContentV1 Read(EvidencePackImageV1 image) => EvidencePackCodecV1.Deserialize(image.Reference,
        image.Reference.Owner, Observation, 4096, image.Bytes);
    internal static async Task<PackFixture> ZipFixture(char character)
    {
        using var stream = new MemoryStream();
        using (var zip = new ZipArchive(stream, ZipArchiveMode.Create, leaveOpen: true))
        {
            using var writer = new StreamWriter(zip.CreateEntry(new string(character, 508) + ".txt", CompressionLevel.NoCompression).Open(), new UTF8Encoding(false));
            for (int index = 0; index < 128; index++) await writer.WriteLineAsync("529.982.247-25");
        }
        stream.Position = 0;
        var policy = LocalPolicyStore.CreateDefault() with { ActiveCategories = new HashSet<Category> { Category.Cpf } };
        var findings = await new ZipArchiveExtractor().InspectAsync(stream, ExtractorRegistry.CreateDefault(), policy, CancellationToken.None);
        Assert.Equal(128, findings.Count);
        var approval = ResourceSerializationLimitsV3Tests.Approval();
        var binding = approval.Binding with { Length = stream.Length, Sha256 = Convert.ToHexString(SHA256.HashData(stream.ToArray())) };
        var operation = approval.Operation with { SizeBytes = stream.Length };
        return Fixture(approval with { Binding = binding, Operation = operation,
            Inspection = approval.Inspection with { Findings = findings.Select(x => new PublicationApprovalFindingV1((int)x.Category, x.MaskedSnippet, x.MemberName)).ToImmutableArray() },
            PolicyCheck = approval.PolicyCheck with { Operation = operation }, Justification = approval.Justification! with { Binding = binding } });
    }
}
#endif
