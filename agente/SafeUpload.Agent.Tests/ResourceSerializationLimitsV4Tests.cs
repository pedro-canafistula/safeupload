#if SAFEUPLOAD_ADMISSION_EVIDENCE
using System.Collections.Immutable;
using System.Text;
using System.Text.Json;
using SafeUpload.Agent.Service.Interception;

namespace SafeUpload.Agent.Tests;

public sealed class ResourceSerializationLimitsV4Tests
{
    [Fact]
    public void Complete_supported_Unicode_ACK_delta_exceeds_W_and_refuses_before_native_issue()
    {
        var x = LongUnicodeAck();
        byte[] basis = StagedJournalEnvelopeV3Codec.Serialize(x.Base, EvidenceCatalogV1.Empty);
        Assert.Equal(basis, StagedJournalEnvelopeV3Codec.Serialize(StagedJournalEnvelopeV3Codec.Deserialize(basis, EvidenceCatalogV1.Empty), EvidenceCatalogV1.Empty));
        // Semantic validation and the complete original-wire validator pass;
        // only actual composed UTF-8 byte accounting refuses the ACK delta.
        StagedJournalEnvelopeV3Codec.Validate(x.Delta, EvidenceCatalogV1.Empty);
        byte[] bytes = ResourceJsonV3.Serialize(x.Delta, 131072);
        using var document = JsonDocument.Parse(bytes);
        int e = Encoding.UTF8.GetByteCount(document.RootElement.GetProperty("EntryReference").GetRawText());
        int s = Encoding.UTF8.GetByteCount(document.RootElement.GetProperty("CompletionState").GetRawText());
        int wrapper = bytes.Length - e - s;
        Assert.True(wrapper > 8192);
        int issues = 0; long priorCharge = x.Base.ResourceClosure!.ChargeBytes;
        Assert.Throws<InvalidDataException>(() => StagedJournalEnvelopeV3Codec.PreflightThenIssue(x.Delta, EvidenceCatalogV1.Empty, _ => issues++));
        Assert.Equal(0, issues); Assert.Equal(priorCharge, x.Base.ResourceClosure.ChargeBytes);
        Console.WriteLine($"Rev9AckStop pathUnits={x.Path.Length} originalBytes=1192 ackRequestBytes=1272 ackReplyBytes=72 base={basis.Length} delta={bytes.Length} wrapper={wrapper} wrapperLimit=8192 envelopeLimit=131072 chargeRetained={priorCharge}");
    }

    internal sealed record AckFixture(string Path, StagedJournalEnvelopeV3 Base, StagedJournalEnvelopeV3 Delta);
    internal static AckFixture LongUnicodeAck()
    {
        var old = ResourceSerializationLimitsV3Tests.Ledger(ResourceSerializationLimitsV3Tests.Approval());
        // This three-unit pattern encodes to repeated '+' Base64 characters.
        // Components stay below NTFS's 255-unit leaf limit; the complete native
        // path fits the existing 511-unit allocation wire carrier.
        string Pattern(string units, int length) => string.Concat(Enumerable.Repeat(units, (length + 2) / 3))[..length];
        const string prefix = @"\Device\HarddiskVolume3\";
        string directory = Pattern("\ubeef\ueffb\ufbbe", 232);
        string path = prefix + directory + "\\" + Pattern("\ufbbe\ubeef\ueffb", 250) + ".txt";
        Assert.Equal(511, path.Length); Assert.All(path.Split('\\').Skip(1), component => Assert.InRange(component.Length, 1, 255));
        byte[] original = Convert.FromBase64String(old.OriginalRequest);
        original.AsSpan(40, 1024).Clear(); Encoding.Unicode.GetBytes(path).CopyTo(original, 40); EvidenceBinaryV1.U32(original, 28, 1022);
        string encoded = Convert.ToBase64String(original);
        Guid fence = Guid.Parse("50000000-1111-2222-3333-444444444444");
        byte[] fenceBytes = Header(192, 5, 128, old.DriverInstanceId, 1);
        EvidenceBinaryV1.U32(fenceBytes, 64, 1); EvidenceBinaryV1.Id(fenceBytes, 72, fence);
        EvidenceBinaryV1.Id(fenceBytes, 88, old.InstallationId); EvidenceBinaryV1.U64(fenceBytes, 104, ulong.MaxValue);
        EvidenceBinaryV1.U64(fenceBytes, 112, 1);
        var release = new ResourceReleaseStateV3 { Kind = ResourceReleaseKindV3.NeverIssued, Slot = 0, Incarnation = 1, Identity = null,
            WitnessId = fence, CustodyTransferReceiptId = null, ClaimRevision = 1 };
        var slot = new ResourceSlotStateV3 { Index = 0, Incarnation = 1, Role = ResourceSlotRoleV2.Stage, Phase = ResourceSlotPhaseV2.Released,
            ReservedMax = 16777216, ExpectedLength = 0, Identity = null, Locator = null, EndOfFile = null, AllocationSize = null, Release = release,
            CustodyClaim = new(fence, old.InstallationId, 0, 1, 1, ResourceClaimKindV3.CreateCopy, ResourceClaimPhaseV3.Drained, null, null, fence) };
        var state = new ResourceStateV4
        {
            Version = 4, InstallationId = old.InstallationId, InitialCapacity = 16777216, RetirementWitnessId = null,
            InitialResolution = new(encoded, ulong.MaxValue, old.InstallationId, old.Sid, 1, ResourceInitialPhaseV3.CleanupComplete,
                fence, 1, Convert.ToBase64String(fenceBytes), fence, 3, null, null),
            GrowthReplay = new(0, null), HistoryHandoff = null, CustodyTransfers = [null, null], EvidenceClaims = [null, null, null, null],
            TransferId = old.TransferId, DriverInstanceId = old.DriverInstanceId, Sid = old.Sid, OriginalRequest = encoded, Alignment = 65536,
            MetadataGranularity = 4096, AuthorizedCapacity = 16777216, MetadataDebit = 1048576, Revision = 5, GrantRevision = 0,
            GrowthClosed = true, GrantMayHaveEscaped = false, Phase = ResourceStatePhaseV2.MetadataOnly, ClosureKind = ResourceClosureV2.UnissuedClosed,
            Binding = null, CurrentDestinationGeneration = null, Slots = [slot, null, null, null], AcceptedRetirement = null,
            StageRelease = null, Companion = null, PendingCompanion = null, FullDebitHeld = false, ChargeBytes = 1048576
        };
        var basis = new StagedJournalEnvelopeV3(3, 4, state.InstallationId, JournalRecordKindV4.ResourceOnlyClosure,
            Guid.Parse("50000001-1111-2222-3333-444444444444"), state.TransferId, 1, null, null, state, null, null, null, null);
        byte[] ackRequest = Header(1272, 6, 1208, state.DriverInstanceId, 2); original.CopyTo(ackRequest, 64); EvidenceBinaryV1.Id(ackRequest, 1256, fence);
        byte[] ackReply = Header(72, 6, 8, state.DriverInstanceId, 2); EvidenceBinaryV1.U32(ackReply, 64, 1);
        var delta = basis with { RecordKind = JournalRecordKindV4.InitialResolutionDelta,
            RecordId = Guid.Parse("50000002-1111-2222-3333-444444444444"), RecordRevision = 2, PreviousRecordId = basis.RecordId,
            ResourceClosure = null, ResolutionDelta = new(ResourceInitialPhaseV3.ResolutionAcknowledged, encoded, fence,
                ulong.MaxValue, Convert.ToBase64String(ackRequest), Convert.ToBase64String(ackReply), 6) };
        return new(path, basis, delta);
    }
    private static byte[] Header(int length, uint opcode, int payload, Guid driver, ulong requestId)
    {
        var bytes = new byte[length]; EvidenceBinaryV1.U32(bytes, 0, 18); EvidenceBinaryV1.U32(bytes, 4, length);
        EvidenceBinaryV1.U32(bytes, 8, 36); EvidenceBinaryV1.U32(bytes, 16, 32); EvidenceBinaryV1.U32(bytes, 20, opcode);
        EvidenceBinaryV1.U64(bytes, 24, requestId); EvidenceBinaryV1.U64(bytes, 32, 9); EvidenceBinaryV1.Id(bytes, 40, driver);
        EvidenceBinaryV1.U32(bytes, 56, payload); return bytes;
    }
}
#endif
