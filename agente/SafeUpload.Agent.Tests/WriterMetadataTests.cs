using System.Buffers.Binary;
using System.Security.Cryptography;
using SafeUpload.Agent.Minifilter;
using SafeUpload.Agent.Service.Interception;

namespace SafeUpload.Agent.Tests;

public sealed class WriterMetadataTests
{
    [Fact]
    public void Complete_ordered_pages_and_final_confirm_preserve_original_and_canonical_security()
    {
        var binding = SecuritySnapshotFixture.Binding();
        byte[] descriptor = SecuritySnapshotFixture.Descriptor(duplicateAces: 3150);
        byte[] envelope = WriterMetadataFixture.Envelope(binding, construction: descriptor, stored: descriptor);
        int pages = 0; uint expectedOffset = 0; bool confirmed = false;
        var result = WriterMetadataV27.Fetch(request =>
        {
            Assert.Equal(136, request.Length); Assert.Equal(18u, WriterMetadataFixture.U32(request, 0));
            Assert.Equal(34u, WriterMetadataFixture.U32(request, 8)); Assert.Equal(0u, WriterMetadataFixture.U32(request, 12));
            Assert.Equal(binding.DriverInstanceId, new Guid(request.AsSpan(24, 16)));
            Assert.Equal(binding.ReservationId, new Guid(request.AsSpan(40, 16)));
            Assert.Equal(17ul, BinaryPrimitives.ReadUInt64LittleEndian(request.AsSpan(56)));
            if (WriterMetadataFixture.U32(request, 20) == 1)
                Assert.All(request[64..], b => Assert.Equal(0, b));
            else
            {
                Assert.Equal(envelope.AsSpan(56, 32).ToArray(), request.AsSpan(64, 32).ToArray());
                Assert.Equal(envelope.AsSpan(104, 32).ToArray(), request.AsSpan(104, 32).ToArray());
                Assert.Equal(expectedOffset, WriterMetadataFixture.U32(request, 96));
                if (WriterMetadataFixture.U32(request, 20) == 2)
                { ++pages; expectedOffset += Math.Min(4096u, (uint)envelope.Length - 136 - expectedOffset); }
                else { Assert.Equal(3u, WriterMetadataFixture.U32(request, 20)); confirmed = true; }
            }
            return WriterMetadataFixture.Page(envelope, request);
        }, binding.DriverInstanceId, binding.ReservationId, 17);
        Assert.True(confirmed); Assert.True(pages > 1); Assert.InRange(pages, 1, 65);
        Assert.Equal(Convert.ToHexString(envelope), result.EnvelopeHex);
        var security = StagedAllocationSecuritySnapshot.FromWriterMetadata(result);
        Assert.Equal(security, StagedAllocationSecuritySnapshot.Decode(security.Encode()));
        Assert.Equal(2u, BinaryPrimitives.ReadUInt32LittleEndian(security.Encode()));
        Assert.Equal(Convert.ToHexString(StagedSecurityDescriptor.Canonicalize(descriptor)), security.ConstructionHex);
    }

    [Theory]
    [InlineData("driver")]
    [InlineData("reservation")]
    [InlineData("request")]
    [InlineData("connection")]
    [InlineData("revision")]
    [InlineData("snapshot")]
    [InlineData("phase")]
    [InlineData("duplicate")]
    [InlineData("out-of-order")]
    [InlineData("total")]
    [InlineData("count")]
    [InlineData("digest")]
    [InlineData("payload")]
    [InlineData("tail")]
    [InlineData("flags")]
    [InlineData("short")]
    [InlineData("missing-confirm")]
    [InlineData("changed-confirm")]
    public void Fetch_rejects_partial_replayed_or_mismatched_pages(string fault)
    {
        var binding = SecuritySnapshotFixture.Binding();
        byte[] envelope = WriterMetadataFixture.Envelope(binding, construction: SecuritySnapshotFixture.Descriptor(duplicateAces: 400));
        byte[]? prior = null;
        Assert.Throws<InvalidDataException>(() => WriterMetadataV27.Fetch(request =>
        {
            byte[] page = WriterMetadataFixture.Page(envelope, request);
            uint phase = WriterMetadataFixture.U32(request, 20), offset = WriterMetadataFixture.U32(request, 96);
            if (phase == 3 && fault == "missing-confirm") return [];
            if (phase == 3 && fault == "changed-confirm") page[64] ^= 1;
            if (phase == 2)
            {
                int field = fault switch
                {
                    "driver" => 16, "reservation" => 32, "request" => 48, "connection" => 56,
                    "revision" => 64, "snapshot" => 72, "phase" => 8, "total" => 92, "count" => 96,
                    "digest" => 104, "flags" => 100, "payload" => 136, _ => -1
                };
                if (field >= 0) page[field] ^= 1;
                if (fault == "short") return page[..^1];
                if (fault == "out-of-order") WriterMetadataFixture.Put32(page, 88, offset + 4096);
                if (fault == "tail" && WriterMetadataFixture.U32(page, 96) < 4096) page[^1] = 1;
                if (fault == "duplicate" && prior is not null) return prior;
                prior = page;
            }
            return page;
        }, binding.DriverInstanceId, binding.ReservationId, 17));
    }

    [Theory]
    [InlineData("overflow")]
    [InlineData("oversize")]
    [InlineData("zero-epoch")]
    [InlineData("zero-revision")]
    [InlineData("not-ready")]
    [InlineData("incomplete-construction")]
    public void Discovery_is_bounded_before_snapshot_allocation(string fault)
    {
        var binding = SecuritySnapshotFixture.Binding(); byte[] envelope = WriterMetadataFixture.Envelope(binding);
        int calls = 0;
        Assert.Throws<InvalidDataException>(() => WriterMetadataV27.Fetch(request =>
        {
            ++calls; byte[] page = WriterMetadataFixture.Page(envelope, request);
            switch (fault)
            {
                case "overflow": WriterMetadataFixture.Put32(page, 92, uint.MaxValue); break;
                case "oversize": WriterMetadataFixture.Put32(page, 92, WriterMetadataV27.MaximumBlobBytes + 1); break;
                case "zero-epoch": WriterMetadataFixture.Put64(page, 56, 0); break;
                case "zero-revision": WriterMetadataFixture.Put64(page, 64, 0); break;
                case "not-ready": WriterMetadataFixture.Put32(page, 12, 4); break;
                case "incomplete-construction": WriterMetadataFixture.Put32(page, 100, 14); break;
            }
            return page;
        }, binding.DriverInstanceId, binding.ReservationId, 17));
        Assert.Equal(1, calls);
    }

    [Theory]
    [InlineData(896, 0u)] // assignment missing
    [InlineData(900, 0xFu)] // partial security query
    [InlineData(904, 0u)] // empty construction is not stored-form substitution
    [InlineData(908, 131229u)]
    [InlineData(860, 129u)]
    [InlineData(912, 2u)] // fabricated seed lineage
    [InlineData(916, 1u)] // no affirmative producer exists
    [InlineData(920, 1u)]
    [InlineData(924, 0u)] // status zero cannot fabricate success
    [InlineData(948, 1u)] // reserved tail
    public void Digest_valid_but_incomplete_or_contradictory_facts_fail_closed(int field, uint value)
    {
        byte[] envelope = WriterMetadataFixture.Envelope(SecuritySnapshotFixture.Binding());
        WriterMetadataFixture.Put32(envelope, 136 + field, value);
        SHA256.HashData(envelope.AsSpan(136)).CopyTo(envelope, 104);
        Assert.Throws<InvalidDataException>(() => WriterMetadataV27.DecodeEnvelope(envelope));
    }

    [Fact]
    public void Cancellation_during_fetch_never_returns_partial_authority()
    {
        var binding = SecuritySnapshotFixture.Binding(); byte[] envelope = WriterMetadataFixture.Envelope(binding);
        using var cancel = new CancellationTokenSource();
        Assert.Throws<OperationCanceledException>(() => WriterMetadataV27.Fetch(request =>
        {
            cancel.Cancel(); return WriterMetadataFixture.Page(envelope, request);
        }, binding.DriverInstanceId, binding.ReservationId, 17, cancel.Token));
    }

    [Fact]
    public void Storage_checks_original_descriptors_against_canonical_pair_and_exact_writer()
    {
        var binding = SecuritySnapshotFixture.Binding(); var security = WriterMetadataFixture.Security(binding);
        var transfer = new StagedTransfer(binding.ReservationId, @"C:\private\stage.txt", @"C:\public\save.txt",
            SafeUpload.Agent.Core.Domain.DestinationKind.Cloud, "writer.exe", 42, 7)
            { RequestorSid = "S-1-5-21-111-222-333-1000", RequestorProcessCreationTime = 123456 };
        security.RequireWriterMetadata(binding, transfer);
        Assert.Throws<InvalidDataException>(() => security.RequireWriterMetadata(binding, transfer with { ProcessId = 43 }));
        Assert.Throws<InvalidDataException>(() => security.RequireWriterMetadata(binding, transfer with { SessionId = 8 }));
        Assert.Throws<InvalidDataException>(() => security.RequireWriterMetadata(binding, transfer with { RequestorProcessCreationTime = 123457 }));
        Assert.Throws<InvalidDataException>(() => security.RequireWriterMetadata(binding, transfer with { RequestorSid = "S-1-5-18" }));
        Assert.Throws<InvalidDataException>(() => (security with { AssignmentRevision = 2 }).Encode());
        byte[] altered = Convert.FromHexString(security.ExpectedStoredHex); altered[1] ^= 1;
        Assert.Throws<InvalidDataException>(() => (security with { ExpectedStoredHex = Convert.ToHexString(altered) }).Encode());
        var historical = security with { WriterMetadataEnvelopeHex = null };
        Assert.Equal(historical, StagedAllocationSecuritySnapshot.Decode(historical.Encode()));
        Assert.Throws<InvalidDataException>(() => historical.RequireWriterMetadata(binding, transfer));
        byte[] missingEnvelope = security.Encode()[..^1];
        Assert.Throws<InvalidDataException>(() => StagedAllocationSecuritySnapshot.Decode(missingEnvelope));
        Assert.Equal(526184, StagedAllocationSecuritySnapshot.MaximumBytes);
    }

    [Fact]
    public void Captured_effective_subject_and_statuses_remain_unproven_export_evidence()
    {
        var binding = SecuritySnapshotFixture.Binding() with { Disposition = 1, PublicTarget = new(7, 81, 82) };
        var security = WriterMetadataFixture.Security(binding);
        var transfer = new StagedTransfer(binding.ReservationId, @"C:\private\stage.txt", @"C:\public\save.txt",
            SafeUpload.Agent.Core.Domain.DestinationKind.Cloud, "writer.exe", 42, 7)
            { RequestorSid = "S-1-5-21-111-222-333-1000", RequestorProcessCreationTime = 123456 };
        var evidence = security.CapturedSeedEvidence(binding, transfer)!;
        Assert.NotEqual(transfer.RequestorSid, evidence.EffectiveSubjectSid);
        Assert.Equal(StagedSeedAuthority.Unproven, evidence.ReadAuthority);
        Assert.Equal(StagedSeedAuthority.Unproven, evidence.RecipientAuthority);
        Assert.Equal(unchecked((int)0xC00000BB), evidence.ReadStatus);
        Assert.Equal(evidence.ReadStatus, evidence.RecipientStatus);
        Assert.Equal(security.Reference(), evidence.Security);
    }
}
