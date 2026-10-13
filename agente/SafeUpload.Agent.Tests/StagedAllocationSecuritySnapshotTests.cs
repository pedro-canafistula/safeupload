using System.Buffers.Binary;
using SafeUpload.Agent.Service.Interception;

namespace SafeUpload.Agent.Tests;

public sealed class StagedAllocationSecuritySnapshotTests
{
    [Theory]
    [InlineData("read-denied", "seed_export_denied")]
    [InlineData("label-denied", "seed_export_denied")]
    [InlineData("sharing-failure", "seed_export_unproven")]
    [InlineData("unsupported-probe", "seed_export_unproven")]
    [InlineData("missing-subject", "seed_export_unproven")]
    [InlineData("other-process-lifetime", "seed_export_unproven")]
    [InlineData("other-source", "seed_export_unproven")]
    [InlineData("other-security", "seed_export_unproven")]
    [InlineData("other-generation", "seed_export_unproven")]
    [InlineData("effective-thread-is-not-recipient", "seed_export_recipient_unproven")]
    [InlineData("other-session", "seed_export_recipient_unproven")]
    [InlineData("recipient-unchecked", "seed_export_recipient_unproven")]
    [InlineData("independent-read-and-recipient-grants", null)]
    public void Export_evidence_requires_exact_source_subject_security_and_recipient(string change, string? failure)
    {
        var transfer = new StagedTransfer(Guid.NewGuid(), @"C:\private\stage.txt", @"C:\public\save.txt",
            SafeUpload.Agent.Core.Domain.DestinationKind.Cloud, "write-only.exe", 42, 7)
            { RequestorSid = "S-1-5-21-111-222-333-1000", RequestorProcessCreationTime = 123456 };
        var entry = new TransferJournalEntry(transfer, TransferJournalState.Allocated, null, DateTimeOffset.UtcNow)
            { StageIdentity = new(7, 51, 52), DestinationGeneration = 1 };
        var (seed, security) = SeedProvenanceFixture.PublicSeed(entry, StagedSeedAuthority.Allowed, StagedSeedAuthority.Allowed);
        var proof = seed.ExportEvidence!;
        proof = change switch
        {
            "read-denied" or "label-denied" => proof with { ReadAuthority = StagedSeedAuthority.Denied },
            "sharing-failure" or "unsupported-probe" => proof with { ReadAuthority = StagedSeedAuthority.Unproven },
            "missing-subject" => proof with { EffectiveSubjectId = Guid.Empty },
            "other-process-lifetime" => proof with { ProcessCreationTime = 999 },
            "other-source" => proof with { PublicSource = new(7, 61, 62) },
            "other-security" => proof with { Security = security.Reference() with { SnapshotId = Guid.NewGuid() } },
            "effective-thread-is-not-recipient" => proof with { RecipientSid = proof.EffectiveSubjectSid },
            "other-session" => proof with { RecipientSessionId = 8 },
            "recipient-unchecked" => proof with { RecipientAuthority = StagedSeedAuthority.Unproven },
            _ => proof
        };
        entry = entry with { SeedProvenance = seed with { ExportEvidence = proof } };
        if (change == "other-generation") entry = entry with { DestinationGeneration = 2 };
        var roundtrip = System.Text.Json.JsonSerializer.Deserialize<TransferJournalEntry>(
            System.Text.Json.JsonSerializer.Serialize(entry))!;
        Assert.Equal(entry, roundtrip);
        Assert.Equal(failure, StagedSeedExport.Failure(roundtrip));
        Assert.NotEqual(transfer.RequestorSid, proof.EffectiveSubjectSid);
        Assert.Equal(security.Encode(), StagedAllocationSecuritySnapshot.Decode(security.Encode()).Encode());
    }

    [Fact]
    public void Missing_bound_provenance_and_stale_failed_diagnostic_are_not_export_authority()
    {
        var binding = SecuritySnapshotFixture.Binding();
        var transfer = new StagedTransfer(binding.ReservationId, @"C:\private\stage", @"C:\public\save.txt",
            SafeUpload.Agent.Core.Domain.DestinationKind.Cloud, "writer.exe", 42, 7);
        var entry = new TransferJournalEntry(transfer, TransferJournalState.Allocated, null, DateTimeOffset.UtcNow)
            { BoundAllocation = binding, DestinationGeneration = 1, StageIdentity = new(7, 21, 22) };
        Assert.Equal("seed_export_unproven", StagedSeedExport.Failure(entry));
        Assert.Equal("seed_export_unproven", StagedSeedExport.Failure(entry with
            { BoundAllocation = null, HandbackFailureReason = "seed_export_unproven", HandbackState = StagedHandbackState.Failed }));
        Assert.Null(StagedSeedExport.Failure(entry with { BoundAllocation = null }));
    }

    [Fact]
    public void Offset_padding_and_shared_sid_storage_do_not_change_the_security_components()
    {
        byte[] first = SecuritySnapshotFixture.Descriptor();
        byte[] padded = new byte[first.Length + 32];
        first.AsSpan(0, 20).CopyTo(padded);
        first.AsSpan(20).CopyTo(padded.AsSpan(36));
        for (int field = 4; field < 20; field += 4)
        {
            uint offset = BinaryPrimitives.ReadUInt32LittleEndian(first.AsSpan(field));
            if (offset != 0) BinaryPrimitives.WriteUInt32LittleEndian(padded.AsSpan(field), offset + 16);
        }
        // Both fields can refer to the same complete SID; partial overlap cannot.
        BinaryPrimitives.WriteUInt32LittleEndian(padded.AsSpan(8),
            BinaryPrimitives.ReadUInt32LittleEndian(padded.AsSpan(4)));
        Assert.Equal(StagedSecurityDescriptor.Canonicalize(first), StagedSecurityDescriptor.Canonicalize(padded));
    }

    [Fact]
    public void Null_absent_and_empty_dacl_are_distinct_and_defaulted_flags_survive()
    {
        byte[] absent = SecuritySnapshotFixture.Descriptor(dacl: false);
        byte[] nullAcl = absent.ToArray();
        BinaryPrimitives.WriteUInt16LittleEndian(nullAcl.AsSpan(2), 0xc01c); // PRESENT + DEFAULTED
        byte[] empty = SecuritySnapshotFixture.Descriptor(emptyDacl: true);
        Assert.NotEqual(Convert.ToHexString(StagedSecurityDescriptor.Canonicalize(absent)),
            Convert.ToHexString(StagedSecurityDescriptor.Canonicalize(nullAcl)));
        Assert.NotEqual(Convert.ToHexString(StagedSecurityDescriptor.Canonicalize(nullAcl)),
            Convert.ToHexString(StagedSecurityDescriptor.Canonicalize(empty)));
        Assert.Equal((ushort)0xc01c, BinaryPrimitives.ReadUInt16LittleEndian(StagedSecurityDescriptor.Canonicalize(nullAcl).AsSpan(2)));
    }

    [Theory]
    [InlineData("ace-order")]
    [InlineData("ace-flags")]
    [InlineData("opaque-payload")]
    [InlineData("label")]
    [InlineData("rm-control")]
    public void Native_security_bytes_are_not_reordered_or_erased(string change)
    {
        byte[] first = SecuritySnapshotFixture.Descriptor(), second = first.ToArray();
        int dacl = (int)BinaryPrimitives.ReadUInt32LittleEndian(first.AsSpan(16));
        int sacl = (int)BinaryPrimitives.ReadUInt32LittleEndian(first.AsSpan(12));
        switch (change)
        {
            case "ace-order":
                first.AsSpan(dacl + 8, 20).CopyTo(second.AsSpan(dacl + 28));
                first.AsSpan(dacl + 28, 20).CopyTo(second.AsSpan(dacl + 8));
                break;
            case "ace-flags": second[dacl + 9] ^= 0x10; break;
            case "opaque-payload": second[dacl + 8 + 40 + 20] ^= 1; break;
            case "label": second[sacl + 12] ^= 2; break;
            case "rm-control": second[1] ^= 1; break;
        }
        Assert.NotEqual(Convert.ToHexString(StagedSecurityDescriptor.Canonicalize(first)),
            Convert.ToHexString(StagedSecurityDescriptor.Canonicalize(second)));
    }

    [Theory]
    [InlineData("absolute")]
    [InlineData("offset-overflow")]
    [InlineData("partial-overlap")]
    [InlineData("sid-overrun")]
    [InlineData("acl-overrun")]
    [InlineData("ace-overrun")]
    public void Invalid_component_ranges_are_rejected_before_copy(string change)
    {
        byte[] bytes = SecuritySnapshotFixture.Descriptor();
        switch (change)
        {
            case "absolute": bytes[3] &= 0x7f; break;
            case "offset-overflow": BinaryPrimitives.WriteUInt32LittleEndian(bytes.AsSpan(4), uint.MaxValue); break;
            case "partial-overlap": bytes[21] = 2; break;
            case "sid-overrun": bytes[21] = 15; BinaryPrimitives.WriteUInt32LittleEndian(bytes.AsSpan(4), (uint)(bytes.Length - 8)); bytes[^8] = 1; bytes[^7] = 15; break;
            case "acl-overrun": BinaryPrimitives.WriteUInt16LittleEndian(bytes.AsSpan((int)BinaryPrimitives.ReadUInt32LittleEndian(bytes.AsSpan(16)) + 2), ushort.MaxValue); break;
            case "ace-overrun": BinaryPrimitives.WriteUInt16LittleEndian(bytes.AsSpan((int)BinaryPrimitives.ReadUInt32LittleEndian(bytes.AsSpan(16)) + 10), ushort.MaxValue); break;
        }
        Assert.Throws<InvalidDataException>(() => StagedSecurityDescriptor.Canonicalize(bytes));
    }

    [Fact]
    public void Construction_and_native_stored_form_round_trip_as_separate_immutable_values()
    {
        var binding = SecuritySnapshotFixture.Binding();
        byte[] construction = SecuritySnapshotFixture.Descriptor(), stored = construction.ToArray();
        stored[2] &= 0xf7; // Expected native form is supplied independently, never synthesized by the codec.
        var snapshot = StagedAllocationSecuritySnapshot.Create(Guid.NewGuid(), binding, 1, 0x7f, construction, stored);
        construction[1] ^= 1;
        Assert.NotEqual(snapshot.ConstructionHex, snapshot.ExpectedStoredHex);
        Assert.Equal(snapshot, StagedAllocationSecuritySnapshot.Decode(snapshot.Encode()));
        Assert.Equal(snapshot.Reference(), StagedAllocationSecuritySnapshot.Decode(snapshot.Encode()).Reference());
        snapshot.RequireBinding(binding);
        Assert.Throws<InvalidDataException>(() => snapshot.RequireBinding(binding with { CanonicalLeaf = "other.txt" }));
        Assert.Throws<InvalidDataException>(() => snapshot.RequireBinding(binding with { ParentCaseSensitive = true }));
        Assert.Throws<InvalidDataException>(() => snapshot.RequireBinding(binding with { DriverInstanceId = Guid.NewGuid() }));
    }

    [Theory]
    [InlineData("version")]
    [InlineData("reserved")]
    [InlineData("length-overflow")]
    [InlineData("trailing-data")]
    public void Framing_refuses_unknown_or_incomplete_records(string change)
    {
        var binding = SecuritySnapshotFixture.Binding();
        byte[] descriptor = SecuritySnapshotFixture.Descriptor();
        byte[] bytes = StagedAllocationSecuritySnapshot.Create(Guid.NewGuid(), binding, 1, 0x7f,
            descriptor, descriptor).Encode();
        switch (change)
        {
            case "version": bytes[0]++; break;
            case "reserved": bytes[72]++; break;
            case "length-overflow": BinaryPrimitives.WriteUInt32LittleEndian(bytes.AsSpan(64), uint.MaxValue); break;
            case "trailing-data": bytes = [.. bytes, 0]; break;
        }
        Assert.Throws<InvalidDataException>(() => StagedAllocationSecuritySnapshot.Decode(bytes));
    }
}

// Binary storage controls, not evidence of native assignment or access checks.
internal static class SecuritySnapshotFixture
{
    internal static StagedAllocationBindingV23 Binding() => new(Guid.NewGuid(), Guid.NewGuid(), Guid.Empty,
        2, 0, Guid.NewGuid(), new(7, 8, 9), new(7, 10, 11), false, "save.txt", null);

    internal static byte[] Descriptor(bool dacl = true, bool emptyDacl = false, int duplicateAces = 0)
    {
        byte[] sid = [1, 1, 0, 0, 0, 0, 0, 5, 18, 0, 0, 0];
        byte[] allow = new byte[20];
        allow[0] = 0; allow[1] = 0x10;
        BinaryPrimitives.WriteUInt16LittleEndian(allow.AsSpan(2), 20);
        BinaryPrimitives.WriteUInt32LittleEndian(allow.AsSpan(4), 0x12019f);
        sid.CopyTo(allow, 8);
        byte[] deny = allow.ToArray(); deny[0] = 1; deny[1] = 0;
        byte[] callback = new byte[24]; allow.CopyTo(callback, 0); callback[0] = 9;
        BinaryPrimitives.WriteUInt16LittleEndian(callback.AsSpan(2), 24);
        callback[20] = 0xa5;
        byte[] label = allow.ToArray(); label[0] = 17; label[1] = 0;
        BinaryPrimitives.WriteUInt32LittleEndian(label.AsSpan(4), 3);
        label[15] = 16; BinaryPrimitives.WriteUInt32LittleEndian(label.AsSpan(16), 8192);
        byte[] sacl = Acl(duplicateAces > 0 ? Enumerable.Repeat(label, duplicateAces).ToArray() : [label]);
        byte[]? acl = !dacl ? null : Acl(emptyDacl ? [] : duplicateAces > 0
            ? Enumerable.Repeat(allow, duplicateAces).ToArray() : [deny, allow, callback]);
        byte[] bytes = new byte[20 + 2 * sid.Length + sacl.Length + (acl?.Length ?? 0)];
        bytes[0] = 1; bytes[1] = 0x37;
        BinaryPrimitives.WriteUInt16LittleEndian(bytes.AsSpan(2), (ushort)(0xc010 | (dacl ? 0xc : 0)));
        int next = 20;
        foreach (var (field, component) in new[] { (4, sid), (8, sid), (12, sacl), (16, acl) })
        {
            if (component is null) continue;
            BinaryPrimitives.WriteUInt32LittleEndian(bytes.AsSpan(field), (uint)next);
            component.CopyTo(bytes, next); next += component.Length;
        }
        return bytes;
    }

    private static byte[] Acl(byte[][] aces)
    {
        byte[] bytes = new byte[8 + aces.Sum(a => a.Length)];
        bytes[0] = 4;
        BinaryPrimitives.WriteUInt16LittleEndian(bytes.AsSpan(2), checked((ushort)bytes.Length));
        BinaryPrimitives.WriteUInt16LittleEndian(bytes.AsSpan(4), checked((ushort)aces.Length));
        int next = 8;
        foreach (byte[] ace in aces) { ace.CopyTo(bytes, next); next += ace.Length; }
        return bytes;
    }
}
