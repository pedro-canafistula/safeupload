#if SAFEUPLOAD_ADMISSION_EVIDENCE
using System.Runtime.InteropServices;
using System.Text;
using SafeUpload.Agent.Minifilter;

namespace SafeUpload.Agent.Tests;

public sealed class BoundAllocationV23Tests
{
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void Exact_carrier_preserves_full_ids_and_unfolded_unicode_leaf(bool sensitive)
    {
        const string leaf = "MiXeD-é-𝄞.txt";
        var original = Payload();
        original.ParentCaseSensitive = sensitive ? (ushort)1 : (ushort)0;
        var request = Request(original, leaf);
        BoundAllocationV23Contract.Verify();
        Contract.Verify();
        Assert.True(request.HasKnownFlags);
        Assert.True(request.TryReadBoundAllocationV23(out var parsed, out string actualLeaf));
        Assert.Equal(124, Marshal.SizeOf<SafeUploadStageAllocateV23>());
        Assert.Equal(original.AllocationReservationId, parsed.AllocationReservationId);
        Assert.Equal(original.PublicTargetIdLow, parsed.PublicTargetIdLow);
        Assert.Equal(original.PublicTargetIdHigh, parsed.PublicTargetIdHigh);
        Assert.Equal(original.MountManagerVolumeId, parsed.MountManagerVolumeId);
        Assert.Equal(original.VolumeRootIdLow, parsed.VolumeRootIdLow);
        Assert.Equal(original.VolumeRootIdHigh, parsed.VolumeRootIdHigh);
        Assert.Equal(original.ParentIdentity, parsed.ParentIdentity);
        Assert.Equal(original.ParentCaseSensitive, parsed.ParentCaseSensitive);
        Assert.Equal(leaf, actualLeaf);
        Assert.False(request.TryReadStagePayload<SafeUploadStageAllocateV19>(Operation.StageAllocate, out _));
        Assert.Throws<InvalidOperationException>(() => request.GetImageName());
    }

    [Theory]
    [InlineData(0u, false, true)]
    [InlineData(0u, true, true)]
    [InlineData(1u, false, false)]
    [InlineData(1u, true, true)]
    [InlineData(2u, false, true)]
    [InlineData(2u, true, false)]
    [InlineData(3u, false, true)]
    [InlineData(3u, true, true)]
    [InlineData(4u, false, false)]
    [InlineData(4u, true, true)]
    [InlineData(5u, false, true)]
    [InlineData(5u, true, true)]
    public void No_reference_disposition_distinguishes_public_absence_from_not_copying(
        uint disposition, bool present, bool accepted)
    {
        var payload = Payload();
        payload.Disposition = disposition;
        if (!present) payload.PublicTargetIdLow = payload.PublicTargetIdHigh = 0;
        Assert.Equal(accepted, Request(payload).TryReadBoundAllocationV23(out _, out _));
    }

    [Theory]
    [InlineData(1u)]
    [InlineData(4u)]
    public void Followup_existence_is_not_inferred_from_public_target_absence(uint disposition)
    {
        var payload = Payload();
        payload.ReferenceKind = StageV19AllocationReferenceKind.Followup;
        payload.ParentTransferId = Guid.NewGuid();
        payload.Disposition = disposition;
        payload.PublicTargetIdLow = payload.PublicTargetIdHigh = 0;
        // The allocator must still validate the exact private predecessor.
        // Parsing these bytes neither proves existence nor grants an open.
        Assert.True(Request(payload).TryReadBoundAllocationV23(out _, out _));
    }

    [Theory]
    [InlineData(2u, false, true)]
    [InlineData(2u, true, false)]
    [InlineData(3u, false, false)]
    public void Tombstone_requires_fresh_create_and_proven_public_absence(
        uint disposition, bool present, bool accepted)
    {
        var payload = Payload();
        payload.ReferenceKind = StageV19AllocationReferenceKind.Tombstone;
        payload.ParentTransferId = Guid.NewGuid();
        payload.Disposition = disposition;
        if (!present) payload.PublicTargetIdLow = payload.PublicTargetIdHigh = 0;
        Assert.Equal(accepted, Request(payload).TryReadBoundAllocationV23(out _, out _));
    }

    [Theory]
    [InlineData("outer-version")]
    [InlineData("outer-size")]
    [InlineData("request-id")]
    [InlineData("process-id")]
    [InlineData("process-overflow")]
    [InlineData("operation")]
    [InlineData("marker")]
    [InlineData("missing-reply-flag")]
    [InlineData("unknown-flag")]
    [InlineData("both-volume-flags")]
    [InlineData("not-normalized")]
    [InlineData("payload-short")]
    [InlineData("payload-over-valid-limit")]
    [InlineData("path-empty")]
    [InlineData("path-odd")]
    [InlineData("path-over-bound")]
    [InlineData("inner-version")]
    [InlineData("inner-size")]
    [InlineData("reservation")]
    [InlineData("mount-guid")]
    [InlineData("root-id")]
    [InlineData("parent-id")]
    [InlineData("disposition")]
    [InlineData("reference-kind")]
    [InlineData("unexpected-parent")]
    [InlineData("missing-parent")]
    [InlineData("case-mode")]
    [InlineData("leaf-empty")]
    [InlineData("leaf-odd")]
    [InlineData("leaf-over-bound")]
    [InlineData("leaf-boundary")]
    public void Malformed_authority_or_envelope_returns_no_partial_binding(string defect)
    {
        var payload = Payload();
        switch (defect)
        {
            case "inner-version": payload.Version = 20; break;
            case "inner-size": payload.StructSize = 120; break;
            case "reservation": payload.AllocationReservationId = Guid.Empty; break;
            case "mount-guid": payload.MountManagerVolumeId = Guid.Empty; break;
            case "root-id": payload.VolumeRootIdLow = payload.VolumeRootIdHigh = 0; break;
            case "parent-id": payload.ParentIdentity.FileIdLow = payload.ParentIdentity.FileIdHigh = 0; break;
            case "disposition": payload.Disposition = 6; break;
            case "reference-kind": payload.ReferenceKind = 3; break;
            case "unexpected-parent": payload.ParentTransferId = Guid.NewGuid(); break;
            case "missing-parent": payload.ReferenceKind = StageV19AllocationReferenceKind.Followup; break;
            case "case-mode": payload.ParentCaseSensitive = 2; break;
        }
        var request = Request(payload);
        switch (defect)
        {
            case "outer-version": request.Version++; break;
            case "outer-size": request.StructSize--; break;
            case "request-id": request.RequestId = 0; break;
            case "process-id": request.RequestorProcessId = 0; break;
            case "process-overflow": request.RequestorProcessId = uint.MaxValue; break;
            case "operation": request.Operation = Operation.Create; break;
            case "marker": request.Reserved = Contract.StageExtensionVersion; break;
            case "missing-reply-flag": request.Flags = 0; break;
            case "unknown-flag": request.Flags |= 0x80000000; break;
            case "both-volume-flags": request.Flags |= 0xc0; break;
            case "not-normalized": request.Flags |= (uint)RequestFlags.PathNotNormalized; break;
            case "payload-short": request.ImageNameLength = 122; break;
            case "payload-over-valid-limit": request.ImageNameLength = 128; break;
            case "path-empty": request.PathLength = 0; break;
            case "path-odd": request.PathLength--; break;
            case "path-over-bound": request.PathLength = 1024; break;
            case "leaf-empty": WriteLeafLength(ref request, 0); break;
            case "leaf-odd": WriteLeafLength(ref request, 3); break;
            case "leaf-over-bound": WriteLeafLength(ref request, 512); break;
            case "leaf-boundary": WriteLeafLength(ref request, 2); break;
        }
        Assert.False(request.TryReadBoundAllocationV23(out var parsed, out string leaf));
        Assert.Equal(default, parsed);
        Assert.Empty(leaf);
        Assert.Throws<InvalidOperationException>(() => request.GetImageName());
    }

    [Theory]
    [InlineData("image-tail")]
    [InlineData("image-end")]
    [InlineData("path-terminator")]
    [InlineData("path-end")]
    public void Nonzero_unused_bytes_are_rejected(string defect)
    {
        var request = Request(Payload());
        var bytes = MemoryMarshal.AsBytes(MemoryMarshal.CreateSpan(ref request, 1));
        int offset = defect switch
        {
            "image-tail" => 1064 + 124,
            "image-end" => 1191,
            "path-terminator" => 40 + checked((int)request.PathLength),
            _ => 1063
        };
        bytes[offset] = 1;
        Assert.False(request.TryReadBoundAllocationV23(out _, out _));
    }

    [Theory]
    [InlineData(".")]
    [InlineData("..")]
    [InlineData("name.")]
    [InlineData("name ")]
    [InlineData("name:stream")]
    [InlineData("name*")]
    [InlineData("name?")]
    [InlineData("name|")]
    [InlineData("name\"")]
    [InlineData("name<")]
    [InlineData("name>")]
    [InlineData("name/child")]
    [InlineData("name\0tail")]
    [InlineData("name\u0001tail")]
    public void Ambiguous_or_noncanonical_leaf_is_not_an_authority(string leaf)
    {
        Assert.False(Request(Payload(), leaf).TryReadBoundAllocationV23(out _, out _));
    }

    [Fact]
    public void Ill_formed_utf16_cannot_produce_a_replacement_character_binding()
    {
        var request = Request(Payload());
        var bytes = MemoryMarshal.AsBytes(MemoryMarshal.CreateSpan(ref request, 1));
        // Replace the final ordinary code unit with an unpaired high surrogate.
        bytes[40 + checked((int)request.PathLength) - 2] = 0x00;
        bytes[40 + checked((int)request.PathLength) - 1] = 0xD8;
        Assert.False(request.TryReadBoundAllocationV23(out _, out _));
    }

    private static SafeUploadStageAllocateV23 Payload() => new()
    {
        Version = Contract.StageBoundAllocationVersion,
        StructSize = BoundAllocationV23Contract.PayloadBytes,
        AllocationReservationId = Guid.NewGuid(),
        Disposition = 5,
        PublicTargetIdLow = 0x1122334455667788,
        PublicTargetIdHigh = 0xFFEEDDCCBBAA0099,
        MountManagerVolumeId = Guid.NewGuid(),
        VolumeRootIdLow = 0x1020304050607080,
        VolumeRootIdHigh = 0x8877665544332211,
        ParentIdentity = new() { VolumeSerialNumber = 42, FileIdLow = 7, FileIdHigh = 9 },
    };

    private static SafeUploadRequest Request(SafeUploadStageAllocateV23 payload, string leaf = "checked.txt")
    {
        byte[] path = Encoding.Unicode.GetBytes(@"\Device\HarddiskVolume3\protected\" + leaf);
        payload.CanonicalLeafBytes = checked((ushort)(leaf.Length * sizeof(char)));
        var request = new SafeUploadRequest
        {
            Version = Contract.Version, StructSize = Contract.RequestSize, RequestId = 1,
            Operation = Operation.StageAllocate, RequestorProcessId = 123,
            Flags = Contract.StageV19ReplyFlag, Reserved = Contract.StageBoundAllocationVersion,
            ImageNameLength = BoundAllocationV23Contract.PayloadBytes, PathLength = checked((uint)path.Length)
        };
        var bytes = MemoryMarshal.AsBytes(MemoryMarshal.CreateSpan(ref request, 1));
        path.AsSpan().CopyTo(bytes[40..]);
        MemoryMarshal.Write(bytes[1064..], in payload);
        return request;
    }

    private static void WriteLeafLength(ref SafeUploadRequest request, ushort bytes)
    {
        var slot = MemoryMarshal.AsBytes(MemoryMarshal.CreateSpan(ref request, 1));
        slot[1064 + 122] = (byte)bytes;
        slot[1064 + 123] = (byte)(bytes >> 8);
    }
}
#endif
