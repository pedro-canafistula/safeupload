using System.Buffers.Binary;
using System.Text;
using SafeUpload.Agent.Core.Application;
using SafeUpload.Agent.Core.Domain;
using SafeUpload.Agent.Core.Infrastructure;
using SafeUpload.Agent.Core.Infrastructure.Extraction;
using SafeUpload.Agent.Service.Interception;

namespace SafeUpload.Agent.Tests;

public sealed class StagedMetadataRound2Tests
{
    [Theory]
    [InlineData(2, true)]
    [InlineData(3, false)]
    [InlineData(5, false)]
    [InlineData(32, false)]
    [InlineData(33, false)]
    [InlineData(123, false)]
    [InlineData(303, false)]
    public void Only_explicit_native_missing_leaf_is_absence(int error, bool missing) =>
        Assert.Equal(missing, StagedFileMetadata.IsMissingLeaf(error));

    [Fact]
    public void Native_security_comparison_accepts_outer_padding_but_preserves_all_components()
    {
        byte[] reference = SecuritySnapshotFixture.Descriptor();
        byte[] padded = new byte[reference.Length + 16];
        reference.AsSpan(0, 20).CopyTo(padded);
        reference.AsSpan(20).CopyTo(padded.AsSpan(36));
        for (int offset = 4; offset < 20; offset += 4)
            BinaryPrimitives.WriteUInt32LittleEndian(padded.AsSpan(offset),
                BinaryPrimitives.ReadUInt32LittleEndian(reference.AsSpan(offset)) + 16);
        Assert.True(StagedPublicationSecurity.Equivalent(reference, padded));
        Assert.Equal(reference, SecuritySnapshotFixture.Descriptor());
        // Owner, group, integrity label, DACL mask, ordered opaque ACE payload.
        foreach (int field in new[] { 4, 8, 12, 16 })
        {
            byte[] changed = reference.ToArray();
            int component = checked((int)BinaryPrimitives.ReadUInt32LittleEndian(changed.AsSpan(field)));
            changed[component + (field < 12 ? 8 : 12)] ^= 1;
            Assert.False(StagedPublicationSecurity.Equivalent(reference, changed, provedMovedFileSave: true));
        }
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void Moved_marker_exception_is_directional_and_requires_shape_evidence(bool moved)
    {
        byte[] reference = SecuritySnapshotFixture.Descriptor(); reference[3] |= 4;
        byte[] stored = reference.ToArray(); stored[3] &= 0xfb;
        Assert.Equal(moved, StagedPublicationSecurity.Equivalent(reference, stored, moved));
        Assert.False(StagedPublicationSecurity.Equivalent(stored, reference, moved));
        Assert.True(StagedPublicationSecurity.Equivalent(reference, reference, moved));
        Assert.Equal(4, reference[3] & 4); // comparator never repairs source evidence
    }

    [Fact]
    public void Moved_marker_exception_never_masks_other_control_RM_or_ACE_bytes()
    {
        byte[] reference = SecuritySnapshotFixture.Descriptor(); reference[3] |= 4;
        foreach (int offset in new[] { 1, 2, 3 })
        {
            for (int bit = 0; bit < 8; bit++)
            {
                if (offset == 3 && bit is 2 or 7) continue; // accepted marker / self-relative format requirement
                byte[] changed = reference.ToArray(); changed[3] &= 0xfb; changed[offset] ^= (byte)(1 << bit);
                Assert.False(StagedPublicationSecurity.Equivalent(reference, changed, provedMovedFileSave: true));
            }
        }
        byte[] malformed = reference.ToArray(); malformed[3] &= 0x7f;
        Assert.Throws<InvalidDataException>(() => StagedPublicationSecurity.Equivalent(reference, malformed, true));
    }

    [Theory]
    [InlineData(-1)]
    [InlineData(65537)]
    [InlineData(long.MaxValue)]
    public async Task MOTW_storage_is_bounded_before_reading(long length)
    {
        using var unreadable = new MemoryStream(); unreadable.Dispose();
        var failure = await Assert.ThrowsAsync<StagedMetadataException>(() =>
            StagedMotwSnapshot.CaptureAsync(unreadable, length, CancellationToken.None));
        Assert.Equal("metadata_zone_size_unsupported", failure.Reason);
    }

    [Theory]
    [InlineData(0, 1)]
    [InlineData(2, 1)]
    [InlineData(1, 2)]
    public async Task MOTW_requires_exact_complete_bytes(int actual, int expected)
    {
        using var stream = new MemoryStream(new byte[actual]);
        var failure = await Assert.ThrowsAsync<StagedMetadataException>(() =>
            StagedMotwSnapshot.CaptureAsync(stream, expected, CancellationToken.None));
        Assert.Equal("metadata_zone_measurement_changed", failure.Reason);
    }

    [Theory]
    [InlineData(0)]
    [InlineData(65536)]
    public async Task MOTW_boundary_snapshot_is_immutable_and_supplies_independent_read_leases(int length)
    {
        byte[] bytes = Enumerable.Repeat((byte)'x', length).ToArray();
        using var input = new MemoryStream(bytes);
        var snapshot = await StagedMotwSnapshot.CaptureAsync(input, length, CancellationToken.None);
        string digest = Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(bytes));
        Array.Clear(bytes);
        using var first = snapshot.OpenRead(); using var second = snapshot.OpenRead();
        Assert.False(first.CanWrite);
        Assert.Equal(digest, snapshot.Sha256Hex);
        Assert.Equal(length, snapshot.Length);
        Assert.Throws<UnauthorizedAccessException>(() => ((MemoryStream)first).GetBuffer());
        Assert.Equal(length == 0 ? -1 : 'x', first.ReadByte());
        Assert.Equal(0, second.Position);
        Assert.Equal(length == 0 ? -1 : 'x', second.ReadByte());
    }

    [Fact]
    public async Task Canceled_MOTW_capture_never_returns_a_partial_snapshot()
    {
        using var source = new MemoryStream([1, 2, 3]);
        using var cancellation = new CancellationTokenSource(); cancellation.Cancel();
        await Assert.ThrowsAsync<OperationCanceledException>(() =>
            StagedMotwSnapshot.CaptureAsync(source, 3, cancellation.Token));
        Assert.Equal(0, source.Position);
    }

    [Theory]
    [InlineData("[ZoneTransfer]\r\nZoneId=3\r\nHostUrl=https://example.test/clean", false)]
    [InlineData("[ZoneTransfer]\r\nZoneId=3\r\nHostUrl=https://example.test/529.982.247-25", true)]
    [InlineData("[ZoneTransfer]\r\nZoneId=3\r\nReferrerUrl=https://example.test/52998224725", true)]
    [InlineData("[ZoneTransfer]\r\nZoneId=3\r\nUnknownField=529.982.247-25", true)]
    public async Task MOTW_inspects_all_text_fields_through_the_ordinary_txt_inspector(string text, bool blocked)
    {
        var result = await Inspect(Encoding.UTF8.GetBytes(text));
        Assert.True(result.InScope); Assert.Equal(blocked, result.IsBlocked);
        Assert.Equal(blocked ? Verdict.Blocked : Verdict.Approved, result.Verdict);
    }

    [Theory]
    [InlineData("C328")]
    [InlineData("FFFE00D8")]
    [InlineData("FFFE000000001100")]
    public async Task Uninspectable_MOTW_is_blocked_instead_of_replacing_invalid_text(string hex)
    {
        var result = await Inspect(Convert.FromHexString(hex));
        Assert.True(result.InScope); Assert.True(result.IsBlocked);
        Assert.Equal(InspectionFailureKind.ReadOrParse, result.FailureKind);
    }

    [Theory]
    [InlineData("utf8")]
    [InlineData("utf16le")]
    [InlineData("utf16be")]
    [InlineData("utf32le")]
    [InlineData("utf32be")]
    public async Task BOMs_do_not_hide_sensitive_MOTW_text(string encoding)
    {
        Encoding textEncoding = encoding switch
        {
            "utf8" => new UTF8Encoding(true),
            "utf16le" => new UnicodeEncoding(false, true),
            "utf16be" => new UnicodeEncoding(true, true),
            "utf32le" => new UTF32Encoding(false, true),
            _ => new UTF32Encoding(true, true)
        };
        var result = await Inspect(textEncoding.GetPreamble().Concat(
            textEncoding.GetBytes("[ZoneTransfer]\r\nHostUrl=https://example.test/529.982.247-25")).ToArray());
        Assert.True(result.IsBlocked); Assert.Null(result.FailureKind);
    }

    [Fact]
    public async Task MOTW_CPF_at_the_storage_boundary_is_inspected()
    {
        byte[] tail = Encoding.UTF8.GetBytes("\r\nHostUrl=https://example.test/529.982.247-25");
        byte[] bytes = Enumerable.Repeat((byte)'x', StagedMotwSnapshot.MaximumBytes).ToArray();
        tail.CopyTo(bytes, bytes.Length - tail.Length);
        var result = await Inspect(bytes);
        Assert.True(result.IsBlocked); Assert.Null(result.FailureKind);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task Out_of_scope_or_unmonitored_text_MOTW_never_supplies_approval(bool docxOnly)
    {
        using var workspace = new TestWorkspace();
        var store = new LocalPolicyStore(workspace.PolicyFile); await store.LoadAsync(CancellationToken.None);
        if (docxOnly)
        {
            var policy = System.Text.Json.Nodes.JsonNode.Parse(await File.ReadAllTextAsync(workspace.PolicyFile))!;
            policy["monitoredScopes"]!["extensions"] = new System.Text.Json.Nodes.JsonArray(".docx");
            workspace.WritePolicy(policy.ToJsonString());
        }
        var inspector = new InspectionService(store, new LocalQueueAuditSink(workspace.QueueFile),
            ExtractorRegistry.CreateDefault(), new VerdictCache());
        byte[] bytes = Encoding.UTF8.GetBytes("[ZoneTransfer]\r\nZoneId=3\r\n");
        using var source = new MemoryStream(bytes);
        var snapshot = await StagedMotwSnapshot.CaptureAsync(source, bytes.Length, CancellationToken.None);
        var operation = new FileOperation("stage", "file.docx", ".docx", 0, DateTimeOffset.UtcNow,
            "explorer.exe", 42, @"E:\file.docx", docxOnly ? DestinationKind.RemovableDrive : DestinationKind.OutOfScope);
        var error = await Assert.ThrowsAsync<StagedMetadataException>(() =>
            snapshot.InspectAsync(inspector, operation, CancellationToken.None));
        Assert.Equal("metadata_zone_inspection_incomplete", error.Reason);
    }

    private static async Task<InspectionResult> Inspect(byte[] bytes)
    {
        using var workspace = new TestWorkspace();
        var store = new LocalPolicyStore(workspace.PolicyFile);
        await store.LoadAsync(CancellationToken.None); // create the same policy as an ordinary text control
        var inspector = new InspectionService(store, new LocalQueueAuditSink(workspace.QueueFile),
            ExtractorRegistry.CreateDefault(), new VerdictCache());
        using var source = new MemoryStream(bytes);
        var snapshot = await StagedMotwSnapshot.CaptureAsync(source, bytes.Length, CancellationToken.None);
        var operation = new FileOperation("private-stage.docx", "download.docx", ".docx", 5,
            DateTimeOffset.UtcNow, "msedge.exe", 42, @"E:\download.docx", DestinationKind.RemovableDrive);
        return await snapshot.InspectAsync(inspector, operation, CancellationToken.None);
    }
}

public sealed class StagedMetadataRound2NativeTests
{
    [Fact]
    public void Missing_parent_is_not_a_missing_leaf()
    {
        using var workspace = new TestWorkspace();
        Assert.Null(StagedFileMetadata.TryCapturePath(Path.Combine(workspace.Root, "absent.txt")));
        var failure = Assert.Throws<StagedMetadataException>(() =>
            StagedFileMetadata.TryCapturePath(Path.Combine(workspace.Root, "absent-parent", "absent.txt")));
        Assert.Equal("metadata_source_open_failed", failure.Reason);
    }
}
