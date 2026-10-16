using System.Buffers.Binary;
using System.Runtime.InteropServices;
using System.Text;
using SafeUpload.Agent.Core.Domain;
using SafeUpload.Agent.Minifilter;
using SafeUpload.Agent.Service.Interception;

namespace SafeUpload.Agent.Tests;

public sealed class StagedFileMetadataTests
{
    [Theory]
    [InlineData(0x4000u, "metadata_efs_unsupported")]
    [InlineData(0x1000u, "metadata_offline_unsupported")]
    [InlineData(0x800u, "metadata_compression_unsupported")]
    [InlineData(0x200u, "metadata_sparse_unsupported")]
    [InlineData(0x400u, "metadata_reparse_unsupported")]
    [InlineData(0x10u, "metadata_attributes_unsupported")]
    public void Unsupported_storage_flags_have_a_specific_reason(uint flags, string reason) =>
        Assert.Equal(reason, Assert.Throws<StagedMetadataException>(() =>
            new StagedFileMetadata(1, 2, 3, flags | 0x20).Validate()).Reason);

    [Fact]
    public void Ordinary_bits_and_zero_time_are_preserved_but_timestamp_controls_are_refused()
    {
        new StagedFileMetadata(0, 2, 3, StagedFileMetadata.SupportedAttributes).Validate();
        foreach (long control in new[] { -1L, -2L, long.MinValue })
        {
            Assert.Throws<StagedMetadataException>(() => new StagedFileMetadata(control, 2, 3, 0x80).Validate());
            Assert.Throws<StagedMetadataException>(() => new StagedFileMetadata(1, control, 3, 0x80).Validate());
            Assert.Throws<StagedMetadataException>(() => new StagedFileMetadata(1, 2, control, 0x80).Validate());
        }
    }

    [Theory]
    [InlineData(":payload:$DATA", "metadata_ads_unsupported")]
    [InlineData(":Zone.Identifier:$DATA", "metadata_zone_transaction_unavailable")]
    [InlineData(":zOnE.iDeNtIfIeR:$DATA", "metadata_zone_transaction_unavailable")]
    [InlineData(":$I30:$INDEX_ALLOCATION", "metadata_ads_unsupported")]
    public void Stream_inventory_does_not_silently_drop_even_MOTW(string name, string reason)
    {
        Assert.Equal(reason, Assert.Throws<StagedMetadataException>(() =>
            StagedFileMetadata.ValidateStreams(StreamEntry(name))).Reason);
    }

    [Theory]
    [InlineData("short")]
    [InlineData("odd-name")]
    [InlineData("long-name")]
    [InlineData("negative-size")]
    [InlineData("overlap")]
    [InlineData("unaligned")]
    [InlineData("missing-tail")]
    public void Malformed_stream_enumeration_fails_closed(string fault)
    {
        byte[] bytes = StreamEntry("::$DATA");
        switch (fault)
        {
            case "short": bytes = bytes[..23]; break;
            case "odd-name": BinaryPrimitives.WriteUInt32LittleEndian(bytes.AsSpan(4), 3); break;
            case "long-name": BinaryPrimitives.WriteUInt32LittleEndian(bytes.AsSpan(4), uint.MaxValue - 1); break;
            case "negative-size": BinaryPrimitives.WriteInt64LittleEndian(bytes.AsSpan(8), -1); break;
            case "overlap": BinaryPrimitives.WriteUInt32LittleEndian(bytes, 8); break;
            case "unaligned": BinaryPrimitives.WriteUInt32LittleEndian(bytes, 39); break;
            case "missing-tail": BinaryPrimitives.WriteUInt32LittleEndian(bytes, 40); break;
        }
        Assert.Throws<StagedMetadataException>(() => StagedFileMetadata.ValidateStreams(bytes));
    }

    [Fact]
    public void Unnamed_stream_is_accepted_including_an_empty_file()
    {
        StagedFileMetadata.ValidateStreams(StreamEntry("::$DATA"));
        StagedFileMetadata.ValidateStreams([]); // complete ERROR_HANDLE_EOF inventory
    }

    [Theory]
    [InlineData("metadata_ads_unsupported", true)]
    [InlineData("metadata_zone_transaction_unavailable", true)]
    [InlineData("metadata_ea_unsupported", true)]
    [InlineData("metadata_readonly_destination", true)]
    [InlineData("metadata_stream_inventory_invalid", true)]
    [InlineData("metadata_query_failed", false)]
    [InlineData("metadata_source_open_failed", false)]
    public void Deterministic_unsupported_metadata_is_not_classified_as_a_transient_allocation_failure(string reason, bool permanent)
    {
        var error = new StagedMetadataException(reason);
        Assert.Equal(permanent, StagedRequestRefusal.IsPermanent(error));
        Assert.Equal(permanent ? (uint?)null : StageV20Result.RetryableFailure,
            MinifilterInterceptor.ClassifyAllocationFailure(error));
    }

    [Fact]
    public void Metadata_seal_is_a_distinct_exact_layout_and_tail_is_checked()
    {
        Contract.Verify();
        var payload = new SafeUploadStageSealMetadata
        {
            Seal = new() { Version = Contract.StageExtensionVersion, StructSize = 72,
                StageIdentity = new() { VolumeSerialNumber = 3, FileIdLow = 4 }, DestinationGeneration = 5 },
            CreationTime = 10, LastAccessTime = 20, LastWriteTime = 30, FileAttributes = 0x2023
        };
        var header = new SafeUploadRequest { Version = Contract.Version, StructSize = Contract.RequestSize,
            Operation = Operation.StageSeal, Reserved = Contract.StageExtensionVersion, PathLength = 2, ImageNameLength = 72 };
        byte[] raw = new byte[Contract.RequestSize];
        MemoryMarshal.Write(raw, in header);
        int imageOffset = (int)Marshal.OffsetOf<SafeUploadRequest>(nameof(SafeUploadRequest.ImageName));
        int pathOffset = (int)Marshal.OffsetOf<SafeUploadRequest>(nameof(SafeUploadRequest.Path));
        MemoryMarshal.Write(raw.AsSpan(imageOffset), in payload); raw[pathOffset] = (byte)'x';
        var request = MemoryMarshal.Read<SafeUploadRequest>(raw);
        Assert.True(request.TryReadStagePayload<SafeUploadStageSealMetadata>(Operation.StageSeal, out var actual));
        Assert.Equal(payload.LastWriteTime, actual.LastWriteTime);
        Assert.False(request.TryReadStagePayload<SafeUploadStageSealV19>(Operation.StageSeal, out _));
        raw[imageOffset + 72] = 1;
        Assert.False(MemoryMarshal.Read<SafeUploadRequest>(raw)
            .TryReadStagePayload<SafeUploadStageSealMetadata>(Operation.StageSeal, out _));
    }

    [Fact]
    public async Task Seal_metadata_is_durable_bound_to_the_exact_version_and_not_replaced_by_replay()
    {
        using var workspace = new TestWorkspace();
        string stage = Path.Combine(workspace.Root, "stage.txt");
        await File.WriteAllTextAsync(stage, "safe bytes");
        var journal = new StagedTransferJournal(Path.Combine(workspace.Root, "journal"));
        var transfer = new StagedTransfer(Guid.NewGuid(), stage, Path.Combine(workspace.Root, "target.txt"),
            DestinationKind.RemovableDrive, "word.exe", 42, 1);
        var allocated = await journal.CreateAsync(transfer, CancellationToken.None);
        var version = StagedTransferJournal.VersionIdentity(allocated);
        var metadata = new StagedFileMetadata(100, 200, 300, 0x2023);
        await Assert.ThrowsAsync<IOException>(() => journal.SealAsync(transfer.TransferId, 42, stage,
            CancellationToken.None, fileMetadata: metadata));
        var sealedEntry = await journal.SealAsync(transfer.TransferId, 42, stage, CancellationToken.None, version, metadata);
        Assert.Equal(metadata, sealedEntry.FileMetadata);
        var restarted = new StagedTransferJournal(Path.Combine(workspace.Root, "journal"));
        Assert.Equal(metadata, (await restarted.ReadAsync(transfer.TransferId, CancellationToken.None)).FileMetadata);
        Assert.Equal(sealedEntry, await restarted.SealAsync(transfer.TransferId, 42, stage,
            CancellationToken.None, version, metadata));
        await Assert.ThrowsAsync<IOException>(() => restarted.SealAsync(transfer.TransferId, 42, stage,
            CancellationToken.None, version, metadata with { Attributes = 0x80 }));
        Assert.Equal(metadata, (await restarted.ReadAsync(transfer.TransferId, CancellationToken.None)).FileMetadata);
    }

    internal static byte[] StreamEntry(string name)
    {
        byte[] text = Encoding.Unicode.GetBytes(name);
        byte[] bytes = new byte[24 + text.Length];
        BinaryPrimitives.WriteUInt32LittleEndian(bytes.AsSpan(4), (uint)text.Length);
        text.CopyTo(bytes, 24);
        return bytes;
    }
}

// Native controls run in the Windows matrix's user partition. SYSTEM legs
// retain the matrix's existing discovery/routing; no extra SYSTEM pass is claimed.
// They deliberately have no platform skip and are not claimed by Linux controls.
public sealed class StagedFileMetadataNativeTests
{
    [Fact]
    public async Task Publication_preserves_writer_dates_and_ordinary_bits_after_handle_cleanup()
    {
        using var workspace = new TestWorkspace();
        string temporary = Path.Combine(workspace.Root, "temporary.txt"), target = Path.Combine(workspace.Root, "target.txt");
        long time = new DateTime(2005, 6, 7, 8, 9, 10, DateTimeKind.Utc).ToFileTimeUtc();
        var expected = new StagedFileMetadata(time, time + 100, time + 200, 0x2023);
        try
        {
            using (var output = StagedDestinationFile.CreateUnbuffered(temporary))
            {
                _ = StagedFileMetadata.Capture(output);
                await StagedDestinationFile.WriteUnbufferedAsync(output, new MemoryStream(Encoding.UTF8.GetBytes("safe text")), CancellationToken.None);
                expected.Apply(output);
                StagedDestinationFile.CommitHandle(output, target);
            }
            Assert.Equal(expected, StagedFileMetadata.CapturePath(target));
            Assert.Equal("safe text", await File.ReadAllTextAsync(target));
        }
        finally { if (File.Exists(target)) File.SetAttributes(target, FileAttributes.Normal); }
    }

    [Fact]
    public void Readonly_uncommitted_temporary_is_deleted_through_its_creating_handle()
    {
        using var workspace = new TestWorkspace();
        string path = Path.Combine(workspace.Root, "readonly.pending");
        using (var output = StagedDestinationFile.CreateUnbuffered(path))
        {
            new StagedFileMetadata(1, 2, 3, 1).Apply(output);
            Assert.True(StagedDestinationFile.TryDeleteUncommitted(output));
        }
        Assert.False(File.Exists(path));
    }

    [Theory]
    [InlineData("payload", "metadata_ads_unsupported")]
    [InlineData("Zone.Identifier", "metadata_zone_transaction_unavailable")]
    public async Task Overwrite_validates_source_streams_even_when_no_bytes_are_seeded(string stream, string reason)
    {
        using var workspace = new TestWorkspace();
        string source = Path.Combine(workspace.Root, "source.txt"), stage = Path.Combine(workspace.Root, "stage.txt");
        await File.WriteAllTextAsync(source, "prior bytes");
        await File.WriteAllTextAsync(source + ":" + stream, "[ZoneTransfer]\r\nZoneId=3\r\n");
        var error = await Assert.ThrowsAsync<StagedMetadataException>(() => StagedBackingFile.CreateAsync(null, stage,
            1024, CancellationToken.None, metadataSource: source));
        Assert.Equal(reason, error.Reason);
        Assert.False(File.Exists(stage));
        Assert.Equal("prior bytes", await File.ReadAllTextAsync(source));
    }
}
