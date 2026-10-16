using System.Buffers.Binary;
using System.Diagnostics;
using System.Text;
using SafeUpload.Agent.Core.Application;
using SafeUpload.Agent.Core.Domain;
using SafeUpload.Agent.Core.Infrastructure;
using SafeUpload.Agent.Core.Infrastructure.Extraction;
using static SafeUpload.Agent.Tests.ArchiveFixture;

namespace SafeUpload.Agent.Tests;

public sealed partial class ArchiveInspectionTests
{
    [Theory]
    [InlineData(".zip", false)]
    [InlineData(".zip", true)]
    [InlineData(".7z", false)]
    public async Task Default_policy_routes_archives_in_both_inspection_paths(string extension, bool sensitive)
    {
        string path = Write(Zip(Text("document.txt", sensitive ? Cpf : "clean")), extension);
        foreach (bool staged in new[] { false, true })
        {
            var service = new InspectionService(new LocalPolicyStore(_workspace.PolicyFile), new LocalQueueAuditSink(_workspace.QueueFile),
                ExtractorRegistry.CreateDefault(), new VerdictCache());
            var result = staged ? await service.InspectStagedAsync(TestWorkspace.Operation(path), CancellationToken.None)
                : await service.InspectAsync(TestWorkspace.Operation(path), CancellationToken.None);
            Assert.True(result.InScope);
            Assert.Equal(extension == ".7z" ? staged ? Verdict.Blocked : Verdict.AllowedWithoutInspection : sensitive ? Verdict.Blocked : Verdict.Approved, result.Verdict);
            Assert.Equal(extension == ".7z" ? "archive_7z_unavailable" : null, result.Reason);
            if (sensitive) Assert.Equal("document.txt", Assert.Single(result.Findings).MemberName);
            else Assert.Empty(result.Findings);
        }
    }

    [Theory]
    [InlineData("central-signature")]
    [InlineData("local-signature")]
    [InlineData("local-name")]
    [InlineData("local-flags")]
    [InlineData("local-length")]
    [InlineData("central-extent")]
    [InlineData("central-count")]
    [InlineData("local-offset")]
    [InlineData("crc")]
    [InlineData("truncated")]
    [InlineData("prefix")]
    [InlineData("suffix")]
    [InlineData("hidden-local")]
    [InlineData("descriptor")]
    public async Task Malformed_local_central_and_descriptor_records_never_approve_partial_content(string shape)
    {
        byte[] bytes = Zip(Text("document.txt", Cpf) with { Descriptor = shape == "descriptor" });
        int central = Central(bytes);
        switch (shape)
        {
            case "central-signature": bytes[central] = 0; break;
            case "local-signature": bytes[0] = 0; break;
            case "local-name": bytes[30] = (byte)'X'; break;
            case "local-flags": U16(bytes, 6, 0); break;
            case "local-length": U32(bytes, 22, 99); break;
            case "central-extent": U32(bytes, bytes.Length - 10, 1); break;
            case "central-count": U16(bytes, bytes.Length - 14, 2); U16(bytes, bytes.Length - 12, 2); break;
            case "local-offset": U32(bytes, central + 42, 1); break;
            case "crc": U32(bytes, 14, 0); U32(bytes, central + 16, 0); break;
            case "truncated": bytes = bytes[..^1]; break;
            case "prefix":
                bytes = new byte[] { 0 }.Concat(bytes).ToArray();
                U32(bytes, bytes.Length - 6, (uint)(central + 1)); U32(bytes, central + 1 + 42, 1); break;
            case "suffix": bytes = bytes.Concat(new byte[] { 0 }).ToArray(); break;
            case "descriptor": bytes[central - 12] ^= 1; break;
            case "hidden-local":
                bytes = Zip(Text("document.txt", Cpf), Text("hidden.txt", "uninspected"));
                central = Central(bytes);
                int firstSize = 46 + Encoding.UTF8.GetByteCount("document.txt");
                int secondSize = 46 + Encoding.UTF8.GetByteCount("hidden.txt");
                var shortened = bytes.ToList(); shortened.RemoveRange(central + firstSize, secondSize); bytes = shortened.ToArray();
                U16(bytes, bytes.Length - 14, 1); U16(bytes, bytes.Length - 12, 1); U32(bytes, bytes.Length - 10, (uint)firstSize); break;
        }
        await ParseFailure(bytes);
    }

    [Theory]
    [InlineData("missing-final-marker")]
    [InlineData("truncated-payload")]
    [InlineData("suffix")]
    [InlineData("concatenated")]
    [InlineData("declared-too-short")]
    [InlineData("declared-too-long")]
    public async Task Deflate_must_finish_exactly_before_any_child_inspector_runs(string shape)
    {
        byte[] data = Encoding.UTF8.GetBytes("clean");
        byte[] encoded = Deflate(data);
        uint length = (uint)data.Length;
        switch (shape)
        {
            // Nonfinal stored DEFLATE block: all output exists and has the
            // correct CRC, but the final block/marker is absent.
            case "missing-final-marker": encoded = new byte[] { 0, 5, 0, 250, 255 }.Concat(data).ToArray(); break;
            case "truncated-payload": encoded = encoded[..^2]; break;
            case "suffix": encoded = encoded.Concat(new byte[] { 0, 1, 2 }).ToArray(); break;
            case "concatenated": encoded = encoded.Concat(Deflate(Encoding.UTF8.GetBytes(Cpf))).ToArray(); break;
            case "declared-too-short": length--; break;
            case "declared-too-long": length++; break;
        }
        byte[] bytes = Zip(new Item("document.txt", data) { Method = 8, Encoded = encoded, Length = length });
        await ParseFailure(bytes);
        var probe = new ProbeExtractor();
        using var source = new MemoryStream(bytes, writable: false);
        await Assert.ThrowsAsync<InvalidDataException>(() => new ZipArchiveExtractor().InspectAsync(source, new ExtractorRegistry([probe]), Policy(), CancellationToken.None));
        Assert.Equal(0, probe.Opened);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task Signed_and_unsigned_data_descriptors_are_fully_reconciled(bool signature)
        => await Check(Write(Zip(Text("document.txt", Cpf) with { Method = 8, Descriptor = true, DescriptorSignature = signature })),
            sensitive: true, memberName: "document.txt");

    [Theory]
    [InlineData("flags")]
    [InlineData("version")]
    [InlineData("method")]
    [InlineData("zip64")]
    [InlineData("split")]
    [InlineData("extra")]
    [InlineData("comment")]
    [InlineData("symlink")]
    [InlineData("directory-data")]
    [InlineData("duplicate")]
    [InlineData("legacy-name")]
    public async Task Non_allowlisted_ZIP_features_are_explicit_refusals(string shape)
    {
        var item = Text(shape == "directory-data" ? "directory/" : shape == "legacy-name" ? "ação.txt" : "document.txt", "clean");
        item = shape switch
        {
            "extra" => item with { Extra = [0xad, 0xde, 0, 0] },
            "comment" => item with { Comment = Encoding.UTF8.GetBytes(Cpf) },
            "symlink" => item with { Attributes = 0xa1ff0000 },
            "legacy-name" => item with { Flags = 0 },
            _ => item
        };
        byte[] bytes = shape == "duplicate" ? Zip(item, item) : Zip(item);
        int central = Central(bytes);
        switch (shape)
        {
            case "flags": U16(bytes, 6, 0x10); U16(bytes, central + 8, 0x10); break;
            case "version": U16(bytes, 4, 45); U16(bytes, central + 6, 45); break;
            case "method": U16(bytes, 8, 12); U16(bytes, central + 10, 12); break;
            case "zip64": U32(bytes, central + 24, uint.MaxValue); break;
            case "split": U16(bytes, bytes.Length - 18, 1); break;
        }
        await Check(Write(bytes), reason: "archive_unsupported_structure");
    }

    [Theory]
    [InlineData("extended-timestamps")]
    [InlineData("ntfs-timestamps")]
    [InlineData("empty-directory")]
    [InlineData("empty-deflate")]
    [InlineData("stored-final-deflate")]
    public async Task Supported_structural_records_are_validated_and_read(string shape)
    {
        var item = Text("document.txt", "clean");
        item = shape switch
        {
            "extended-timestamps" => item with { Extra = [0x55, 0x54, 5, 0, 1, 0, 0, 0, 0] },
            "ntfs-timestamps" => item with { Extra = new byte[] { 10, 0, 32, 0, 0, 0, 0, 0, 1, 0, 24, 0 }.Concat(new byte[24]).ToArray() },
            "empty-directory" => Text("directory/", "") with { Attributes = 0x41ed0010 },
            "empty-deflate" => Text("document.txt", "") with { Method = 8 },
            "stored-final-deflate" => Text("document.txt", "clean") with { Method = 8, Encoded = new byte[] { 1, 5, 0, 250, 255 }.Concat(Encoding.UTF8.GetBytes("clean")).ToArray() },
            _ => item
        };
        await Check(Write(Zip(item)));
    }

    [Theory]
    [InlineData(1000)]
    [InlineData(1001)]
    public void Declared_ratio_is_bounded_before_decoder_creation(int ratio)
    {
        // Only preflight admission is under test here. A deliberately invalid
        // one-byte deflate frame must still fail when ReadMember is attempted.
        using var source = new MemoryStream(Zip(new Item("data.txt", new byte[ratio]) { Method = 8, Encoded = [0] }), writable: false);
        var budget = new ArchiveInspectionBudget(20L * 1024 * 1024);
        if (ratio == 1000) Assert.Single(ZipInspectionGuard.Inspect(source, budget, 1, CancellationToken.None));
        else Assert.Throws<InspectionLimitException>(() => ZipInspectionGuard.Inspect(source, budget, 1, CancellationToken.None));
    }

    [Fact]
    public async Task Malformed_UTF8_names_are_not_silently_replaced()
    {
        byte[] bytes = Zip(Text("document.txt", "clean"));
        int central = Central(bytes); bytes[30] = bytes[central + 46] = 255;
        foreach (bool staged in new[] { false, true })
        {
            var result = await Inspect(Write(bytes), staged);
            Assert.Equal(staged ? Verdict.Blocked : Verdict.AllowedWithoutInspection, result.Verdict);
            Assert.Equal("parse_error:DecoderFallbackException", result.Reason); Assert.Empty(result.Findings);
        }
    }

    [Fact]
    public async Task A_malformed_late_Office_member_discards_earlier_sensitive_findings()
    {
        byte[] word = Member(".docx", Cpf);
        using (var data = new MemoryStream())
        {
            data.Write(word); data.Position = 0;
            using (var package = new System.IO.Compression.ZipArchive(data, System.IO.Compression.ZipArchiveMode.Update, leaveOpen: true))
            {
                package.GetEntry("word/document.xml")!.Delete();
                using var writer = new StreamWriter(package.CreateEntry("word/document.xml").Open()); writer.Write("<broken");
            }
            word = data.ToArray();
        }
        foreach (bool staged in new[] { false, true })
        {
            var result = await Inspect(Write(Zip(Text("first.txt", Cpf), new Item("late.docx", word))), staged);
            Assert.Equal(staged ? Verdict.Blocked : Verdict.AllowedWithoutInspection, result.Verdict);
            Assert.Equal(InspectionFailureKind.ReadOrParse, result.FailureKind); Assert.Empty(result.Findings);
        }
    }

    [Fact]
    public async Task Actual_held_length_is_checked_even_when_operation_metadata_claims_a_smaller_archive()
    {
        string path = Write(Zip(new Item("data.txt", Letters(1024 * 1024 + 1))));
        var policy = Policy() with { MaxFileSizeMb = 1 };
        var service = new InspectionService(new FixedPolicyStore(policy), new LocalQueueAuditSink(_workspace.QueueFile), ExtractorRegistry.CreateDefault(), new VerdictCache());
        var operation = TestWorkspace.Operation(path, sizeBytes: 1);
        foreach (bool staged in new[] { false, true })
        {
            var result = staged ? await service.InspectStagedAsync(operation, CancellationToken.None) : await service.InspectAsync(operation, CancellationToken.None);
            Assert.Equal(staged ? Verdict.Blocked : Verdict.AllowedWithoutInspection, result.Verdict);
            Assert.Equal("file_too_large", result.Reason); Assert.Empty(result.Findings);
        }
    }

    [Fact]
    public async Task Caller_timeout_keeps_the_archive_worker_and_lease_until_the_member_reader_really_finishes()
    {
        byte[] bytes = Zip(Text("document.txt", "clean")); string path = Write(bytes);
        var entered = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var release = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var child = new ProbeExtractor(entered, release);
        var service = new InspectionService(new FixedPolicyStore(Policy() with { InspectionTimeoutSeconds = 1 }), new LocalQueueAuditSink(_workspace.QueueFile),
            new ExtractorRegistry([new ZipArchiveExtractor(), child]), new VerdictCache());
        var lease = new TrackedInput(bytes);
        try
        {
            var task = service.InspectStagedAsync(TestWorkspace.Operation(path), () => lease, CancellationToken.None);
            await entered.Task.WaitAsync(TimeSpan.FromSeconds(3));
            var result = await task;
            Assert.Equal("inspection_timeout", result.Reason); Assert.Equal(Verdict.Blocked, result.Verdict); Assert.Empty(result.Findings);
            Assert.Equal(1, service.ActiveInspectionWorkers); Assert.False(lease.Disposed);
        }
        finally { release.TrySetResult(); }
        var elapsed = Stopwatch.StartNew();
        while (service.ActiveInspectionWorkers != 0 && elapsed.Elapsed < TimeSpan.FromSeconds(3)) await Task.Delay(10);
        Assert.Equal(0, service.ActiveInspectionWorkers); Assert.True(lease.Disposed);
    }

    private async Task ParseFailure(byte[] bytes)
    {
        string path = Write(bytes);
        foreach (bool staged in new[] { false, true })
        {
            var result = await Inspect(path, staged);
            Assert.Equal(staged ? Verdict.Blocked : Verdict.AllowedWithoutInspection, result.Verdict);
            Assert.Equal(InspectionFailureKind.ReadOrParse, result.FailureKind); Assert.StartsWith("parse_error:", result.Reason);
            Assert.Empty(result.Findings); Assert.Equal(bytes, File.ReadAllBytes(path));
        }
    }
    private sealed class ProbeExtractor(TaskCompletionSource? entered = null, TaskCompletionSource? release = null) : IStreamingTextExtractor
    {
        internal int Opened;
        public IReadOnlySet<string> SupportedExtensions { get; } = new HashSet<string> { ".txt" };
        public async Task<TextReader> OpenReaderAsync(Stream content, CancellationToken cancellationToken)
        {
            Opened++; entered?.TrySetResult();
            if (release is not null) await release.Task;
            return new StringReader(Cpf);
        }
        public Task<string> ExtractAsync(Stream content, CancellationToken cancellationToken) => throw new InvalidOperationException("Archive service inspection must stream members.");
    }
    private sealed class TrackedInput(byte[] bytes) : MemoryStream(bytes, writable: false)
    {
        internal bool Disposed;
        protected override void Dispose(bool disposing) { if (disposing) Disposed = true; base.Dispose(disposing); }
    }
}
