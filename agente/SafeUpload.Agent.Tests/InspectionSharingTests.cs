using System.Runtime.InteropServices;
using System.IO.MemoryMappedFiles;
using System.Text;
using Microsoft.Win32.SafeHandles;
using SafeUpload.Agent.Core.Application;
using SafeUpload.Agent.Core.Domain;
using SafeUpload.Agent.Core.Infrastructure;
using SafeUpload.Agent.Core.Infrastructure.Extraction;

namespace SafeUpload.Agent.Tests;

public sealed class InspectionSharingTests
{
    [Fact]
    public async Task Source_inspection_can_coexist_with_an_approved_replacement_handle()
    {
        if (!OperatingSystem.IsWindows()) return;
        using var workspace = new TestWorkspace();
        string path = workspace.WriteText("replace.txt", "ordinary approved content");
        // A rename/delete-capable handle exposes the sharing conflict without
        // timing a race between the source classifier and the publisher.
        using var rename = CreateFile(path, 0x10000, 7, IntPtr.Zero, 3, 0x80, IntPtr.Zero);
        Assert.False(rename.IsInvalid);
        var service = new InspectionService(new LocalPolicyStore(workspace.PolicyFile),
            new LocalQueueAuditSink(workspace.QueueFile), ExtractorRegistry.CreateDefault(),
            new VerdictCache(), "PC-TESTE", "usuario.teste");
        var result = await service.InspectAsync(TestWorkspace.Operation(path), CancellationToken.None);
        Assert.Equal(Verdict.Approved, result.Verdict);
    }

    [Theory]
    [InlineData(".txt")]
    [InlineData(".csv")]
    [InlineData(".docx")]
    [InlineData(".xlsx")]
    [InlineData(".pdf")]
    public async Task Staged_extraction_reads_the_opened_version_when_its_name_is_replaced(string extension)
    {
        using var workspace = new TestWorkspace();
        string path = WriteDocument(workspace, "snapshot" + extension, "ordinary report");
        var extractor = new PausedExtractor(ExtractorRegistry.CreateDefault().Resolve(extension)!);
        var service = new InspectionService(new LocalPolicyStore(workspace.PolicyFile),
            new LocalQueueAuditSink(workspace.QueueFile), new ExtractorRegistry([extractor]),
            new VerdictCache());
        var inspection = service.InspectStagedAsync(TestWorkspace.Operation(path), CancellationToken.None);
        try
        {
            await extractor.Entered.Task.WaitAsync(TimeSpan.FromSeconds(5));
            if (OperatingSystem.IsWindows())
            {
                // Ordinary writer handles cannot change the private image during extraction.
                Assert.Throws<IOException>(() =>
                {
                    using var writer = new FileStream(path, FileMode.Open, FileAccess.Write,
                        FileShare.ReadWrite | FileShare.Delete);
                });
            }
            File.Move(path, path + ".old");
            WriteDocument(workspace, "snapshot" + extension, "CPF: 529.982.247-25");
        }
        finally
        {
            extractor.Resume.TrySetResult();
        }
        var oldVersion = await inspection;
        Assert.Equal(Verdict.Approved, oldVersion.Verdict);
        Assert.Empty(oldVersion.Findings);
        Assert.False(oldVersion.FromCache);

        var newVersion = await service.InspectStagedAsync(TestWorkspace.Operation(path), CancellationToken.None);
        Assert.Equal(Verdict.Blocked, newVersion.Verdict);
        Assert.Contains(newVersion.Findings, finding => finding.Category == Category.Cpf);
        Assert.False(newVersion.FromCache);
    }

    [Fact]
    public async Task Legacy_hash_and_scan_use_one_capture_when_a_mapping_changes_the_source_during_extraction()
    {
        if (!OperatingSystem.IsWindows()) return;
        using var workspace = new TestWorkspace();
        string path = Path.Combine(workspace.Root, "mapped.txt");
        byte[] clean = Encoding.UTF8.GetBytes("ordinary report".PadRight(64));
        File.WriteAllBytes(path, clean);
        var operation = TestWorkspace.Operation(path);
        var extractor = new PausedExtractor(new PlainTextExtractor());
        var service = new InspectionService(new LocalPolicyStore(workspace.PolicyFile),
            new LocalQueueAuditSink(workspace.QueueFile), new ExtractorRegistry([extractor]),
            new VerdictCache());
        var inspection = service.InspectAsync(operation, CancellationToken.None);
        try
        {
            await extractor.Entered.Task.WaitAsync(TimeSpan.FromSeconds(5));
            // Legacy extraction starts after the input capture closes its read
            // handle. The actor can now mutate the name while parsing continues.
            // Mapping before that point correctly prevents opening the reader.
            using var source = new FileStream(path, FileMode.Open, FileAccess.ReadWrite,
                FileShare.ReadWrite | FileShare.Delete);
            using var mapping = MemoryMappedFile.CreateFromFile(source, null, 0,
                MemoryMappedFileAccess.ReadWrite, HandleInheritability.None, leaveOpen: true);
            using var view = mapping.CreateViewAccessor();
            source.Dispose();
            byte[] sensitive = Encoding.UTF8.GetBytes("CPF: 529.982.247-25".PadRight(clean.Length));
            view.WriteArray(0, sensitive, 0, sensitive.Length);
            view.Flush();
        }
        finally
        {
            extractor.Resume.TrySetResult();
        }
        var captured = await inspection;
        Assert.Equal(Verdict.Approved, captured.Verdict);
        Assert.Empty(captured.Findings);
        Assert.False(captured.FromCache);

        // Deliberately reuse the same size/timestamp hints. Only the byte hash
        // can invalidate the cached clean result after the mapping's write.
        var changed = await service.InspectAsync(operation, CancellationToken.None);
        Assert.Equal(Verdict.Blocked, changed.Verdict);
        Assert.Contains(changed.Findings, finding => finding.Category == Category.Cpf);
        Assert.False(changed.FromCache);
        var cached = await service.InspectAsync(operation, CancellationToken.None);
        Assert.Equal(Verdict.Blocked, cached.Verdict);
        Assert.True(cached.FromCache);
    }

    private static string WriteDocument(TestWorkspace workspace, string name, string text)
        => Path.GetExtension(name) switch
        {
            ".docx" => workspace.WriteWordDocument(name, text),
            ".xlsx" => workspace.WriteSpreadsheet(name, text),
            ".pdf" => workspace.WritePdf(name, text),
            _ => workspace.WriteText(name, text)
        };

    private sealed class PausedExtractor(ITextExtractor inner) : ITextExtractor
    {
        private int _calls;
        public TaskCompletionSource Entered { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        public TaskCompletionSource Resume { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        public IReadOnlySet<string> SupportedExtensions => inner.SupportedExtensions;
        public async Task<string> ExtractAsync(Stream content, CancellationToken cancellationToken)
        {
            if (Interlocked.Increment(ref _calls) == 1)
            {
                Entered.TrySetResult();
                await Resume.Task.WaitAsync(cancellationToken);
            }
            return await inner.ExtractAsync(content, cancellationToken);
        }
    }

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern SafeFileHandle CreateFile(string path, uint access, uint share,
        IntPtr security, uint disposition, uint flags, IntPtr template);
}
