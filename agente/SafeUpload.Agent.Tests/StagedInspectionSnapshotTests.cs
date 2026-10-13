using System.Buffers.Binary;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using Microsoft.Win32.SafeHandles;
using SafeUpload.Agent.Core.Application;
using SafeUpload.Agent.Core.Domain;
using SafeUpload.Agent.Core.Infrastructure;
using SafeUpload.Agent.Core.Infrastructure.Extraction;
using SafeUpload.Agent.Service.Interception;

namespace SafeUpload.Agent.Tests;

[Collection("Plaintext memory")]
public sealed class StagedInspectionSnapshotTests : IDisposable
{
    private readonly TestWorkspace _workspace = new();
    public void Dispose() => _workspace.Dispose();

    [Theory]
    [InlineData(".txt", false)]
    [InlineData(".txt", true)]
    [InlineData(".docx", false)]
    [InlineData(".docx", true)]
    [InlineData(".xlsx", false)]
    [InlineData(".xlsx", true)]
    [InlineData(".pdf", false)]
    [InlineData(".pdf", true)]
    public async Task Held_snapshots_inspect_all_formats_without_reopening_the_exclusive_path(string extension, bool sensitive)
    {
        string text = sensitive ? "CPF: 529.982.247-25" : "Clean snapshot content.";
        string path = extension switch
        {
            ".docx" => _workspace.WriteWordDocument("source.docx", text),
            ".xlsx" => _workspace.WriteSpreadsheet("source.xlsx", text),
            ".pdf" => _workspace.WritePdf("source.pdf", text),
            _ => _workspace.WriteText("source.txt", text)
        };
        byte[] original = await File.ReadAllBytesAsync(path);
        await using var source = File.OpenRead(path);
        var snapshot = await StagedInspectionSnapshot.CreateAsync(source, _workspace.Root, extension, source.Length, CancellationToken.None);
        try
        {
            Assert.Throws<IOException>(() => File.OpenRead(snapshot.Path));
            Assert.Equal(Convert.ToHexString(SHA256.HashData(original)), snapshot.Digest);
            var result = await Service().InspectStagedAsync(TestWorkspace.Operation(path) with { FilePath = snapshot.Path },
                snapshot.OpenRead, CancellationToken.None);
            Assert.Null(result.Reason);
            Assert.Equal(sensitive ? Verdict.Blocked : Verdict.Approved, result.Verdict);
            if (sensitive) Assert.Equal(Category.Cpf, Assert.Single(result.Findings).Category);
            else Assert.Empty(result.Findings);
            Assert.False(result.FromCache);
            snapshot.Stream.Position = 0;
            var captured = new byte[original.Length];
            await snapshot.Stream.ReadExactlyAsync(captured);
            Assert.Equal(original, captured);
            Assert.Empty(await new LocalQueueAuditSink(_workspace.QueueFile).ReadRecentAsync(5, CancellationToken.None));
        }
        finally { await snapshot.DisposeAsync(); }
        Assert.False(File.Exists(snapshot.Path));
        Assert.Equal(original, await File.ReadAllBytesAsync(path));
    }

    [Fact]
    public async Task Read_lease_has_no_write_or_delete_rights_and_survives_the_owner_until_its_last_close()
    {
        string path = _workspace.WriteText("source.txt", "CPF: 529.982.247-25");
        byte[] original = await File.ReadAllBytesAsync(path);
        await using var source = File.OpenRead(path);
        var snapshot = await StagedInspectionSnapshot.CreateAsync(source, _workspace.Root, ".txt", source.Length, CancellationToken.None);
        await using var lease = Assert.IsType<FileStream>(snapshot.OpenRead());
        var information = new byte[56]; // PUBLIC_OBJECT_BASIC_INFORMATION: GrantedAccess at offset four.
        Assert.Equal(0, NtQueryObject(lease.SafeFileHandle, 0, information, (uint)information.Length, out uint returned));
        Assert.Equal((uint)information.Length, returned);
        uint granted = BinaryPrimitives.ReadUInt32LittleEndian(information.AsSpan(4));
        Assert.Equal(0x00120089u, granted);
        Assert.False(lease.CanWrite);
        await snapshot.DisposeAsync();
        Assert.True(File.Exists(snapshot.Path));
        lease.Position = 0;
        var bytes = new byte[original.Length];
        await lease.ReadExactlyAsync(bytes);
        Assert.Equal(original, bytes);
        await lease.DisposeAsync();
        Assert.False(File.Exists(snapshot.Path));
        Assert.Equal(original, await File.ReadAllBytesAsync(path));
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task Empty_content_is_measured_on_the_owned_lease_instead_of_trusting_zero_metadata(bool forgedZero)
    {
        string path = Path.Combine(_workspace.Root, "source.docx");
        await File.WriteAllBytesAsync(path, forgedZero ? [42] : []);
        await using var source = File.OpenRead(path);
        await using var snapshot = await StagedInspectionSnapshot.CreateAsync(source, _workspace.Root, ".docx", source.Length, CancellationToken.None);
        var result = await Service().InspectStagedAsync(TestWorkspace.Operation(path) with { FilePath = snapshot.Path, SizeBytes = 0 },
            snapshot.OpenRead, CancellationToken.None);
        Assert.Equal(forgedZero ? Verdict.Blocked : Verdict.Approved, result.Verdict);
        Assert.Equal(forgedZero ? "parse_error:IOException" : null, result.Reason);
        Assert.Empty(result.Findings);
    }

    [Fact]
    public async Task Concurrent_read_leases_keep_independent_offsets_on_the_same_native_object()
    {
        byte[] original = Enumerable.Range(0, 256 * 1024).Select(i => (byte)(i % 251)).ToArray();
        string path = Path.Combine(_workspace.Root, "source.txt");
        await File.WriteAllBytesAsync(path, original);
        await using var source = File.OpenRead(path);
        await using var snapshot = await StagedInspectionSnapshot.CreateAsync(source, _workspace.Root, ".txt", source.Length, CancellationToken.None);
        await using var first = snapshot.OpenRead();
        await using var second = snapshot.OpenRead();
        async Task VerifyAsync(Stream reader, int offset)
        {
            reader.Position = offset;
            var buffer = new byte[4096];
            for (int i = 0; i < 32; i++)
            {
                await reader.ReadExactlyAsync(buffer);
                Assert.Equal(original.AsSpan(offset + i * buffer.Length, buffer.Length).ToArray(), buffer);
                await Task.Yield();
            }
            Assert.Equal(offset + 128L * 1024, reader.Position);
        }
        await Task.WhenAll(VerifyAsync(first, 0), VerifyAsync(second, 128 * 1024));
        snapshot.Stream.Position = 0;
        Assert.Equal(snapshot.Digest, Convert.ToHexString(await SHA256.HashDataAsync(snapshot.Stream)));
        Assert.Equal(original, await File.ReadAllBytesAsync(path));
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task Failed_or_cancelled_capture_removes_only_its_temporary_object(bool cancel)
    {
        string path = _workspace.WriteText("source.txt", "Original private bytes.");
        byte[] original = await File.ReadAllBytesAsync(path);
        await using var source = File.OpenRead(path);
        using var canceled = new CancellationTokenSource();
        if (cancel) canceled.Cancel();
        if (cancel)
            await Assert.ThrowsAnyAsync<OperationCanceledException>(() =>
                StagedInspectionSnapshot.CreateAsync(source, _workspace.Root, ".txt", source.Length, canceled.Token));
        else
            await Assert.ThrowsAsync<IOException>(() =>
                StagedInspectionSnapshot.CreateAsync(source, _workspace.Root, ".txt", source.Length + 1, canceled.Token));
        Assert.Empty(Directory.EnumerateFiles(_workspace.Root, "*.inspection*"));
        Assert.Equal(original, await File.ReadAllBytesAsync(path));
    }

    [Fact]
    public async Task A_timed_out_parser_keeps_its_read_lease_until_it_finishes_without_late_authority()
    {
        string path = _workspace.WriteText("source.txt", "CPF: 529.982.247-25");
        await using var source = File.OpenRead(path);
        var snapshot = await StagedInspectionSnapshot.CreateAsync(source, _workspace.Root, ".txt", source.Length, CancellationToken.None);
        var parser = new DelayedParser();
        var service = Service(parser, timeoutSeconds: 1);
        try
        {
            var inspection = service.InspectStagedAsync(TestWorkspace.Operation(path) with { FilePath = snapshot.Path },
                snapshot.OpenRead, CancellationToken.None);
            await parser.Entered.Task.WaitAsync(TimeSpan.FromSeconds(10));
            var result = await inspection;
            Assert.Equal(Verdict.Blocked, result.Verdict);
            Assert.Equal("inspection_timeout", result.Reason);
            Assert.Empty(result.Findings);
            Assert.Equal(1, service.ActiveInspectionWorkers);
            await snapshot.DisposeAsync();
            Assert.True(File.Exists(snapshot.Path));
            parser.Release.TrySetResult();
            await parser.Finished.Task.WaitAsync(TimeSpan.FromSeconds(10));
            var wait = Stopwatch.StartNew();
            while (service.ActiveInspectionWorkers != 0 && wait.Elapsed < TimeSpan.FromSeconds(10)) await Task.Delay(10);
            Assert.Equal(0, service.ActiveInspectionWorkers);
            Assert.Contains("529.982.247-25", parser.ReadText);
            Assert.False(File.Exists(snapshot.Path));
            Assert.Empty(await new LocalQueueAuditSink(_workspace.QueueFile).ReadRecentAsync(5, CancellationToken.None));
        }
        finally { parser.Release.TrySetResult(); await snapshot.DisposeAsync(); }
    }

    [Theory]
    [InlineData("length")]
    [InlineData("write")]
    [InlineData("missing")]
    public async Task Invalid_owned_leases_fail_closed_without_opening_a_fallback_path(string shape)
    {
        string path = _workspace.WriteText("clean.txt", "clean");
        var operation = TestWorkspace.Operation(path) with
        {
            FilePath = Path.Combine(_workspace.Root, "must-not-open.txt"), SizeBytes = 5
        };
        MemoryStream? lease = null;
        var result = await Service().InspectStagedAsync(operation, () => shape == "missing" ? null! :
            lease = new MemoryStream(Encoding.UTF8.GetBytes(shape == "length" ? "x" : "clean"), writable: shape == "write"),
            CancellationToken.None);
        Assert.Equal(Verdict.Blocked, result.Verdict);
        Assert.Equal("parse_error:IOException", result.Reason);
        Assert.Empty(result.Findings);
        if (lease is not null) Assert.False(lease.CanRead);
        Assert.Equal("clean", await File.ReadAllTextAsync(path));
    }

    [Fact]
    public async Task Windows_process_termination_closes_delete_on_close_files_without_a_path_sweep()
    {
        string temporary = Path.Combine(_workspace.Root, "crash.inspection.txt"), ready = Path.Combine(_workspace.Root, "ready");
        string sentinel = _workspace.WriteText("retained-stage.txt", "Retained private stage.");
        string script = "$ErrorActionPreference='Stop'; $f=[IO.FileStream]::new('" + temporary.Replace("'", "''") +
            "',[IO.FileMode]::CreateNew,[IO.FileAccess]::ReadWrite,[IO.FileShare]::None,4096,[IO.FileOptions]::DeleteOnClose); " +
            "$f.WriteByte(42); $f.Flush($true); [IO.File]::WriteAllText('" + ready.Replace("'", "''") + "','ready'); Start-Sleep 60";
        var start = new ProcessStartInfo("powershell.exe") { UseShellExecute = false, CreateNoWindow = true };
        foreach (string arg in new[] { "-NoProfile", "-NonInteractive", "-EncodedCommand", Convert.ToBase64String(Encoding.Unicode.GetBytes(script)) })
            start.ArgumentList.Add(arg);
        using var child = Process.Start(start)!;
        try
        {
            var wait = Stopwatch.StartNew();
            while (!File.Exists(ready) && !child.HasExited && wait.Elapsed < TimeSpan.FromSeconds(10)) await Task.Delay(10);
            Assert.True(File.Exists(ready));
            Assert.True(File.Exists(temporary));
            child.Kill(entireProcessTree: true);
            await child.WaitForExitAsync().WaitAsync(TimeSpan.FromSeconds(10));
            Assert.False(File.Exists(temporary));
            Assert.Equal("Retained private stage.", await File.ReadAllTextAsync(sentinel));
        }
        finally { if (!child.HasExited) { child.Kill(entireProcessTree: true); await child.WaitForExitAsync(); } }
    }

    private InspectionService Service(ITextExtractor? extractor = null, int timeoutSeconds = 5) => new(
        new FixedPolicyStore(LocalPolicyStore.CreateDefault() with { InspectionTimeoutSeconds = timeoutSeconds }),
        new LocalQueueAuditSink(_workspace.QueueFile), new ExtractorRegistry(extractor is null
            ? [new PlainTextExtractor(), new OpenXmlWordExtractor(), new OpenXmlSheetExtractor(), new PdfExtractor()]
            : [extractor]), new VerdictCache());

    private sealed class FixedPolicyStore(Policy policy) : IPolicyStore
    {
        public Task<Policy> LoadAsync(CancellationToken token) => Task.FromResult(policy);
        public Task<Policy> LoadCurrentAsync(CancellationToken token) => LoadAsync(token);
    }

    private sealed class DelayedParser : ITextExtractor
    {
        public IReadOnlySet<string> SupportedExtensions { get; } = new HashSet<string> { ".txt" };
        public TaskCompletionSource Entered { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        public TaskCompletionSource Release { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        public TaskCompletionSource Finished { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        public string? ReadText { get; private set; }
        public async Task<string> ExtractAsync(Stream content, CancellationToken token)
        {
            Entered.TrySetResult();
            try
            {
                await Release.Task;
                using var reader = new StreamReader(content, leaveOpen: true);
                string text = await reader.ReadToEndAsync();
                ReadText = text;
                return text;
            }
            finally { Finished.TrySetResult(); }
        }
    }

    [DllImport("ntdll.dll")]
    private static extern int NtQueryObject(SafeFileHandle file, int informationClass,
        [Out] byte[] information, uint length, out uint returned);
}
