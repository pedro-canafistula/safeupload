using SafeUpload.Agent.Core.Application;
using SafeUpload.Agent.Core.Contracts;
using SafeUpload.Agent.Core.Domain;
using SafeUpload.Agent.Core.Infrastructure;
using SafeUpload.Agent.Core.Infrastructure.Extraction;
using SafeUpload.Agent.Service.Interception;
using SafeUpload.Agent.Service.Notifications;
using System.Text.Json.Nodes;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

namespace SafeUpload.Agent.Tests;

public sealed class StagedTransferPublisherTests : IDisposable
{
    private readonly TestWorkspace _workspace = new();
    private readonly string _stagingRoot;
    private readonly NotificationHub _notifications = NotificationTestHub.Create();
    private readonly StagedTransferJournal _journal;
    private readonly StagedTransferPublisher _publisher;

    public StagedTransferPublisherTests()
    {
        _stagingRoot = Path.Combine(_workspace.Root, "staging");
        Directory.CreateDirectory(_stagingRoot);
        _journal = new StagedTransferJournal(Path.Combine(_workspace.Root, "journal"));

        var inspector = new InspectionService(
            new LocalPolicyStore(_workspace.PolicyFile),
            new LocalQueueAuditSink(_workspace.QueueFile),
            ExtractorRegistry.CreateDefault(),
            new VerdictCache());

        _publisher = new StagedTransferPublisher(inspector, _notifications, _journal, _stagingRoot, new TestPublicationGate());
    }

    public void Dispose() => _workspace.Dispose();

    [Theory]
    [InlineData(false, true)]
    [InlineData(true, false)]
    [InlineData(true, true)]
    public async Task Committed_publication_remains_released_after_revocation_failure_or_cancellation(
        bool cancel, bool failRevoke)
    {
        using var cancellation = new CancellationTokenSource();
        using var subscription = _notifications.Subscribe();
        var gate = new FinalizationPublicationGate(cancel ? cancellation : null, failRevoke);
        var publisher = new StagedTransferPublisher(new InspectionService(
            new LocalPolicyStore(_workspace.PolicyFile), new LocalQueueAuditSink(_workspace.QueueFile),
            ExtractorRegistry.CreateDefault(), new VerdictCache()),
            _notifications, _journal, _stagingRoot, gate);
        var transfer = Transfer("committed.txt", "approved committed version");

        Assert.Equal(StagedTransferOutcome.Released,
            await publisher.PublishAsync(transfer, cancellation.Token));
        Assert.True(gate.Disposed);
        Assert.Equal("approved committed version", await File.ReadAllTextAsync(transfer.DestinationPath));
        Assert.Equal(TransferJournalState.Released,
            (await _journal.ReadAsync(transfer.TransferId, CancellationToken.None)).State);
        var phases = new List<TransferPhase>();
        while (subscription.Reader.TryRead(out var notification))
            if (notification is TransferNotification transferNotification) phases.Add(transferNotification.Phase);
        Assert.Contains(TransferPhase.Released, phases);
        Assert.DoesNotContain(TransferPhase.Retained, phases);
    }

    private sealed class FinalizationPublicationGate(CancellationTokenSource? cancellation, bool fail)
        : IStagedPublicationGate, IDisposable
    {
        public bool Disposed;
        public IDisposable Authorize(StagedTransfer transfer, string temporaryDestination, string digest) => this;
        public void Dispose()
        {
            Disposed = true;
            cancellation?.Cancel();
            if (fail) throw new IOException("Injected disconnect during permit revocation.");
        }
    }

    [Fact]
    public async Task Approved_replacement_preserves_a_live_public_reader()
    {
        var transfer = Transfer("replace-reader.txt", "new approved bytes");
        Directory.CreateDirectory(Path.GetDirectoryName(transfer.DestinationPath)!);
        await File.WriteAllTextAsync(transfer.DestinationPath, "old approved bytes");
        using var reader = new FileStream(transfer.DestinationPath, FileMode.Open,
            FileAccess.Read, FileShare.Read | FileShare.Delete);
        Assert.Equal(StagedTransferOutcome.Released,
            await _publisher.PublishAsync(transfer, CancellationToken.None));
        using var text = new StreamReader(reader);
        Assert.Equal("old approved bytes", await text.ReadToEndAsync());
        Assert.Equal("new approved bytes", await File.ReadAllTextAsync(transfer.DestinationPath));
    }

    [Fact]
    public async Task Approved_replacement_preserves_a_public_mapping_after_handle_close()
    {
        var transfer = Transfer("replace-map.txt", "new approved bytes");
        Directory.CreateDirectory(Path.GetDirectoryName(transfer.DestinationPath)!);
        await File.WriteAllTextAsync(transfer.DestinationPath, "old approved bytes");
        var reader = new FileStream(transfer.DestinationPath, FileMode.Open,
            FileAccess.Read, FileShare.Read | FileShare.Delete);
        using var mapping = System.IO.MemoryMappedFiles.MemoryMappedFile.CreateFromFile(reader, null, 0,
            System.IO.MemoryMappedFiles.MemoryMappedFileAccess.Read, HandleInheritability.None, leaveOpen: true);
        using var view = mapping.CreateViewAccessor(0, 0, System.IO.MemoryMappedFiles.MemoryMappedFileAccess.Read);
        reader.Dispose();
        Assert.Equal(StagedTransferOutcome.Released,
            await _publisher.PublishAsync(transfer, CancellationToken.None));
        byte[] prior = new byte[18];
        view.ReadArray(0, prior, 0, prior.Length);
        Assert.Equal("old approved bytes", System.Text.Encoding.UTF8.GetString(prior));
        Assert.Equal("new approved bytes", await File.ReadAllTextAsync(transfer.DestinationPath));
    }

    [Fact]
    public async Task Readonly_public_destination_is_not_replaced_or_reported_released()
    {
        var transfer = Transfer("replace-readonly.txt", "new approved bytes");
        Directory.CreateDirectory(Path.GetDirectoryName(transfer.DestinationPath)!);
        await File.WriteAllTextAsync(transfer.DestinationPath, "old approved bytes");
        File.SetAttributes(transfer.DestinationPath, FileAttributes.ReadOnly);
        try
        {
            Assert.Equal(StagedTransferOutcome.Retained,
                await _publisher.PublishAsync(transfer, CancellationToken.None));
            Assert.Equal("old approved bytes", await File.ReadAllTextAsync(transfer.DestinationPath));
            Assert.Equal(TransferJournalState.Retained,
                (await _journal.ReadAsync(transfer.TransferId, CancellationToken.None)).State);
            Assert.Empty(Directory.GetFiles(Path.GetDirectoryName(transfer.DestinationPath)!, "*.pending"));
        }
        finally { File.SetAttributes(transfer.DestinationPath, FileAttributes.Normal); }
    }

    [Theory]
    [InlineData(false, false)]
    [InlineData(false, true)]
    [InlineData(true, false)]
    public async Task Kernel_publication_permission_is_required_only_after_inspected_approval(
        bool sensitive, bool refusePermit)
    {
        var gate = new RecordingPublicationGate(refusePermit);
        var publisher = new StagedTransferPublisher(new InspectionService(
            new LocalPolicyStore(_workspace.PolicyFile), new LocalQueueAuditSink(_workspace.QueueFile),
            ExtractorRegistry.CreateDefault(), new VerdictCache()),
            _notifications, _journal, _stagingRoot, gate);
        var transfer = Transfer("permit.txt", sensitive ? "CPF: 529.982.247-25" : "clean version");
        var outcome = await publisher.PublishAsync(transfer, CancellationToken.None);
        Assert.Equal(sensitive ? StagedTransferOutcome.Blocked : refusePermit
            ? StagedTransferOutcome.Retained : StagedTransferOutcome.Released, outcome);
        Assert.Equal(!sensitive, gate.Called);
        Assert.Equal(!sensitive && !refusePermit, File.Exists(transfer.DestinationPath));
        if (gate.Called)
        {
            Assert.Equal(transfer, gate.Transfer);
            Assert.Equal(Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(
                File.ReadAllBytes(transfer.StagePath))), gate.Digest);
            Assert.Equal(Path.Combine(Path.GetDirectoryName(transfer.DestinationPath)!,
                ".safeupload-" + transfer.TransferId.ToString("N") + ".pending"), gate.Temporary);
            Assert.Equal(!refusePermit, gate.Disposed);
        }
    }

    private sealed class RecordingPublicationGate(bool refuse) : IStagedPublicationGate, IDisposable
    {
        public bool Called, Disposed;
        public StagedTransfer? Transfer;
        public string? Temporary, Digest;
        public IDisposable Authorize(StagedTransfer transfer, string temporaryDestination, string digest)
        {
            Called = true; Transfer = transfer; Temporary = temporaryDestination; Digest = digest;
            if (refuse) throw new IOException("Disconnected kernel publication gate.");
            return this;
        }
        public void Dispose() => Disposed = true;
    }

    [Theory]
    [InlineData(false, false, StagedTransferOutcome.Released)]
    [InlineData(true, false, StagedTransferOutcome.Retained)]
    [InlineData(false, true, StagedTransferOutcome.Blocked)]
    public async Task Justification_is_bound_to_the_exact_inspected_version_and_policy(
        bool changeBytes, bool changePolicy, StagedTransferOutcome expected)
    {
        var store = new LocalPolicyStore(_workspace.PolicyFile);
        await store.LoadAsync(CancellationToken.None);
        var policy = JsonNode.Parse(await File.ReadAllTextAsync(_workspace.PolicyFile))!;
        policy["overrideAllowed"] = true;
        await File.WriteAllTextAsync(_workspace.PolicyFile, policy.ToJsonString());
        var broker = new StagedJustifications();
        var publisher = new StagedTransferPublisher(new InspectionService(store,
            new LocalQueueAuditSink(_workspace.QueueFile), ExtractorRegistry.CreateDefault(),
            new VerdictCache()), _notifications, _journal, _stagingRoot, new TestPublicationGate(), broker);
        var original = Transfer("justify.txt", "CPF: 529.982.247-25");
        // Transfer() journals immediately; give this independent transfer an
        // authenticated notification session before journaling it.
        var transfer = original with { TransferId = Guid.NewGuid(), SessionId = 7 };
        await _journal.CreateAsync(transfer, CancellationToken.None);
        await _journal.TransitionAsync(transfer.TransferId, TransferJournalState.Allocated,
            TransferJournalState.Sealed, null, CancellationToken.None);
        Assert.Equal(StagedTransferOutcome.Blocked,
            await publisher.PublishAsync(transfer, CancellationToken.None));
        Assert.True(broker.TryConsume(transfer.TransferId.ToString("D"), 8, out var wrongSession));
        Assert.Null(wrongSession);
        Assert.True(broker.TryConsume(transfer.TransferId.ToString("D"), 7, out var publish));
        Assert.NotNull(publish);
        Assert.False(broker.TryConsume(transfer.TransferId.ToString("D"), 7, out _));
        if (changeBytes) await File.WriteAllTextAsync(transfer.StagePath, "changed bytes");
        if (changePolicy)
        {
            policy["version"] = 2;
            await File.WriteAllTextAsync(_workspace.PolicyFile, policy.ToJsonString());
        }
        Assert.Equal(expected == StagedTransferOutcome.Released,
            await publish!(CancellationToken.None));
        Assert.Equal(expected == StagedTransferOutcome.Released, File.Exists(transfer.DestinationPath));
        if (expected == StagedTransferOutcome.Released)
            Assert.Equal("CPF: 529.982.247-25", await File.ReadAllTextAsync(transfer.DestinationPath));
        else
            Assert.Equal(expected == StagedTransferOutcome.Blocked
                    ? TransferJournalState.Blocked : TransferJournalState.Retained,
                (await _journal.ReadAsync(transfer.TransferId, CancellationToken.None)).State);
    }

    private sealed class TestPublicationGate : IStagedPublicationGate, IDisposable
    {
        public IDisposable Authorize(StagedTransfer transfer, string temporaryDestination, string digest) => this;
        public void Dispose() { }
    }

    private StagedTransfer Transfer(string name, string content, DestinationKind kind = DestinationKind.RemovableDrive)
    {
        string stage = Path.Combine(_stagingRoot, name);
        File.WriteAllText(stage, content);
        string destination = Path.Combine(_workspace.Root, "destination", name);
        Directory.CreateDirectory(Path.GetDirectoryName(destination)!);

        var transfer = new StagedTransfer(
            Guid.NewGuid(), stage, destination,
            kind,
            "explorer.exe", 4242, null);
        _journal.CreateAsync(transfer, CancellationToken.None).GetAwaiter().GetResult();
        _journal.TransitionAsync(transfer.TransferId,
            TransferJournalState.Allocated, TransferJournalState.Sealed,
            null, CancellationToken.None).GetAwaiter().GetResult();
        return transfer;
    }

    [Fact]
    public async Task Sensitive_content_never_reaches_the_destination()
    {
        var transfer = Transfer("sensitive.txt", "CPF: 529.982.247-25");

        var outcome = await _publisher.PublishAsync(transfer, CancellationToken.None);

        Assert.Equal(StagedTransferOutcome.Blocked, outcome);
        Assert.False(File.Exists(transfer.DestinationPath));
        Assert.True(File.Exists(transfer.StagePath));
        Assert.Equal(TransferJournalState.Blocked,
            (await _journal.ReadAsync(transfer.TransferId, CancellationToken.None)).State);
        var audit = await new LocalQueueAuditSink(_workspace.QueueFile)
            .ReadRecentAsync(10, CancellationToken.None);
        Assert.Single(audit);
        Assert.Equal(Verdict.Blocked, audit[0].Verdict);
    }

    [Theory]
    [InlineData("Clean office save.", StagedTransferOutcome.Released)]
    [InlineData("CPF: 529.982.247-25", StagedTransferOutcome.Blocked)]
    public async Task Renamed_temporary_version_is_inspected_using_the_final_format(
        string content, StagedTransferOutcome expected)
    {
        var transfer = Transfer("office.tmp", content);
        Assert.Equal(StagedTransferOutcome.Retained,
            await _publisher.PublishAsync(transfer, CancellationToken.None));
        Assert.False(File.Exists(transfer.DestinationPath));
        string final = Path.ChangeExtension(transfer.DestinationPath, ".txt");
        await _journal.PrepareRenameAsync(transfer.TransferId, 1,
            transfer.ProcessId, final, true, CancellationToken.None);
        var renamed = await _journal.CompleteRenameAsync(transfer.TransferId, 1,
            transfer.ProcessId, final, true, CancellationToken.None);
        await Assert.ThrowsAsync<InvalidOperationException>(() =>
            _publisher.PublishAsync(transfer, CancellationToken.None));
        Assert.Equal(expected, await _publisher.PublishAsync(renamed.Transfer, CancellationToken.None));
        Assert.Equal(expected == StagedTransferOutcome.Released, File.Exists(final));
        Assert.False(File.Exists(transfer.DestinationPath));
    }

    [Fact]
    public async Task Prepared_rename_cannot_publish_until_the_kernel_commits_it()
    {
        var transfer = Transfer("before.txt", "Clean text.");
        string renamed = Path.ChangeExtension(transfer.DestinationPath, ".renamed.txt");
        await _journal.PrepareRenameAsync(transfer.TransferId, 77, transfer.ProcessId,
            renamed, true, CancellationToken.None);
        await Assert.ThrowsAsync<InvalidOperationException>(() =>
            _publisher.PublishAsync(transfer, CancellationToken.None));
        Assert.False(File.Exists(transfer.DestinationPath));
        Assert.False(File.Exists(renamed));
        var committed = await _journal.CompleteRenameAsync(transfer.TransferId, 77,
            transfer.ProcessId, renamed, true, CancellationToken.None);
        Assert.Equal(StagedTransferOutcome.Released,
            await _publisher.PublishAsync(committed.Transfer, CancellationToken.None));
        Assert.False(File.Exists(transfer.DestinationPath));
        Assert.Equal("Clean text.", await File.ReadAllTextAsync(renamed));
    }

    private async Task SetLocalPolicyAsync(string directory, int version = 1)
    {
        await new LocalPolicyStore(_workspace.PolicyFile).LoadAsync(CancellationToken.None);
        var policy = JsonNode.Parse(await File.ReadAllTextAsync(_workspace.PolicyFile))!;
        policy["version"] = version;
        policy["monitoredScopes"]!["destinationPaths"] = new JsonArray(JsonValue.Create(directory));
        policy["monitoredScopes"]!["removableDrives"] = false;
        policy["monitoredScopes"]!["networkPaths"] = false;
        await File.WriteAllTextAsync(_workspace.PolicyFile, policy.ToJsonString());
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public async Task Local_publication_requires_the_exact_monitored_folder(bool inScope)
    {
        var transfer = Transfer("local.txt", "Clean local content.", DestinationKind.Cloud);
        await SetLocalPolicyAsync(inScope ? Path.GetDirectoryName(transfer.DestinationPath)! :
            Path.Combine(_workspace.Root, "other-folder"));
        var outcome = await _publisher.PublishAsync(transfer, CancellationToken.None);
        Assert.Equal(inScope ? StagedTransferOutcome.Released : StagedTransferOutcome.Retained, outcome);
        Assert.Equal(inScope, File.Exists(transfer.DestinationPath));
        if (inScope) Assert.Equal("Clean local content.", await File.ReadAllTextAsync(transfer.DestinationPath));
        else Assert.True(File.Exists(transfer.StagePath));
    }

    [Fact]
    public async Task Local_scope_shrink_during_inspection_retains_bytes()
    {
        var transfer = Transfer("local-shrink.txt", "Clean local content.", DestinationKind.Cloud);
        await SetLocalPolicyAsync(Path.GetDirectoryName(transfer.DestinationPath)!);
        var extractor = new PausingExtractor();
        var inspection = new InspectionService(new LocalPolicyStore(_workspace.PolicyFile),
            new LocalQueueAuditSink(_workspace.QueueFile), new ExtractorRegistry([extractor]), new VerdictCache());
        var publisher = new StagedTransferPublisher(inspection, _notifications, _journal, _stagingRoot,
            new TestPublicationGate());
        var publication = publisher.PublishAsync(transfer, CancellationToken.None);
        await extractor.Entered.Task.WaitAsync(TimeSpan.FromSeconds(5));
        await SetLocalPolicyAsync(Path.Combine(_workspace.Root, "other-folder"), 2);
        extractor.Continue.SetResult();
        Assert.Equal(StagedTransferOutcome.Retained, await publication);
        Assert.False(File.Exists(transfer.DestinationPath));
        Assert.True(File.Exists(transfer.StagePath));
        Assert.Equal(TransferJournalState.Retained,
            (await _journal.ReadAsync(transfer.TransferId, CancellationToken.None)).State);
    }

    [Fact]
    public async Task Inspected_clean_content_is_released()
    {
        var transfer = Transfer("clean.txt", "Relatorio sem dados pessoais.");

        var outcome = await _publisher.PublishAsync(transfer, CancellationToken.None);

        Assert.Equal(StagedTransferOutcome.Released, outcome);
        Assert.Equal("Relatorio sem dados pessoais.",
            await File.ReadAllTextAsync(transfer.DestinationPath));
        Assert.Equal(TransferJournalState.Released,
            (await _journal.ReadAsync(transfer.TransferId, CancellationToken.None)).State);
        var audit = await new LocalQueueAuditSink(_workspace.QueueFile)
            .ReadRecentAsync(10, CancellationToken.None);
        Assert.Single(audit);
        Assert.Equal(Verdict.Approved, audit[0].Verdict);
        Assert.Equal(transfer.TransferId, audit[0].EventId);
    }

    [Fact]
    public async Task Destination_stays_empty_and_stage_stays_locked_during_analysis()
    {
        var extractor = new PausingExtractor();
        var inspector = new InspectionService(
            new LocalPolicyStore(_workspace.PolicyFile),
            new LocalQueueAuditSink(_workspace.QueueFile),
            new ExtractorRegistry([extractor]),
            new VerdictCache());
        var publisher = new StagedTransferPublisher(inspector, _notifications, _journal, _stagingRoot, new TestPublicationGate());
        var transfer = Transfer("waiting.txt", "Clean text.");

        Task<StagedTransferOutcome> publication =
            publisher.PublishAsync(transfer, CancellationToken.None);
        await extractor.Entered.Task.WaitAsync(TimeSpan.FromSeconds(5));

        await Assert.ThrowsAsync<IOException>(() => _journal.PrepareRenameAsync(
            transfer.TransferId, 1, transfer.ProcessId,
            Path.ChangeExtension(transfer.DestinationPath, ".renamed.txt"), true,
            CancellationToken.None));

        Assert.False(File.Exists(transfer.DestinationPath));
        Assert.Empty(await new LocalQueueAuditSink(_workspace.QueueFile)
            .ReadRecentAsync(10, CancellationToken.None));
        Assert.Throws<IOException>(() => new FileStream(
            transfer.StagePath, FileMode.Open, FileAccess.Write, FileShare.None));

        extractor.Continue.SetResult();
        Assert.Equal(StagedTransferOutcome.Released, await publication);
        Assert.Equal("Clean text.", await File.ReadAllTextAsync(transfer.DestinationPath));
    }

    [Fact]
    public async Task Sealed_file_waits_for_last_filesystem_writer_before_inspection()
    {
        var transfer = Transfer("writer-open.txt", "Clean text.");
        using (var writer = new FileStream(transfer.StagePath, FileMode.Open,
                   FileAccess.Write, FileShare.None))
        {
            Assert.Equal(StagedTransferOutcome.Retained,
                await _publisher.PublishAsync(transfer, CancellationToken.None));
            Assert.Equal(TransferJournalState.Sealed,
                (await _journal.ReadAsync(transfer.TransferId, CancellationToken.None)).State);
            Assert.False(File.Exists(transfer.DestinationPath));
        }

        Assert.Equal(StagedTransferOutcome.Released,
            await _publisher.PublishAsync(transfer, CancellationToken.None));
        Assert.Equal("Clean text.", await File.ReadAllTextAsync(transfer.DestinationPath));
    }

    [Fact]
    public async Task Policy_change_during_inspection_retains_the_file()
    {
        var extractor = new PausingExtractor();
        var inspector = new InspectionService(
            new LocalPolicyStore(_workspace.PolicyFile),
            new LocalQueueAuditSink(_workspace.QueueFile),
            new ExtractorRegistry([extractor]),
            new VerdictCache());
        var publisher = new StagedTransferPublisher(inspector, _notifications, _journal, _stagingRoot, new TestPublicationGate());
        var transfer = Transfer("policy-change.txt", "Clean text.");

        Task<StagedTransferOutcome> publication =
            publisher.PublishAsync(transfer, CancellationToken.None);
        await extractor.Entered.Task.WaitAsync(TimeSpan.FromSeconds(5));

        var policy = JsonNode.Parse(await File.ReadAllTextAsync(_workspace.PolicyFile))!;
        policy["version"] = 2;
        await File.WriteAllTextAsync(_workspace.PolicyFile, policy.ToJsonString());
        extractor.Continue.SetResult();

        Assert.Equal(StagedTransferOutcome.Retained, await publication);
        Assert.False(File.Exists(transfer.DestinationPath));
        Assert.True(File.Exists(transfer.StagePath));
        var audit = await new LocalQueueAuditSink(_workspace.QueueFile)
            .ReadRecentAsync(10, CancellationToken.None);
        Assert.Single(audit);
        Assert.Equal(Verdict.Retained, audit[0].Verdict);
        Assert.Equal("policy_changed", audit[0].NotInspectedReason);
        Assert.Equal(transfer.TransferId, audit[0].EventId);
    }

    [Fact]
    public async Task Writable_section_prevents_inspection_after_its_file_handle_closes()
    {
        var extractor = new PausingExtractor();
        var inspector = new InspectionService(new LocalPolicyStore(_workspace.PolicyFile),
            new LocalQueueAuditSink(_workspace.QueueFile), new ExtractorRegistry([extractor]),
            new VerdictCache());
        var publisher = new StagedTransferPublisher(inspector, _notifications, _journal, _stagingRoot, new TestPublicationGate());
        var transfer = Transfer("late-map.txt", "Clean text with room for modified bytes.");
        var file = new FileStream(transfer.StagePath, FileMode.Open, FileAccess.ReadWrite, FileShare.ReadWrite);
        using var mapping = CreateFileMapping(file.SafeFileHandle, IntPtr.Zero, 4, 0, 0, null);
        Assert.False(mapping.IsInvalid);
        IntPtr view = MapViewOfFile(mapping, 2, 0, 0, UIntPtr.Zero);
        Assert.NotEqual(IntPtr.Zero, view);
        file.Dispose();
        try
        {
            Assert.Equal(StagedTransferOutcome.Retained,
                await publisher.PublishAsync(transfer, CancellationToken.None));
            Assert.False(extractor.Entered.Task.IsCompleted);
            Assert.Equal(TransferJournalState.Sealed,
                (await _journal.ReadAsync(transfer.TransferId, CancellationToken.None)).State);
            byte[] changed = System.Text.Encoding.UTF8.GetBytes("CPF: 529.982.247-25");
            Marshal.Copy(changed, 0, view, changed.Length);
            Assert.False(File.Exists(transfer.DestinationPath));
        }
        finally { UnmapViewOfFile(view); }
        mapping.Dispose();
        var publication = publisher.PublishAsync(transfer, CancellationToken.None);
        await extractor.Entered.Task.WaitAsync(TimeSpan.FromSeconds(5));
        extractor.Continue.SetResult();
        Assert.Equal(StagedTransferOutcome.Blocked, await publication);
        Assert.False(File.Exists(transfer.DestinationPath));
    }

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern SafeFileHandle CreateFileMapping(SafeFileHandle file,
        IntPtr attributes, uint protection, uint maximumHigh, uint maximumLow, string? name);
    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr MapViewOfFile(SafeFileHandle mapping, uint access,
        uint offsetHigh, uint offsetLow, UIntPtr bytes);
    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool UnmapViewOfFile(IntPtr view);

    [Fact]
    public async Task Uninspectable_content_remains_local()
    {
        var transfer = Transfer("unknown.md", "CPF: 529.982.247-25");

        var outcome = await _publisher.PublishAsync(transfer, CancellationToken.None);

        Assert.Equal(StagedTransferOutcome.Retained, outcome);
        Assert.False(File.Exists(transfer.DestinationPath));
        Assert.True(File.Exists(transfer.StagePath));
        Assert.Equal(TransferJournalState.Retained,
            (await _journal.ReadAsync(transfer.TransferId, CancellationToken.None)).State);
        var audit = await new LocalQueueAuditSink(_workspace.QueueFile)
            .ReadRecentAsync(10, CancellationToken.None);
        Assert.Single(audit);
        Assert.Equal(Verdict.Retained, audit[0].Verdict);
    }

    [Theory]
    [InlineData("size", "file_too_large")]
    [InlineData("parser", "parse_error:InvalidDataException")]
    [InlineData("timeout", "inspection_timeout")]
    public async Task Failed_inspection_never_requests_a_permit_or_changes_existing_destination(
        string failure, string reason)
    {
        var store = new LocalPolicyStore(_workspace.PolicyFile);
        await store.LoadAsync(CancellationToken.None);
        var policy = JsonNode.Parse(await File.ReadAllTextAsync(_workspace.PolicyFile))!;
        policy["maxFileSizeMb"] = 1;
        policy["inspectionTimeoutSeconds"] = 1;
        await File.WriteAllTextAsync(_workspace.PolicyFile, policy.ToJsonString());
        var paused = new PausingExtractor();
        var registry = failure == "parser" ? new ExtractorRegistry([new ThrowingExtractor()])
            : failure == "timeout" ? new ExtractorRegistry([paused]) : ExtractorRegistry.CreateDefault();
        var gate = new RecordingPublicationGate(false);
        var publisher = new StagedTransferPublisher(new InspectionService(store,
            new LocalQueueAuditSink(_workspace.QueueFile), registry, new VerdictCache()),
            _notifications, _journal, _stagingRoot, gate);
        string content = failure == "size" ? new string('x', 1024 * 1024 + 1) : "Clean fixture bytes.";
        var transfer = Transfer("negative-" + failure + ".txt", content);
        await File.WriteAllTextAsync(transfer.DestinationPath, "public original");
        using var subscription = _notifications.Subscribe();
        try
        {
            Assert.Equal(StagedTransferOutcome.Retained,
                await publisher.PublishAsync(transfer, CancellationToken.None).WaitAsync(TimeSpan.FromSeconds(5)));
            Assert.False(gate.Called);
            Assert.Equal("public original", await File.ReadAllTextAsync(transfer.DestinationPath));
            Assert.Equal(content, await File.ReadAllTextAsync(transfer.StagePath));
            Assert.Equal(TransferJournalState.Retained,
                (await _journal.ReadAsync(transfer.TransferId, CancellationToken.None)).State);
            var audit = Assert.Single(await new LocalQueueAuditSink(_workspace.QueueFile)
                .ReadRecentAsync(10, CancellationToken.None));
            Assert.Equal(Verdict.Retained, audit.Verdict);
            Assert.Equal(reason, audit.NotInspectedReason);
            while (subscription.Reader.TryRead(out var notification))
                if (notification is TransferNotification transferNotification)
                    Assert.NotEqual(TransferPhase.Released, transferNotification.Phase);
            Assert.Empty(Directory.GetFiles(Path.GetDirectoryName(transfer.DestinationPath)!, "*.pending"));
        }
        finally { paused.Continue.TrySetResult(); }
    }

    private sealed class ThrowingExtractor : ITextExtractor
    {
        public IReadOnlySet<string> SupportedExtensions { get; } = new HashSet<string> { ".txt" };
        public Task<string> ExtractAsync(Stream content, CancellationToken cancellationToken)
            => throw new InvalidDataException("Injected parser failure.");
    }

    [Fact]
    public async Task Failed_publication_is_retained_and_never_audited_as_sent()
    {
        var transfer = Transfer("clean.txt", "Clean text.");
        Directory.Delete(Path.GetDirectoryName(transfer.DestinationPath)!);

        var outcome = await _publisher.PublishAsync(transfer, CancellationToken.None);

        Assert.Equal(StagedTransferOutcome.Retained, outcome);
        Assert.False(File.Exists(transfer.DestinationPath));
        Assert.True(File.Exists(transfer.StagePath));
        Assert.Equal(TransferJournalState.Retained,
            (await _journal.ReadAsync(transfer.TransferId, CancellationToken.None)).State);
        var audit = await new LocalQueueAuditSink(_workspace.QueueFile)
            .ReadRecentAsync(10, CancellationToken.None);
        Assert.Single(audit);
        Assert.Equal(Verdict.Retained, audit[0].Verdict);
        Assert.Equal("publication_failed", audit[0].NotInspectedReason);
        Assert.Equal(transfer.TransferId, audit[0].EventId);
    }

    [Fact]
    public async Task A_stage_outside_the_private_root_is_rejected()
    {
        var transfer = Transfer("clean.txt", "safe");
        transfer = transfer with { StagePath = _workspace.WriteText("outside.txt", "safe") };

        await Assert.ThrowsAsync<ArgumentException>(() =>
            _publisher.PublishAsync(transfer, CancellationToken.None));
        Assert.False(File.Exists(transfer.DestinationPath));
    }

    [Fact]
    public async Task Interrupted_unsealed_file_cannot_be_published()
    {
        string stage = Path.Combine(_stagingRoot, "unsealed.txt");
        await File.WriteAllTextAsync(stage, "Clean text.");
        string destination = Path.Combine(_workspace.Root, "destination", "unsealed.txt");
        var transfer = new StagedTransfer(Guid.NewGuid(), stage, destination,
            DestinationKind.RemovableDrive, "explorer.exe", 4242, null);
        await _journal.CreateAsync(transfer, CancellationToken.None);
        await _journal.RetainInterruptedAsync(CancellationToken.None);

        await Assert.ThrowsAsync<InvalidOperationException>(() =>
            _publisher.PublishAsync(transfer, CancellationToken.None));
        Assert.False(File.Exists(destination));
        Assert.True(File.Exists(stage));
    }

    private sealed class PausingExtractor : ITextExtractor
    {
        public IReadOnlySet<string> SupportedExtensions { get; } = new HashSet<string> { ".txt" };
        public TaskCompletionSource Entered { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        public TaskCompletionSource Continue { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);

        public async Task<string> ExtractAsync(Stream content, CancellationToken cancellationToken)
        {
            Entered.SetResult();
            await Continue.Task.WaitAsync(cancellationToken);
            using var reader = new StreamReader(content);
            return await reader.ReadToEndAsync(cancellationToken);
        }
    }
}
