using SafeUpload.Agent.Core.Application;
using SafeUpload.Agent.Core.Contracts;
using SafeUpload.Agent.Core.Domain;
using SafeUpload.Agent.Core.Infrastructure;
using SafeUpload.Agent.Core.Infrastructure.Extraction;
using StageDisposeOutcome = SafeUpload.Agent.Minifilter.StageDisposeOutcome;
using SafeUpload.Agent.Service.Interception;
using SafeUpload.Agent.Service.Notifications;
using System.Text.Json.Nodes;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;
using Microsoft.Extensions.Logging.Abstractions;

namespace SafeUpload.Agent.Tests;

public sealed class StagedTransferPublisherTests : IDisposable
{
    private const string TestRequestorSid = "S-1-5-21-111-222-333-1000";
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

        _publisher = new StagedTransferPublisher(inspector, _notifications, _journal, _stagingRoot,
            new TestPublicationGate(), sessionUserSidResolver: _ => TestRequestorSid);
    }

    public void Dispose() => _workspace.Dispose();

    [Theory]
    [InlineData(false, false)]
    [InlineData(true, false)]
    [InlineData(false, true)]
    [InlineData(true, true)]
    public async Task Completed_native_publication_recovers_its_journal_without_republishing(
        bool afterReplacement, bool changePublicBytes)
    {
        bool injected = false;
        var journal = new StagedTransferJournal(Path.Combine(_workspace.Root, "fault-journal"), false, 100,
            (point, entry) =>
            {
                if (injected || entry.State != TransferJournalState.Released ||
                    point != (afterReplacement ? StagedJournalWritePoint.AfterReplacement : StagedJournalWritePoint.BeforeReplacement))
                    return;
                injected = true;
                throw new System.ComponentModel.Win32Exception(5);
            });
        var gate = new CountingPublicationGate();
        var publisher = new StagedTransferPublisher(new InspectionService(
            new LocalPolicyStore(_workspace.PolicyFile), new LocalQueueAuditSink(_workspace.QueueFile),
            ExtractorRegistry.CreateDefault(), new VerdictCache()), _notifications, journal, _stagingRoot, gate,
            sessionUserSidResolver: _ => TestRequestorSid);
        var transfer = Transfer("completed-publication.txt", "approved first version");
        await journal.CreateAsync(transfer, CancellationToken.None);
        await journal.TransitionAsync(transfer.TransferId, TransferJournalState.Allocated,
            TransferJournalState.Sealed, null, CancellationToken.None);

        var failure = await Assert.ThrowsAsync<StagedJournalPersistenceException>(() =>
            publisher.PublishAsync(transfer, CancellationToken.None));
        Assert.Equal(afterReplacement, failure.ReplacementReturned);
        Assert.True(publisher.HasConfirmedPublication(transfer.TransferId));
        Assert.Equal("approved first version", await File.ReadAllTextAsync(transfer.DestinationPath));
        if (changePublicBytes) await File.WriteAllTextAsync(transfer.DestinationPath, "newer public content");

        await publisher.RecoverConfirmedPublicationsAsync(CancellationToken.None);
        Assert.Equal(TransferJournalState.Released,
            (await journal.ReadAsync(transfer.TransferId, CancellationToken.None)).State);
        Assert.False(publisher.HasConfirmedPublication(transfer.TransferId));
        Assert.Equal(changePublicBytes ? "newer public content" : "approved first version",
            await File.ReadAllTextAsync(transfer.DestinationPath));
        Assert.Equal(1, gate.AuthorizeCalls);
        Assert.False(File.Exists(transfer.StagePath));
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task Restart_without_a_native_receipt_holds_even_matching_bytes_and_explains_the_file(bool changePublicBytes)
    {
        var journal = new StagedTransferJournal(Path.Combine(_workspace.Root, "restart-journal"), false, 100,
            (point, entry) =>
            {
                if (entry.State == TransferJournalState.Released && point == StagedJournalWritePoint.BeforeReplacement)
                    throw new System.ComponentModel.Win32Exception(5);
            });
        var gate = new CountingPublicationGate();
        StagedTransferPublisher Publisher(StagedTransferJournal j) => new(new InspectionService(
            new LocalPolicyStore(_workspace.PolicyFile), new LocalQueueAuditSink(_workspace.QueueFile),
            ExtractorRegistry.CreateDefault(), new VerdictCache()), _notifications, j, _stagingRoot, gate,
            sessionUserSidResolver: _ => TestRequestorSid);
        var transfer = Transfer("crash-publication.txt", "approved first version");
        await journal.CreateAsync(transfer, CancellationToken.None);
        await journal.TransitionAsync(transfer.TransferId, TransferJournalState.Allocated,
            TransferJournalState.Sealed, null, CancellationToken.None);
        await Assert.ThrowsAsync<StagedJournalPersistenceException>(() => Publisher(journal).PublishAsync(transfer, CancellationToken.None));
        if (changePublicBytes) await File.WriteAllTextAsync(transfer.DestinationPath, "newer public content");

        var restarted = new StagedTransferJournal(Path.Combine(_workspace.Root, "restart-journal"));
        using var owner = _notifications.Subscribe(7, TestRequestorSid);
        var publisher = Publisher(restarted);
        await restarted.ReconcilePublishingAsync(CancellationToken.None);
        await publisher.RecoverPendingTransferAsync(await restarted.ReadAsync(transfer.TransferId, CancellationToken.None), CancellationToken.None);
        Assert.Equal(TransferJournalState.Publishing, (await restarted.ReadAsync(transfer.TransferId, CancellationToken.None)).State);
        Assert.Equal(changePublicBytes ? "newer public content" : "approved first version", await File.ReadAllTextAsync(transfer.DestinationPath));
        Assert.True(File.Exists(transfer.StagePath));
        Assert.Equal(1, gate.AuthorizeCalls);
        var notifications = new List<TransferNotification>();
        while (owner.Reader.TryRead(out var notification))
            if (notification is TransferNotification transferNotification) notifications.Add(transferNotification);
        var hold = Assert.Single(notifications, n => n.RecoveryAdvice == StagedRecoveryAdvice.PublicationUnresolved);
        Assert.Equal(transfer.DestinationPath, hold.FileName);
        Assert.Equal(TransferPhase.Retained, hold.Phase);
        Assert.Equal(StagedRecoveryAdvice.PublicationUnresolved, hold.RecoveryAdvice);
        Assert.False(hold.OverrideAllowed);
    }

    [Fact]
    public async Task A_confirmed_publication_receipt_cannot_advance_a_renamed_journal_version()
    {
        bool injected = false;
        var journal = new StagedTransferJournal(Path.Combine(_workspace.Root, "rename-journal"), false, 100,
            (point, entry) =>
            {
                if (!injected && entry.State == TransferJournalState.Released && point == StagedJournalWritePoint.AfterReplacement)
                { injected = true; throw new System.ComponentModel.Win32Exception(5); }
            });
        var gate = new CountingPublicationGate();
        var publisher = new StagedTransferPublisher(new InspectionService(
            new LocalPolicyStore(_workspace.PolicyFile), new LocalQueueAuditSink(_workspace.QueueFile),
            ExtractorRegistry.CreateDefault(), new VerdictCache()), _notifications, journal, _stagingRoot, gate,
            sessionUserSidResolver: _ => TestRequestorSid);
        var transfer = Transfer("old-name.txt", "approved first version");
        await journal.CreateAsync(transfer, CancellationToken.None);
        await journal.TransitionAsync(transfer.TransferId, TransferJournalState.Allocated,
            TransferJournalState.Sealed, null, CancellationToken.None);
        await Assert.ThrowsAsync<StagedJournalPersistenceException>(() => publisher.PublishAsync(transfer, CancellationToken.None));
        string nextName = Path.Combine(Path.GetDirectoryName(transfer.DestinationPath)!, "new-name.txt");
        await journal.PrepareRenameAsync(transfer.TransferId, 41, transfer.ProcessId, nextName, true, CancellationToken.None);
        var renamed = await journal.CompleteRenameAsync(transfer.TransferId, 41, transfer.ProcessId, nextName, true, CancellationToken.None);

        await publisher.RecoverConfirmedPublicationsAsync(CancellationToken.None);
        var after = await journal.ReadAsync(transfer.TransferId, CancellationToken.None);
        Assert.Equal(renamed.Transfer, after.Transfer);
        Assert.Equal(renamed.DestinationGeneration, after.DestinationGeneration);
        Assert.Equal(TransferJournalState.Sealed, after.State);
        Assert.False(File.Exists(nextName));
        Assert.Equal("approved first version", await File.ReadAllTextAsync(transfer.DestinationPath));
        Assert.True(File.Exists(transfer.StagePath));
        Assert.Equal(1, gate.AuthorizeCalls);
    }

    [Theory]
    [InlineData("empty.txt", false)]
    [InlineData("empty.txt", true)]
    [InlineData(".gitkeep", false)]
    [InlineData("__init__.py", false)]
    [InlineData("marker.lock", false)]
    [InlineData("empty.docx", false)]
    public async Task Measured_empty_content_publishes_normally_without_extraction_or_private_notice(
        string name, bool replaceExisting)
    {
        using var owner = _notifications.Subscribe(7, TestRequestorSid);
        using var wrongSession = _notifications.Subscribe(8, TestRequestorSid);
        using var wrongUser = _notifications.Subscribe(7, "S-1-5-21-999-888-777-1000");
        StagedTransfer transfer = Transfer(name, string.Empty);
        if (replaceExisting) await File.WriteAllTextAsync(transfer.DestinationPath, "previous public version");
        var extractor = new CountingExtractor();
        var gate = new CountingPublicationGate();
        var publisher = new StagedTransferPublisher(new InspectionService(
                new LocalPolicyStore(_workspace.PolicyFile), new LocalQueueAuditSink(_workspace.QueueFile),
                new ExtractorRegistry([extractor]), new VerdictCache()),
            _notifications, _journal, _stagingRoot, gate,
            sessionUserSidResolver: _ => TestRequestorSid);
        Assert.Equal(StagedTransferOutcome.Released, await publisher.PublishAsync(transfer, CancellationToken.None));
        TransferJournalEntry released = await _journal.ReadAsync(transfer.TransferId, CancellationToken.None);
        Assert.Equal(TransferJournalState.Released, released.State);
        Assert.Equal(0, released.SealedLength);
        Assert.Equal(StagedTransferJournal.EmptySha256Hex, released.Sha256Hex);
        Assert.True(File.Exists(transfer.DestinationPath));
        Assert.Empty(await File.ReadAllBytesAsync(transfer.DestinationPath));
        Assert.True(released.StageDeleted);
        Assert.False(File.Exists(transfer.StagePath));
        Assert.Equal(0, extractor.Calls);
        Assert.Equal(1, gate.AuthorizeCalls);
        var notices = new List<TransferNotification>();
        while (owner.Reader.TryRead(out AgentNotification? raw)) notices.Add(Assert.IsType<TransferNotification>(raw));
        Assert.Contains(notices, notice => notice.Phase == TransferPhase.Released &&
            notice.PublishedSha256Hex == StagedTransferJournal.EmptySha256Hex);
        Assert.DoesNotContain(notices, notice => notice.Phase == TransferPhase.Blocked || notice.BlockReason is not null);
        Assert.False(wrongSession.Reader.TryRead(out _));
        Assert.False(wrongUser.Reader.TryRead(out _));
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task Changed_length_cannot_turn_a_measured_version_into_an_implicit_empty_approval(bool originallyEmpty)
    {
        StagedTransfer transfer = Transfer("changed-length.txt", originallyEmpty ? string.Empty : "positive sealed bytes");
        await File.WriteAllTextAsync(transfer.DestinationPath, "previous public version");
        if (originallyEmpty) await File.WriteAllTextAsync(transfer.StagePath, "CPF: 529.982.247-25");
        else await File.WriteAllBytesAsync(transfer.StagePath, []);
        var gate = new CountingPublicationGate();
        var publisher = new StagedTransferPublisher(new InspectionService(
                new LocalPolicyStore(_workspace.PolicyFile), new LocalQueueAuditSink(_workspace.QueueFile),
                ExtractorRegistry.CreateDefault(), new VerdictCache()),
            _notifications, _journal, _stagingRoot, gate);
        Assert.Equal(StagedTransferOutcome.Retained, await publisher.PublishAsync(transfer, CancellationToken.None));
        Assert.Equal("previous public version", await File.ReadAllTextAsync(transfer.DestinationPath));
        Assert.True(File.Exists(transfer.StagePath));
        Assert.Equal(0, gate.AuthorizeCalls);
        Assert.Equal(TransferJournalState.Retained,
            (await _journal.ReadAsync(transfer.TransferId, CancellationToken.None)).State);
    }

    [Fact]
    public async Task Empty_publication_still_requires_the_kernel_permit()
    {
        StagedTransfer transfer = Transfer("empty-permit.txt", string.Empty);
        await File.WriteAllTextAsync(transfer.DestinationPath, "previous public version");
        var gate = new RecordingPublicationGate(refuse: true);
        var publisher = new StagedTransferPublisher(new InspectionService(
                new LocalPolicyStore(_workspace.PolicyFile), new LocalQueueAuditSink(_workspace.QueueFile),
                ExtractorRegistry.CreateDefault(), new VerdictCache()),
            _notifications, _journal, _stagingRoot, gate);
        Assert.Equal(StagedTransferOutcome.Retained, await publisher.PublishAsync(transfer, CancellationToken.None));
        Assert.True(gate.Called);
        Assert.Equal(StagedTransferJournal.EmptySha256Hex, gate.Digest);
        Assert.Equal("previous public version", await File.ReadAllTextAsync(transfer.DestinationPath));
    }

    [Theory]
    [InlineData(false, true)]
    [InlineData(true, false)]
    [InlineData(true, true)]
    public async Task Committed_publication_remains_released_after_revocation_failure_or_cancellation(
        bool cancel, bool failRevoke)
    {
        using var cancellation = new CancellationTokenSource();
        using var subscription = _notifications.Subscribe(7, TestRequestorSid);
        var gate = new FinalizationPublicationGate(cancel ? cancellation : null, failRevoke);
        var publisher = new StagedTransferPublisher(new InspectionService(
            new LocalPolicyStore(_workspace.PolicyFile), new LocalQueueAuditSink(_workspace.QueueFile),
            ExtractorRegistry.CreateDefault(), new VerdictCache()),
            _notifications, _journal, _stagingRoot, gate,
            sessionUserSidResolver: _ => TestRequestorSid);
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
        public bool DisposeStage(Guid transferId, uint outcome, uint committedRenames) => false;
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
        // Held: the kernel still holds the published version, so the stage stays for the digest check below.
        public bool DisposeStage(Guid transferId, uint outcome, uint committedRenames) => true;
        public void Dispose() => Disposed = true;
    }

    /// <summary>Records SAFEUPLOAD_CONTROL_STAGE_DISPOSE calls; Held is the driver's answer.</summary>
    private sealed class DisposingPublicationGate(bool held) : IStagedPublicationGate, IDisposable
    {
        public readonly List<(Guid TransferId, uint Outcome)> Disposals = [];
        public IDisposable Authorize(StagedTransfer transfer, string temporaryDestination, string digest) => this;
        public bool DisposeStage(Guid transferId, uint outcome, uint committedRenames)
        {
            Disposals.Add((transferId, outcome));
            return held;
        }
        public void Dispose() { }
    }

    private StagedTransferPublisher DisposingPublisher(DisposingPublicationGate gate) =>
        new(new InspectionService(new LocalPolicyStore(_workspace.PolicyFile),
                new LocalQueueAuditSink(_workspace.QueueFile), ExtractorRegistry.CreateDefault(), new VerdictCache()),
            _notifications, _journal, _stagingRoot, gate, sessionUserSidResolver: _ => TestRequestorSid);

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task Approved_publication_disposes_the_stage(bool held)
    {
        var gate = new DisposingPublicationGate(held);
        var transfer = Transfer("disposed.txt", "approved disposed version");

        Assert.Equal(StagedTransferOutcome.Released,
            await DisposingPublisher(gate).PublishAsync(transfer, CancellationToken.None));
        Assert.Equal(new[] { (transfer.TransferId, StageDisposeOutcome.Released) }, gate.Disposals);
        // A version the driver still holds keeps its stage until the driver releases it; otherwise the service deletes it.
        Assert.Equal(held, File.Exists(transfer.StagePath));
        Assert.Equal(!held, (await _journal.ReadAsync(transfer.TransferId, CancellationToken.None)).StageDeleted);
        Assert.Equal("approved disposed version", await File.ReadAllTextAsync(transfer.DestinationPath));
    }

    [Fact]
    public async Task Released_stage_disposal_never_deletes_a_replacement_object()
    {
        var held = new DisposingPublicationGate(held: true);
        var transfer = Transfer("released-stage-replacement.txt", "approved original bytes");
        Assert.Equal(StagedTransferOutcome.Released,
            await DisposingPublisher(held).PublishAsync(transfer, CancellationToken.None));
        TransferJournalEntry released = await _journal.ReadAsync(transfer.TransferId, CancellationToken.None);
        Assert.False(released.StageDeleted);
        Assert.NotNull(released.StageIdentity);

        File.Delete(transfer.StagePath);
        await File.WriteAllTextAsync(transfer.StagePath, "replacement private object");
        var restarted = new DisposingPublicationGate(held: false);
        await DisposingPublisher(restarted).DisposeReleasedStagesAsync(CancellationToken.None);

        Assert.Equal("replacement private object", await File.ReadAllTextAsync(transfer.StagePath));
        Assert.False((await _journal.ReadAsync(transfer.TransferId, CancellationToken.None)).StageDeleted);
    }

    [Fact]
    public async Task Blocked_publication_keeps_the_stage_and_disposes_nothing()
    {
        var gate = new DisposingPublicationGate(held: false);
        var transfer = Transfer("blocked-disposal.txt", "CPF: 529.982.247-25");

        Assert.Equal(StagedTransferOutcome.Blocked,
            await DisposingPublisher(gate).PublishAsync(transfer, CancellationToken.None));
        Assert.Empty(gate.Disposals);
        Assert.True(File.Exists(transfer.StagePath));
    }

    [Fact]
    public async Task Service_start_disposes_released_stages_left_on_disk()
    {
        var running = new DisposingPublicationGate(held: true);
        var transfer = Transfer("left-on-disk.txt", "approved version left on disk");
        Assert.Equal(StagedTransferOutcome.Released,
            await DisposingPublisher(running).PublishAsync(transfer, CancellationToken.None));
        Assert.True(File.Exists(transfer.StagePath));

        var restarted = new DisposingPublicationGate(held: false);
        await DisposingPublisher(restarted).DisposeReleasedStagesAsync(CancellationToken.None);

        Assert.Equal(new[] { (transfer.TransferId, StageDisposeOutcome.Released) }, restarted.Disposals);
        Assert.False(File.Exists(transfer.StagePath));
        Assert.True((await _journal.ReadAsync(transfer.TransferId, CancellationToken.None)).StageDeleted);
        Assert.Equal("approved version left on disk", await File.ReadAllTextAsync(transfer.DestinationPath));
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
            new VerdictCache()), _notifications, _journal, _stagingRoot, new TestPublicationGate(), broker,
            handbackCopier: new SuccessfulHandbackCopier(_workspace.Root),
            sessionUserSidResolver: _ => TestRequestorSid);
        var original = Transfer("justify.txt", "CPF: 529.982.247-25");
        // Transfer() journals immediately; give this independent transfer an
        // authenticated notification session before journaling it.
        var transfer = original with { TransferId = Guid.NewGuid(), SessionId = 7 };
        await _journal.CreateAsync(transfer, CancellationToken.None);
        await _journal.TransitionAsync(transfer.TransferId, TransferJournalState.Allocated,
            TransferJournalState.Sealed, null, CancellationToken.None);
        Assert.Equal(StagedTransferOutcome.Blocked,
            await publisher.PublishAsync(transfer, CancellationToken.None));
        Assert.True(broker.TryConsume(transfer.TransferId.ToString("D"), 8, TestRequestorSid,
            out var wrongSession));
        Assert.Null(wrongSession);
        Assert.True(broker.TryConsume(transfer.TransferId.ToString("D"), 7, "S-1-5-21-999-888-777-1000",
            out var wrongUser));
        Assert.Null(wrongUser);
        Assert.True(broker.TryConsume(transfer.TransferId.ToString("D"), 7, TestRequestorSid,
            out var publish));
        Assert.NotNull(publish);
        Assert.False(broker.TryConsume(transfer.TransferId.ToString("D"), 7, TestRequestorSid, out _));
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
        public bool DisposeStage(Guid transferId, uint outcome, uint committedRenames) => false;
        public void Dispose() { }
    }

    private sealed class CountingPublicationGate : IStagedPublicationGate
    {
        public int AuthorizeCalls;
        public IDisposable Authorize(StagedTransfer transfer, string temporaryDestination, string digest)
        {
            AuthorizeCalls++;
            return new TestPublicationGate();
        }
        public bool DisposeStage(Guid transferId, uint outcome, uint committedRenames) => false;
    }

    private sealed class CountingExtractor : ITextExtractor
    {
        public int Calls;
        public IReadOnlySet<string> SupportedExtensions { get; } = new HashSet<string> { ".txt" };
        public Task<string> ExtractAsync(Stream content, CancellationToken cancellationToken)
        {
            Calls++;
            return Task.FromResult(string.Empty);
        }
    }

    private sealed class SuccessfulHandbackCopier(string root) : IStagedHandbackCopier
    {
        public Task<string> CopyVerifiedAsync(StagedTransfer transfer, FileStream sealedSnapshot,
            long length, string sha256Hex, CancellationToken token) => Task.FromResult(Path.Combine(
            root, "handback", transfer.TransferId.ToString("N") + Path.GetExtension(transfer.DestinationPath)));

        public IDisposable OpenVerifiedReadLease(StagedTransfer transfer, string handbackPath,
            long length, string sha256Hex) => new NoopLease();

        public void CleanupUncommittedTemporary(StagedTransfer transfer) { }

        private sealed class NoopLease : IDisposable { public void Dispose() { } }
    }

    private StagedTransfer Transfer(string name, string content, DestinationKind kind = DestinationKind.RemovableDrive,
        string? sourceFile = null)
    {
        string stage = Path.Combine(_stagingRoot, name);
        if (sourceFile is null) File.WriteAllText(stage, content);
        else File.Copy(sourceFile, stage, overwrite: true);
        string destination = Path.Combine(_workspace.Root, "destination", name);
        Directory.CreateDirectory(Path.GetDirectoryName(destination)!);

        var transfer = new StagedTransfer(
            Guid.NewGuid(), stage, destination,
            kind,
            "explorer.exe", 4242, 7)
        { RequestorSid = TestRequestorSid };
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
        Assert.Equal(2, audit.Count);
        Assert.Contains(audit, item => item.Verdict == Verdict.Blocked);
        Assert.Contains(audit, item => item.Verdict == Verdict.Retained &&
            item.NotInspectedReason == "handback_failed");
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
        using var subscription = _notifications.Subscribe(7, TestRequestorSid);

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
        string digest = Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(
            await File.ReadAllBytesAsync(transfer.DestinationPath)));
        Assert.Equal(digest, audit[0].PublishedSha256Hex);
        var notifications = new List<TransferNotification>();
        while (subscription.Reader.TryRead(out var notification))
            if (notification is TransferNotification transferNotification)
                notifications.Add(transferNotification);
        TransferNotification released = Assert.Single(notifications,
            notification => notification.Phase == TransferPhase.Released);
        Assert.Equal(digest, released.PublishedSha256Hex);
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
    [InlineData("size", "file_too_large", false)]
    [InlineData("size", "file_too_large", true)]
    [InlineData("format", "unsupported_format", false)]
    [InlineData("format", "unsupported_format", true)]
    [InlineData("image", "unsupported_format", false)]
    [InlineData("image", "unsupported_format", true)]
    [InlineData("parser", "parse_error:InvalidDataException", false)]
    [InlineData("parser", "parse_error:InvalidDataException", true)]
    [InlineData("timeout", "inspection_timeout", false)]
    [InlineData("timeout", "inspection_timeout", true)]
    public async Task Failed_inspection_is_blocked_with_exact_handback_and_policy_bound_justification(
        string failure, string reason, bool overrideAllowed)
    {
        var store = new LocalPolicyStore(_workspace.PolicyFile);
        await store.LoadAsync(CancellationToken.None);
        var policy = JsonNode.Parse(await File.ReadAllTextAsync(_workspace.PolicyFile))!;
        policy["maxFileSizeMb"] = 1;
        policy["inspectionTimeoutSeconds"] = failure == "timeout" ? 1 : 5;
        policy["overrideAllowed"] = overrideAllowed;
        await File.WriteAllTextAsync(_workspace.PolicyFile, policy.ToJsonString());
        var paused = new PausingExtractor();
        var registry = failure switch
        {
            "parser" => new ExtractorRegistry([new ThrowingExtractor()]),
            "timeout" => new ExtractorRegistry([paused]),
            "format" => new ExtractorRegistry([]),
            _ => ExtractorRegistry.CreateDefault()
        };
        var gate = new RecordingPublicationGate(false);
        var broker = new StagedJustifications();
        var publisher = new StagedTransferPublisher(new InspectionService(store,
            new LocalQueueAuditSink(_workspace.QueueFile), registry, new VerdictCache()),
            _notifications, _journal, _stagingRoot, gate, broker,
            handbackCopier: new VerifiedSnapshotHandbackCopier(_workspace.Root),
            sessionUserSidResolver: _ => TestRequestorSid);
        string content = failure == "size" ? new string('x', 1024 * 1024 + 1) : "Clean fixture bytes.";
        string? imagePdf = failure == "image"
            ? _workspace.WritePdfWithImage("image-source.pdf", imagePageText: "Clean cover text.")
            : null;
        var transfer = Transfer("negative-" + failure + (failure == "image" ? ".pdf" : ".txt"),
            content, sourceFile: imagePdf);
        byte[] inspectedBytes = await File.ReadAllBytesAsync(transfer.StagePath);
        await File.WriteAllTextAsync(transfer.DestinationPath, "public original");
        using var subscription = _notifications.Subscribe(7, TestRequestorSid);
        try
        {
            Assert.Equal(StagedTransferOutcome.Blocked,
                await publisher.PublishAsync(transfer, CancellationToken.None).WaitAsync(TimeSpan.FromSeconds(5)));
            Assert.False(gate.Called);
            Assert.Equal("public original", await File.ReadAllTextAsync(transfer.DestinationPath));
            Assert.Equal(inspectedBytes, await File.ReadAllBytesAsync(transfer.StagePath));
            var entry = await _journal.ReadAsync(transfer.TransferId, CancellationToken.None);
            Assert.Equal(TransferJournalState.Blocked, entry.State);
            Assert.Equal(StagedHandbackState.Verified, entry.HandbackState);
            Assert.Equal(inspectedBytes, await File.ReadAllBytesAsync(entry.HandbackPath!));
            InspectionFailureKind expectedFailure = failure switch
            {
                "size" => InspectionFailureKind.TooLarge,
                "format" or "image" => InspectionFailureKind.UnsupportedFormat,
                "timeout" => InspectionFailureKind.Timeout,
                _ => InspectionFailureKind.ReadOrParse
            };
            Assert.Equal(expectedFailure, entry.BlockedInspectionFailure);
            string digest = Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(
                await File.ReadAllBytesAsync(transfer.StagePath)));
            Assert.Equal(digest, entry.Sha256Hex);
            Assert.Equal(new FileInfo(transfer.StagePath).Length, entry.HandbackLength);
            Assert.Equal(!overrideAllowed, entry.JustificationWindowClosed);
            var audit = Assert.Single(await new LocalQueueAuditSink(_workspace.QueueFile)
                .ReadRecentAsync(10, CancellationToken.None));
            Assert.Equal(Verdict.Blocked, audit.Verdict);
            Assert.Equal(reason, audit.NotInspectedReason);
            var messages = new List<TransferNotification>();
            while (subscription.Reader.TryRead(out var notification))
                if (notification is TransferNotification transferNotification)
                    messages.Add(transferNotification);
            Assert.DoesNotContain(messages, message => message.Phase == TransferPhase.Released);
            var blocked = Assert.Single(messages, message => message.Phase == TransferPhase.Blocked);
            Assert.Equal(overrideAllowed, blocked.OverrideAllowed);
            Assert.True(blocked.HandbackVerified);
            Assert.Equal(entry.HandbackPath, blocked.HandbackPath);
            Assert.Equal(digest, blocked.SnapshotSha256Hex);
            Assert.Empty(blocked.Findings!);
            Assert.Equal(expectedFailure, blocked.InspectionFailure);
            string wire = NotificationProtocol.Serialize(blocked);
            Assert.DoesNotContain("InvalidDataException", wire);
            Assert.DoesNotContain("529.982.247-25", wire);
            var restoredNotification = Assert.IsType<TransferNotification>(
                NotificationProtocol.Deserialize(wire.TrimEnd('\n')));
            Assert.Equal(expectedFailure, restoredNotification.InspectionFailure);
            var restartedJournal = new StagedTransferJournal(Path.Combine(_workspace.Root, "journal"));
            var restartedEntry = await restartedJournal.ReadAsync(transfer.TransferId, CancellationToken.None);
            Assert.Equal(expectedFailure, restartedEntry.BlockedInspectionFailure);
            Assert.Empty(Directory.GetFiles(Path.GetDirectoryName(transfer.DestinationPath)!, "*.pending"));

            await publisher.RecoverBlockedAsync(restartedEntry, CancellationToken.None);
            var recoveryMessages = new List<TransferNotification>();
            while (subscription.Reader.TryRead(out var recoveredNotification))
                if (recoveredNotification is TransferNotification recoveredTransfer)
                    recoveryMessages.Add(recoveredTransfer);
            var recoveredBlock = Assert.Single(recoveryMessages,
                message => message.Phase == TransferPhase.Blocked);
            Assert.Equal(expectedFailure, recoveredBlock.InspectionFailure);
            Assert.Equal(digest, recoveredBlock.SnapshotSha256Hex);
            Assert.True(recoveredBlock.HandbackVerified);
            Assert.False(gate.Called);

            Assert.Equal(overrideAllowed, broker.TryConsume(transfer.TransferId.ToString("D"), 8, TestRequestorSid, out var wrongSession));
            Assert.Null(wrongSession);
            Assert.Equal(overrideAllowed, broker.TryConsume(transfer.TransferId.ToString("D"), 7,
                "S-1-5-21-999-888-777-1000", out var wrongUser));
            Assert.Null(wrongUser);
            Assert.Equal(overrideAllowed, broker.TryConsume(transfer.TransferId.ToString("D"), 7, TestRequestorSid, out var justify));
            if (overrideAllowed)
            {
                Assert.NotNull(justify);
                Assert.True(await justify!(CancellationToken.None).WaitAsync(TimeSpan.FromSeconds(5)));
                Assert.True(gate.Called);
                Assert.Equal(digest, gate.Digest);
                Assert.Equal(inspectedBytes, await File.ReadAllBytesAsync(transfer.DestinationPath));
                Assert.Equal(TransferJournalState.Released,
                    (await _journal.ReadAsync(transfer.TransferId, CancellationToken.None)).State);
            }
            else
            {
                Assert.Null(justify);
                Assert.False(gate.Called);
                Assert.Equal("public original", await File.ReadAllTextAsync(transfer.DestinationPath));
            }
        }
        finally { paused.Continue.TrySetResult(); }
    }

    private sealed class ThrowingExtractor : ITextExtractor
    {
        public IReadOnlySet<string> SupportedExtensions { get; } = new HashSet<string> { ".txt" };
        public Task<string> ExtractAsync(Stream content, CancellationToken cancellationToken)
            => throw new InvalidDataException("Injected parser failure.");
    }

    private sealed class VerifiedSnapshotHandbackCopier(string root) : IStagedHandbackCopier
    {
        public async Task<string> CopyVerifiedAsync(StagedTransfer transfer, FileStream snapshot,
            long length, string sha256Hex, CancellationToken token)
        {
            string directory = Path.Combine(root, "handback");
            Directory.CreateDirectory(directory);
            string path = Path.Combine(directory, transfer.TransferId.ToString("N") + Path.GetExtension(transfer.DestinationPath));
            snapshot.Position = 0;
            await using (var output = new FileStream(path, FileMode.CreateNew, FileAccess.Write, FileShare.None))
                await snapshot.CopyToAsync(output, token);
            using var proof = OpenVerifiedReadLease(transfer, path, length, sha256Hex);
            return path;
        }

        public IDisposable OpenVerifiedReadLease(StagedTransfer transfer, string path, long length, string sha256Hex)
        {
            var input = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read);
            try
            {
                string digest = Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(input));
                if (input.Length != length || !string.Equals(digest, sha256Hex, StringComparison.Ordinal))
                    throw new IOException("The test hand-back does not match the sealed snapshot.");
                input.Position = 0;
                return input;
            }
            catch { input.Dispose(); throw; }
        }

        public void CleanupUncommittedTemporary(StagedTransfer transfer) { }
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
            Entered.TrySetResult();
            await Continue.Task.WaitAsync(cancellationToken);
            using var reader = new StreamReader(content);
            return await reader.ReadToEndAsync(cancellationToken);
        }
    }
}
