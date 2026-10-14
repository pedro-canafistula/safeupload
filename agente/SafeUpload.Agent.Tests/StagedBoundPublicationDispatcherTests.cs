#if SAFEUPLOAD_ADMISSION_EVIDENCE
using System.Text;
using SafeUpload.Agent.Core.Application;
using SafeUpload.Agent.Core.Contracts;
using SafeUpload.Agent.Core.Domain;
using SafeUpload.Agent.Core.Infrastructure;
using SafeUpload.Agent.Core.Infrastructure.Extraction;
using SafeUpload.Agent.Minifilter;
using SafeUpload.Agent.Service.Interception;
using SafeUpload.Agent.Service.Notifications;

namespace SafeUpload.Agent.Tests;

// Real durable heads/manifests, fake kernel/native calls. These controls do not
// establish descriptor equivalence, NTFS semantics or protected qualification.
public sealed partial class StagedPublicationNativeJournalTests
{
    private sealed class Crash : Exception { }

    private sealed class PublicationFake(StagedAllocationBindingV23 binding, TransferJournalEntry entry) :
        IStagedBoundPublicationTransport, IStagedBoundPublicationNative, IStagedBoundPublicationDirectory, IStagedBoundPublicationFile
    {
        internal readonly List<string> Events = [];
        internal Action<string>? At;
        internal BoundPublicationFactsRowV26 Facts;
        internal ulong Revision = 1;
        internal bool Exists, Crashed, FailCreate, UnknownRename, FailRename, StaleReply, DenyPermit, NotReady;
        internal bool LoseAckReply, RetainAckRow;
        internal int Creates, Renames, Deletes, Acks;
        internal StagedStageIdentity? PublicIdentity;
        internal Func<Task>? BeforeWrite;
        internal BoundPublicationReplay? ReplayOverride;
        public StagedStageIdentity Identity { get; } = new(entry.StageIdentity!.VolumeSerialNumber, 0, entry.StageIdentity.FileIdLow + 100);
        internal void Point(string point)
        {
            Events.Add(point);
            At?.Invoke(point);
        }
        internal void Available() { if (Crashed) throw new Crash(); }
        public IStagedBoundPublicationDirectory Open(StagedAllocationBindingV23 value)
        { Available(); Assert.Equal(binding, value); return this; }
        public StagedDestinationNameObservation Observe(CancellationToken token)
        {
            Point("observe");
            return new(binding.Destination, binding.Parent, binding.Parent, true, PublicIdentity);
        }
        public IStagedBoundPublicationFile Create(BoundPublicationRequestV26 request, StagedAllocationSecuritySnapshot security)
        {
            Available(); Creates++;
            Assert.Equal(StagedTransferJournal.PublicationRequestBytes(Facts.Create), StagedTransferJournal.PublicationRequestBytes(request));
            Facts.Flags = BoundPublicationFacts.CreateConsumed | BoundPublicationFacts.CreateForwarded | BoundPublicationFacts.CreateResultKnown;
            if (FailCreate) { Facts.CreateStatus = unchecked((int)0xc0000035); Facts.CreateInformation = 4; }
            else
            {
                Facts.Flags |= BoundPublicationFacts.CreateAccepted | BoundPublicationFacts.TemporaryIdentityKnown;
                Facts.TemporaryIdentity = Wire(Identity); Facts.CreateInformation = 2;
            }
            Revision++; Point("create-native");
            if (FailCreate) throw new IOException("collision");
            return this;
        }
        public async Task<long> WriteAsync(Stream snapshot, CancellationToken token)
        {
            Available();
            if (BeforeWrite is not null) await BeforeWrite();
            long count = 0; byte[] bytes = new byte[4096]; int read;
            while ((read = await snapshot.ReadAsync(bytes, token)) != 0) count += read;
            Point("copy"); return count;
        }
        public void Rename(IStagedBoundPublicationFile file, BoundPublicationRequestV26 request)
        {
            Available(); Assert.Same(this, file); Renames++;
            Facts.Flags |= BoundPublicationFacts.RenameConsumed | BoundPublicationFacts.RenameForwarded |
                BoundPublicationFacts.TargetObservationKnown;
            Facts.ObservedPublicIdentity = PublicIdentity is null ? default : Wire(PublicIdentity);
            if (PublicIdentity is null) Facts.Flags |= BoundPublicationFacts.TargetAbsent;
            if (!UnknownRename)
            {
                Facts.Flags |= BoundPublicationFacts.RenameResultKnown;
                if (FailRename) Facts.RenameStatus = unchecked((int)0xc0000022);
                else { Facts.Flags |= BoundPublicationFacts.RenameAccepted; PublicIdentity = Identity; }
            }
            Revision++; Point("rename-native");
        }
        public BoundPublicationReplyV26 Send(BoundPublicationRequestV26 request)
        {
            Available();
            if (request.Phase == BoundPublicationPhase.Create)
            {
                Assert.True(!Exists || NotReady); Exists = true;
                Facts = new() { Create = request, OriginalProcessId = 1234, OriginalSessionId = 1,
                    OriginalProcessCreationTime = 123456, OriginalConnectionEpoch = 11, OsBootSequence = 42 };
                Revision++; Point("create-permit");
            }
            if (request.Phase == BoundPublicationPhase.Rename)
            {
                Assert.False(Facts.Flags.HasFlag(BoundPublicationFacts.RenameArmed));
                Facts.Rename = request;
                Facts.Flags |= BoundPublicationFacts.RenameArmed | BoundPublicationFacts.DataFenced |
                    BoundPublicationFacts.DataDrained | BoundPublicationFacts.FlushResultKnown | BoundPublicationFacts.FlushSucceeded;
                Facts.ObservedEof = request.MeasuredLength;
                Revision++; Point("rename-permit");
            }
            if (request.Phase == BoundPublicationPhase.Revoke)
            {
                if (!Facts.Flags.HasFlag(BoundPublicationFacts.RenameAccepted) &&
                    (!Facts.Flags.HasFlag(BoundPublicationFacts.RenameForwarded) || Facts.Flags.HasFlag(BoundPublicationFacts.RenameResultKnown)))
                {
                    Facts.Flags |= BoundPublicationFacts.DataFenced | BoundPublicationFacts.DataDrained | BoundPublicationFacts.CleanupArmed;
                    if (Facts.Flags.HasFlag(BoundPublicationFacts.RenameArmed) && !Facts.Flags.HasFlag(BoundPublicationFacts.RenameForwarded))
                        Facts.Flags |= BoundPublicationFacts.RenameConsumed | BoundPublicationFacts.RenameNotForwarded;
                    Facts.CleanupOperationId = Guid.NewGuid(); Facts.CleanupNonce = Guid.NewGuid();
                }
                Revision++;
            }
            var reply = Reply(request, request.Phase == BoundPublicationPhase.Revoke ? BoundPublicationResult.Revoked :
                NotReady ? BoundPublicationResult.NotReady : DenyPermit ? BoundPublicationResult.Consumed : BoundPublicationResult.Prepared);
            if (StaleReply) reply.DestinationGeneration++;
            return reply;
        }
        internal static BoundPublicationReplyV26 Reply(BoundPublicationRequestV26 request, BoundPublicationResult result) => new()
        {
            ExtensionVersion = 26, StructSize = 128, Phase = request.Phase, TransferId = request.TransferId,
            DriverInstanceId = request.DriverInstanceId, PermitNonce = request.PermitNonce, CreateNonce = request.CreateNonce,
            OperationId = request.OperationId, DestinationGeneration = request.DestinationGeneration, ConnectionEpoch = 11,
            AuthorityRevision = 19, Result = result
        };
        public BoundPublicationReplay ReadFacts()
        {
            Available(); Point("facts-query");
            if (ReplayOverride is { } replay) return replay;
            Point(Facts.Flags.HasFlag(BoundPublicationFacts.RenameAccepted) ? "rename-facts-reply" : "create-facts-reply");
            return new(binding.DriverInstanceId, 11, Revision, 42, Exists ? [new(Facts)] : []);
        }
        public BoundPublicationReplyV26 Acknowledge(BoundPublicationReplay replay, BoundPublicationReplayRow row)
        {
            Available(); Assert.True(row.HasTerminalLocalProof); Acks++;
            if (LoseAckReply) throw new IOException("publication_replay_or_ack_pending");
            Exists = RetainAckRow; Revision++; Point("ack");
            var reply = Reply(row.Facts.Create, BoundPublicationResult.Acknowledged); reply.Phase = BoundPublicationPhase.CleanupAck;
            return reply;
        }
        public void Delete()
        {
            Available(); Assert.False(Facts.Flags.HasFlag(BoundPublicationFacts.RenameAccepted)); Deletes++;
            Facts.Flags |= BoundPublicationFacts.CleanupForwarded | BoundPublicationFacts.CleanupResultKnown | BoundPublicationFacts.CleanupAccepted;
            Revision++; Point("cleanup-native");
        }
        public void Dispose()
        {
            if (Exists && Facts.Flags.HasFlag(BoundPublicationFacts.TemporaryIdentityKnown) && !Crashed &&
                !Facts.Flags.HasFlag(BoundPublicationFacts.LastCleanup))
            { Facts.Flags |= BoundPublicationFacts.LastCleanup; Revision++; }
        }
        internal void Restart()
        {
            At = null; Crashed = false;
            // The fake supplies actual process-handle cleanup, not wall-clock or
            // service restart as a replacement for missing kernel lifetime proof.
            Dispose();
        }
    }

    private StagedTransferJournal ObservedJournal(PublicationFake fake) => new(JournalPath, false, 128,
        (point, entry) => { if (point == StagedJournalWritePoint.AfterReplacement && entry.State == TransferJournalState.Released) fake.Point("released"); })
    {
        DestinationHeadWritten = head =>
        {
            if (head.PublicationAttempts?.Length != 1) return;
            var attempt = head.PublicationAttempts[0];
            if (head.PublicationNativeReceipts?.Length != 1) { fake.Point("create-intent"); return; }
            var receipt = head.PublicationNativeReceipts[0];
            var row = BoundPublicationV26.DecodeFactRow(Convert.FromBase64String(receipt.FactsBase64), receipt.DriverInstanceId,
                receipt.ConnectionEpoch, receipt.OsBootSequence);
            if (head.LatestPublished > 0) fake.Point("published");
            else if (row.Facts.Flags.HasFlag(BoundPublicationFacts.RenameAccepted)) fake.Point("facts-persisted");
            else if (attempt.RenameBase64 is not null) fake.Point("rename-intent");
            else fake.Point("create-facts");
        }
    };
    private static StagedBoundPublicationDispatcher Dispatcher(StagedTransferJournal journal, PublicationFake fake, bool ready = true) =>
        new(journal, fake, fake, () => ready);
    private static async Task<TransferJournalEntry> Publishing(StagedTransferJournal journal, TransferJournalEntry entry) =>
        await journal.TransitionAsync(entry.Transfer.TransferId, TransferJournalState.Approved, TransferJournalState.Publishing, null, default);
    private static Task<StagedBoundPublicationResult> Publish(StagedTransferJournal journal, PublicationFake fake,
        TransferJournalEntry entry, Func<CancellationToken, Task<bool>>? policy = null, CancellationToken token = default) =>
        Dispatcher(journal, fake).PublishAsync(entry, new MemoryStream(new byte[checked((int)entry.SealedLength!.Value)]),
            policy ?? (_ => Task.FromResult(true)), () => { fake.Point("snapshot-released"); return ValueTask.CompletedTask; }, token);

    [Fact]
    public async Task Bound_order_is_intent_permit_native_facts_published_released_and_later_ack_removal()
    {
        var f = await Allocate(); var fake = new PublicationFake(f.Binding, f.Entry); var journal = ObservedJournal(fake);
        var entry = await Publishing(journal, f.Entry);
        Assert.True((await Publish(journal, fake, entry)).Released);
        string[] order = ["create-intent", "create-permit", "create-native", "create-facts", "copy", "snapshot-released",
            "rename-intent", "rename-permit", "rename-native", "facts-persisted", "published", "released", "ack"];
        int previous = -1;
        foreach (string point in order) { int index = fake.Events.IndexOf(point); Assert.True(index > previous, point); previous = index; }
        var head = (await Journal().ReadDestinationHeadAsync(f.Binding.Destination, default))!;
        Assert.Single(head.PublicationNativeReceipts!); Assert.Single(head.PublicationAttempts!);
        Assert.NotNull(head.PublicationNativeReceipts![0].AcknowledgedRevision);
        Assert.True((await Dispatcher(Journal(), fake).ReconcileAsync(entry, default)).Released);
        head = (await Journal().ReadDestinationHeadAsync(f.Binding.Destination, default))!;
        Assert.Empty(head.PublicationNativeReceipts!); Assert.Empty(head.PublicationAttempts!);
        Assert.Equal(f.Entry.DestinationGeneration, head.LatestPublished); Assert.Equal(1, fake.Creates); Assert.Equal(1, fake.Renames);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task Pending_publication_ACK_does_not_suppress_justified_stage_last_close_cleanup(bool loseAckReply)
    {
        var f = await Allocate(approve: false, content: Encoding.UTF8.GetBytes("blocked private snapshot"));
        var journal = Journal(); var transfer = f.Entry.Transfer;
        string digest = Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(await File.ReadAllBytesAsync(transfer.StagePath)));
        await journal.TransitionAsync(transfer.TransferId, TransferJournalState.Sealed, TransferJournalState.Inspecting, digest, default);
        await journal.TransitionAsync(transfer.TransferId, TransferJournalState.Inspecting, TransferJournalState.Blocked, digest, default,
            blockedEvidence: new BlockedTransferEvidence(1, DateTimeOffset.UtcNow.AddMinutes(5), WindowClosed: false));
        string handback = Path.Combine(_workspace.Root, "handback.txt");
        await journal.BeginHandbackAttemptAsync(transfer.TransferId, default);
        File.Copy(transfer.StagePath, handback);
        await journal.CompleteHandbackAsync(transfer.TransferId, handback, f.Entry.SealedLength, null, default);
        // Model the existing justified path through its real journal transitions;
        // publication itself uses the durable head/receipt dispatcher below.
        await journal.TransitionAsync(transfer.TransferId, TransferJournalState.Blocked, TransferJournalState.Inspecting, digest, default,
            closeJustificationWindow: true);
        var approved = await journal.TransitionAsync(transfer.TransferId, TransferJournalState.Inspecting, TransferJournalState.Approved, digest, default);
        var fake = new PublicationFake(f.Binding, approved) { LoseAckReply = loseAckReply, RetainAckRow = !loseAckReply };
        Assert.True((await Publish(journal, fake, await Publishing(journal, approved))).Released);
        var released = await journal.ReadAsync(transfer.TransferId, default);
        Assert.Equal(TransferJournalState.Released, released.State);
        Assert.Equal(StagedHandbackState.Verified, released.HandbackState);
        Assert.True(released.JustificationWindowClosed);
        var cleanup = new BoundCleanupGate(transfer.TransferId);
        var copier = new VerifiedCleanupHandback(transfer, handback, digest);
        var publisher = new StagedTransferPublisher(new InspectionService(new LocalPolicyStore(_workspace.PolicyFile),
            new LocalQueueAuditSink(_workspace.QueueFile), ExtractorRegistry.CreateDefault(), new VerdictCache()),
            NotificationTestHub.Create(), journal, Stages, cleanup, handbackCopier: copier,
            sessionUserSidResolver: _ => transfer.RequestorSid) { BoundPublication = Dispatcher(journal, fake) };
        long now = 0; publisher.RecoveryTimestamp = () => now;
        await publisher.RecoverBoundReceiptsAsync(default);
        // Grow only the receipt retry to eight seconds. A successful ACK reply
        // with a retained row is unfinished too, even without a diagnostic.
        foreach (double seconds in new[] { .25, .5, 1, 2, 4 })
        {
            int acks = fake.Acks;
            now += (long)(seconds * System.Diagnostics.Stopwatch.Frequency);
            await publisher.RecoverBoundReceiptsAsync(default);
            Assert.Equal(acks + 1, fake.Acks);
        }
        long receiptDue = now + 8 * System.Diagnostics.Stopwatch.Frequency;
        int pendingAcks = fake.Acks;
        using (var driver = new FileStream(transfer.StagePath, FileMode.Open, FileAccess.Read, FileShare.Read | FileShare.Delete))
        {
            await publisher.RecoverPendingTransferAsync(released, default, cleanupOnly: true);
            var pending = await journal.ReadAsync(transfer.TransferId, default);
            Assert.True(StagedTransferJournal.MatchesBlockedDeletionReceipt(pending)); // fails before finding-2 fix
            Assert.False(pending.StageDeleted); Assert.True(pending.StageCleanupStarted);
            long reads = journal.ManifestReads; int disposals = cleanup.Disposals;
            now += System.Diagnostics.Stopwatch.Frequency / 4 - 1;
            for (int pass = 0; pass < 8; pass++)
                await publisher.RecoverPendingTransferAsync(pending, default, cleanupOnly: true);
            Assert.Equal(reads, journal.ManifestReads); Assert.Equal(disposals, cleanup.Disposals);
        }
        now++;
        await publisher.RecoverPendingTransferAsync(released, default, cleanupOnly: true);
        var terminal = await journal.ReadAsync(transfer.TransferId, default);
        Assert.True(StagedTransferJournal.BlockedCleanupComplete(terminal));
        Assert.False(File.Exists(transfer.StagePath)); Assert.True(now < receiptDue);
        var head = (await journal.ReadDestinationHeadAsync(f.Binding.Destination, default))!;
        Assert.Single(head.PublicationAttempts!); Assert.Single(head.PublicationNativeReceipts!);
        Assert.Equal(terminal.DestinationGeneration, head.LatestPublished);
        await publisher.RecoverBoundReceiptsAsync(default);
        Assert.Equal(pendingAcks, fake.Acks); // cleanup did not clear the receipt deadline
        long terminalReads = journal.ManifestReads;
        for (int pass = 0; pass < 8; pass++) await publisher.RecoverPendingTransferAsync(terminal, default);
        Assert.Equal(terminalReads, journal.ManifestReads);
        fake.LoseAckReply = false; fake.RetainAckRow = false;
        now = receiptDue;
        await publisher.RecoverBoundReceiptsAsync(default); // ACK alone retains durable obligations
        Assert.Single((await journal.ReadDestinationHeadAsync(f.Binding.Destination, default))!.PublicationAttempts!);
        now += 8 * System.Diagnostics.Stopwatch.Frequency;
        await publisher.RecoverBoundReceiptsAsync(default); // later exact replay retires them
        head = (await journal.ReadDestinationHeadAsync(f.Binding.Destination, default))!;
        Assert.Empty(head.PublicationAttempts!); Assert.Empty(head.PublicationNativeReceipts!);
        Assert.Equal(1, fake.Creates); Assert.Equal(1, fake.Renames); Assert.Equal(0, fake.Deletes);
        Assert.Equal(fake.Identity, fake.PublicIdentity); Assert.True(copier.Reads > 0);
    }

    private sealed class BoundCleanupGate(Guid id) : IStagedPublicationGate
    {
        internal int Disposals;
        public IDisposable Authorize(StagedTransfer transfer, string temporaryDestination, string digest) =>
            throw new InvalidOperationException("Cleanup repeated publication");
        public bool DisposeStage(Guid transferId, uint outcome, uint committedRenames)
        {
            Assert.Equal(id, transferId); Assert.Equal(StageDisposeOutcome.CleanedUp, outcome); Assert.Equal(0u, committedRenames);
            Disposals++; return true;
        }
    }

    private sealed class VerifiedCleanupHandback(StagedTransfer expected, string path, string digest) : IStagedHandbackCopier
    {
        internal int Reads;
        public Task<string> CopyVerifiedAsync(StagedTransfer transfer, FileStream snapshot, long length, string sha256, CancellationToken token) =>
            throw new InvalidOperationException("Cleanup recopied the hand-back");
        public IDisposable OpenVerifiedReadLease(StagedTransfer transfer, string verifiedPath, long length, string sha256)
        {
            Assert.Equal(expected, transfer); Assert.Equal(path, verifiedPath); Assert.Equal(digest, sha256);
            var lease = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read);
            try
            {
                Assert.Equal(length, lease.Length);
                Assert.Equal(digest, Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(lease)));
                Reads++; return lease;
            }
            catch { lease.Dispose(); throw; }
        }
        public void CleanupUncommittedTemporary(StagedTransfer transfer) =>
            throw new InvalidOperationException("Cleanup discarded a committed hand-back");
    }

    public static IEnumerable<object[]> FailureBoundaries() =>
        new[] { "create-intent", "create-permit", "create-native", "create-facts-reply", "create-facts", "rename-intent", "rename-permit",
            "rename-native", "rename-facts-reply", "facts-persisted", "published", "released", "ack" }
        .SelectMany(point => new[] { new object[] { point, false }, new object[] { point, true } });

    [Theory]
    [MemberData(nameof(FailureBoundaries))]
    public async Task Lost_reply_or_restart_at_each_boundary_never_repeats_native_mutation(string boundary, bool crash)
    {
        var f = await Allocate(); var fake = new PublicationFake(f.Binding, f.Entry); var journal = ObservedJournal(fake);
        var entry = await Publishing(journal, f.Entry); bool injected = false;
        fake.At = point =>
        {
            if (point != boundary || injected) return;
            injected = true;
            if (crash) { fake.Crashed = true; throw new Crash(); }
            throw new IOException("injected reply loss");
        };
        _ = await Record.ExceptionAsync(() => Publish(journal, fake, entry));
        Assert.True(injected, boundary);
        int creates = fake.Creates, renames = fake.Renames, deletes = fake.Deletes;
        fake.Restart();
        var reopened = Journal(); var dispatcher = Dispatcher(reopened, fake);
        _ = await dispatcher.ReconcileAsync(entry, default);
        _ = await dispatcher.ReconcileAsync(entry, default);
        Assert.Equal(creates, fake.Creates); Assert.Equal(renames, fake.Renames); Assert.Equal(deletes, fake.Deletes);
        var actual = await reopened.ReadAsync(entry.Transfer.TransferId, default);
        if (renames == 1)
        {
            Assert.Equal(TransferJournalState.Released, actual.State);
            Assert.Equal(entry.DestinationGeneration, (await reopened.ReadDestinationHeadAsync(f.Binding.Destination, default))!.LatestPublished);
        }
        else
        {
            Assert.NotEqual(TransferJournalState.Released, actual.State);
            Assert.Equal(0, (await reopened.ReadDestinationHeadAsync(f.Binding.Destination, default))!.LatestPublished);
        }
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public async Task Failed_create_and_failed_rename_keep_native_status_through_ack_loss(bool create)
    {
        var f = await Allocate(); var fake = new PublicationFake(f.Binding, f.Entry) { FailCreate = create, FailRename = !create };
        fake.At = point => { if (point == "ack") throw new IOException("lost ACK"); };
        var journal = Journal(); var entry = await Publishing(journal, f.Entry);
        Assert.False((await Publish(journal, fake, entry)).Released);
        var head = (await Journal().ReadDestinationHeadAsync(f.Binding.Destination, default))!;
        var receipt = Assert.Single(head.PublicationNativeReceipts!);
        var facts = BoundPublicationV26.DecodeFactRow(Convert.FromBase64String(receipt.FactsBase64), _driver, 11, 42).Facts;
        Assert.Equal(create ? unchecked((int)0xc0000035) : 0, facts.CreateStatus);
        Assert.Equal(create ? 4ul : 2ul, facts.CreateInformation);
        Assert.Equal(create ? 0 : unchecked((int)0xc0000022), facts.RenameStatus);
        Assert.Equal(0, head.LatestPublished); Assert.Null(head.PendingCommit);
        Assert.NotNull(receipt.AcknowledgedRevision);
        fake.Restart(); await Dispatcher(Journal(), fake).ReconcileAsync(entry, default);
        Assert.Empty((await Journal().ReadDestinationHeadAsync(f.Binding.Destination, default))!.PublicationNativeReceipts!);
        Assert.Equal(1, fake.Creates); Assert.Equal(create ? 0 : 1, fake.Renames); Assert.Equal(create ? 0 : 1, fake.Deletes);
    }

    [Fact]
    public async Task Unknown_rename_holds_pending_commit_and_never_cleans_or_retries()
    {
        var f = await Allocate(); var fake = new PublicationFake(f.Binding, f.Entry) { UnknownRename = true };
        var journal = Journal(); var entry = await Publishing(journal, f.Entry);
        Assert.False((await Publish(journal, fake, entry)).Released);
        await Dispatcher(Journal(), fake).ReconcileAsync(entry, default);
        var head = (await Journal().ReadDestinationHeadAsync(f.Binding.Destination, default))!;
        Assert.NotNull(head.PendingCommit); Assert.NotNull(Assert.Single(head.PublicationAttempts!).Diagnostic);
        Assert.Equal(0, fake.Deletes); Assert.Equal(0, fake.Acks); Assert.Equal(1, fake.Renames);
    }

    [Theory]
    [InlineData("stale-reply")]
    [InlineData("consumed")]
    [InlineData("not-ready")]
    [InlineData("kernel-not-ready")]
    public async Task Exact_prepared_and_service_readiness_are_both_required(string refusal)
    {
        var f = await Allocate(); var fake = new PublicationFake(f.Binding, f.Entry)
            { StaleReply = refusal == "stale-reply", DenyPermit = refusal == "consumed", NotReady = refusal == "kernel-not-ready" };
        var journal = Journal(); var entry = await Publishing(journal, f.Entry);
        using var bytes = new MemoryStream(new byte[37]);
        var result = await Dispatcher(journal, fake, refusal != "not-ready").PublishAsync(entry, bytes,
            _ => Task.FromResult(true), () => ValueTask.CompletedTask, default);
        Assert.False(result.Released); Assert.Equal(0, fake.Creates); Assert.Equal(0, fake.Renames);
    }

    [Fact]
    public async Task Newer_allocation_during_copy_bars_stale_generation_without_publishing()
    {
        var f = await Allocate(); var fake = new PublicationFake(f.Binding, f.Entry); var journal = Journal();
        var entry = await Publishing(journal, f.Entry);
        fake.BeforeWrite = async () =>
        {
            using var allocation = await journal.EnterDestinationCommitTurnAsync(f.Binding.Destination, StagedDestinationTurnPurpose.Allocation, default);
            await journal.ReserveSaveGenerationAsync(allocation, Guid.NewGuid(), entry.Transfer.DestinationPath, 0, default);
        };
        Assert.False((await Publish(journal, fake, entry)).Released);
        Assert.Equal(0, fake.Renames);
        var head = (await Journal().ReadDestinationHeadAsync(f.Binding.Destination, default))!;
        Assert.Equal(0, head.LatestPublished); Assert.True(head.CurrentSaveGeneration > entry.DestinationGeneration);
    }

    [Fact]
    public async Task Policy_change_while_preparing_or_after_fence_never_forwards_rename()
    {
        foreach (int failAt in new[] { 2, 3 })
        {
            var f = await Allocate(); var fake = new PublicationFake(f.Binding, f.Entry); var journal = Journal();
            var entry = await Publishing(journal, f.Entry); int checks = 0;
            Assert.False((await Publish(journal, fake, entry, _ => Task.FromResult(++checks < failAt))).Released);
            Assert.Equal(0, fake.Renames); Assert.Equal(1, fake.Deletes);
        }
    }

    [Fact]
    public async Task Newer_published_successor_is_not_replaced_by_old_receipt_bookkeeping()
    {
        var first = await Allocate(); var old = new PublicationFake(first.Binding, first.Entry); var journal = Journal();
        var entry = await Publishing(journal, first.Entry);
        Assert.True((await Publish(journal, old, entry)).Released);
        var later = await Allocate(); var next = new PublicationFake(later.Binding, later.Entry) { PublicIdentity = old.Identity };
        Assert.True((await Publish(journal, next, await Publishing(journal, later.Entry))).Released);
        Assert.True((await Dispatcher(Journal(), old).ReconcileAsync(entry, default)).Released);
        var head = (await Journal().ReadDestinationHeadAsync(first.Binding.Destination, default))!;
        Assert.Equal(later.Entry.DestinationGeneration, head.LatestPublished); Assert.Equal(next.Identity, head.PublishedIdentity);
        Assert.Equal(1, old.Renames); Assert.Equal(1, next.Renames);
    }

    [Fact]
    public async Task Accepted_delete_reservation_releases_snapshot_and_waits_without_holding_the_turn()
    {
        var old = await Allocate(); var journal = Journal();
        var publicId = new StagedStageIdentity(old.Entry.StageIdentity!.VolumeSerialNumber, 0, 7654321);
        var deletion = new StagedPublicDeleteBinding(Guid.NewGuid(), Guid.NewGuid(), _driver, 11, publicId,
            old.Entry.Transfer.ProcessId, old.Entry.Transfer.RequestorProcessCreationTime!.Value,
            old.Entry.Transfer.SessionId!.Value, old.Entry.Transfer.RequestorSid!, 42, old.Binding.MountManagerVolumeId);
        StagedPublicDeleteRecord admitted;
        using (var turn = await journal.EnterDestinationCommitTurnAsync(old.Binding.Destination, StagedDestinationTurnPurpose.Allocation, default))
            admitted = await journal.AdmitPublicDeleteAsync(turn, deletion, old.Entry.Transfer.DestinationPath, 0, default);
        using (var turn = await journal.EnterDestinationCommitTurnAsync(old.Binding.Destination, StagedDestinationTurnPurpose.Reconciliation, default))
        {
            var operation = Guid.NewGuid();
            await journal.BeginPublicDeleteDispositionAsync(turn, deletion, operation, default);
            await journal.RecordPublicDeleteDispositionResultAsync(turn, deletion, operation, true);
        }
        var later = await Allocate(); var fake = new PublicationFake(later.Binding, later.Entry) { PublicIdentity = publicId };
        var entry = await Publishing(journal, later.Entry);
        var prepared = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        fake.At = point => { if (point == "snapshot-released") prepared.TrySetResult(); };
        using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        Task<StagedBoundPublicationResult> publication = Publish(journal, fake, entry, token: deadline.Token);
        await prepared.Task.WaitAsync(deadline.Token);
        Assert.False(publication.IsCompleted); Assert.Equal(0, fake.Renames);
        using (var turn = await journal.EnterDestinationCommitTurnAsync(old.Binding.Destination,
            StagedDestinationTurnPurpose.Reconciliation, deadline.Token))
        {
            // Independent exact-delete evidence is supplied by the fake. The
            // waiting publisher must not own the turn needed for this receipt.
            fake.PublicIdentity = null;
            await journal.RecordPublicDeletePhysicalCompleteAsync(turn, deletion, deadline.Token);
        }
        Assert.True((await publication).Released);
        var head = (await Journal().ReadDestinationHeadAsync(old.Binding.Destination, default))!;
        Assert.Equal(admitted.Generation, head.CommittedDelete); Assert.Equal(entry.DestinationGeneration, head.LatestPublished);
        Assert.True(head.LatestPublished > head.CommittedDelete);
        Assert.Equal(StagedPublicDeleteState.Complete, Assert.Single(head.Deletes).State);
    }

    [Theory]
    [InlineData("allocated")]
    [InlineData("sealed")]
    [InlineData("approved")]
    [InlineData("blocked")]
    [InlineData("published")]
    public async Task Only_a_published_successor_supersedes_an_admitted_delete(string successor)
    {
        var first = await Allocate(); var journal = Journal();
        var binding = new StagedPublicDeleteBinding(Guid.NewGuid(), Guid.NewGuid(), _driver, 11,
            new(first.Entry.StageIdentity!.VolumeSerialNumber, 0, 998877), first.Entry.Transfer.ProcessId,
            first.Entry.Transfer.RequestorProcessCreationTime!.Value, first.Entry.Transfer.SessionId!.Value,
            first.Entry.Transfer.RequestorSid!, 42, first.Binding.MountManagerVolumeId);
        using (var turn = await journal.EnterDestinationCommitTurnAsync(first.Binding.Destination, StagedDestinationTurnPurpose.Allocation, default))
            await journal.AdmitPublicDeleteAsync(turn, binding, first.Entry.Transfer.DestinationPath, 0, default);
        var later = await Allocate(approve: successor is "approved" or "published", seal: successor != "allocated");
        if (successor == "published")
        {
            var fake = new PublicationFake(later.Binding, later.Entry);
            Assert.True((await Publish(journal, fake, await Publishing(journal, later.Entry))).Released);
        }
        if (successor == "blocked")
        {
            string digest = Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(await File.ReadAllBytesAsync(later.Entry.Transfer.StagePath)));
            await journal.TransitionAsync(later.Entry.Transfer.TransferId, TransferJournalState.Sealed, TransferJournalState.Inspecting, digest, default);
            await journal.TransitionAsync(later.Entry.Transfer.TransferId, TransferJournalState.Inspecting, TransferJournalState.Blocked,
                digest, default, blockedEvidence: new(1, null, WindowClosed: true));
        }
        using (var turn = await journal.EnterDestinationCommitTurnAsync(first.Binding.Destination, StagedDestinationTurnPurpose.Reconciliation, default))
        {
            var operation = Guid.NewGuid();
            var decision = await journal.BeginPublicDeleteDispositionAsync(turn, binding, operation, default);
            Assert.Equal(successor == "published" ? StagedPublicDeleteState.Superseded : StagedPublicDeleteState.Intent, decision.State);
            if (successor != "published")
            {
                await journal.RecordPublicDeleteDispositionResultAsync(turn, binding, operation, true);
                await journal.RecordPublicDeletePhysicalCompleteAsync(turn, binding, default); // exact fake native absence
            }
        }
        var reopened = (await Journal().ReadDestinationHeadAsync(first.Binding.Destination, default))!;
        Assert.Equal(successor == "published" ? 0 : 2, reopened.CommittedDelete);
        Assert.Equal(successor == "published" ? later.Entry.DestinationGeneration : 0, reopened.LatestPublished);
        using var physical = await journal.EnterDestinationCommitTurnAsync(first.Binding.Destination,
            StagedDestinationTurnPurpose.PhysicalCommit, default);
        await Assert.ThrowsAsync<IOException>(() => journal.BeginDestinationPublicationAsync(physical, Guid.NewGuid(),
            first.Entry.Transfer.TransferId, first.Entry.DestinationGeneration, null, binding.PublicIdentity,
            0, StagedTransferJournal.EmptySha256Hex, default));
    }

    [Fact]
    public async Task Unacknowledged_bound_attempt_pins_manifest_security_and_ancestry_for_compaction()
    {
        var f = await Allocate(); var fake = new PublicationFake(f.Binding, f.Entry); var journal = Journal();
        var entry = await Publishing(journal, f.Entry);
        Assert.True((await Publish(journal, fake, entry)).Released);
        _ = await Allocate(); // Advance the independent generation head.
        File.Delete(entry.Transfer.StagePath); // Fake exact released-stage disposal.
        await journal.CompactAsync(DateTimeOffset.UtcNow.AddDays(1), default);
        Assert.Equal(TransferJournalState.Released, (await Journal().ReadAsync(entry.Transfer.TransferId, default)).State);
        Assert.NotNull(await Journal().ReadBoundAllocationSecurityAsync(entry.Transfer.TransferId, default));
        await Dispatcher(journal, fake).ReconcileAsync(entry, default); // Later replay proves ACK removal.
        Assert.Equal(1, await journal.CompactAsync(DateTimeOffset.UtcNow.AddDays(1), default));
        await Assert.ThrowsAsync<FileNotFoundException>(() => Journal().ReadAsync(entry.Transfer.TransferId, default));
    }

    private sealed class NoLegacy : IStagedPublicationGate
    {
        internal int Calls;
        public IDisposable Authorize(StagedTransfer transfer, string temporaryDestination, string digest)
        { Calls++; throw new InvalidOperationException("Bound entry reached legacy publication"); }
        public bool DisposeStage(Guid transferId, uint outcome, uint committedRenames) => true;
    }
    private sealed class PolicyFake(Policy initial) : IPolicyStore
    {
        internal Policy Current = initial;
        public Task<Policy> LoadAsync(CancellationToken token) => Task.FromResult(Current);
        public Task<Policy> LoadCurrentAsync(CancellationToken token) => Task.FromResult(Current);
    }
    private sealed class ExtractorFake(Func<string> extract) : ITextExtractor
    {
        public IReadOnlySet<string> SupportedExtensions { get; } = new HashSet<string> { ".txt" };
        public Task<string> ExtractAsync(Stream content, CancellationToken token) => Task.FromResult(extract());
    }

    [Theory]
    [InlineData("clean")]
    [InlineData("empty")]
    [InlineData("blocked")]
    [InlineData("incomplete")]
    [InlineData("policy-change")]
    public async Task Bound_publisher_uses_shared_inspection_gates_without_any_legacy_fallback(string scenario)
    {
        var f = await Allocate(approve: false, content: Encoding.UTF8.GetBytes(scenario == "empty" ? "" : "private snapshot"));
        var fake = new PublicationFake(f.Binding, f.Entry); var journal = ObservedJournal(fake); var legacy = new NoLegacy();
        var baseline = await new LocalPolicyStore(_workspace.PolicyFile).LoadAsync(default);
        var policy = new PolicyFake(baseline with { MonitoredScopes = baseline.MonitoredScopes with { DestinationPaths = [Parent] } });
        var extractor = new ExtractorFake(() =>
        {
            if (scenario == "policy-change") policy.Current = policy.Current with { Version = policy.Current.Version + 1 };
            if (scenario == "incomplete") throw new IOException("incomplete extraction");
            return scenario == "blocked" ? "CPF 529.982.247-25" : "clean text";
        });
        var publisher = new StagedTransferPublisher(new InspectionService(policy, new LocalQueueAuditSink(_workspace.QueueFile),
            new ExtractorRegistry([extractor]), new VerdictCache()), NotificationTestHub.Create(), journal, Stages, legacy,
            sessionUserSidResolver: _ => f.Entry.Transfer.RequestorSid)
        { BoundPublication = Dispatcher(journal, fake) };
        var result = await publisher.PublishAsync(f.Entry.Transfer, default);
        var expected = scenario is "clean" or "empty" ? StagedTransferOutcome.Released :
            scenario == "policy-change" ? StagedTransferOutcome.Retained : StagedTransferOutcome.Blocked;
        Assert.Equal(expected, result); Assert.Equal(0, legacy.Calls);
        Assert.Equal(expected == StagedTransferOutcome.Released ? 1 : 0, fake.Renames);
        if (expected != StagedTransferOutcome.Released) Assert.Equal(0, fake.Creates);
        if (scenario == "policy-change") Assert.Empty((await Journal().ReadDestinationHeadAsync(f.Binding.Destination, default))!.PublicationAttempts ?? []);
    }

    [Fact]
    public async Task Bound_export_unproved_recovery_keeps_blocked_private_and_justification_closed()
    {
        var f = await Allocate(approve: false); var journal = Journal(); var fake = new PublicationFake(f.Binding, f.Entry);
        string digest = Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(await File.ReadAllBytesAsync(f.Entry.Transfer.StagePath)));
        await journal.TransitionAsync(f.Entry.Transfer.TransferId, TransferJournalState.Sealed, TransferJournalState.Inspecting, digest, default);
        var blocked = await journal.TransitionAsync(f.Entry.Transfer.TransferId, TransferJournalState.Inspecting,
            TransferJournalState.Blocked, digest, default, blockedEvidence: new BlockedTransferEvidence(1,
                DateTimeOffset.UtcNow.AddMinutes(5), WindowClosed: false));
        var entry = blocked with { SeedCompletion = null };
        // Simulate a durable blocked version missing the seed-completion proof.
        // It must not acquire export authority from service restart or clean bytes.
        await SeedProvenanceFixture.WriteAsync(JournalPath, entry);
        var broker = new StagedJustifications(); var copier = new NoExport(); var legacy = new NoLegacy();
        var publisher = new StagedTransferPublisher(new InspectionService(new LocalPolicyStore(_workspace.PolicyFile),
            new LocalQueueAuditSink(_workspace.QueueFile), ExtractorRegistry.CreateDefault(), new VerdictCache()),
            NotificationTestHub.Create(), journal, Stages, legacy, justifications: broker, handbackCopier: copier,
            sessionUserSidResolver: _ => entry.Transfer.RequestorSid) { BoundPublication = Dispatcher(journal, fake) };
        await publisher.RecoverBlockedAsync(entry, default);
        var retained = await Journal().ReadAsync(entry.Transfer.TransferId, default);
        Assert.Equal(TransferJournalState.Blocked, retained.State);
        Assert.Equal(StagedHandbackState.Failed, retained.HandbackState);
        Assert.Equal(StagedSeedExport.Unproven, retained.HandbackFailureReason);
        Assert.True(retained.JustificationWindowClosed); Assert.Null(retained.HandbackPath);
        Assert.Equal(0, copier.Calls); Assert.Equal(0, fake.Creates); Assert.Equal(0, legacy.Calls);
        Assert.False(broker.TryConsume(entry.Transfer.TransferId.ToString("D"), entry.Transfer.SessionId!.Value,
            entry.Transfer.RequestorSid!, out _));
        Assert.True(File.Exists(entry.Transfer.StagePath));
    }
    private sealed class NoExport : IStagedHandbackCopier
    {
        internal int Calls;
        public Task<string> CopyVerifiedAsync(StagedTransfer transfer, FileStream snapshot, long length, string digest, CancellationToken token)
        { Calls++; throw new InvalidOperationException("Export-restricted version reached the copier"); }
        public IDisposable OpenVerifiedReadLease(StagedTransfer transfer, string path, long length, string digest)
        { Calls++; throw new InvalidOperationException("Export-restricted version reached the reader"); }
        // Removing this transfer's own uncommitted temporary exports nothing.
        public void CleanupUncommittedTemporary(StagedTransfer transfer) { }
    }

    [Fact]
    public async Task Missing_bound_dispatcher_is_an_explicit_rejection_never_a_legacy_fallback()
    {
        var f = await Allocate(approve: false); var legacy = new NoLegacy();
        var publisher = new StagedTransferPublisher(new InspectionService(new LocalPolicyStore(_workspace.PolicyFile),
            new LocalQueueAuditSink(_workspace.QueueFile), ExtractorRegistry.CreateDefault(), new VerdictCache()),
            NotificationTestHub.Create(), Journal(), Stages, legacy);
        await Assert.ThrowsAsync<IOException>(() => publisher.PublishAsync(f.Entry.Transfer, default));
        Assert.Equal(0, legacy.Calls);
    }

    [Fact]
    public async Task Bound_released_cannot_be_written_through_the_legacy_transition()
    {
        var f = await Allocate(); var journal = Journal(); await Publishing(journal, f.Entry);
        await Assert.ThrowsAsync<IOException>(() => journal.TransitionAsync(f.Entry.Transfer.TransferId,
            TransferJournalState.Publishing, TransferJournalState.Released, null, default));
    }
}
#endif
