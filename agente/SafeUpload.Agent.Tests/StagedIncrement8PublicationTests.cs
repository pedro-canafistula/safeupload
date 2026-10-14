#if SAFEUPLOAD_ADMISSION_EVIDENCE
using SafeUpload.Agent.Core.Application;
using SafeUpload.Agent.Core.Infrastructure;
using SafeUpload.Agent.Core.Infrastructure.Extraction;
using SafeUpload.Agent.Minifilter;
using SafeUpload.Agent.Service.Interception;

namespace SafeUpload.Agent.Tests;

public sealed partial class StagedPublicationNativeJournalTests
{
    private StagedTransferPublisher RecoveryPublisher(StagedTransferJournal journal, PublicationFake fake) =>
        new(new InspectionService(new LocalPolicyStore(_workspace.PolicyFile), new LocalQueueAuditSink(_workspace.QueueFile),
                ExtractorRegistry.CreateDefault(), new VerdictCache()), NotificationTestHub.Create(), journal, Stages, new NoLegacy())
        { BoundPublication = Dispatcher(journal, fake, ready: false) };

    [Theory]
    [InlineData("retained")]
    [InlineData("ack-armed")]
    [InlineData("retired")]
    public async Task Restart_at_retained_ack_persistence_and_receipt_removal_preserves_native_counts(string boundary)
    {
        var f = await Allocate(); var fake = new PublicationFake(f.Binding, f.Entry) { FailCreate = boundary == "retained" };
        bool injected = false;
        void Fail()
        {
            if (injected) return;
            injected = true; fake.Crashed = true; throw new Crash();
        }
        var journal = new StagedTransferJournal(JournalPath, false, 128, (point, entry) =>
        {
            if (boundary == "retained" && point == StagedJournalWritePoint.AfterReplacement &&
                entry.State == TransferJournalState.Retained) Fail();
        })
        {
            DestinationHeadWritten = head =>
            {
                if (boundary == "ack-armed" && (head.PublicationNativeReceipts ?? []).Any(r => r.AcknowledgedRevision is not null)) Fail();
                if (boundary == "retired" && head.PublicationAttempts is { Length: 0 }) Fail();
            }
        };
        var entry = await Publishing(journal, f.Entry);
        if (boundary == "retired")
        {
            await Publish(journal, fake, entry);
            await Assert.ThrowsAsync<Crash>(() => Dispatcher(journal, fake).ReconcileAsync(entry, default));
        }
        else await Assert.ThrowsAsync<Crash>(() => Publish(journal, fake, entry));
        Assert.True(injected);
        var mutations = (fake.Creates, fake.Renames, fake.Deletes);
        fake.Restart();
        await RecoveryPublisher(Journal(), fake).RecoverBoundReceiptsAsync(default);
        await RecoveryPublisher(Journal(), fake).RecoverBoundReceiptsAsync(default);
        Assert.Equal(mutations, (fake.Creates, fake.Renames, fake.Deletes));
        Assert.Empty((await Journal().ReadDestinationHeadAsync(f.Binding.Destination, default))!.PublicationAttempts!);
        Assert.Equal(boundary == "retained" ? TransferJournalState.Retained : TransferJournalState.Released,
            (await Journal().ReadAsync(entry.Transfer.TransferId, default)).State);
    }

    [Theory]
    [InlineData("released")]
    [InlineData("failed-create")]
    [InlineData("failed-rename")]
    public async Task Startup_and_worker_find_receipts_after_publishing_state_and_lost_ack(string shape)
    {
        var f = await Allocate(); var journal = Journal(); var entry = await Publishing(journal, f.Entry);
        var fake = new PublicationFake(f.Binding, f.Entry)
            { FailCreate = shape == "failed-create", FailRename = shape == "failed-rename" };
        fake.At = point => { if (point == "ack") throw new IOException("lost ACK reply"); };
        await Publish(journal, fake, entry);
        Assert.Equal(shape == "released" ? TransferJournalState.Released : TransferJournalState.Retained,
            (await Journal().ReadAsync(entry.Transfer.TransferId, default)).State);
        var receipt = Assert.Single((await Journal().ReadDestinationHeadAsync(f.Binding.Destination, default))!.PublicationNativeReceipts!);
        Assert.NotNull(receipt.AcknowledgedRevision);
        var before = (fake.Creates, fake.Renames, fake.Deletes, fake.Acks);
        fake.Restart();
        await RecoveryPublisher(Journal(), fake).RecoverBoundReceiptsAsync(default);
        Assert.Empty((await Journal().ReadDestinationHeadAsync(f.Binding.Destination, default))!.PublicationAttempts!);
        Assert.Equal(before, (fake.Creates, fake.Renames, fake.Deletes, fake.Acks));
        await RecoveryPublisher(Journal(), fake).RecoverBoundReceiptsAsync(default);
        Assert.Equal(before, (fake.Creates, fake.Renames, fake.Deletes, fake.Acks));
    }

    [Fact]
    public async Task Durable_published_head_finishes_released_after_driver_loss_without_retiring_unproved_cleanup()
    {
        var f = await Allocate(); var fake = new PublicationFake(f.Binding, f.Entry);
        var journal = ObservedJournal(fake); var entry = await Publishing(journal, f.Entry);
        fake.At = point => { if (point == "published") { fake.Crashed = true; throw new Crash(); } };
        await Assert.ThrowsAsync<Crash>(() => Publish(journal, fake, entry));
        fake.Restart();
        fake.ReplayOverride = new(Guid.NewGuid(), 1, 1, 43, []);
        await RecoveryPublisher(Journal(), fake).RecoverBoundReceiptsAsync(default);
        Assert.Equal(TransferJournalState.Released, (await Journal().ReadAsync(entry.Transfer.TransferId, default)).State);
        var head = (await Journal().ReadDestinationHeadAsync(f.Binding.Destination, default))!;
        Assert.Single(head.PublicationNativeReceipts!); Assert.Single(head.PublicationAttempts!);
        Assert.Equal(entry.DestinationGeneration, head.LatestPublished);
        Assert.Equal(1, fake.Creates); Assert.Equal(1, fake.Renames); Assert.Equal(0, fake.Deletes); Assert.Equal(0, fake.Acks);
    }

    [Fact]
    public async Task Recovery_rechecks_authenticated_facts_after_anchored_observation()
    {
        var f = await Allocate(); var fake = new PublicationFake(f.Binding, f.Entry);
        var journal = Journal(); var entry = await Publishing(journal, f.Entry);
        fake.At = point => { if (point == "rename-native") { fake.Crashed = true; throw new Crash(); } };
        await Assert.ThrowsAsync<Crash>(() => Publish(journal, fake, entry));
        fake.Restart(); fake.At = point => { if (point == "observe") fake.Revision++; };
        var result = await Dispatcher(Journal(), fake).ReconcileAsync(entry, default);
        Assert.False(result.Released); Assert.Equal("publication_replay_changed", result.Diagnostic);
        Assert.NotNull((await Journal().ReadDestinationHeadAsync(f.Binding.Destination, default))!.PendingCommit);
        Assert.Equal(1, fake.Renames); Assert.Equal(0, fake.Acks);
        fake.At = null;
        Assert.True((await Dispatcher(Journal(), fake).ReconcileAsync(entry, default)).Released);
        Assert.Equal(1, fake.Renames);
    }

    [Fact]
    public async Task Retired_publication_facts_cannot_resurrect_an_attempt_or_mutation()
    {
        var f = await Allocate(); var fake = new PublicationFake(f.Binding, f.Entry); var journal = Journal();
        var entry = await Publishing(journal, f.Entry); await Publish(journal, fake, entry);
        var receipt = Assert.Single((await Journal().ReadDestinationHeadAsync(f.Binding.Destination, default))!.PublicationNativeReceipts!);
        var row = BoundPublicationV26.DecodeFactRow(Convert.FromBase64String(receipt.FactsBase64), receipt.DriverInstanceId,
            receipt.ConnectionEpoch, receipt.OsBootSequence);
        var replay = new BoundPublicationReplay(receipt.DriverInstanceId, receipt.ConnectionEpoch, receipt.Revision,
            receipt.OsBootSequence, [row]);
        await Dispatcher(Journal(), fake).ReconcileAsync(entry, default);
        using var turn = await journal.EnterDestinationCommitTurnAsync(f.Binding.Destination,
            StagedDestinationTurnPurpose.Reconciliation, default);
        await Assert.ThrowsAsync<IOException>(() => journal.RecordBoundPublicationNativeResultAsync(turn, replay, row));
        Assert.Empty((await Journal().ReadDestinationHeadAsync(f.Binding.Destination, default))!.PublicationAttempts!);
        Assert.Equal(1, fake.Renames); Assert.Equal(1, fake.Creates);
    }

    [Fact]
    public async Task Outstanding_ordinary_open_receipt_pins_its_original_manifest_and_security_after_publication_retirement()
    {
        var f = await Allocate(); var fake = new PublicationFake(f.Binding, f.Entry); var journal = Journal();
        var entry = await Publishing(journal, f.Entry); await Publish(journal, fake, entry);
        await Dispatcher(journal, fake).ReconcileAsync(entry, default); // retire the V26 receipt first
        _ = await Allocate(); // old manifest no longer owns the max-generation claim
        var head = (await journal.ReadDestinationHeadAsync(f.Binding.Destination, default))!;
        var binding = new StagedPublicDeleteBinding(Guid.NewGuid(), Guid.NewGuid(), _driver, 11, fake.Identity,
            entry.Transfer.ProcessId, entry.Transfer.RequestorProcessCreationTime!.Value,
            entry.Transfer.SessionId!.Value, entry.Transfer.RequestorSid!, 42, f.Binding.MountManagerVolumeId);
        var original = new StagedPublicRelayIntent(entry.Transfer.TransferId, Guid.NewGuid(), Guid.NewGuid(),
            1, head.LatestPublished, head.PublishedIdentity, 13, 1, 1, 0x10000, entry.Transfer.ProcessId);
        using (var turn = await journal.EnterDestinationCommitTurnAsync(f.Binding.Destination,
            StagedDestinationTurnPurpose.Reconciliation, default))
            await journal.BeginPublicRelayAsync(turn, binding, Guid.NewGuid(), original,
                new(f.Binding.Destination, f.Binding.Parent, f.Binding.Parent, true, fake.Identity), default);
        File.Delete(entry.Transfer.StagePath); // independent fake released-stage disposal
        await Journal().CompactAsync(DateTimeOffset.UtcNow.AddDays(1), default);
        Assert.Equal(TransferJournalState.Released, (await Journal().ReadAsync(entry.Transfer.TransferId, default)).State);
        Assert.NotNull(await Journal().ReadBoundAllocationSecurityAsync(entry.Transfer.TransferId, default));
        Assert.Single((await Journal().ReadDestinationHeadAsync(f.Binding.Destination, default))!.PublicRelayReceipts!);
    }
}
#endif
