using System.Text.Json;
using System.Text.Json.Nodes;
using SafeUpload.Agent.Core.Infrastructure;
using SafeUpload.Agent.Service.Interception;

namespace SafeUpload.Agent.Tests;

public sealed partial class StagedAttachmentV20Tests
{
    // T8 Word drop 2 (owner, 2026-10-30; mvpWdiagG4): Word reopened a document for writing 19 ms after a save sealed it. The
    // follow-up seeded from that sealed version superseded it before inspection, so it stayed Retained for ever. Once the
    // follow-up is published, the superseded version is retired: never inspected or published, its stage disposed of like a
    // released one (the driver deletes it at release, or the service deletes the exact stage), then archived.
    [Fact]
    public async Task Superseded_retained_version_is_retired_by_its_published_followup_and_disposed_by_recovery()
    {
        var parent = await UnboundSealedAsync();
        MonitorDestination(parent); // inspection and publication only for a monitored destination
        var child = await FollowupFixtureAsync(parent, "follow-up bytes");
        await Assert.ThrowsAsync<IOException>(() => parent.Journal.TransitionAsync(parent.Transfer.TransferId,
            TransferJournalState.Sealed, TransferJournalState.Inspecting, null, default));
        await parent.Journal.TransitionAsync(parent.Transfer.TransferId, TransferJournalState.Sealed,
            TransferJournalState.Retained, null, default);
        Assert.Null(await parent.Journal.RetireSupersededByFollowupAsync(parent.Transfer.TransferId,
            [child.Transfer.TransferId], default)); // unpublished

        await CompleteAttachmentAsync(child, 17501);
        await ObserveAndSealAsync(child, 17504);
        Assert.Equal(StagedTransferOutcome.Released, await PublishAsync(child)); // its release records the predecessor
        Assert.Equal("follow-up bytes", await File.ReadAllTextAsync(child.Transfer.DestinationPath));

        var retired = await parent.Journal.ReadAsync(parent.Transfer.TransferId, default);
        Assert.Equal(child.Version, retired.SupersededByFollowup);
        Assert.Equal(TransferJournalState.Retained, retired.State);
        Assert.True(StagedTransferJournal.PendingDispatchRequired(retired));
        Assert.Equal(retired, await parent.Journal.RetireSupersededByFollowupAsync(parent.Transfer.TransferId,
            [child.Transfer.TransferId], default));
        await Assert.ThrowsAsync<IOException>(() => parent.Journal.TransitionAsync(parent.Transfer.TransferId,
            TransferJournalState.Retained, TransferJournalState.Inspecting, null, default));
        await Assert.ThrowsAsync<IOException>(() => CancelUnboundAsync(parent, Guid.NewGuid()));
        await Assert.ThrowsAsync<IOException>(() => parent.Journal.CompleteSupersededStageDisposalAsync(retired, default));

        // The real recovery dispatcher: while the driver holds the version it deletes the stage itself at release.
        var gate = new SupersededStageGate(parent.Transfer.TransferId, held: true);
        long clock = 1;
        var recovery = RecoveryPublisher(parent, gate);
        recovery.RecoveryTimestamp = () => clock;
        await recovery.RecoverPendingTransferAsync(retired, default);
        Assert.Equal(1, gate.Disposals);
        Assert.True(File.Exists(parent.Transfer.StagePath));
        Assert.False((await parent.Journal.ReadAsync(parent.Transfer.TransferId, default)).StageDeleted);

        // Released by the driver without deleting (or never held): the service deletes the exact stage and archives.
        gate.Held = false;
        clock += 60 * System.Diagnostics.Stopwatch.Frequency;
        await recovery.RecoverPendingTransferAsync(retired, default);
        Assert.Equal(2, gate.Disposals);
        Assert.False(File.Exists(parent.Transfer.StagePath));
        Assert.DoesNotContain(await parent.Journal.ReadPendingAsync(default),
            entry => entry.Transfer.TransferId == parent.Transfer.TransferId);
        var restarted = new StagedTransferJournal(parent.JournalDirectory);
        var disposed = await restarted.ReadAsync(parent.Transfer.TransferId, default);
        Assert.True(disposed.StageDeleted);
        Assert.Equal(child.Version, disposed.SupersededByFollowup);
        Assert.False(StagedTransferJournal.PendingDispatchRequired(disposed));
        Assert.Equal("follow-up bytes", await File.ReadAllTextAsync(child.Transfer.DestinationPath));
    }

    // Review (f6509aac): a crash between the follow-up's release and the predecessor's retirement, and a newer archived save
    // that takes the destination's maximum claim, must not lose the obligation. Startup/live reconciliation finds the
    // follow-up by its parent link.
    [Fact]
    public async Task Superseded_reconciliation_after_restart_finds_a_followup_hidden_by_a_newer_archived_save()
    {
        var parent = await UnboundSealedAsync();
        MonitorDestination(parent); // inspection and publication only for a monitored destination
        var child = await FollowupFixtureAsync(parent, "follow-up bytes");
        await CompleteAttachmentAsync(child, 17601);
        await ObserveAndSealAsync(child, 17604);
        Assert.Equal(StagedTransferOutcome.Released, await PublishAsync(child)); // the predecessor is still Sealed: no-op
        await parent.Journal.TransitionAsync(parent.Transfer.TransferId, TransferJournalState.Sealed,
            TransferJournalState.Retained, null, default); // no trigger: models the lost retirement
        Assert.Null((await parent.Journal.ReadAsync(parent.Transfer.TransferId, default)).SupersededByFollowup);

        var newer = await CreateFixtureAsync(false, child, content: "a newer unrelated save");
        await CompleteAttachmentAsync(newer, 17611);
        await ObserveAndSealAsync(newer, 17614);
        Assert.Equal(StagedTransferOutcome.Released, await PublishAsync(newer));
        Assert.Equal("a newer unrelated save", await File.ReadAllTextAsync(parent.Transfer.DestinationPath));

        var restarted = new StagedTransferJournal(parent.JournalDirectory);
        var recovery = RecoveryPublisher(parent, new SupersededStageGate(parent.Transfer.TransferId, held: false), restarted);
        var retired = await recovery.ReconcileSupersededAsync(
            await restarted.ReadAsync(parent.Transfer.TransferId, default), await restarted.ReadPendingAsync(default), default);
        Assert.NotNull(retired);
        Assert.Equal(child.Version, retired.SupersededByFollowup);
        Assert.Equal("a newer unrelated save", await File.ReadAllTextAsync(parent.Transfer.DestinationPath));
    }

    // Only a Retained version with a complete history showing it was never public qualifies, and only for its own
    // published follow-up. A blocked follow-up or an empty legacy history leaves it Retained.
    [Theory]
    [InlineData("sealed-parent")]
    [InlineData("unpublished-child")]
    [InlineData("blocked-child")]
    [InlineData("empty-history")]
    public async Task Superseded_retirement_refuses_without_exact_evidence(string shape)
    {
        var parent = await UnboundSealedAsync();
        MonitorDestination(parent); // inspection and publication only for a monitored destination
        var child = await FollowupFixtureAsync(parent,
            shape == "blocked-child" ? "CPF: 529.982.247-25" : "follow-up bytes");
        if (shape is "unpublished-child" or "blocked-child")
            await parent.Journal.TransitionAsync(parent.Transfer.TransferId, TransferJournalState.Sealed,
                TransferJournalState.Retained, null, default);
        await CompleteAttachmentAsync(child, 17701);
        await ObserveAndSealAsync(child, 17704);
        var journal = parent.Journal;
        if (shape == "blocked-child") Assert.Equal(StagedTransferOutcome.Blocked, await PublishAsync(child));
        else if (shape is "sealed-parent" or "empty-history") Assert.Equal(StagedTransferOutcome.Released, await PublishAsync(child));
        if (shape == "empty-history")
        {
            await parent.Journal.TransitionAsync(parent.Transfer.TransferId, TransferJournalState.Sealed,
                TransferJournalState.Retained, null, default); // after the release, so no trigger ran
            string manifest = Path.Combine(parent.JournalDirectory, parent.Transfer.TransferId.ToString("N") + ".json");
            JsonObject json = JsonNode.Parse(await File.ReadAllTextAsync(manifest))!.AsObject();
            json["StateHistory"] = new JsonArray();
            await File.WriteAllTextAsync(manifest, json.ToJsonString());
            journal = new StagedTransferJournal(parent.JournalDirectory);
        }
        Assert.Null(await journal.RetireSupersededByFollowupAsync(parent.Transfer.TransferId,
            [child.Transfer.TransferId], default));
        Assert.True(File.Exists(parent.Transfer.StagePath));
        Assert.Null((await journal.ReadAsync(parent.Transfer.TransferId, default)).SupersededByFollowup);
    }

    private void MonitorDestination(Fixture f) =>
        _workspace.WritePolicy(JsonSerializer.Serialize(PolicyDocument.Default with
        {
            MonitoredScopes = MonitoredScopesDocument.Default with
            { DestinationPaths = [Path.GetDirectoryName(f.Transfer.DestinationPath)!] }
        }));

    private static async Task<Fixture> FollowupFixtureAsync(Fixture parent, string content)
    {
        Guid id = Guid.NewGuid();
        string stage = Path.Combine(Path.GetDirectoryName(parent.Transfer.StagePath)!, id.ToString("N") + ".txt");
        await File.WriteAllTextAsync(stage, content);
        var transfer = parent.Transfer with { TransferId = id, StagePath = stage };
        TransferJournalEntry entry = await parent.Journal.CreateAsync(transfer, CancellationToken.None,
            parentTransferId: parent.Transfer.TransferId, allocationDisposition: 1,
            allocationReferenceId: parent.Transfer.TransferId, allocationReferenceKind: 1,
            driverInstanceId: parent.DriverInstanceId, parentDirectoryIdentity: parent.ParentDirectoryIdentity);
        Assert.Equal(parent.Version, entry.ParentVersionIdentity);
        Assert.True(entry.DestinationGeneration > parent.Version.DestinationGeneration);
        return parent with { Transfer = transfer,
            Version = new StagedVersionIdentity(id, entry.DestinationGeneration, entry.StageIdentity!) };
    }

    private sealed class SupersededStageGate(Guid expectedId, bool held) : IStagedPublicationGate
    {
        internal int Disposals;
        internal bool Held = held;
        public IDisposable Authorize(StagedTransfer transfer, string temporaryDestination, string digest) =>
            throw new Xunit.Sdk.XunitException("A superseded version must never be published.");
        public bool DisposeStage(Guid transferId, uint outcome, uint committedRenames)
        {
            Disposals++;
            Assert.Equal(expectedId, transferId);
            Assert.Equal(SafeUpload.Agent.Minifilter.StageDisposeOutcome.Released, outcome);
            Assert.Equal(0u, committedRenames);
            return Held;
        }
    }
}
