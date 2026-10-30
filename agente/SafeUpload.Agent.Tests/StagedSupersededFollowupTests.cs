using SafeUpload.Agent.Service.Interception;

namespace SafeUpload.Agent.Tests;

public sealed partial class StagedAttachmentV20Tests
{
    // T8 Word drop 2 (owner, 2026-10-30; mvpWdiagG4): Word reopened a document for writing 19 ms after a save sealed it. The
    // follow-up seeded from that sealed version superseded it before inspection, so it stayed Retained for ever. Once the
    // follow-up is published, the superseded version is retired: never inspected or published, its stage disposed of.
    [Fact]
    public async Task Superseded_retained_version_is_retired_once_its_own_followup_is_published()
    {
        var parent = await UnboundSealedAsync();
        var child = await FollowupFixtureAsync(parent, "follow-up bytes");
        await Assert.ThrowsAsync<IOException>(() => parent.Journal.TransitionAsync(parent.Transfer.TransferId,
            TransferJournalState.Sealed, TransferJournalState.Inspecting, null, default));
        await parent.Journal.TransitionAsync(parent.Transfer.TransferId, TransferJournalState.Sealed,
            TransferJournalState.Retained, null, default);
        Assert.Null(await parent.Journal.RetireSupersededByFollowupAsync(parent.Transfer.TransferId, default));

        await CompleteAttachmentAsync(child, 17501);
        await ObserveAndSealAsync(child, 17504);
        Assert.Equal(StagedTransferOutcome.Released, await PublishAsync(child)); // its release records the predecessor
        Assert.Equal("follow-up bytes", await File.ReadAllTextAsync(child.Transfer.DestinationPath));

        var retired = await parent.Journal.ReadAsync(parent.Transfer.TransferId, default);
        Assert.Equal(child.Version, retired.SupersededByFollowup);
        Assert.Equal(TransferJournalState.Retained, retired.State);
        Assert.True(StagedTransferJournal.PendingDispatchRequired(retired));
        Assert.Equal(retired, await parent.Journal.RetireSupersededByFollowupAsync(parent.Transfer.TransferId, default));
        await Assert.ThrowsAsync<IOException>(() => parent.Journal.TransitionAsync(parent.Transfer.TransferId,
            TransferJournalState.Retained, TransferJournalState.Inspecting, null, default));
        await Assert.ThrowsAsync<IOException>(() => parent.Journal.CompleteSupersededStageDisposalAsync(retired, default));

        Assert.True(StagedDiscardCleanup.TryDeleteExactAndConfirmAbsent(parent.Transfer.StagePath, retired.StageIdentity, out _));
        await parent.Journal.CompleteSupersededStageDisposalAsync(retired, default);
        var restarted = new StagedTransferJournal(parent.JournalDirectory);
        var disposed = await restarted.ReadAsync(parent.Transfer.TransferId, default);
        Assert.True(disposed.StageDeleted);
        Assert.Equal(child.Version, disposed.SupersededByFollowup);
        Assert.False(StagedTransferJournal.PendingDispatchRequired(disposed));
        Assert.True(await restarted.ArchiveCompletedAsync(disposed, default));
        Assert.Equal("follow-up bytes", await File.ReadAllTextAsync(child.Transfer.DestinationPath));
    }

    // Only a Retained, never-public version qualifies, and only for its own published follow-up.
    [Fact]
    public async Task Superseded_retirement_needs_a_retained_predecessor_and_its_own_published_followup()
    {
        var parent = await UnboundSealedAsync();
        var child = await FollowupFixtureAsync(parent, "follow-up bytes");
        Assert.Null(await parent.Journal.RetireSupersededByFollowupAsync(parent.Transfer.TransferId, default)); // still Sealed
        await parent.Journal.TransitionAsync(parent.Transfer.TransferId, TransferJournalState.Sealed,
            TransferJournalState.Retained, null, default);
        await CompleteAttachmentAsync(child, 17601);
        await ObserveAndSealAsync(child, 17604);
        Assert.Null(await parent.Journal.RetireSupersededByFollowupAsync(parent.Transfer.TransferId, default)); // not published
        Assert.True(File.Exists(parent.Transfer.StagePath));
        Assert.Null((await parent.Journal.ReadAsync(parent.Transfer.TransferId, default)).SupersededByFollowup);
    }

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
}
