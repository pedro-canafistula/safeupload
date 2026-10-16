using SafeUpload.Agent.Service.Interception;

namespace SafeUpload.Agent.Tests;

public sealed partial class StagedAttachmentV20Tests
{
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task Lost_prepare_aborts_before_or_after_prepare_and_releases_only_after_exact_cleanup(bool prepared)
    {
        string destinationDirectory = Path.Combine(_workspace.Root, "destination");
        Directory.CreateDirectory(destinationDirectory);
        await File.WriteAllTextAsync(Path.Combine(destinationDirectory, "document.txt"), "original public bytes");
        Fixture f = await CreateFixtureAsync(false, content: "CPF: 529.982.247-25");
        if (prepared) Assert.Equal(6u, await ApplyAsync(f, 12, 12001));
        var abort = new StagedAttachmentRequestV20(14, 12002, f.Version, f.DriverInstanceId,
            f.ParentDirectoryIdentity, f.Transfer.DestinationPath, f.Transfer.ProcessId);
        Assert.Equal(8u, await f.Journal.ApplyAttachmentV20Async(abort,
            ownerIsLive: false, commitPolicyAllowed: false, default));

        // Model loss of the Abort reply and a service restart. Its durable
        // disposition fences late Prepare/Commit without live owner authority.
        f = f with { Journal = new StagedTransferJournal(f.JournalDirectory) };
        Assert.Equal(8u, await f.Journal.ApplyAttachmentV20Async(abort,
            ownerIsLive: false, commitPolicyAllowed: false, default));
        TransferJournalEntry pending = await f.Journal.ReadAsync(f.Transfer.TransferId, default);
        Assert.Equal(StagedAttachmentStateV20.Aborted, pending.AttachmentStateV20);
        Assert.Equal(TransferJournalState.DiscardPending, pending.State);
        Assert.Null(pending.DiscardAcknowledgedAtUtc);
        Assert.True(File.Exists(f.Transfer.StagePath));
        if (prepared) Assert.Equal(6u, await ApplyAsync(f, 12, 12001)); // read-only historical receipt
        else await Assert.ThrowsAnyAsync<IOException>(() => ApplyAsync(f, 12, 12001));
        await Assert.ThrowsAnyAsync<IOException>(() => ApplyAsync(f, 12, 12003));
        await Assert.ThrowsAnyAsync<IOException>(() => ApplyAsync(f, 13, 12004));
        await Assert.ThrowsAnyAsync<IOException>(() => ApplyAsync(f, 15, 12005));

        StagedDiscardRequest cleanup = Assert.Single(await f.Journal.ReadDiscardPendingAsync(default));
        Assert.Equal(StagedDiscardKind.UnattachedAllocation, cleanup.Kind);
        Assert.Equal(f.Version, cleanup.Version);
        Assert.Equal(StagedDiscardStatus.Acknowledged, await f.Journal.CompleteDiscardAsync(cleanup, default));
        TransferJournalEntry terminal = await f.Journal.ReadAsync(f.Transfer.TransferId, default);
        Assert.NotNull(terminal.DiscardAcknowledgedAtUtc);
        Assert.False(terminal.StageDeleted); // kind-5 ACK is separate from publication disposal
        Assert.False(File.Exists(f.Transfer.StagePath));
        Assert.Equal(StagedDiscardStatus.Acknowledged, await f.Journal.CompleteDiscardAsync(cleanup, default));
        Assert.Equal(terminal, await f.Journal.ReadAsync(f.Transfer.TransferId, default));
        Assert.Equal(8u, await f.Journal.ApplyAttachmentV20Async(abort,
            ownerIsLive: false, commitPolicyAllowed: false, default));
        Assert.Equal("original public bytes", await File.ReadAllTextAsync(f.Transfer.DestinationPath));
        Fixture successor = await CreateFixtureAsync(false, f);
        Assert.True(successor.Version.DestinationGeneration > f.Version.DestinationGeneration);
        Assert.NotEqual(f.Transfer.TransferId, successor.Transfer.TransferId);
        await CompleteAttachmentAsync(successor, 12010);
    }

    [Theory]
    [InlineData(false, false)]
    [InlineData(false, true)]
    [InlineData(true, false)]
    [InlineData(true, true)]
    public async Task Lost_prepare_abort_persistence_failure_replays_exact_disposition(bool prepared, bool afterReplacement)
    {
        Fixture f = await CreateFixtureAsync(false);
        if (prepared) Assert.Equal(6u, await ApplyAsync(f, 12, 12101));
        bool injected = false;
        f = f with { Journal = new StagedTransferJournal(f.JournalDirectory, requireProtectedParent: false,
            scanCacheCapacity: 4, writeObserver: (point, entry) =>
            {
                if (injected || entry.AttachmentStateV20 != StagedAttachmentStateV20.Aborted ||
                    point != (afterReplacement ? StagedJournalWritePoint.AfterReplacement :
                        StagedJournalWritePoint.BeforeReplacement)) return;
                injected = true;
                throw new IOException("injected abort persistence failure");
            }) };
        await Assert.ThrowsAsync<StagedJournalPersistenceException>(() => ApplyAsync(f, 14, 12102));
        Assert.True(injected);
        Assert.True(File.Exists(f.Transfer.StagePath));
        Assert.False(File.Exists(f.Transfer.DestinationPath));
        f = f with { Journal = new StagedTransferJournal(f.JournalDirectory) };
        var durable = await f.Journal.ReadAsync(f.Transfer.TransferId, default);
        Assert.Equal(afterReplacement, durable.AttachmentStateV20 == StagedAttachmentStateV20.Aborted);
        Assert.Equal(8u, await ApplyAsync(f, 14, 12102));
        var cleanup = Assert.Single(await f.Journal.ReadDiscardPendingAsync(default));
        Assert.Equal(StagedDiscardStatus.Acknowledged, await f.Journal.CompleteDiscardAsync(cleanup, default));
        Assert.Equal(8u, await ApplyAsync(f, 14, 12102));
        Assert.False(File.Exists(f.Transfer.StagePath));
    }

    [Theory]
    [InlineData("generation")]
    [InlineData("identity")]
    [InlineData("epoch")]
    [InlineData("parent")]
    [InlineData("process")]
    [InlineData("path")]
    public async Task Lost_prepare_abort_rejects_changed_exact_allocation(string changed)
    {
        Fixture f = await CreateFixtureAsync(false);
        var request = new StagedAttachmentRequestV20(14, 12201, f.Version, f.DriverInstanceId,
            f.ParentDirectoryIdentity, f.Transfer.DestinationPath, f.Transfer.ProcessId);
        request = changed switch
        {
            "generation" => request with { Version = f.Version with { DestinationGeneration = f.Version.DestinationGeneration + 1 } },
            "identity" => request with { Version = f.Version with { StageIdentity = f.ParentDirectoryIdentity } },
            "epoch" => request with { DriverInstanceId = Guid.NewGuid() },
            "parent" => request with { ParentDirectoryIdentity = f.Version.StageIdentity },
            "process" => request with { RequestorProcessId = f.Transfer.ProcessId + 1 },
            _ => request with { DestinationPath = f.Transfer.DestinationPath + ".other" }
        };
        await Assert.ThrowsAnyAsync<IOException>(() => f.Journal.ApplyAttachmentV20Async(request,
            ownerIsLive: false, commitPolicyAllowed: false, default));
        Assert.Equal(TransferJournalState.Allocated, (await f.Journal.ReadAsync(f.Transfer.TransferId, default)).State);
        Assert.True(File.Exists(f.Transfer.StagePath));
        Assert.Empty(await f.Journal.ReadDiscardPendingAsync(default));
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task Lost_prepare_abort_cannot_discard_a_committed_or_permitted_version(bool permitted)
    {
        Fixture f = await CreateFixtureAsync(false);
        Assert.Equal(6u, await ApplyAsync(f, 12, 12301));
        Assert.Equal(7u, await ApplyAsync(f, 13, 12302));
        if (permitted) Assert.Equal(16u, await ApplyAsync(f, 15, 12303));
        TransferJournalEntry before = await f.Journal.ReadAsync(f.Transfer.TransferId, default);
        Assert.Equal(10u, await ApplyAsync(f, 14, 12304));
        Assert.Equal(before, await f.Journal.ReadAsync(f.Transfer.TransferId, default));
        Assert.True(File.Exists(f.Transfer.StagePath));
        Assert.Empty(await f.Journal.ReadDiscardPendingAsync(default));
    }
}
