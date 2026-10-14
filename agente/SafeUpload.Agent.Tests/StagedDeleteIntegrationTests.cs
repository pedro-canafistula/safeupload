using SafeUpload.Agent.Service.Interception;

namespace SafeUpload.Agent.Tests;

public sealed partial class StagedDestinationCommitJournalTests
{
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task Owner_tombstone_requires_acceptance_and_survives_restart_with_exact_identity(bool scheduled)
    {
        var journal = Journal(); var destination = Destination();
        var binding = Binding() with { OsBootSequence = 42 }; var operation = Guid.NewGuid();
        if (scheduled) await NativeCreateIntent(journal, destination, binding, operation);
        else await Admit(journal, destination, binding);
        var head = (await Journal().ReadDestinationHeadAsync(destination, default))!;
        Assert.False(StagedTransferJournal.HasAcceptedOwnerTombstone(head, _publicIdentity, binding.OwnerProcessId,
            binding.OwnerProcessCreationTime));
        if (scheduled)
        {
            using var turn = await journal.EnterDestinationCommitTurnAsync(destination, StagedDestinationTurnPurpose.Reconciliation, default);
            // NTFS accepted, identity tracking was lost: preserve accepted/unresolved.
            await journal.RecordNativeDeleteOnCloseCreateResultAsync(turn, binding, operation, true, false);
        }
        else await Accept(journal, destination, binding, operation);
        head = (await Journal().ReadDestinationHeadAsync(destination, default))!;
        Assert.True(StagedTransferJournal.HasAcceptedOwnerTombstone(head, _publicIdentity, binding.OwnerProcessId,
            binding.OwnerProcessCreationTime));
        Assert.False(StagedTransferJournal.HasAcceptedOwnerTombstone(head, _temporaryIdentity, binding.OwnerProcessId,
            binding.OwnerProcessCreationTime));
        Assert.False(StagedTransferJournal.HasAcceptedOwnerTombstone(head, _publicIdentity, binding.OwnerProcessId,
            binding.OwnerProcessCreationTime + 1));
        var later = await Allocate(journal, destination, Guid.NewGuid());
        Assert.True(later > Assert.Single(head.Deletes).Generation);
        Assert.True(StagedTransferJournal.HasAcceptedOwnerTombstone((await Journal().ReadDestinationHeadAsync(destination, default))!,
            _publicIdentity, binding.OwnerProcessId, binding.OwnerProcessCreationTime));
    }

    [Fact]
    public async Task False_cancels_accepted_ordinary_only_leaving_later_unforwarded_true_and_scheduled_create()
    {
        var journal = Journal(); var destination = Destination(); var scheduled = Binding() with { OsBootSequence = 42 };
        var scheduledOperation = Guid.NewGuid();
        await NativeCreateIntent(journal, destination, scheduled, scheduledOperation);
        using (var turn = await journal.EnterDestinationCommitTurnAsync(destination, StagedDestinationTurnPurpose.Reconciliation, default))
            await journal.RecordNativeDeleteOnCloseCreateResultAsync(turn, scheduled, scheduledOperation, true, true);
        var accepted = Binding(20); var later = Binding(30);
        await Admit(journal, destination, accepted); await Admit(journal, destination, later);
        await Accept(journal, destination, accepted, Guid.NewGuid());
        using (var turn = await journal.EnterDestinationCommitTurnAsync(destination, StagedDestinationTurnPurpose.Reconciliation, default))
        {
            var clear = Guid.NewGuid();
            await journal.BeginPublicDeleteClearAsync(turn, clear, _publicIdentity, default);
            await journal.RecordPublicDeleteClearResultAsync(turn, clear, _publicIdentity, true);
        }
        var head = (await Journal().ReadDestinationHeadAsync(destination, default))!;
        Assert.Equal(StagedPublicDeleteState.Canceled, head.Deletes.Single(d => d.Binding == accepted).State);
        Assert.Equal(StagedPublicDeleteState.Admitted, head.Deletes.Single(d => d.Binding == later).State);
        Assert.Equal(StagedPublicDeleteState.Admitted, head.Deletes.Single(d => d.Binding == scheduled).State);
        Assert.Equal(0, head.CommittedDelete);
        await Accept(journal, destination, later, Guid.NewGuid());
        Assert.Equal(StagedPublicDeleteState.Accepted,
            (await Journal().ReadDestinationHeadAsync(destination, default))!.Deletes.Single(d => d.Binding == later).State);
    }
}
