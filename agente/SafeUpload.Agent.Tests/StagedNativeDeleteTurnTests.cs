#if SAFEUPLOAD_ADMISSION_EVIDENCE
using SafeUpload.Agent.Minifilter;
using SafeUpload.Agent.Service.Interception;

namespace SafeUpload.Agent.Tests;

public sealed partial class StagedNativeLifecycleDispatcherTests
{
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task Scheduled_create_queues_behind_publication_and_rechecks_the_original_link(bool published)
    {
        var destination = StagedNativeStartupRecovery.Destination(Row);
        var save = Guid.NewGuid(); long generation;
        using (var allocation = await _journal.EnterDestinationCommitTurnAsync(destination,
            StagedDestinationTurnPurpose.Allocation, default))
            generation = await _journal.ReserveSaveGenerationAsync(allocation, save,
                Path.Combine(_workspace.Root, "document.txt"), 0, default);
        var physical = await _journal.EnterDestinationCommitTurnAsync(destination,
            StagedDestinationTurnPurpose.PhysicalCommit, default);
        Task<NativeLifecycleReplyV24> waiting;
        try
        {
            waiting = Send(Request(NativeLifecycleV24.Prepare));
            Assert.False(waiting.IsCompleted);
            if (published)
            {
                var operation = Guid.NewGuid(); var identity = new StagedStageIdentity(7, 0, 99);
                await _journal.BeginDestinationPublicationAsync(physical, operation, save, generation,
                    new(7, 0, 3), identity, 0, StagedTransferJournal.EmptySha256Hex, default);
                await _journal.RecordDestinationPublicationResultAsync(physical, operation, save, identity, true);
                _child = Id(99);
            }
        }
        finally { physical.Dispose(); }
        if (published)
        {
            await Assert.ThrowsAsync<IOException>(() => waiting.WaitAsync(TimeSpan.FromSeconds(10)));
            Assert.Empty((await Head()).Deletes); // No stale CREATE was authorized or emulated.
            Assert.Equal(generation, (await Head()).LatestPublished);
        }
        else
        {
            var receipt = await waiting.WaitAsync(TimeSpan.FromSeconds(10));
            Assert.Equal(NativeLifecycleV24.Prepared, receipt.Result);
            Assert.Equal(checked((ulong)(generation + 1)), receipt.JournalGeneration);
            Assert.Null(Assert.Single((await Head()).Deletes).NativeCreateAccepted);
            Assert.False(StagedTransferJournal.HasAcceptedOwnerTombstone(await Head(), new(7, 0, 3),
                1234, Row.CallerProcessCreationTime));
        }
        Assert.Equal(1, _observations);
    }
}
#endif
