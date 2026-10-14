#if SAFEUPLOAD_ADMISSION_EVIDENCE
using System.Runtime.InteropServices;
using SafeUpload.Agent.Minifilter;
using SafeUpload.Agent.Service.Interception;

namespace SafeUpload.Agent.Tests;

public sealed partial class StagedPublicationNativeJournalTests
{
    private static PrivateCancellationRequestV28 Cancellation(TransferJournalEntry entry) => new()
    {
        Version = 28, StructSize = 104, OperationId = Guid.NewGuid(), TransferId = entry.Transfer.TransferId,
        DriverInstanceId = entry.DriverInstanceId!.Value, Generation = checked((ulong)entry.DestinationGeneration),
        StageIdentity = Wire(entry.StageIdentity!), OwnerProcessId = checked((uint)entry.Transfer.ProcessId),
        OwnerCreationTime = entry.Transfer.RequestorProcessCreationTime!.Value
    };

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task Sealed_private_cancellation_survives_lost_reply_bars_old_version_and_allocates_no_public_delete(bool loseReply)
    {
        var fixture = await Allocate(approve: false);
        var request = Cancellation(fixture.Entry);
        var journal = new StagedTransferJournal(JournalPath)
        {
            DestinationHeadWritten = head =>
            {
                if (loseReply && head.PrivateCancellations?.Length > 0) throw new IOException("injected lost cancellation reply");
            }
        };
        static StagedDestinationNameObservation Absent(StagedAllocationBindingV23 b, CancellationToken _) =>
            new(b.Destination, b.Parent, b.Parent, true, null);
        var dispatcher = new StagedPrivateCancellationDispatcher(journal, Absent, () => true);
        if (loseReply) await Assert.ThrowsAsync<IOException>(() => dispatcher.ProcessAsync(request, _driver, default));
        else Assert.Equal(PrivateCancellationV28.Canceled, (await dispatcher.ProcessAsync(request, _driver, default)).Result);
        var restarted = Journal();
        dispatcher = new(restarted, Absent, () => true);
        var receipt = await dispatcher.ProcessAsync(request, _driver, default);
        var head = (await restarted.ReadDestinationHeadAsync(fixture.Binding.Destination, default))!;
        Assert.Equal(request.Generation + 1, receipt.CancellationGeneration);
        Assert.Equal(checked((long)receipt.CancellationGeneration), head.MaxAllocated);
        Assert.Single(head.PrivateCancellations!); Assert.Empty(head.Deletes);
        Assert.Equal(0, head.CommittedDelete); Assert.Null(head.PendingCommit);
        Assert.True(File.Exists(fixture.Entry.Transfer.StagePath)); // cancellation is not physical cleanup
        await Assert.ThrowsAsync<IOException>(() => restarted.TransitionAsync(request.TransferId,
            TransferJournalState.Sealed, TransferJournalState.Inspecting, StagedTransferJournal.EmptySha256Hex, default));
        using var turn = await restarted.EnterDestinationCommitTurnAsync(fixture.Binding.Destination,
            StagedDestinationTurnPurpose.Allocation, default);
        Assert.Equal(head.MaxAllocated + 1, await restarted.ReserveSaveGenerationAsync(turn, Guid.NewGuid(),
            fixture.Entry.Transfer.DestinationPath, 0, default));
    }

    [Fact]
    public async Task Sealed_cancellation_waiting_on_publication_requires_real_public_delete_if_publication_wins()
    {
        var fixture = await Allocate(); var request = Cancellation(fixture.Entry);
        var journal = Journal(); var row = Native(fixture.Binding, fixture.Entry, true);
        var turn = await journal.EnterDestinationCommitTurnAsync(fixture.Binding.Destination,
            StagedDestinationTurnPurpose.PhysicalCommit, default);
        StagedStageIdentity? observed = null;
        var dispatcher = new StagedPrivateCancellationDispatcher(journal,
            (b, _) => new(b.Destination, b.Parent, b.Parent, true, observed), () => true);
        Task<PrivateCancellationReplyV28> waiting;
        try
        {
            waiting = dispatcher.ProcessAsync(request, _driver, default);
            Assert.False(waiting.IsCompleted);
            await Begin(journal, turn, row);
            await journal.RecordBoundPublicationNativeResultAsync(turn, Replay(row), row);
            observed = new(row.Facts.TemporaryIdentity.VolumeSerialNumber, row.Facts.TemporaryIdentity.FileIdHigh,
                row.Facts.TemporaryIdentity.FileIdLow);
        }
        finally { turn.Dispose(); }
        var receipt = await waiting.WaitAsync(TimeSpan.FromSeconds(10));
        Assert.Equal(PrivateCancellationV28.RequiresPublicDelete, receipt.Result);
        Assert.Equal(0ul, receipt.CancellationGeneration);
        var head = (await Journal().ReadDestinationHeadAsync(fixture.Binding.Destination, default))!;
        Assert.Null(head.PrivateCancellations); Assert.Empty(head.Deletes);
        Assert.Equal(fixture.Entry.DestinationGeneration, head.LatestPublished);
    }

    [Theory]
    [InlineData("owner")]
    [InlineData("identity")]
    [InlineData("driver")]
    [InlineData("ready")]
    [InlineData("rename")]
    public async Task Private_cancellation_refuses_substitution_or_closed_readiness_before_any_generation(string change)
    {
        var fixture = await Allocate(false); var request = Cancellation(fixture.Entry);
        switch (change)
        {
            case "owner": request.OwnerCreationTime++; break;
            case "identity": request.StageIdentity.FileIdLow++; break;
            case "driver": request.DriverInstanceId = Guid.NewGuid(); break;
        }
        if (change == "rename")
        {
            string destination = Path.Combine(Parent, "other.txt");
            var exact = new StagedRenameRequestV20(911, new(request.TransferId,
                fixture.Entry.DestinationGeneration, fixture.Entry.StageIdentity!), _driver,
                fixture.Entry.ParentDirectoryIdentity!, 1, fixture.Entry.Transfer.ProcessId,
                destination, true, destination);
            await Journal().PrepareRenameAsync(request.TransferId, 911, fixture.Entry.Transfer.ProcessId,
                destination, true, default, exact);
        }
        var dispatcher = new StagedPrivateCancellationDispatcher(Journal(),
            (b, _) => new(b.Destination, b.Parent, b.Parent, true, null), () => change != "ready");
        await Assert.ThrowsAsync<IOException>(() => dispatcher.ProcessAsync(request, _driver, default));
        var head = (await Journal().ReadDestinationHeadAsync(fixture.Binding.Destination, default))!;
        Assert.Null(head.PrivateCancellations); Assert.Equal(fixture.Entry.DestinationGeneration, head.MaxAllocated);
    }

    [Fact]
    public void Private_cancellation_wire_is_exact_opaque_and_distinct_from_discard_and_public_delete()
    {
        PrivateCancellationV28.Verify();
        var payload = new PrivateCancellationRequestV28 { Version = 28, StructSize = 104,
            OperationId = Guid.NewGuid(), TransferId = Guid.NewGuid(), DriverInstanceId = _driver,
            StageIdentity = new() { VolumeSerialNumber = 1, FileIdLow = 2 }, Generation = 3,
            OwnerCreationTime = 4, OwnerProcessId = 1234 };
        SafeUploadRequest outer = new() { Version = Contract.Version, StructSize = Contract.RequestSize,
            RequestId = 1, Operation = 22, Reserved = 28, Flags = Contract.StageV19ReplyFlag,
            RequestorProcessId = 1234, ImageNameLength = 104 };
        var bytes = MemoryMarshal.AsBytes(MemoryMarshal.CreateSpan(ref outer, 1));
        MemoryMarshal.Write(bytes[1064..], in payload);
        Assert.True(outer.HasKnownFlags); Assert.True(outer.TryReadPrivateCancellationV28(out _));
        var opaque = outer;
        Assert.Throws<InvalidOperationException>(() => opaque.GetImageName());
        bytes[1064 + 104] = 1;
        Assert.False(outer.TryReadPrivateCancellationV28(out _));
    }
}
#else
using SafeUpload.Agent.Minifilter;

namespace SafeUpload.Agent.Tests;

public sealed class PrivateCancellationDisabledTests
{
    [Fact]
    public void Normal_build_rejects_private_cancellation_and_has_no_typed_sender()
    {
        var request = new SafeUploadRequest { Version = Contract.Version, StructSize = Contract.RequestSize,
            RequestId = 1, Operation = 22, Reserved = 28, Flags = Contract.StageV19ReplyFlag };
        Assert.False(request.HasKnownFlags);
        Assert.True(request.UsesStageBinaryPayload);
        Assert.Throws<InvalidOperationException>(() => request.GetImageName());
        Assert.Null(typeof(FilterPort).GetMethod("ReplyPrivateCancellationV28"));
    }
}
#endif
