using SafeUpload.Agent.Service.Interception;

namespace SafeUpload.Agent.Tests;

public sealed partial class StagedAttachmentV20Tests
{
    private async Task<Fixture> UnboundSealedAsync(bool empty = false)
    {
        var f = await CreateFixtureAsync(empty);
        await CompleteAttachmentAsync(f, 17001);
        await ObserveAndSealAsync(f, 17004);
        return f;
    }

    private static Task<(bool RequiresPublicDelete, long Generation)> CancelUnboundAsync(Fixture f, Guid operation) =>
        f.Journal.CancelUnboundPrivateAsync(operation, f.Version, f.DriverInstanceId,
            f.Transfer.ProcessId, ProcessCreationTime, default);

    private static async Task<TransferJournalEntry> UnboundIntentAsync(Fixture f)
    {
        await f.Journal.TransitionAsync(f.Transfer.TransferId, TransferJournalState.Sealed,
            TransferJournalState.Inspecting, null, default);
        await f.Journal.TransitionAsync(f.Transfer.TransferId, TransferJournalState.Inspecting,
            TransferJournalState.Approved, Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(
                await File.ReadAllBytesAsync(f.Transfer.StagePath))), default);
        return await f.Journal.TransitionAsync(f.Transfer.TransferId, TransferJournalState.Approved,
            TransferJournalState.Publishing, null, default);
    }

    [Theory]
    [InlineData(false, false)]
    [InlineData(false, true)]
    [InlineData(true, false)]
    [InlineData(true, true)]
    public async Task Unbound_cancellation_replays_after_restart_and_fences_a_prepared_final_rename(bool empty, bool publishing)
    {
        var f = await UnboundSealedAsync(empty);
        var intent = publishing ? await UnboundIntentAsync(f) : null;
        Guid operation = Guid.NewGuid();
        var cancelled = await CancelUnboundAsync(f, operation);
        Assert.False(cancelled.RequiresPublicDelete);
        Assert.True(cancelled.Generation > f.Version.DestinationGeneration);
        var restarted = new StagedTransferJournal(f.JournalDirectory);
        Assert.Equal(cancelled, await restarted.CancelUnboundPrivateAsync(operation, f.Version, f.DriverInstanceId,
            f.Transfer.ProcessId, ProcessCreationTime, default));
        Assert.NotNull((await restarted.ReadAsync(f.Transfer.TransferId, default)).UnboundCancellation);
        bool renamed = false;
        if (intent is not null)
            await Assert.ThrowsAsync<IOException>(() => f.Journal.CommitUnboundPublicationAsync(intent,
                () => renamed = true, default));
        Assert.False(renamed);
        await Assert.ThrowsAsync<IOException>(() => restarted.TransitionAsync(f.Transfer.TransferId,
            TransferJournalState.Retained, TransferJournalState.Inspecting, null, default));
        Assert.True(File.Exists(f.Transfer.StagePath)); // cancellation is not a cleanup receipt
        Assert.False(File.Exists(f.Transfer.DestinationPath));
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task Unbound_publisher_final_rename_rechecks_cancellation_or_private_retarget(bool retarget)
    {
        var f = await CreateFixtureAsync(false, kind: SafeUpload.Agent.Core.Domain.DestinationKind.RemovableDrive);
        await CompleteAttachmentAsync(f, 17301);
        await ObserveAndSealAsync(f, 17304);
        string destination = Path.Combine(Path.GetDirectoryName(f.Transfer.DestinationPath)!, "retargeted.txt");
        TransferJournalEntry? moved = null;
        var gate = new NamespacePublicationGate(() => {
            if (!retarget) { CancelUnboundAsync(f, Guid.NewGuid()).GetAwaiter().GetResult(); return; }
            var request = RenameRequest(f, 17310, destination) with { SealedVersion = true };
            f.Journal.PrepareRenameAsync(f.Transfer.TransferId, request.TransactionId, f.Transfer.ProcessId,
                destination, true, default, request).GetAwaiter().GetResult();
            moved = f.Journal.CompleteRenameAsync(f.Transfer.TransferId, request.TransactionId, f.Transfer.ProcessId,
                destination, true, default, request).GetAwaiter().GetResult();
        });
        var inspector = new SafeUpload.Agent.Core.Application.InspectionService(
            new SafeUpload.Agent.Core.Infrastructure.LocalPolicyStore(_workspace.PolicyFile),
            new SafeUpload.Agent.Core.Infrastructure.LocalQueueAuditSink(_workspace.QueueFile),
            SafeUpload.Agent.Core.Infrastructure.Extraction.ExtractorRegistry.CreateDefault(),
            new SafeUpload.Agent.Core.Application.VerdictCache());
        var publisher = new StagedTransferPublisher(inspector,
            SafeUpload.Agent.Tests.NotificationTestHub.Create(), f.Journal,
            Path.GetDirectoryName(f.Transfer.StagePath)!, gate, sessionUserSidResolver: _ => RequestorSid);
        var failure = await Record.ExceptionAsync(() => publisher.PublishAsync(f.Transfer, default));
        Assert.NotNull(failure);
        Assert.True(failure is IOException or InvalidOperationException, failure.ToString());
        Assert.False(File.Exists(f.Transfer.DestinationPath));
        Assert.False(File.Exists(destination));
        var current = await f.Journal.ReadAsync(f.Transfer.TransferId, default);
        Assert.NotEqual(TransferJournalState.Released, current.State);
        if (!retarget) Assert.NotNull(current.UnboundCancellation);
        else
        {
            Assert.NotNull(moved);
            var adopted = f with { Transfer = moved.Transfer,
                Version = f.Version with { DestinationGeneration = moved.DestinationGeneration } };
            // A successful publication may dispose the stage before returning.
            string expected = await File.ReadAllTextAsync(f.Transfer.StagePath);
            Assert.Equal(StagedTransferOutcome.Released, await PublishAsync(adopted));
            Assert.Equal(expected, await File.ReadAllTextAsync(destination));
            Assert.False(File.Exists(f.Transfer.DestinationPath));
        }
    }

    private sealed class NamespacePublicationGate(Action before) : IStagedPublicationGate, IDisposable
    {
        public IDisposable Authorize(StagedTransfer transfer, string temporaryDestination, string digest) { before(); return this; }
        public bool DisposeStage(Guid transferId, uint outcome, uint committedRenames) => false;
        public void Dispose() { }
    }

    [Fact]
    public async Task Unbound_cancelled_cleanup_records_absence_and_stops_pending_dispatch()
    {
        var f = await UnboundSealedAsync();
        await CancelUnboundAsync(f, Guid.NewGuid());
        var entry = await f.Journal.ReadAsync(f.Transfer.TransferId, default);
        Assert.True(StagedTransferJournal.PendingDispatchRequired(entry));
        await Assert.ThrowsAsync<IOException>(() => f.Journal.CompleteUnboundCancellationCleanupAsync(entry, default));
        Assert.True(StagedDiscardCleanup.TryDeleteExactAndConfirmAbsent(f.Transfer.StagePath, entry.StageIdentity, out _));
        await f.Journal.CompleteUnboundCancellationCleanupAsync(entry, default);
        var restarted = new StagedTransferJournal(f.JournalDirectory);
        var cleaned = await restarted.ReadAsync(f.Transfer.TransferId, default);
        Assert.True(cleaned.StageDeleted);
        Assert.NotNull(cleaned.UnboundCancellation);
        Assert.False(StagedTransferJournal.PendingDispatchRequired(cleaned));
        Assert.False(File.Exists(f.Transfer.DestinationPath));
    }

    [Theory]
    [InlineData(TransferJournalState.Inspecting)]
    [InlineData(TransferJournalState.Approved)]
    [InlineData(TransferJournalState.Retained)]
    public async Task Unbound_cancellation_is_terminal_during_inspection_approval_and_retention(TransferJournalState state)
    {
        var f = await UnboundSealedAsync();
        var next = state == TransferJournalState.Retained ? state : TransferJournalState.Inspecting;
        await f.Journal.TransitionAsync(f.Transfer.TransferId, TransferJournalState.Sealed, next, null, default);
        if (state == TransferJournalState.Approved)
            await f.Journal.TransitionAsync(f.Transfer.TransferId, TransferJournalState.Inspecting,
                state, new string('A', 64), default);
        await CancelUnboundAsync(f, Guid.NewGuid());
        var entry = await f.Journal.ReadAsync(f.Transfer.TransferId, default);
        Assert.NotNull(entry.UnboundCancellation);
        Assert.Equal(TransferJournalState.Retained, entry.State);
        await Assert.ThrowsAsync<IOException>(() => f.Journal.TransitionAsync(f.Transfer.TransferId,
            TransferJournalState.Retained, TransferJournalState.Inspecting, null, default));
    }

    [Fact]
    public async Task Unbound_cancellation_rejects_changed_exact_tuple_and_operation_replay()
    {
        var f = await UnboundSealedAsync();
        var journal = f.Journal;
        Guid operation = Guid.NewGuid();
        await Assert.ThrowsAsync<IOException>(() => journal.CancelUnboundPrivateAsync(operation,
            f.Version with { DestinationGeneration = f.Version.DestinationGeneration + 1 }, f.DriverInstanceId,
            f.Transfer.ProcessId, ProcessCreationTime, default));
        await Assert.ThrowsAsync<IOException>(() => journal.CancelUnboundPrivateAsync(operation,
            f.Version, Guid.NewGuid(), f.Transfer.ProcessId, ProcessCreationTime, default));
        await Assert.ThrowsAsync<IOException>(() => journal.CancelUnboundPrivateAsync(operation,
            f.Version, f.DriverInstanceId, f.Transfer.ProcessId, ProcessCreationTime + 1, default));
        await Assert.ThrowsAsync<IOException>(() => journal.CancelUnboundPrivateAsync(operation,
            f.Version with { StageIdentity = f.Version.StageIdentity! with { FileIdLow = f.Version.StageIdentity!.FileIdLow ^ 1 } },
            f.DriverInstanceId, f.Transfer.ProcessId, ProcessCreationTime, default));
        await Assert.ThrowsAsync<IOException>(() => journal.CancelUnboundPrivateAsync(operation,
            f.Version, f.DriverInstanceId, f.Transfer.ProcessId + 1, ProcessCreationTime, default));
        await CancelUnboundAsync(f, operation);
        await Assert.ThrowsAsync<IOException>(() => CancelUnboundAsync(f, Guid.NewGuid()));
    }

    [Fact]
    public async Task Unbound_successful_final_rename_wins_cancellation_and_cannot_be_repeated()
    {
        var f = await UnboundSealedAsync();
        var intent = await UnboundIntentAsync(f);
        int mutations = 0;
        await f.Journal.CommitUnboundPublicationAsync(intent, () => mutations++, default);
        Assert.True((await CancelUnboundAsync(f, Guid.NewGuid())).RequiresPublicDelete);
        await Assert.ThrowsAsync<IOException>(() => f.Journal.CommitUnboundPublicationAsync(intent,
            () => mutations++, default));
        Assert.Equal(1, mutations);
        var restarted = new StagedTransferJournal(f.JournalDirectory);
        await Assert.ThrowsAsync<IOException>(() => restarted.CancelUnboundPrivateAsync(Guid.NewGuid(), f.Version,
            f.DriverInstanceId, f.Transfer.ProcessId, ProcessCreationTime, default));
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task Unbound_retarget_after_a_publication_receipt_requires_a_durable_release(bool afterReplacement)
    {
        var f = await UnboundSealedAsync();
        bool injected = false;
        // Interrupt bookkeeping at its durability boundary without invoking
        // Windows-only I/O-failure diagnostics on developer hosts.
        var interruption = new InvalidOperationException("Injected release acknowledgement failure.");
        var journal = new StagedTransferJournal(f.JournalDirectory, false, 100, (point, entry) =>
        {
            if (!injected && entry.State == TransferJournalState.Released &&
                point == (afterReplacement ? StagedJournalWritePoint.AfterReplacement : StagedJournalWritePoint.BeforeReplacement))
            {
                injected = true;
                throw interruption;
            }
        });
        f = f with { Journal = journal };
        var intent = await UnboundIntentAsync(f);
        int mutations = 0;
        await journal.CommitUnboundPublicationAsync(intent, () => mutations++, default);
        Assert.Same(interruption, await Assert.ThrowsAsync<InvalidOperationException>(() =>
            journal.CompleteConfirmedPublicationAsync(intent, default)));
        string destination = Path.Combine(Path.GetDirectoryName(f.Transfer.DestinationPath)!, "after-release.txt");
        var request = RenameRequest(f, 17410, destination) with { SealedVersion = true };
        if (!afterReplacement)
        {
            Assert.Equal(TransferJournalState.Publishing, (await journal.ReadAsync(f.Transfer.TransferId, default)).State);
            await Assert.ThrowsAsync<IOException>(() => journal.PrepareRenameAsync(f.Transfer.TransferId,
                request.TransactionId, f.Transfer.ProcessId, destination, true, default, request));
            await journal.CompleteConfirmedPublicationAsync(intent, default);
        }
        Assert.Equal(TransferJournalState.Released, (await journal.ReadAsync(f.Transfer.TransferId, default)).State);
        await Assert.ThrowsAsync<IOException>(() => journal.CommitUnboundPublicationAsync(intent,
            () => mutations++, default));
        await journal.PrepareRenameAsync(f.Transfer.TransferId, request.TransactionId,
            f.Transfer.ProcessId, destination, true, default, request);
        var moved = await journal.CompleteRenameAsync(f.Transfer.TransferId, request.TransactionId,
            f.Transfer.ProcessId, destination, true, default, request);
        await Assert.ThrowsAsync<IOException>(() => journal.CompleteConfirmedPublicationAsync(intent, default));
        var current = await journal.ReadAsync(f.Transfer.TransferId, default);
        Assert.Equal(moved, current);
        Assert.Equal(TransferJournalState.Sealed, current.State);
        Assert.Null(current.Sha256Hex);
        Assert.True(File.Exists(f.Transfer.StagePath));
        Assert.False(File.Exists(destination));
        Assert.Equal(1, mutations);

        // The live commit marker belongs to the prior version, not this retarget.
        var adopted = f with { Transfer = moved.Transfer,
            Version = f.Version with { DestinationGeneration = moved.DestinationGeneration } };
        var nextIntent = await UnboundIntentAsync(adopted);
        await journal.CommitUnboundPublicationAsync(nextIntent, () => mutations++, default);
        Assert.Equal(2, mutations);
    }

    [Fact]
    public async Task Unbound_cancel_and_final_rename_serialize_without_a_check_use_gap()
    {
        var f = await UnboundSealedAsync();
        var intent = await UnboundIntentAsync(f);
        using var entered = new ManualResetEventSlim();
        using var release = new ManualResetEventSlim();
        Task commit = Task.Run(() => f.Journal.CommitUnboundPublicationAsync(intent, () =>
        {
            entered.Set();
            Assert.True(release.Wait(TimeSpan.FromSeconds(10)));
        }, default));
        Assert.True(entered.Wait(TimeSpan.FromSeconds(10)));
        Task<(bool RequiresPublicDelete, long Generation)> cancellation = CancelUnboundAsync(f, Guid.NewGuid());
        Assert.False(cancellation.IsCompleted);
        release.Set();
        await commit;
        Assert.True((await cancellation).RequiresPublicDelete);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task Unbound_private_retarget_invalidates_inflight_inspection_and_final_rename(bool publishing)
    {
        var f = await UnboundSealedAsync();
        TransferJournalEntry? oldIntent = null;
        if (publishing) oldIntent = await UnboundIntentAsync(f);
        else await f.Journal.TransitionAsync(f.Transfer.TransferId, TransferJournalState.Sealed,
            TransferJournalState.Inspecting, null, default);
        string destination = Path.Combine(Path.GetDirectoryName(f.Transfer.DestinationPath)!, "new-name.txt");
        var request = RenameRequest(f, 17010, destination) with { SealedVersion = true };
        await f.Journal.PrepareRenameAsync(f.Transfer.TransferId, request.TransactionId, f.Transfer.ProcessId,
            destination, true, default, request);
        if (oldIntent is not null)
            await Assert.ThrowsAsync<IOException>(() => f.Journal.CommitUnboundPublicationAsync(oldIntent,
                () => throw new Exception("stale rename executed"), default));
        var moved = await f.Journal.CompleteRenameAsync(f.Transfer.TransferId, request.TransactionId,
            f.Transfer.ProcessId, destination, true, default, request);
        Assert.Equal(destination, moved.Transfer.DestinationPath);
        Assert.Equal(TransferJournalState.Sealed, moved.State);
        Assert.Null(moved.Sha256Hex);
        await f.Journal.TransitionAsync(f.Transfer.TransferId, TransferJournalState.Sealed,
            TransferJournalState.Inspecting, null, default, moved.Transfer, expectedGeneration: moved.DestinationGeneration);
        await Assert.ThrowsAsync<InvalidOperationException>(() => f.Journal.TransitionAsync(f.Transfer.TransferId,
            TransferJournalState.Inspecting, TransferJournalState.Approved, new string('B', 64), default,
            f.Transfer, expectedGeneration: moved.DestinationGeneration));
        Assert.Equal(TransferJournalState.Inspecting, (await f.Journal.ReadAsync(f.Transfer.TransferId, default)).State);
        Assert.False(File.Exists(f.Transfer.DestinationPath));
    }

    [Fact]
    public async Task Unbound_word_swap_placeholder_cannot_win_after_temp_retarget()
    {
        var placeholder = await UnboundSealedAsync(empty: true);
        var placeholderIntent = await UnboundIntentAsync(placeholder);
        var temp = await CreateFixtureAsync(false, placeholder, "~WRD0001.tmp", "inspected Word replacement");
        await CompleteAttachmentAsync(temp, 17100);
        await ObserveAndSealAsync(temp, 17104);
        await CancelUnboundAsync(placeholder, Guid.NewGuid()); // kernel's sealed replacement-target cancellation
        var request = RenameRequest(temp, 17110, placeholder.Transfer.DestinationPath) with { SealedVersion = true };
        await temp.Journal.PrepareRenameAsync(temp.Transfer.TransferId, request.TransactionId,
            temp.Transfer.ProcessId, request.DestinationPath, true, default, request);
        await Assert.ThrowsAsync<IOException>(() => placeholder.Journal.CommitUnboundPublicationAsync(placeholderIntent,
            () => throw new Exception("placeholder committed"), default));
        var moved = await temp.Journal.CompleteRenameAsync(temp.Transfer.TransferId, request.TransactionId,
            temp.Transfer.ProcessId, request.DestinationPath, true, default, request);
        var adopted = temp with { Transfer = moved.Transfer, Version = temp.Version with {
            DestinationGeneration = moved.DestinationGeneration } };
        var intent = await UnboundIntentAsync(adopted);
        await temp.Journal.CommitUnboundPublicationAsync(intent,
            () => File.WriteAllText(intent.Transfer.DestinationPath, "inspected Word replacement"), default);
        Assert.Equal("inspected Word replacement", await File.ReadAllTextAsync(placeholder.Transfer.DestinationPath));
        Assert.False(File.Exists(temp.Transfer.DestinationPath));
    }
}

#if SAFEUPLOAD_ADMISSION_EVIDENCE
public sealed partial class StagedAttachmentV20Tests
{
    [Fact]
    public async Task Unbound_v28_dispatch_uses_the_exact_manifest_without_bound_readiness_or_observation()
    {
        var f = await UnboundSealedAsync();
        var request = new SafeUpload.Agent.Minifilter.PrivateCancellationRequestV28 {
            Version = 28, StructSize = 104, OperationId = Guid.NewGuid(), TransferId = f.Transfer.TransferId,
            DriverInstanceId = f.DriverInstanceId, Generation = checked((ulong)f.Version.DestinationGeneration),
            OwnerProcessId = checked((uint)f.Transfer.ProcessId), OwnerCreationTime = ProcessCreationTime,
            StageIdentity = new SafeUpload.Agent.Minifilter.SafeUploadStageIdentityV19 {
                VolumeSerialNumber = f.Version.StageIdentity!.VolumeSerialNumber,
                FileIdHigh = f.Version.StageIdentity.FileIdHigh, FileIdLow = f.Version.StageIdentity.FileIdLow }
        };
        var outer = new SafeUpload.Agent.Minifilter.SafeUploadRequest {
            Version = SafeUpload.Agent.Minifilter.Contract.Version, StructSize = SafeUpload.Agent.Minifilter.Contract.RequestSize,
            RequestId = 17200, Operation = 22, Reserved = 28, Flags = SafeUpload.Agent.Minifilter.Contract.StageV19ReplyFlag,
            RequestorProcessId = request.OwnerProcessId, ImageNameLength = 104
        };
        WriteCancellation(ref outer, request);
        Assert.True(outer.TryReadPrivateCancellationV28(out var decoded));
        var dispatcher = new StagedPrivateCancellationDispatcher(f.Journal,
            (_, _) => throw new Exception("Unbound cancellation attempted a bound observer"), () => true);
        var reply = await dispatcher.ProcessAsync(decoded, f.DriverInstanceId, default);
        Assert.Equal(SafeUpload.Agent.Minifilter.PrivateCancellationV28.Canceled, reply.Result);
        Assert.True(SafeUpload.Agent.Minifilter.PrivateCancellationV28.Valid(reply));
        Assert.Equal(decoded.TransferId, reply.Request.TransferId);
        var restarted = new StagedTransferJournal(f.JournalDirectory);
        var replay = await new StagedPrivateCancellationDispatcher(restarted,
            (_, _) => throw new Exception("Unbound replay attempted a bound observer"), () => true)
            .ProcessAsync(decoded, f.DriverInstanceId, default);
        Assert.Equal(reply.CancellationGeneration, replay.CancellationGeneration);
        await Assert.ThrowsAsync<IOException>(() => new StagedPrivateCancellationDispatcher(restarted,
            (_, _) => throw new Exception("Not ready"), () => false).ProcessAsync(decoded, f.DriverInstanceId, default));
    }

    private static void WriteCancellation(ref SafeUpload.Agent.Minifilter.SafeUploadRequest outer,
        SafeUpload.Agent.Minifilter.PrivateCancellationRequestV28 request) =>
        System.Runtime.InteropServices.MemoryMarshal.Write(
            System.Runtime.InteropServices.MemoryMarshal.AsBytes(
                System.Runtime.InteropServices.MemoryMarshal.CreateSpan(ref outer, 1))[1064..], in request);
}
#endif
