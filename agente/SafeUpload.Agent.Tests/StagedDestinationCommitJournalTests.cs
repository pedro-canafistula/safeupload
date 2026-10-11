using System.Text.Json.Nodes;
using SafeUpload.Agent.Service.Interception;

namespace SafeUpload.Agent.Tests;

// These exercise the real on-disk journal and queue. Fake bindings/result inputs
// model the future checked kernel dispatcher; they do not qualify NTFS delete,
// caller authorization, physical byte privacy or an integrated product path.
public sealed class StagedDestinationCommitJournalTests : IDisposable
{
    private readonly TestWorkspace _workspace = new();
    private readonly Guid _driverInstance = Guid.NewGuid();
    private readonly StagedStageIdentity _publicIdentity = new(7, 91, 92);
    private readonly StagedStageIdentity _temporaryIdentity = new(7, 101, 102);
    private string JournalPath => Path.Combine(_workspace.Root, "journal");
    private string Locator(string name = "document.txt") => Path.Combine(_workspace.Root, "destination", name);
    private StagedTransferJournal Journal() => new(JournalPath);
    private static StagedDestinationIdentity Destination(string leaf = "document.txt", bool caseSensitive = false) =>
        new(new(7, 11, 12), new(7, 21, 22), caseSensitive, leaf);
    private StagedPublicDeleteBinding Binding(int owner = 1234) => new(Guid.NewGuid(), Guid.NewGuid(),
        _driverInstance, 17, _publicIdentity, owner, 123456, 1, "S-1-5-21-100-200-300-1001");

    public void Dispose() => _workspace.Dispose();

    private async Task<long> Allocate(StagedTransferJournal journal, StagedDestinationIdentity destination,
        Guid transferId, long priorManifestHead = 0)
    {
        using var turn = await journal.EnterDestinationCommitTurnAsync(destination,
            StagedDestinationTurnPurpose.Allocation, CancellationToken.None);
        return await journal.ReserveSaveGenerationAsync(turn, transferId,
            Locator(destination.CanonicalLeaf), priorManifestHead, CancellationToken.None);
    }

    private async Task<StagedPublicDeleteRecord> Admit(StagedTransferJournal journal,
        StagedDestinationIdentity destination, StagedPublicDeleteBinding binding)
    {
        using var turn = await journal.EnterDestinationCommitTurnAsync(destination,
            StagedDestinationTurnPurpose.Allocation, CancellationToken.None);
        return await journal.AdmitPublicDeleteAsync(turn, binding, Locator(destination.CanonicalLeaf), 0, CancellationToken.None);
    }

    private async Task Accept(StagedTransferJournal journal, StagedDestinationIdentity destination,
        StagedPublicDeleteBinding binding, Guid operationId)
    {
        using var turn = await journal.EnterDestinationCommitTurnAsync(destination,
            StagedDestinationTurnPurpose.Reconciliation, CancellationToken.None);
        Assert.Equal(StagedPublicDeleteState.Intent, (await journal.BeginPublicDeleteDispositionAsync(
            turn, binding, operationId, CancellationToken.None)).State);
        await journal.RecordPublicDeleteDispositionResultAsync(turn, binding, operationId, ntfsAccepted: true);
    }

    private async Task Publish(StagedTransferJournal journal, StagedDestinationIdentity destination,
        Guid transferId, long generation)
    {
        using var turn = await journal.EnterDestinationCommitTurnAsync(destination,
            StagedDestinationTurnPurpose.PhysicalCommit, CancellationToken.None);
        Guid operation = Guid.NewGuid();
        await journal.BeginDestinationPublicationAsync(turn, operation, transferId, generation, _publicIdentity,
            _temporaryIdentity, 0, StagedTransferJournal.EmptySha256Hex, CancellationToken.None);
        await journal.RecordDestinationPublicationResultAsync(turn, operation, transferId, _temporaryIdentity, renameCommitted: true);
    }

    [Fact]
    public void Destination_key_joins_case_insensitive_aliases_and_keeps_full_volume_parent_identity()
    {
        Assert.Equal(Destination(), Destination("DOCUMENT.TXT"));
        Assert.Equal(Destination().StorageKey, Destination("DOCUMENT.TXT").StorageKey);
        Assert.NotEqual(Destination("document.txt", true).StorageKey, Destination("DOCUMENT.TXT", true).StorageKey);
        Assert.NotEqual(Destination().StorageKey, new StagedDestinationIdentity(new(7, 11, 12),
            new(7, 121, 22), false, "document.txt").StorageKey);
        Assert.NotEqual(Destination().StorageKey, new StagedDestinationIdentity(new(7, 111, 12),
            new(7, 21, 22), false, "document.txt").StorageKey);
        Assert.NotEqual(Destination().StorageKey, new StagedDestinationIdentity(new(8, 11, 12),
            new(8, 21, 22), false, "document.txt").StorageKey);
        foreach (string leaf in new[] { "../document.txt", "document.txt:stream", "document.txt.", "document.txt ", "\ud800" })
            Assert.Throws<ArgumentException>(() => Destination(leaf));
        Assert.Throws<ArgumentException>(() => new StagedDestinationIdentity(new(7, 11, 12), new(8, 21, 22), false, "document.txt"));
    }

    [Fact]
    public async Task Allocated_successor_does_not_cancel_delete_and_publication_waits_for_exact_completion()
    {
        var journal = Journal(); var destination = Destination(); var old = Guid.NewGuid(); var successor = Guid.NewGuid();
        Assert.Equal(1, await Allocate(journal, destination, old));
        var binding = Binding();
        Assert.Equal(2, (await Admit(journal, destination, binding)).Generation);
        Assert.Equal(3, await Allocate(journal, destination, successor));
        await Accept(journal, destination, binding, Guid.NewGuid());
        Assert.Equal(0, (await journal.ReadDestinationHeadAsync(destination, CancellationToken.None))!.CommittedDelete);

        using var cancel = new CancellationTokenSource();
        Task<StagedTransferJournal.DestinationCommitTurn> waiting = journal.EnterDestinationCommitTurnAsync(destination,
            StagedDestinationTurnPurpose.PhysicalCommit, cancel.Token);
        using (var continuation = await journal.EnterDestinationCommitTurnAsync(destination,
            StagedDestinationTurnPurpose.Reconciliation, CancellationToken.None))
        {
            Assert.False(waiting.IsCompleted);
            await Assert.ThrowsAsync<IOException>(() => journal.CancelAdmittedPublicDeleteAsync(
                continuation, binding, CancellationToken.None));
            await journal.RecordPublicDeletePhysicalCompleteAsync(continuation, binding, CancellationToken.None);
        }
        using (await waiting.WaitAsync(TimeSpan.FromSeconds(10))) { }
        var completed = (await journal.ReadDestinationHeadAsync(destination, CancellationToken.None))!;
        Assert.Equal(2, completed.CommittedDelete);
        Assert.Equal(StagedPublicDeleteState.Complete, Assert.Single(completed.Deletes).State);
        using (var turn = await journal.EnterDestinationCommitTurnAsync(destination,
            StagedDestinationTurnPurpose.PhysicalCommit, CancellationToken.None))
            await Assert.ThrowsAsync<IOException>(() => journal.BeginDestinationPublicationAsync(turn, Guid.NewGuid(),
                old, 1, null, _temporaryIdentity, 0, StagedTransferJournal.EmptySha256Hex, CancellationToken.None));
        await Publish(journal, destination, successor, 3);
        Assert.Equal(3, (await journal.ReadDestinationHeadAsync(destination, CancellationToken.None))!.LatestPublished);
    }

    [Fact]
    public async Task Only_a_newer_durable_publication_supersedes_an_admitted_delete()
    {
        var journal = Journal(); var destination = Destination();
        Assert.Equal(1, await Allocate(journal, destination, Guid.NewGuid()));
        var binding = Binding(); var delete = await Admit(journal, destination, binding);
        var next = Guid.NewGuid(); long generation = await Allocate(journal, destination, next);
        await Publish(journal, destination, next, generation);
        using var turn = await journal.EnterDestinationCommitTurnAsync(destination,
            StagedDestinationTurnPurpose.Reconciliation, CancellationToken.None);
        var result = await journal.BeginPublicDeleteDispositionAsync(turn, binding, Guid.NewGuid(), CancellationToken.None);
        Assert.Equal(StagedPublicDeleteState.Superseded, result.State);
        var head = (await journal.ReadDestinationHeadAsync(destination, CancellationToken.None))!;
        Assert.Equal(generation, head.LatestPublished); Assert.Equal(_temporaryIdentity, head.PublishedIdentity);
        Assert.Equal(0, head.CommittedDelete); Assert.Null(head.PendingCommit);
        Assert.True(head.MaxAllocated > delete.Generation);
    }

    [Fact]
    public async Task Accepted_reservation_allows_allocation_and_other_destinations_without_holding_a_thread_or_global_gate()
    {
        var journal = Journal(); var destination = Destination(); var binding = Binding();
        await Admit(journal, destination, binding); await Accept(journal, destination, binding, Guid.NewGuid());
        using var cancellation = new CancellationTokenSource();
        var waiting = journal.EnterDestinationCommitTurnAsync(destination, StagedDestinationTurnPurpose.PhysicalCommit,
            cancellation.Token);
        Assert.Equal(2, await Allocate(journal, destination, Guid.NewGuid()));
        Assert.Equal(1, await Allocate(journal, Destination("another.txt"), Guid.NewGuid()));
        Assert.False(waiting.IsCompleted);
        cancellation.Cancel();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => waiting);
        Assert.Equal(3, await Allocate(journal, destination, Guid.NewGuid()));
        Assert.Equal(StagedPublicDeleteState.Accepted,
            Assert.Single((await journal.ReadDestinationHeadAsync(destination, CancellationToken.None))!.Deletes).State);
    }

    [Fact]
    public async Task Ordinary_clear_cancels_every_owner_for_the_exact_object_and_preserves_current_private_content()
    {
        var journal = Journal(); var destination = Destination(); var save = Guid.NewGuid();
        long saveGeneration = await Allocate(journal, destination, save);
        var first = Binding(); var second = Binding(5678);
        await Admit(journal, destination, first); await Admit(journal, destination, second);
        await Accept(journal, destination, first, Guid.NewGuid()); await Accept(journal, destination, second, Guid.NewGuid());
        using (var turn = await journal.EnterDestinationCommitTurnAsync(destination,
            StagedDestinationTurnPurpose.Reconciliation, CancellationToken.None))
        {
            Guid failedClear = Guid.NewGuid();
            await journal.BeginPublicDeleteClearAsync(turn, failedClear, _publicIdentity, CancellationToken.None);
            await journal.RecordPublicDeleteClearResultAsync(turn, failedClear, _publicIdentity, ntfsCleared: false);
            Assert.All((await journal.ReadDestinationHeadAsync(destination, CancellationToken.None))!.Deletes,
                d => Assert.Equal(StagedPublicDeleteState.Accepted, d.State));
            Guid clear = Guid.NewGuid();
            await journal.BeginPublicDeleteClearAsync(turn, clear, _publicIdentity, CancellationToken.None);
            await journal.RecordPublicDeleteClearResultAsync(turn, clear, _publicIdentity, ntfsCleared: true);
            await journal.RecordPublicDeleteClearResultAsync(turn, clear, _publicIdentity, ntfsCleared: true); // Exact reply replay.
        }
        var head = (await journal.ReadDestinationHeadAsync(destination, CancellationToken.None))!;
        Assert.All(head.Deletes, d => Assert.Equal(StagedPublicDeleteState.Canceled, d.State));
        Assert.Equal(3, head.MaxAllocated); Assert.Equal(0, head.CommittedDelete);
        Assert.Equal(save, head.CurrentSaveTransferId);
        await Publish(journal, destination, save, saveGeneration);
        Assert.Equal(4, await Allocate(journal, destination, Guid.NewGuid()));
        var later = Binding(); await Admit(journal, destination, later); await Accept(journal, destination, later, Guid.NewGuid());
        head = (await journal.ReadDestinationHeadAsync(destination, CancellationToken.None))!;
        Assert.Equal(StagedPublicDeleteState.Accepted, head.Deletes.Single(d => d.Binding == later).State);
        Assert.Equal(2, head.Deletes.Count(d => d.State == StagedPublicDeleteState.Canceled));
    }

    [Fact]
    public async Task Completed_delete_is_immutable_and_clear_cannot_resurrect_it_or_clear_another_object()
    {
        var journal = Journal(); var destination = Destination(); var binding = Binding();
        await Admit(journal, destination, binding); await Accept(journal, destination, binding, Guid.NewGuid());
        using var turn = await journal.EnterDestinationCommitTurnAsync(destination,
            StagedDestinationTurnPurpose.Reconciliation, CancellationToken.None);
        await Assert.ThrowsAsync<IOException>(() => journal.BeginPublicDeleteClearAsync(turn,
            Guid.NewGuid(), _publicIdentity with { FileIdHigh = 991 }, CancellationToken.None));
        await journal.RecordPublicDeletePhysicalCompleteAsync(turn, binding, CancellationToken.None);
        await journal.RecordPublicDeletePhysicalCompleteAsync(turn, binding, CancellationToken.None);
        await Assert.ThrowsAsync<IOException>(() => journal.BeginPublicDeleteClearAsync(turn,
            Guid.NewGuid(), _publicIdentity, CancellationToken.None));
        var head = (await journal.ReadDestinationHeadAsync(destination, CancellationToken.None))!;
        Assert.Equal(1, head.CommittedDelete); Assert.Equal(StagedPublicDeleteState.Complete, Assert.Single(head.Deletes).State);
    }

    [Fact]
    public async Task Restart_preserves_unknown_physical_intent_and_never_uses_path_absence_as_a_receipt()
    {
        var journal = Journal(); var destination = Destination(); var binding = Binding(); var operation = Guid.NewGuid();
        await Admit(journal, destination, binding);
        using (var turn = await journal.EnterDestinationCommitTurnAsync(destination,
            StagedDestinationTurnPurpose.Reconciliation, CancellationToken.None))
            await journal.BeginPublicDeleteDispositionAsync(turn, binding, operation, CancellationToken.None);
        var restart = Journal();
        Assert.False(File.Exists(Locator()));
        Assert.NotNull((await restart.ReadDestinationHeadAsync(destination, CancellationToken.None))!.PendingCommit);
        using var cancel = new CancellationTokenSource();
        var waiting = restart.EnterDestinationCommitTurnAsync(destination, StagedDestinationTurnPurpose.Allocation, cancel.Token);
        using (var turn = await restart.EnterDestinationCommitTurnAsync(destination,
            StagedDestinationTurnPurpose.Reconciliation, CancellationToken.None))
        {
            Assert.False(waiting.IsCompleted);
            await Assert.ThrowsAsync<IOException>(() => restart.RecordPublicDeletePhysicalCompleteAsync(turn, binding, CancellationToken.None));
            await restart.RecordPublicDeleteDispositionResultAsync(turn, binding, operation, ntfsAccepted: true);
        }
        using (await waiting.WaitAsync(TimeSpan.FromSeconds(10))) { }
        var head = (await restart.ReadDestinationHeadAsync(destination, CancellationToken.None))!;
        Assert.Equal(0, head.CommittedDelete); Assert.Equal(StagedPublicDeleteState.Accepted, Assert.Single(head.Deletes).State);
    }

    [Fact]
    public async Task Exact_terminal_receipt_retirement_and_manifest_compaction_never_reset_the_delete_barrier()
    {
        var journal = Journal(); var destination = Destination(); var old = Guid.NewGuid();
        Assert.Equal(41, await Allocate(journal, destination, old, 40));
        var binding = Binding(); await Admit(journal, destination, binding); await Accept(journal, destination, binding, Guid.NewGuid());
        using (var turn = await journal.EnterDestinationCommitTurnAsync(destination,
            StagedDestinationTurnPurpose.Reconciliation, CancellationToken.None))
        {
            await Assert.ThrowsAsync<IOException>(() => journal.RetirePublicDeleteReceiptAsync(turn, binding, CancellationToken.None));
            await journal.RecordPublicDeletePhysicalCompleteAsync(turn, binding, CancellationToken.None);
            await journal.RetirePublicDeleteReceiptAsync(turn, binding, CancellationToken.None);
        }
        Assert.Equal(0, await journal.CompactAsync(DateTimeOffset.UtcNow, CancellationToken.None));
        var restart = Journal(); var head = (await restart.ReadDestinationHeadAsync(destination, CancellationToken.None))!;
        Assert.Empty(head.Deletes); Assert.Equal(42, head.CommittedDelete); Assert.Equal(42, head.MaxAllocated);
        using (var turn = await restart.EnterDestinationCommitTurnAsync(destination,
            StagedDestinationTurnPurpose.PhysicalCommit, CancellationToken.None))
            await Assert.ThrowsAsync<IOException>(() => restart.BeginDestinationPublicationAsync(turn, Guid.NewGuid(), old,
                41, null, _temporaryIdentity, 0, StagedTransferJournal.EmptySha256Hex, CancellationToken.None));
        Assert.Equal(43, await Allocate(restart, destination, Guid.NewGuid()));
    }

    [Fact]
    public async Task Mismatched_owner_nonce_epoch_identity_or_operation_cannot_consume_a_delete_intent()
    {
        var journal = Journal(); var destination = Destination(); var binding = Binding(); var operation = Guid.NewGuid();
        await Admit(journal, destination, binding);
        using var turn = await journal.EnterDestinationCommitTurnAsync(destination,
            StagedDestinationTurnPurpose.Reconciliation, CancellationToken.None);
        await journal.BeginPublicDeleteDispositionAsync(turn, binding, operation, CancellationToken.None);
        foreach (var mismatch in new[] { binding with { RequestNonce = Guid.NewGuid() }, binding with { ConnectionEpoch = 18 },
            binding with { DriverInstanceId = Guid.NewGuid() }, binding with { OwnerProcessCreationTime = 123457 },
            binding with { PublicIdentity = _publicIdentity with { FileIdHigh = 191 } } })
            await Assert.ThrowsAsync<IOException>(() => journal.RecordPublicDeleteDispositionResultAsync(turn, mismatch,
                operation, ntfsAccepted: true));
        await Assert.ThrowsAsync<IOException>(() => journal.RecordPublicDeleteDispositionResultAsync(turn, binding,
            Guid.NewGuid(), ntfsAccepted: true));
        Assert.Equal(StagedPublicDeleteState.Intent,
            Assert.Single((await journal.ReadDestinationHeadAsync(destination, CancellationToken.None))!.Deletes).State);
        await journal.RecordPublicDeleteDispositionResultAsync(turn, binding, operation, ntfsAccepted: true);
        await journal.RecordPublicDeleteDispositionResultAsync(turn, binding, operation, ntfsAccepted: true);
    }

    [Fact]
    public async Task Physical_publication_turn_serializes_allocation_and_preserves_exact_zero_byte_receipts()
    {
        var journal = Journal(); var destination = Destination(); var save = Guid.NewGuid();
        long generation = await Allocate(journal, destination, save);
        Guid operation = Guid.NewGuid();
        Task<StagedTransferJournal.DestinationCommitTurn> waiting;
        using (var turn = await journal.EnterDestinationCommitTurnAsync(destination,
            StagedDestinationTurnPurpose.PhysicalCommit, CancellationToken.None))
        {
            waiting = journal.EnterDestinationCommitTurnAsync(destination,
                StagedDestinationTurnPurpose.Allocation, CancellationToken.None);
            Assert.False(waiting.IsCompleted);
            await journal.BeginDestinationPublicationAsync(turn, operation, save, generation, _publicIdentity,
                _temporaryIdentity, 0, StagedTransferJournal.EmptySha256Hex, CancellationToken.None);
            await Assert.ThrowsAsync<IOException>(() => journal.RecordDestinationPublicationResultAsync(turn,
                operation, save, _temporaryIdentity with { FileIdHigh = 999 }, renameCommitted: true));
            Assert.Equal(0, (await journal.ReadDestinationHeadAsync(destination, CancellationToken.None))!.LatestPublished);
            await journal.RecordDestinationPublicationResultAsync(turn, operation, save, _temporaryIdentity, renameCommitted: true);
            await journal.RecordDestinationPublicationResultAsync(turn, operation, save, _temporaryIdentity, renameCommitted: true);
            Assert.False(waiting.IsCompleted);
        }
        using (await waiting.WaitAsync(TimeSpan.FromSeconds(10))) { }
        var head = (await Journal().ReadDestinationHeadAsync(destination, CancellationToken.None))!;
        Assert.Equal(1, head.LatestPublished); Assert.Equal(_temporaryIdentity, head.PublishedIdentity);
        Assert.Equal(0, head.LastMutationResult!.Intent.Length);
        Assert.Equal(StagedTransferJournal.EmptySha256Hex, head.LastMutationResult.Intent.Sha256Hex);
    }

    [Fact]
    public async Task Concurrent_alias_allocations_have_unique_monotonic_durable_generations()
    {
        var journal = Journal();
        long[] generations = await Task.WhenAll(Enumerable.Range(0, 64).Select(i => Allocate(journal,
            Destination(i % 2 == 0 ? "DOCUMENT.TXT" : "document.txt"), Guid.NewGuid())));
        Assert.Equal(Enumerable.Range(1, 64).Select(i => (long)i), generations.Order());
        var head = (await Journal().ReadDestinationHeadAsync(Destination(), CancellationToken.None))!;
        Assert.Equal(64, head.MaxAllocated); Assert.Equal(64, head.CurrentSaveGeneration);
        Assert.Single(Directory.GetFiles(JournalPath, "destination-*.state"));
    }

    [Theory]
    [InlineData("negative-head")]
    [InlineData("missing-intent")]
    [InlineData("unknown-state")]
    [InlineData("wrong-parent")]
    [InlineData("duplicate-delete")]
    [InlineData("unpaired-result")]
    public async Task Malformed_durable_heads_fail_closed_instead_of_admitting_a_new_generation(string mutation)
    {
        var journal = Journal(); var destination = Destination(); var binding = Binding();
        await Admit(journal, destination, binding);
        using (var turn = await journal.EnterDestinationCommitTurnAsync(destination,
            StagedDestinationTurnPurpose.Reconciliation, CancellationToken.None))
            await journal.BeginPublicDeleteDispositionAsync(turn, binding, Guid.NewGuid(), CancellationToken.None);
        string path = Assert.Single(Directory.GetFiles(JournalPath, "destination-*.state"));
        var head = JsonNode.Parse(await File.ReadAllTextAsync(path))!.AsObject();
        switch (mutation)
        {
            case "negative-head": head["MaxAllocated"] = -1; break;
            case "missing-intent": head["PendingCommit"] = null; break;
            case "unknown-state": head["Deletes"]![0]!["State"] = 999; break;
            case "wrong-parent": head["Destination"]!["Parent"]!["FileIdHigh"] = 999; break;
            case "duplicate-delete": head["Deletes"]!.AsArray().Add(head["Deletes"]![0]!.DeepClone()); break;
            case "unpaired-result": head["LastMutationResult"] = new JsonObject
                { ["Intent"] = head["PendingCommit"]!.DeepClone(), ["Succeeded"] = true };
                head["LastMutationResult"]!["Intent"]!["Mutation"] = 1; break;
        }
        await File.WriteAllTextAsync(path, head.ToJsonString());
        await Assert.ThrowsAsync<InvalidDataException>(() => journal.EnterDestinationCommitTurnAsync(destination,
            StagedDestinationTurnPurpose.Allocation, CancellationToken.None));
    }

    [Fact]
    public async Task Disposed_or_foreign_turns_cannot_mutate_a_destination_and_canceled_waits_leave_it_usable()
    {
        var journal = Journal(); var destination = Destination();
        var turn = await journal.EnterDestinationCommitTurnAsync(destination,
            StagedDestinationTurnPurpose.Allocation, CancellationToken.None);
        await Assert.ThrowsAsync<InvalidOperationException>(() => Journal().ReserveSaveGenerationAsync(turn,
            Guid.NewGuid(), Locator(), 0, CancellationToken.None));
        using var cancel = new CancellationTokenSource();
        var waiting = journal.EnterDestinationCommitTurnAsync(destination, StagedDestinationTurnPurpose.Allocation, cancel.Token);
        cancel.Cancel(); await Assert.ThrowsAnyAsync<OperationCanceledException>(() => waiting);
        turn.Dispose(); turn.Dispose();
        await Assert.ThrowsAsync<InvalidOperationException>(() => journal.ReserveSaveGenerationAsync(turn,
            Guid.NewGuid(), Locator(), 0, CancellationToken.None));
        Assert.Equal(1, await Allocate(journal, destination, Guid.NewGuid()));
    }
}
