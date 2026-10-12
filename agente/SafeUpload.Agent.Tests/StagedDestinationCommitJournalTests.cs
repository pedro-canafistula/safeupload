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
    private static readonly Guid MountVolume = Guid.Parse("22000000-0000-0000-0000-000000000002");
    private readonly StagedStageIdentity _publicIdentity = new(7, 91, 92);
    private readonly StagedStageIdentity _temporaryIdentity = new(7, 101, 102);
    private string JournalPath => Path.Combine(_workspace.Root, "journal");
    private string Locator(string name = "document.txt") => Path.Combine(_workspace.Root, "destination", name);
    private StagedTransferJournal Journal() => new(JournalPath);
    private static StagedDestinationIdentity Destination(string leaf = "document.txt", bool caseSensitive = false) =>
        new(new(7, 11, 12), new(7, 21, 22), caseSensitive, leaf, MountVolume);
    private StagedPublicDeleteBinding Binding(int owner = 1234) => new(Guid.NewGuid(), Guid.NewGuid(),
        _driverInstance, 17, _publicIdentity, owner, 123456, 1, "S-1-5-21-100-200-300-1001",
        MountManagerVolumeId: MountVolume);

    public void Dispose() => _workspace.Dispose();

    [Fact]
    public async Task Cloned_filesystem_ids_with_different_volume_guids_have_distinct_durable_heads()
    {
        var journal = Journal(); var original = Destination();
        var clone = new StagedDestinationIdentity(original.VolumeRoot, original.Parent,
            original.CaseSensitive, original.CanonicalLeaf, Guid.NewGuid());
        Assert.NotEqual(original.StorageKey, clone.StorageKey);
        var first = await Allocate(journal, original, Guid.NewGuid());
        var second = await Allocate(journal, clone, Guid.NewGuid());
        Assert.Equal(1, first); Assert.Equal(1, second);
        var reopened = await Journal().ReadDestinationHeadsAsync(CancellationToken.None);
        Assert.Equal(2, reopened.Count);
        Assert.Contains(reopened, h => h.Destination == original);
        Assert.Contains(reopened, h => h.Destination == clone);
    }

    [Fact]
    public async Task Native_create_cannot_substitute_another_mount_or_omit_captured_volume_identity()
    {
        var journal = Journal(); var binding = Binding() with { OsBootSequence = 42 };
        await Assert.ThrowsAsync<ArgumentException>(() => NativeCreateIntent(journal, Destination(),
            binding with { MountManagerVolumeId = Guid.NewGuid() }, Guid.NewGuid()));
        await Assert.ThrowsAsync<ArgumentException>(() => NativeCreateIntent(journal, Destination(),
            binding with { MountManagerVolumeId = null }, Guid.NewGuid()));
        var legacy = new StagedDestinationIdentity(Destination().VolumeRoot, Destination().Parent, false, "document.txt");
        await Assert.ThrowsAsync<ArgumentException>(() => NativeCreateIntent(journal, legacy,
            binding with { MountManagerVolumeId = null }, Guid.NewGuid()));
        Assert.Empty(await journal.ReadDestinationHeadsAsync(CancellationToken.None));
    }

    [Fact]
    public async Task Legacy_admitted_native_record_without_volume_guid_remains_a_publication_hold()
    {
        var journal = Journal(); var destination = Destination(); var operation = Guid.NewGuid();
        var binding = Binding() with { OsBootSequence = 42 };
        await NativeCreateIntent(journal, destination, binding, operation);
        using (var turn = await journal.EnterDestinationCommitTurnAsync(destination,
                   StagedDestinationTurnPurpose.Reconciliation, CancellationToken.None))
            await journal.RecordNativeDeleteOnCloseCreateResultAsync(turn, binding, operation, true, true);
        string currentPath = Assert.Single(Directory.GetFiles(JournalPath, "destination-*.state"));
        var oldHead = JsonNode.Parse(await File.ReadAllTextAsync(currentPath))!;
        oldHead["Destination"]!.AsObject().Remove("MountManagerVolumeId");
        oldHead["Deletes"]![0]!["Binding"]!.AsObject().Remove("MountManagerVolumeId");
        var legacy = new StagedDestinationIdentity(destination.VolumeRoot, destination.Parent,
            destination.CaseSensitive, destination.CanonicalLeaf);
        string legacyPath = Path.Combine(JournalPath, "destination-" + legacy.StorageKey + ".state");
        await File.WriteAllTextAsync(currentPath, oldHead.ToJsonString()); File.Move(currentPath, legacyPath);

        var restarted = Journal();
        var retained = Assert.Single(await restarted.ReadDestinationHeadsAsync(CancellationToken.None));
        Assert.Null(retained.Destination.MountManagerVolumeId);
        Assert.Equal(StagedPublicDeleteState.Admitted, Assert.Single(retained.Deletes).State);
        using var cancellation = new CancellationTokenSource();
        Task<StagedTransferJournal.DestinationCommitTurn> wait = restarted.EnterDestinationCommitTurnAsync(legacy,
            StagedDestinationTurnPurpose.PhysicalCommit, cancellation.Token);
        Assert.False(wait.IsCompleted); cancellation.Cancel();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => wait);
        string unchanged = await File.ReadAllTextAsync(legacyPath);
        using (var turn = await restarted.EnterDestinationCommitTurnAsync(legacy,
                   StagedDestinationTurnPurpose.Reconciliation, CancellationToken.None))
            await Assert.ThrowsAsync<IOException>(() => restarted.ReconcileNativeDeleteOnCloseAsync(turn,
                binding with { MountManagerVolumeId = null }, operation,
                CleanupProof(binding with { MountManagerVolumeId = null }, operation), Observation(legacy, _publicIdentity),
                CancellationToken.None));
        Assert.Equal(unchanged, await File.ReadAllTextAsync(legacyPath));
    }

    [Fact]
    public async Task Startup_discovers_durable_native_holds_without_a_surviving_driver_record_or_manifest()
    {
        var journal = Journal(); var destination = Destination(); var operation = Guid.NewGuid();
        var binding = Binding() with { OsBootSequence = 42 };
        await NativeCreateIntent(journal, destination, binding, operation);
        await Allocate(journal, Destination("other.txt"), Guid.NewGuid());
        Assert.Empty(Directory.GetFiles(JournalPath, "*.json"));
        var recovered = await Journal().ReadDestinationHeadsAsync(CancellationToken.None);
        Assert.Equal(2, recovered.Count);
        var hold = Assert.Single(recovered.Single(h => h.Destination == destination).Deletes);
        Assert.Equal(binding, hold.Binding); Assert.Equal(operation, hold.OperationId);
        Assert.Equal(StagedPublicDeleteState.AcceptedUnresolved, hold.State);
        Assert.Equal(1, hold.Generation);
        using var cancel = new CancellationTokenSource();
        var blocked = journal.EnterDestinationCommitTurnAsync(destination, StagedDestinationTurnPurpose.PhysicalCommit, cancel.Token);
        Assert.False(blocked.IsCompleted);
        cancel.Cancel(); await Assert.ThrowsAnyAsync<OperationCanceledException>(() => blocked);
    }

    [Fact]
    public async Task Startup_refuses_a_copied_head_under_another_identity_instead_of_skipping_its_hold()
    {
        var journal = Journal();
        await NativeCreateIntent(journal, Destination(), Binding() with { OsBootSequence = 42 }, Guid.NewGuid());
        string head = Assert.Single(Directory.GetFiles(JournalPath, "destination-*.state"));
        File.Copy(head, Path.Combine(JournalPath, "destination-" + new string('0', 64) + ".state"));
        await Assert.ThrowsAsync<InvalidDataException>(() => Journal().ReadDestinationHeadsAsync(CancellationToken.None));
    }

    [Fact]
    public async Task Startup_refuses_corrupt_native_hold_state_and_releases_its_metadata_gate()
    {
        var journal = Journal();
        await NativeCreateIntent(journal, Destination(), Binding() with { OsBootSequence = 42 }, Guid.NewGuid());
        string path = Assert.Single(Directory.GetFiles(JournalPath, "destination-*.state"));
        string original = await File.ReadAllTextAsync(path);
        var head = JsonNode.Parse(original)!.AsObject(); head["Deletes"]![0]!["State"] = 999;
        await File.WriteAllTextAsync(path, head.ToJsonString());
        await Assert.ThrowsAsync<InvalidDataException>(() => journal.ReadDestinationHeadsAsync(CancellationToken.None));
        await File.WriteAllTextAsync(path, original);
        Assert.Single(await journal.ReadDestinationHeadsAsync(CancellationToken.None));
    }

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

    private async Task<StagedPublicDeleteRecord> NativeCreateIntent(StagedTransferJournal journal,
        StagedDestinationIdentity destination, StagedPublicDeleteBinding binding, Guid operation)
    {
        using var turn = await journal.EnterDestinationCommitTurnAsync(destination,
            StagedDestinationTurnPurpose.Allocation, CancellationToken.None);
        return await journal.BeginNativeDeleteOnCloseCreateAsync(turn, binding, operation,
            Locator(destination.CanonicalLeaf), 0, CancellationToken.None);
    }

    private static StagedDestinationNameObservation Observation(StagedDestinationIdentity destination,
        StagedStageIdentity? identity) => new(destination, destination.Parent, destination.Parent, true, identity);

    private static StagedNativeRecoverySession.Proof CleanupProof(StagedPublicDeleteBinding binding,
        Guid operation, uint? currentBoot = null)
    {
        var session = new StagedNativeRecoverySession(binding.DriverInstanceId, binding.ConnectionEpoch + 1,
            currentBoot ?? binding.OsBootSequence);
        return session.ReconcileReplay(binding.DriverInstanceId, binding.ConnectionEpoch + 1, true, true,
            [new(binding, operation, true)]);
    }

    private static StagedNativeRecoverySession.Proof BootProof(StagedPublicDeleteBinding binding,
        uint? currentBoot, Guid currentDriver, bool complete = true, bool reconciled = true)
    {
        var session = new StagedNativeRecoverySession(currentDriver, binding.ConnectionEpoch + 1, currentBoot);
        return session.ReconcileReplay(currentDriver, binding.ConnectionEpoch + 1, complete, reconciled, []);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task Exact_last_cleanup_releases_exceptional_hold_without_forging_physical_completion(bool absent)
    {
        var journal = Journal(); var destination = Destination(); var operation = Guid.NewGuid();
        var binding = Binding() with { OsBootSequence = 42 };
        Assert.Equal(StagedPublicDeleteState.AcceptedUnresolved,
            (await NativeCreateIntent(journal, destination, binding, operation)).State);
        var successor = Guid.NewGuid(); long generation = await Allocate(journal, destination, successor);
        using var cancel = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        var waiting = journal.EnterDestinationCommitTurnAsync(destination, StagedDestinationTurnPurpose.PhysicalCommit, cancel.Token);
        using (var turn = await journal.EnterDestinationCommitTurnAsync(destination,
            StagedDestinationTurnPurpose.Reconciliation, CancellationToken.None))
        {
            await journal.RecordNativeDeleteOnCloseCreateResultAsync(turn, binding, operation, true, false);
            Assert.False(waiting.IsCompleted);
            var result = await journal.ReconcileNativeDeleteOnCloseAsync(turn, binding, operation,
                CleanupProof(binding, operation), Observation(destination, absent ? null : _publicIdentity), CancellationToken.None);
            Assert.Equal(StagedPublicDeleteState.Admitted, result.State);
            Assert.Equal(StagedPublicDeleteKind.NativeOnClose, result.Kind);
            Assert.True(result.NativeCreateAccepted);
            await Assert.ThrowsAsync<IOException>(() => journal.CancelAdmittedPublicDeleteAsync(turn, binding, CancellationToken.None));
            await Assert.ThrowsAsync<IOException>(() => journal.RecordPublicDeletePhysicalCompleteAsync(turn, binding, CancellationToken.None));
        }
        using (await waiting.WaitAsync(TimeSpan.FromSeconds(10))) { }
        var head = (await Journal().ReadDestinationHeadAsync(destination, CancellationToken.None))!;
        Assert.Equal(0, head.CommittedDelete); Assert.Equal(operation, Assert.Single(head.Deletes).OperationId);
        await Publish(journal, destination, successor, generation);
        Assert.Equal(generation, (await journal.ReadDestinationHeadAsync(destination, CancellationToken.None))!.LatestPublished);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task Native_terminal_unlink_retains_receipt_until_post_ack_authenticated_removal(bool trackingBound)
    {
        var journal = Journal(); var destination = Destination(); var operation = Guid.NewGuid();
        var binding = Binding() with { OsBootSequence = 42 };
        var native = await NativeCreateIntent(journal, destination, binding, operation);
        using var turn = await journal.EnterDestinationCommitTurnAsync(destination,
            StagedDestinationTurnPurpose.Reconciliation, CancellationToken.None);
        await journal.RecordNativeDeleteOnCloseCreateResultAsync(turn, binding, operation, true, trackingBound);
        var session = new StagedNativeRecoverySession(binding.DriverInstanceId, binding.ConnectionEpoch + 1, 42);
        var live = session.ReconcileReplay(binding.DriverInstanceId, binding.ConnectionEpoch + 1, true, true,
            [new(binding, operation, false)], nativeMapRevision: 17);
        await Assert.ThrowsAsync<IOException>(() => journal.CompleteNativeDeleteOnCloseAsync(turn, binding, operation,
            live, Observation(destination, null), CancellationToken.None));
        var cleaned = session.ReconcileReplay(binding.DriverInstanceId, binding.ConnectionEpoch + 1, true, true,
            [new(binding, operation, true)], nativeMapRevision: 17);
        var pending = await journal.CompleteNativeDeleteOnCloseAsync(turn, binding, operation,
            cleaned, Observation(destination, _publicIdentity), CancellationToken.None);
        Assert.Equal(trackingBound ? StagedPublicDeleteState.Admitted : StagedPublicDeleteState.AcceptedUnresolved, pending.State);
        await Assert.ThrowsAsync<IOException>(() => journal.CompleteNativeDeleteOnCloseAsync(turn, binding, operation,
            cleaned, Observation(destination, _temporaryIdentity), CancellationToken.None));
        var complete = await journal.CompleteNativeDeleteOnCloseAsync(turn, binding, operation,
            cleaned, Observation(destination, null), CancellationToken.None);
        Assert.Equal(StagedPublicDeleteState.Complete, complete.State);
        var retained = (await Journal().ReadDestinationHeadAsync(destination, CancellationToken.None))!;
        Assert.Equal(native.Generation, retained.CommittedDelete);
        Assert.Equal(complete, Assert.Single(retained.Deletes));
        await Assert.ThrowsAsync<IOException>(() => journal.RetirePublicDeleteReceiptAsync(turn, binding, CancellationToken.None));
        await Assert.ThrowsAsync<IOException>(() => journal.RetireNativeDeleteReceiptAsync(turn, binding, operation,
            cleaned, 17, CancellationToken.None));
        var stale = session.ReconcileReplay(binding.DriverInstanceId, binding.ConnectionEpoch + 1, true, true, [], nativeMapRevision: 17);
        await Assert.ThrowsAsync<IOException>(() => journal.RetireNativeDeleteReceiptAsync(turn, binding, operation,
            stale, 17, CancellationToken.None));
        var removed = session.ReconcileReplay(binding.DriverInstanceId, binding.ConnectionEpoch + 1, true, true, [], nativeMapRevision: 18);
        await journal.RetireNativeDeleteReceiptAsync(turn, binding, operation, removed, 17, CancellationToken.None);
        retained = (await Journal().ReadDestinationHeadAsync(destination, CancellationToken.None))!;
        Assert.Empty(retained.Deletes);
        Assert.Equal(native.Generation, retained.CommittedDelete);
        Assert.Equal(native.Generation, retained.MaxAllocated);
    }

    [Fact]
    public async Task Native_terminal_supersede_requires_newer_published_identity_and_retains_cleanup_receipt()
    {
        var journal = Journal(); var destination = Destination(); var operation = Guid.NewGuid();
        var binding = Binding() with { OsBootSequence = 42 };
        await NativeCreateIntent(journal, destination, binding, operation);
        using (var turn = await journal.EnterDestinationCommitTurnAsync(destination,
                   StagedDestinationTurnPurpose.Reconciliation, CancellationToken.None))
            await journal.RecordNativeDeleteOnCloseCreateResultAsync(turn, binding, operation, true, true);
        var successor = Guid.NewGuid(); long generation = await Allocate(journal, destination, successor);
        using (var turn = await journal.EnterDestinationCommitTurnAsync(destination,
                   StagedDestinationTurnPurpose.Reconciliation, CancellationToken.None))
            await Assert.ThrowsAsync<IOException>(() => journal.CompleteNativeDeleteOnCloseAsync(turn, binding, operation,
                CleanupProof(binding, operation), Observation(destination, _temporaryIdentity), CancellationToken.None));
        await Publish(journal, destination, successor, generation);
        using (var turn = await journal.EnterDestinationCommitTurnAsync(destination,
                   StagedDestinationTurnPurpose.Reconciliation, CancellationToken.None))
            Assert.Equal(StagedPublicDeleteState.Superseded,
                (await journal.CompleteNativeDeleteOnCloseAsync(turn, binding, operation,
                    CleanupProof(binding, operation), Observation(destination, _temporaryIdentity), CancellationToken.None)).State);
        var head = (await Journal().ReadDestinationHeadAsync(destination, CancellationToken.None))!;
        Assert.Equal(StagedPublicDeleteState.Superseded, Assert.Single(head.Deletes).State);
        Assert.Equal(generation, head.LatestPublished); Assert.Equal(_temporaryIdentity, head.PublishedIdentity);
        Assert.Equal(0, head.CommittedDelete);
    }

    [Theory]
    [InlineData("below", false)]
    [InlineData("below", true)]
    [InlineData("above", false)]
    [InlineData("above", true)]
    public async Task Exact_before_handle_cancellation_reconciles_after_service_restart_without_inventing_no_effect(
        string cancellingFilter, bool absent)
    {
        var destination = Destination(); var binding = Binding() with { OsBootSequence = 42 };
        var operation = Guid.NewGuid(); var journal = Journal();
        var intent = await NativeCreateIntent(journal, destination, binding, operation);
        var successor = Guid.NewGuid(); long generation = await Allocate(journal, destination, successor);
        Assert.True(generation > intent.Generation);
        var restart = Journal();
        var session = new StagedNativeRecoverySession(binding.DriverInstanceId, binding.ConnectionEpoch + 1, 42);
        using var cancel = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        var waiting = restart.EnterDestinationCommitTurnAsync(destination,
            StagedDestinationTurnPurpose.PhysicalCommit, cancel.Token);
        using (var turn = await restart.EnterDestinationCommitTurnAsync(destination,
            StagedDestinationTurnPurpose.Reconciliation, CancellationToken.None))
        {
            var unproven = session.ReconcileReplay(binding.DriverInstanceId, binding.ConnectionEpoch + 1,
                true, true, [new(binding, operation, false)]);
            await Assert.ThrowsAsync<IOException>(() => restart.ReconcileNativeDeleteOnCloseAsync(turn,
                binding, operation, unproven, Observation(destination, absent ? null : _publicIdentity), CancellationToken.None));
            Assert.False(waiting.IsCompleted);
            var proof = session.ReconcileReplay(binding.DriverInstanceId, binding.ConnectionEpoch + 1,
                true, true, [new(binding, operation, false, CancelledBeforeHandle: cancellingFilter == "below",
                    CancelledCloseObserved: cancellingFilter == "above")]);
            var recovered = await restart.ReconcileNativeDeleteOnCloseAsync(turn, binding, operation,
                proof, Observation(destination, absent ? null : _publicIdentity), CancellationToken.None);
            Assert.Equal(StagedPublicDeleteState.Admitted, recovered.State);
            Assert.Null(recovered.NativeCreateAccepted); // Never treat cancellation as a harmless rejected CREATE.
            Assert.Equal(intent.Generation, recovered.Generation);
            await Assert.ThrowsAsync<IOException>(() => restart.RecordPublicDeletePhysicalCompleteAsync(turn,
                binding, CancellationToken.None));
        }
        using (await waiting.WaitAsync(TimeSpan.FromSeconds(10))) { }
        Assert.Equal(0, (await restart.ReadDestinationHeadAsync(destination, CancellationToken.None))!.CommittedDelete);
        await Publish(restart, destination, successor, generation);
        Assert.Equal(generation, (await restart.ReadDestinationHeadAsync(destination, CancellationToken.None))!.LatestPublished);
    }

    [Fact]
    public async Task Restart_keeps_unresolved_pre_create_until_exact_cleanup_or_qualified_boot_replay()
    {
        var journal = Journal(); var destination = Destination(); var operation = Guid.NewGuid();
        var binding = Binding() with { OsBootSequence = 42 };
        await NativeCreateIntent(journal, destination, binding, operation);
        var restart = Journal();
        var persisted = Assert.Single((await restart.ReadDestinationHeadAsync(destination, CancellationToken.None))!.Deletes);
        Assert.Equal(StagedPublicDeleteState.AcceptedUnresolved, persisted.State);
        Assert.Equal(binding, persisted.Binding); Assert.Null(persisted.NativeCreateAccepted);
        using var turn = await restart.EnterDestinationCommitTurnAsync(destination,
            StagedDestinationTurnPurpose.Reconciliation, CancellationToken.None);
        foreach (uint? boot in new uint?[] { null, 0, 41, 42 })
            await Assert.ThrowsAsync<IOException>(() => restart.ReconcileNativeDeleteOnCloseAsync(turn, binding, operation,
                BootProof(binding, boot, Guid.NewGuid()), Observation(destination, null), CancellationToken.None));
        await Assert.ThrowsAsync<IOException>(() => restart.ReconcileNativeDeleteOnCloseAsync(turn, binding, operation,
            CleanupProof(binding with { DriverInstanceId = Guid.NewGuid(), ConnectionEpoch = 18 }, operation),
            Observation(destination, _publicIdentity), CancellationToken.None));
        var recovered = await restart.ReconcileNativeDeleteOnCloseAsync(turn, binding, operation,
            BootProof(binding, 43, Guid.NewGuid()), Observation(destination, null), CancellationToken.None);
        Assert.Equal(StagedPublicDeleteState.Admitted, recovered.State);
        Assert.Null(recovered.NativeCreateAccepted); // Recovery never invents NTFS acceptance or cleanup ACK.
        Assert.Equal(0, (await restart.ReadDestinationHeadAsync(destination, CancellationToken.None))!.CommittedDelete);
    }

    [Fact]
    public async Task Unknown_parent_or_replacement_and_wrong_cleanup_binding_keep_the_recovery_hold()
    {
        var journal = Journal(); var destination = Destination(); var operation = Guid.NewGuid();
        var binding = Binding() with { OsBootSequence = 42 };
        await NativeCreateIntent(journal, destination, binding, operation);
        using var turn = await journal.EnterDestinationCommitTurnAsync(destination,
            StagedDestinationTurnPurpose.Reconciliation, CancellationToken.None);
        var original = Observation(destination, _publicIdentity);
        foreach (var invalid in new[] { original with { CompleteEnumeration = false },
            original with { ParentAfter = destination.Parent with { FileIdHigh = 999 } },
            original with { Destination = Destination("another.txt") },
            original with { PublicIdentity = _publicIdentity with { FileIdHigh = 999 } } })
            await Assert.ThrowsAsync<IOException>(() => journal.ReconcileNativeDeleteOnCloseAsync(turn, binding, operation,
                CleanupProof(binding, operation), invalid, CancellationToken.None));
        foreach (var cleanup in new[] { CleanupProof(binding, Guid.NewGuid()),
            CleanupProof(binding with { OwnerProcessCreationTime = binding.OwnerProcessCreationTime + 1 }, operation),
            CleanupProof(binding with { PublicIdentity = _publicIdentity with { FileIdLow = 999 } }, operation) })
            await Assert.ThrowsAsync<IOException>(() => journal.ReconcileNativeDeleteOnCloseAsync(turn, binding, operation,
                cleanup, original, CancellationToken.None));
        Assert.Equal(StagedPublicDeleteState.AcceptedUnresolved,
            Assert.Single((await journal.ReadDestinationHeadAsync(destination, CancellationToken.None))!.Deletes).State);
    }

    [Theory]
    [InlineData(false, false)]
    [InlineData(true, false)]
    [InlineData(false, true)]
    public async Task Partial_or_unreconciled_new_driver_replay_cannot_release_a_later_boot_hold(bool complete, bool reconciled)
    {
        var journal = Journal(); var destination = Destination(); var operation = Guid.NewGuid();
        var binding = Binding() with { OsBootSequence = 42 };
        await NativeCreateIntent(journal, destination, binding, operation);
        using var turn = await journal.EnterDestinationCommitTurnAsync(destination,
            StagedDestinationTurnPurpose.Reconciliation, CancellationToken.None);
        await Assert.ThrowsAsync<IOException>(() => journal.ReconcileNativeDeleteOnCloseAsync(turn, binding, operation,
            BootProof(binding, 43, Guid.NewGuid(), complete, reconciled), Observation(destination, null), CancellationToken.None));
        Assert.Equal(StagedPublicDeleteState.AcceptedUnresolved,
            Assert.Single((await Journal().ReadDestinationHeadAsync(destination, CancellationToken.None))!.Deletes).State);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task Resume_or_same_boot_driver_reload_never_releases_without_exact_cleanup(bool changedDriver)
    {
        var journal = Journal(); var destination = Destination(); var operation = Guid.NewGuid();
        var binding = Binding() with { OsBootSequence = 42 };
        await NativeCreateIntent(journal, destination, binding, operation);
        using var turn = await journal.EnterDestinationCommitTurnAsync(destination,
            StagedDestinationTurnPurpose.Reconciliation, CancellationToken.None);
        Guid driver = changedDriver ? Guid.NewGuid() : binding.DriverInstanceId;
        uint boot = changedDriver ? 42u : 43u;
        await Assert.ThrowsAsync<IOException>(() => journal.ReconcileNativeDeleteOnCloseAsync(turn, binding, operation,
            BootProof(binding, boot, driver), Observation(destination, null), CancellationToken.None));
        var session = new StagedNativeRecoverySession(binding.DriverInstanceId, 18, 43);
        var live = session.ReconcileReplay(binding.DriverInstanceId, 18, true, true, [new(binding, operation, false)]);
        await Assert.ThrowsAsync<IOException>(() => journal.ReconcileNativeDeleteOnCloseAsync(turn, binding, operation,
            live, Observation(destination, _publicIdentity), CancellationToken.None));
        Assert.Equal(StagedPublicDeleteState.AcceptedUnresolved,
            Assert.Single((await Journal().ReadDestinationHeadAsync(destination, CancellationToken.None))!.Deletes).State);
    }

    [Theory]
    [InlineData("disconnect")]
    [InlineData("partial-replay")]
    [InlineData("unbound-replay")]
    [InlineData("reconstructed-token")]
    public async Task Stale_or_reconstructed_recovery_proof_cannot_change_the_durable_hold(string invalidation)
    {
        var journal = Journal(); var destination = Destination(); var operation = Guid.NewGuid();
        var binding = Binding() with { OsBootSequence = 42 };
        await NativeCreateIntent(journal, destination, binding, operation);
        var session = new StagedNativeRecoverySession(binding.DriverInstanceId, 18, 42);
        var records = new StagedNativeRecordReplay[] { new(binding, operation, true) };
        var proof = session.ReconcileReplay(binding.DriverInstanceId, 18, true, true, records);
        if (invalidation == "disconnect") session.Invalidate();
        else if (invalidation == "partial-replay") session.ReconcileReplay(binding.DriverInstanceId, 18, false, false, []);
        else if (invalidation == "unbound-replay")
            Assert.Throws<IOException>(() => session.ReconcileReplay(binding.DriverInstanceId, 19, true, true, records));
        else proof = new StagedNativeRecoverySession.Proof(session, 1, true, true, records);
        using var turn = await journal.EnterDestinationCommitTurnAsync(destination,
            StagedDestinationTurnPurpose.Reconciliation, CancellationToken.None);
        await Assert.ThrowsAsync<IOException>(() => journal.ReconcileNativeDeleteOnCloseAsync(turn, binding, operation,
            proof, Observation(destination, null), CancellationToken.None));
        Assert.Equal(StagedPublicDeleteState.AcceptedUnresolved,
            Assert.Single((await Journal().ReadDestinationHeadAsync(destination, CancellationToken.None))!.Deletes).State);
    }

    [Theory]
    [InlineData(0u)]
    [InlineData(41u)]
    [InlineData(43u)]
    public async Task Service_restart_replays_exact_cleanup_even_if_boot_counter_changed(uint currentBoot)
    {
        var journal = Journal(); var destination = Destination(); var operation = Guid.NewGuid();
        var binding = Binding() with { OsBootSequence = 42 };
        await NativeCreateIntent(journal, destination, binding, operation);
        var restarted = Journal();
        using var turn = await restarted.EnterDestinationCommitTurnAsync(destination,
            StagedDestinationTurnPurpose.Reconciliation, CancellationToken.None);
        var result = await restarted.ReconcileNativeDeleteOnCloseAsync(turn, binding, operation,
            CleanupProof(binding, operation, currentBoot), Observation(destination, null), CancellationToken.None);
        Assert.Equal(StagedPublicDeleteState.Admitted, result.State);
        Assert.Equal(StagedPublicDeleteKind.NativeOnClose, result.Kind);
    }

    [Fact]
    public void Native_replay_rejects_unbound_and_duplicate_original_objects_and_copies_its_input()
    {
        var binding = Binding() with { OsBootSequence = 42 }; var operation = Guid.NewGuid();
        var session = new StagedNativeRecoverySession(binding.DriverInstanceId, 18, 42);
        var live = new StagedNativeRecordReplay(binding, operation, false);
        foreach (var record in new[] { live with { Binding = binding with { DriverInstanceId = Guid.NewGuid() } },
            live with { Binding = binding with { ConnectionEpoch = 19 } }, live with { OperationId = Guid.Empty } })
            Assert.Throws<IOException>(() => session.ReconcileReplay(binding.DriverInstanceId, 18, true, true, [record]));
        Assert.Throws<IOException>(() => session.ReconcileReplay(binding.DriverInstanceId, 18, true, true,
            [live, live with { LastHandleCleanedUp = true }]));
        var records = new[] { live };
        var proof = session.ReconcileReplay(binding.DriverInstanceId, 18, true, true, records);
        records[0] = live with { LastHandleCleanedUp = true };
        Assert.Throws<IOException>(() => proof.RequireExactLifetimeEnded(binding, operation));
    }

    [Fact]
    public async Task Successful_tracking_is_nonblocking_but_older_saves_stay_below_the_native_delete_floor()
    {
        var journal = Journal(); var destination = Destination(); var old = Guid.NewGuid();
        long oldGeneration = await Allocate(journal, destination, old);
        var operation = Guid.NewGuid(); var binding = Binding() with { OsBootSequence = 42 };
        var native = await NativeCreateIntent(journal, destination, binding, operation);
        using (var turn = await journal.EnterDestinationCommitTurnAsync(destination,
            StagedDestinationTurnPurpose.Reconciliation, CancellationToken.None))
            Assert.Equal(StagedPublicDeleteState.Admitted,
                (await journal.RecordNativeDeleteOnCloseCreateResultAsync(turn, binding, operation, true, true)).State);
        using (var turn = await journal.EnterDestinationCommitTurnAsync(destination,
            StagedDestinationTurnPurpose.PhysicalCommit, CancellationToken.None))
            await Assert.ThrowsAsync<IOException>(() => journal.BeginDestinationPublicationAsync(turn, Guid.NewGuid(), old,
                oldGeneration, _publicIdentity, _temporaryIdentity, 0, StagedTransferJournal.EmptySha256Hex, CancellationToken.None));
        var successor = Guid.NewGuid(); long generation = await Allocate(journal, destination, successor);
        Assert.True(generation > native.Generation);
        await Publish(journal, destination, successor, generation);
    }

    [Fact]
    public async Task Acceptance_replay_cannot_clear_exceptional_hold_or_contradict_the_original_ntfs_result()
    {
        var journal = Journal(); var destination = Destination(); var operation = Guid.NewGuid();
        var binding = Binding() with { OsBootSequence = 42 };
        await NativeCreateIntent(journal, destination, binding, operation);
        using var turn = await journal.EnterDestinationCommitTurnAsync(destination,
            StagedDestinationTurnPurpose.Reconciliation, CancellationToken.None);
        await journal.RecordNativeDeleteOnCloseCreateResultAsync(turn, binding, operation, true, false);
        Assert.Equal(StagedPublicDeleteState.AcceptedUnresolved,
            (await journal.RecordNativeDeleteOnCloseCreateResultAsync(turn, binding, operation, true, true)).State);
        await Assert.ThrowsAsync<IOException>(() => journal.RecordNativeDeleteOnCloseCreateResultAsync(turn, binding, operation, false, false));
        await Assert.ThrowsAsync<IOException>(() => journal.BeginPublicDeleteDispositionAsync(turn, binding, Guid.NewGuid(), CancellationToken.None));
        await Assert.ThrowsAsync<IOException>(() => journal.RecordPublicDeleteDispositionResultAsync(turn, binding, operation, true));
        await Assert.ThrowsAsync<IOException>(() => journal.RetirePublicDeleteReceiptAsync(turn, binding, CancellationToken.None));
    }

    [Fact]
    public async Task Failed_native_create_releases_the_guard_and_ordinary_clear_never_cancels_a_native_on_close_intent()
    {
        var journal = Journal(); var destination = Destination(); var failedOperation = Guid.NewGuid();
        var failed = Binding() with { OsBootSequence = 42 };
        await NativeCreateIntent(journal, destination, failed, failedOperation);
        using (var turn = await journal.EnterDestinationCommitTurnAsync(destination,
            StagedDestinationTurnPurpose.Reconciliation, CancellationToken.None))
            Assert.Equal(StagedPublicDeleteState.Failed,
                (await journal.RecordNativeDeleteOnCloseCreateResultAsync(turn, failed, failedOperation, false, false)).State);
        using (await journal.EnterDestinationCommitTurnAsync(destination, StagedDestinationTurnPurpose.PhysicalCommit,
            CancellationToken.None)) { }
        var operation = Guid.NewGuid(); var native = Binding() with { OsBootSequence = 42 };
        await NativeCreateIntent(journal, destination, native, operation);
        using (var turn = await journal.EnterDestinationCommitTurnAsync(destination,
            StagedDestinationTurnPurpose.Reconciliation, CancellationToken.None))
            await journal.RecordNativeDeleteOnCloseCreateResultAsync(turn, native, operation, true, true);
        var ordinary = Binding(5678); await Admit(journal, destination, ordinary);
        await Accept(journal, destination, ordinary, Guid.NewGuid());
        using (var turn = await journal.EnterDestinationCommitTurnAsync(destination,
            StagedDestinationTurnPurpose.Reconciliation, CancellationToken.None))
        {
            Guid clear = Guid.NewGuid();
            await journal.BeginPublicDeleteClearAsync(turn, clear, _publicIdentity, CancellationToken.None);
            await journal.RecordPublicDeleteClearResultAsync(turn, clear, _publicIdentity, true);
        }
        var head = (await journal.ReadDestinationHeadAsync(destination, CancellationToken.None))!;
        Assert.Equal(StagedPublicDeleteState.Admitted, head.Deletes.Single(d => d.Binding == native).State);
        Assert.Equal(StagedPublicDeleteState.Canceled, head.Deletes.Single(d => d.Binding == ordinary).State);
    }

    [Theory]
    [InlineData("ordinary-kind")]
    [InlineData("missing-boot")]
    [InlineData("rejected-unresolved")]
    [InlineData("unknown-kind")]
    public async Task Malformed_native_intents_are_never_reinterpreted_as_publishable_ordinary_deletes(string mutation)
    {
        var journal = Journal(); var destination = Destination();
        await NativeCreateIntent(journal, destination, Binding() with { OsBootSequence = 42 }, Guid.NewGuid());
        string path = Assert.Single(Directory.GetFiles(JournalPath, "destination-*.state"));
        var head = JsonNode.Parse(await File.ReadAllTextAsync(path))!.AsObject();
        var delete = head["Deletes"]![0]!;
        switch (mutation)
        {
            case "ordinary-kind": delete["Kind"] = 0; break;
            case "missing-boot": delete["Binding"]!["OsBootSequence"] = null; break;
            case "rejected-unresolved": delete["NativeCreateAccepted"] = false; break;
            case "unknown-kind": delete["Kind"] = 999; break;
        }
        await File.WriteAllTextAsync(path, head.ToJsonString());
        await Assert.ThrowsAsync<InvalidDataException>(() => journal.EnterDestinationCommitTurnAsync(destination,
            StagedDestinationTurnPurpose.PhysicalCommit, CancellationToken.None));
    }

    [Fact]
    public void Destination_key_joins_case_insensitive_aliases_and_keeps_full_volume_parent_identity()
    {
        Assert.Equal(Destination(), Destination("DOCUMENT.TXT"));
        Assert.Equal(Destination().GetHashCode(), Destination("DOCUMENT.TXT").GetHashCode());
        Assert.Equal("document.txt", Destination().CanonicalLeaf);
        Assert.Equal("DOCUMENT.TXT", Destination("DOCUMENT.TXT").CanonicalLeaf);
        // Raw serialization addresses differ. Existing concurrent-alias and
        // reopen tests assert the stronger property: one actual durable head.
        Assert.NotEqual(Destination().StorageKey, Destination("DOCUMENT.TXT").StorageKey);
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

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task Exact_unicode_leaves_share_a_head_only_under_the_windows_insensitive_bucket(bool sensitive)
    {
        var journal = Journal();
        var first = Destination("MiXeD-é.txt", sensitive);
        var second = Destination("MIXED-É.TXT", sensitive);
        Assert.Equal("MiXeD-é.txt", first.CanonicalLeaf);
        Assert.Equal("MIXED-É.TXT", second.CanonicalLeaf);
        Assert.Equal(!sensitive, first == second);
        Assert.Equal(1, await Allocate(journal, first, Guid.NewGuid()));
        Assert.Equal(sensitive ? 1 : 2, await Allocate(journal, second, Guid.NewGuid()));
        var reopened = Journal();
        var heads = await reopened.ReadDestinationHeadsAsync(CancellationToken.None);
        Assert.Equal(sensitive ? 2 : 1, heads.Count);
        Assert.Equal(sensitive ? 1 : 2,
            (await reopened.ReadDestinationHeadAsync(second, CancellationToken.None))!.MaxAllocated);
        Assert.Contains(heads, head => head.Destination.CanonicalLeaf == "MiXeD-é.txt");
    }

    [Fact]
    public async Task Legacy_folded_head_is_reused_without_inventing_an_alias_head_after_restart()
    {
        var folded = Destination("DOCUMENT.TXT");
        var journal = Journal();
        Assert.Equal(1, await Allocate(journal, folded, Guid.NewGuid()));
        string originalPath = Assert.Single(Directory.GetFiles(JournalPath, "destination-*.state"));
        Assert.EndsWith("destination-" + folded.StorageKey + ".state", originalPath);
        var reopened = Journal();
        Assert.Equal(2, await Allocate(reopened, Destination(), Guid.NewGuid()));
        Assert.Equal(originalPath, Assert.Single(Directory.GetFiles(JournalPath, "destination-*.state")));
        var head = (await reopened.ReadDestinationHeadAsync(Destination(), CancellationToken.None))!;
        Assert.Equal("DOCUMENT.TXT", head.Destination.CanonicalLeaf);
        Assert.Equal(folded.MountManagerVolumeId, head.Destination.MountManagerVolumeId);
        Assert.Equal(2, head.MaxAllocated);
    }

    [Fact]
    public async Task Equivalent_duplicate_heads_fail_closed_for_discovery_lookup_and_allocation()
    {
        var journal = Journal();
        var lower = Destination();
        await Allocate(journal, lower, Guid.NewGuid());
        string originalPath = Assert.Single(Directory.GetFiles(JournalPath, "destination-*.state"));
        string original = await File.ReadAllTextAsync(originalPath);
        var duplicate = JsonNode.Parse(original)!;
        var upper = Destination("DOCUMENT.TXT");
        duplicate["Destination"]!["CanonicalLeaf"] = upper.CanonicalLeaf;
        duplicate["Locator"] = Locator(upper.CanonicalLeaf);
        string duplicatePath = Path.Combine(JournalPath, "destination-" + upper.StorageKey + ".state");
        await File.WriteAllTextAsync(duplicatePath, duplicate.ToJsonString());
        var reopened = Journal();
        await Assert.ThrowsAsync<InvalidDataException>(() => reopened.ReadDestinationHeadsAsync(CancellationToken.None));
        await Assert.ThrowsAsync<InvalidDataException>(() => reopened.ReadDestinationHeadAsync(lower, CancellationToken.None));
        await Assert.ThrowsAsync<InvalidDataException>(() => Allocate(reopened, upper, Guid.NewGuid()));
        Assert.Equal(original, await File.ReadAllTextAsync(originalPath));
        Assert.Equal(2, Directory.GetFiles(JournalPath, "destination-*.state").Length);
    }

    [Fact]
    public async Task Alias_turns_serialize_while_an_unrelated_leaf_continues()
    {
        var journal = Journal();
        await Allocate(journal, Destination(), Guid.NewGuid());
        using var cancellation = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        var held = await journal.EnterDestinationCommitTurnAsync(Destination(),
            StagedDestinationTurnPurpose.Reconciliation, cancellation.Token);
        var alias = journal.EnterDestinationCommitTurnAsync(Destination("DOCUMENT.TXT"),
            StagedDestinationTurnPurpose.Allocation, cancellation.Token);
        try
        {
            Assert.False(alias.IsCompleted);
            using (var other = await journal.EnterDestinationCommitTurnAsync(Destination("unrelated.txt"),
                       StagedDestinationTurnPurpose.Allocation, cancellation.Token))
                Assert.Equal(1, await journal.ReserveSaveGenerationAsync(other, Guid.NewGuid(),
                    Locator("unrelated.txt"), 0, cancellation.Token));
            Assert.False(alias.IsCompleted);
        }
        finally { held.Dispose(); }
        using var acquired = await alias;
        Assert.Equal(2, await journal.ReserveSaveGenerationAsync(acquired, Guid.NewGuid(),
            Locator("DOCUMENT.TXT"), 0, cancellation.Token));
        Assert.Equal(2, (await journal.ReadDestinationHeadAsync(Destination(), cancellation.Token))!.MaxAllocated);
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

    [Theory]
    [InlineData(false, 0, false)]
    [InlineData(true, 0, false)]
    [InlineData(true, -1073741790, false)]
    [InlineData(true, -1073741536, true)]
    public async Task Relay_intent_retains_exact_native_result_without_replaying_or_losing_its_generation(
        bool deleting, int nativeStatus, bool notForwarded)
    {
        var journal = Journal(); var destination = Destination();
        using (var bind = await journal.EnterDestinationCommitTurnAsync(destination,
                   StagedDestinationTurnPurpose.Allocation, CancellationToken.None))
            await journal.CapturePublicOpenHeadAsync(bind, _publicIdentity, Locator(),
                Observation(destination, _publicIdentity), CancellationToken.None);
        var binding = Binding() with { OsBootSequence = 42 };
        var original = new StagedPublicRelayIntent(Guid.NewGuid(), Guid.NewGuid(), Guid.NewGuid(), 1,
            0, null, 13, deleting ? 1u : 0u, 1, 0x10000, 1234);
        Guid operation = Guid.NewGuid();
        using (var turn = await journal.EnterDestinationCommitTurnAsync(destination,
                   StagedDestinationTurnPurpose.Reconciliation, CancellationToken.None))
        {
            var first = await journal.BeginPublicRelayAsync(turn, binding, operation, original,
                Observation(destination, _publicIdentity), CancellationToken.None);
            Assert.Equal(deleting ? 1 : 0, first.Generation);
            Assert.Equal(first, await journal.BeginPublicRelayAsync(turn, binding, operation, original,
                Observation(destination, _publicIdentity), CancellationToken.None));
        }
        var reopened = Journal();
        var pending = (await reopened.ReadDestinationHeadAsync(destination, CancellationToken.None))!;
        Assert.Equal(operation, pending.PendingCommit!.OperationId);
        Assert.Null(Assert.Single(pending.PublicRelayReceipts!).NativeStatus);
        using (var turn = await reopened.EnterDestinationCommitTurnAsync(destination,
                   StagedDestinationTurnPurpose.Reconciliation, CancellationToken.None))
        {
            var recorded = await reopened.RecordPublicRelayResultAsync(turn, binding, operation, original,
                nativeStatus, notForwarded);
            Assert.Equal(nativeStatus, recorded.NativeStatus); Assert.Equal(notForwarded, recorded.NotForwarded);
            Assert.Equal(recorded, await reopened.RecordPublicRelayResultAsync(turn, binding, operation, original,
                nativeStatus, notForwarded));
            await Assert.ThrowsAsync<IOException>(() => reopened.RecordPublicRelayResultAsync(turn, binding,
                operation, original, nativeStatus == 0 ? -1 : 0, false));
        }
        var result = (await Journal().ReadDestinationHeadAsync(destination, CancellationToken.None))!;
        Assert.Null(result.PendingCommit); Assert.Equal(deleting ? 1 : 0, result.MaxAllocated);
        Assert.Equal(0, result.CommittedDelete);
        if (deleting)
            Assert.Equal(notForwarded ? StagedPublicDeleteState.Canceled :
                nativeStatus >= 0 ? StagedPublicDeleteState.Accepted : StagedPublicDeleteState.Failed,
                Assert.Single(result.Deletes).State);
        else Assert.Empty(result.Deletes);
    }

    [Theory]
    [InlineData(false, false)]
    [InlineData(false, true)]
    [InlineData(true, false)]
    [InlineData(true, true)]
    public async Task Native_false_no_op_has_durable_intent_without_delete_generation_and_preserves_scheduled_state(
        bool scheduledOnClose, bool ntfsSucceeded)
    {
        var journal = Journal(); var destination = Destination();
        using (var bind = await journal.EnterDestinationCommitTurnAsync(destination,
                   StagedDestinationTurnPurpose.Allocation, CancellationToken.None))
        {
            var captured = await journal.CapturePublicOpenHeadAsync(bind, _publicIdentity, Locator(),
                Observation(destination, _publicIdentity), CancellationToken.None);
            Assert.Equal(0, captured.MaxAllocated); Assert.Null(captured.CurrentSaveTransferId);
            Assert.Equal(0, captured.LatestPublished); Assert.Null(captured.PublishedIdentity);
            Assert.Empty(captured.Deletes);
        }
        if (scheduledOnClose)
            await NativeCreateIntent(journal, destination, Binding() with { OsBootSequence = 42 }, Guid.NewGuid());
        var before = (await journal.ReadDestinationHeadAsync(destination, CancellationToken.None))!;
        Guid operation = Guid.NewGuid();
        using (var turn = await journal.EnterDestinationCommitTurnAsync(destination,
                   StagedDestinationTurnPurpose.Reconciliation, CancellationToken.None))
            await journal.BeginPublicDeleteClearAsync(turn, operation, _publicIdentity, CancellationToken.None,
                Observation(destination, _publicIdentity));
        var restarted = Journal();
        var pending = (await restarted.ReadDestinationHeadAsync(destination, CancellationToken.None))!;
        Assert.Equal(before.MaxAllocated, pending.MaxAllocated); Assert.Equal(before.Deletes, pending.Deletes);
        Assert.Equal(StagedDestinationMutation.ClearDisposition, pending.PendingCommit!.Mutation);
        Assert.Equal(operation, pending.PendingCommit.OperationId); Assert.Equal(0, pending.PendingCommit.Generation);
        using var cancel = new CancellationTokenSource();
        var held = restarted.EnterDestinationCommitTurnAsync(destination, StagedDestinationTurnPurpose.PhysicalCommit, cancel.Token);
        Assert.False(held.IsCompleted);
        using (var turn = await restarted.EnterDestinationCommitTurnAsync(destination,
                   StagedDestinationTurnPurpose.Reconciliation, CancellationToken.None))
        {
            await Assert.ThrowsAsync<IOException>(() => restarted.RecordPublicDeleteClearResultAsync(turn,
                operation, _publicIdentity with { FileIdLow = 99 }, ntfsSucceeded));
            await restarted.RecordPublicDeleteClearResultAsync(turn, operation, _publicIdentity, ntfsSucceeded);
            await restarted.RecordPublicDeleteClearResultAsync(turn, operation, _publicIdentity, ntfsSucceeded);
        }
        var after = (await Journal().ReadDestinationHeadAsync(destination, CancellationToken.None))!;
        Assert.Null(after.PendingCommit); Assert.Equal(before.MaxAllocated, after.MaxAllocated);
        Assert.Equal(before.Deletes, after.Deletes); Assert.Equal(before.CommittedDelete, after.CommittedDelete);
        Assert.Equal(ntfsSucceeded, after.LastMutationResult!.Succeeded);
        if (scheduledOnClose)
        {
            Assert.Equal(StagedPublicDeleteState.AcceptedUnresolved, Assert.Single(after.Deletes).State);
            Assert.False(held.IsCompleted); cancel.Cancel();
            await Assert.ThrowsAnyAsync<OperationCanceledException>(() => held);
        }
        else
        {
            using var resumed = await held.WaitAsync(TimeSpan.FromSeconds(10));
            Assert.Equal(StagedDestinationTurnPurpose.PhysicalCommit, resumed.Purpose);
        }
    }

    [Theory]
    [InlineData(0)]
    [InlineData(1)]
    [InlineData(2)]
    [InlineData(3)]
    [InlineData(4)]
    [InlineData(5)]
    public async Task Native_no_op_without_provisional_intent_refuses_incomplete_or_changed_link_evidence(int change)
    {
        var journal = Journal(); var destination = Destination();
        using (var bind = await journal.EnterDestinationCommitTurnAsync(destination,
                   StagedDestinationTurnPurpose.Allocation, CancellationToken.None))
            await journal.CapturePublicOpenHeadAsync(bind, _publicIdentity, Locator(),
                Observation(destination, _publicIdentity), CancellationToken.None);
        var observed = Observation(destination, _publicIdentity);
        StagedDestinationNameObservation? invalid = change switch
        {
            0 => null,
            1 => observed with { CompleteEnumeration = false },
            2 => observed with { ParentBefore = _temporaryIdentity },
            3 => observed with { ParentAfter = _temporaryIdentity },
            4 => observed with { PublicIdentity = null },
            _ => observed with { Destination = Destination("other.txt") }
        };
        string statePath = Assert.Single(Directory.GetFiles(JournalPath, "destination-*.state"));
        byte[] before = await File.ReadAllBytesAsync(statePath);
        using var turn = await journal.EnterDestinationCommitTurnAsync(destination,
            StagedDestinationTurnPurpose.Reconciliation, CancellationToken.None);
        await Assert.ThrowsAsync<IOException>(() => journal.BeginPublicDeleteClearAsync(turn,
            Guid.NewGuid(), _publicIdentity, CancellationToken.None, invalid));
        Assert.Equal(before, await File.ReadAllBytesAsync(statePath));
        Assert.Null((await journal.ReadDestinationHeadAsync(destination, CancellationToken.None))!.PendingCommit);
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

    [Fact]
    public async Task Transfer_ids_cannot_cross_save_and_delete_roles_and_empty_intents_require_the_empty_digest()
    {
        var journal = Journal(); var destination = Destination(); var save = Guid.NewGuid();
        await Allocate(journal, destination, save);
        var binding = Binding();
        using (var turn = await journal.EnterDestinationCommitTurnAsync(destination,
            StagedDestinationTurnPurpose.Allocation, CancellationToken.None))
        {
            await Assert.ThrowsAsync<IOException>(() => journal.AdmitPublicDeleteAsync(turn,
                binding with { TransferId = save }, Locator(), 0, CancellationToken.None));
            await journal.AdmitPublicDeleteAsync(turn, binding, Locator(), 0, CancellationToken.None);
            await Assert.ThrowsAsync<IOException>(() => journal.ReserveSaveGenerationAsync(turn,
                binding.TransferId, Locator(), 0, CancellationToken.None));
        }
        using var physical = await journal.EnterDestinationCommitTurnAsync(destination,
            StagedDestinationTurnPurpose.PhysicalCommit, CancellationToken.None);
        await Assert.ThrowsAsync<ArgumentException>(() => journal.BeginDestinationPublicationAsync(physical,
            Guid.NewGuid(), save, 1, _publicIdentity, _temporaryIdentity, 0, new string('A', 64), CancellationToken.None));
        Assert.Null((await journal.ReadDestinationHeadAsync(destination, CancellationToken.None))!.PendingCommit);
    }
}
