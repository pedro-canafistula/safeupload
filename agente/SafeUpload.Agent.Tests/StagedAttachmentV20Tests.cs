using System.Text.Json;
using SafeUpload.Agent.Core.Domain;
using SafeUpload.Agent.Service.Interception;

namespace SafeUpload.Agent.Tests;

public sealed class StagedAttachmentV20Tests : IDisposable
{
    private const string RequestorSid = "S-1-5-21-111-222-333-1000";
    private const long ProcessCreationTime = 638953632000000000;
    private const uint RequiredCapabilities = 0x3f;

    [Fact]
    public async Task Ordinary_empty_profile_rejects_old_capabilities_before_accepting_an_epoch()
    {
        string directory = Path.Combine(_workspace.Root, "ordinary-empty-profile");
        var journal = new StagedTransferJournal(directory);
        Guid driver = Guid.NewGuid();
        Assert.Equal(StagedDriverEpochReconcileV20.Rejected,
            await journal.ReconcileDriverInstanceV20Async(driver, 0x1f, CancellationToken.None));
        Assert.False(File.Exists(Path.Combine(directory, "driver-epoch.state")));
        Assert.Equal(StagedDriverEpochReconcileV20.Active,
            await journal.ReconcileDriverInstanceV20Async(driver, RequiredCapabilities, CancellationToken.None));
        Assert.Equal(3u, SafeUpload.Agent.Minifilter.StageV19Result.Sealed);
        Assert.Equal(2u, SafeUpload.Agent.Minifilter.StageV19Result.ReservedEmptyHeld);
    }

    [Theory]
    [InlineData("zero")]
    [InlineData("nonempty")]
    [InlineData("unknown-epoch")]
    [InlineData("discard")]
    [InlineData("replacement")]
    [InlineData("missing")]
    public async Task Legacy_empty_migration_requires_fresh_exact_content_and_reconciled_obligations(string shape)
    {
        Fixture fixture = await CreateFixtureAsync(empty: true);
        await CompleteAttachmentAsync(fixture, firstRequestId: 701);
        Assert.Equal(17u, await ApplyAsync(fixture, 19, 704));
        TransferJournalEntry sealedEntry = await fixture.Journal.SealAsync(fixture.Transfer.TransferId,
            fixture.Transfer.ProcessId, fixture.Transfer.StagePath, CancellationToken.None, fixture.Version);
        // Model an actual old manifest: persisted enum number 11 and no digest.
        string manifest = Path.Combine(fixture.JournalDirectory, fixture.Transfer.TransferId.ToString("N") + ".json");
        TransferJournalEntry legacy = sealedEntry with
        {
            State = TransferJournalState.LegacyEmptyHeld,
            Sha256Hex = null,
            StateHistory = sealedEntry.StateHistory.Select(change => change.State == TransferJournalState.Sealed
                ? change with { State = TransferJournalState.LegacyEmptyHeld } : change).ToArray()
        };
        if (shape == "unknown-epoch") legacy = legacy with { DriverInstanceId = Guid.NewGuid() };
        if (shape == "discard") legacy = legacy with
        {
            DiscardReservationId = fixture.Transfer.TransferId,
            DiscardKind = StagedDiscardKind.OwnerExitEmpty,
            DiscardRequestedAtUtc = DateTimeOffset.UtcNow
        };
        await File.WriteAllTextAsync(manifest, JsonSerializer.Serialize(legacy));
        if (shape == "nonempty") await File.WriteAllTextAsync(fixture.Transfer.StagePath, "CPF: 529.982.247-25");
        if (shape == "replacement")
        {
            File.Move(fixture.Transfer.StagePath, fixture.Transfer.StagePath + ".retained");
            await File.WriteAllBytesAsync(fixture.Transfer.StagePath, []);
        }
        if (shape == "missing") File.Delete(fixture.Transfer.StagePath);
        if (shape is "replacement" or "missing")
        {
            await Assert.ThrowsAnyAsync<IOException>(() => fixture.Journal.TryMigrateLegacyEmptyAsync(
                fixture.Transfer.TransferId, CancellationToken.None));
            await fixture.Journal.RetainInterruptedAsync(CancellationToken.None);
            Assert.Equal(TransferJournalState.LegacyEmptyHeld,
                (await fixture.Journal.ReadAsync(fixture.Transfer.TransferId, CancellationToken.None)).State);
        }
        else
        {
            TransferJournalEntry migrated = await fixture.Journal.TryMigrateLegacyEmptyAsync(
                fixture.Transfer.TransferId, CancellationToken.None);
            Assert.Equal(shape is "zero" or "nonempty" ? TransferJournalState.Sealed : TransferJournalState.LegacyEmptyHeld,
                migrated.State);
            Assert.Equal(legacy.DestinationGeneration, migrated.DestinationGeneration);
            if (shape is "zero" or "nonempty")
            {
                byte[] bytes = await File.ReadAllBytesAsync(fixture.Transfer.StagePath);
                Assert.Equal(bytes.LongLength, migrated.SealedLength);
                Assert.Equal(Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(bytes)), migrated.Sha256Hex);
            }
        }
        Assert.False(File.Exists(fixture.Transfer.DestinationPath));
    }
    private readonly TestWorkspace _workspace = new();

    public void Dispose() => _workspace.Dispose();

    [Fact]
    public async Task V20_attachment_order_blocks_seal_until_handle_receipt_and_allows_positive_save()
    {
        Fixture fixture = await CreateFixtureAsync(empty: false);

        await Assert.ThrowsAsync<IOException>(() => ApplyAsync(fixture, 15, 100));
        await Assert.ThrowsAsync<IOException>(() => fixture.Journal.SealAsync(
            fixture.Transfer.TransferId, fixture.Transfer.ProcessId, fixture.Transfer.StagePath,
            CancellationToken.None, fixture.Version));

        Assert.Equal(6u, await ApplyAsync(fixture, 12, 101));
        await Assert.ThrowsAsync<IOException>(() => ApplyAsync(fixture, 13, 101));
        Assert.Equal(7u, await ApplyAsync(fixture, 13, 102));
        await Assert.ThrowsAsync<IOException>(() => ApplyAsync(fixture, 14, 102));
        Assert.Equal(10u, await ApplyAsync(fixture, 14, 103));
        Assert.Equal(16u, await ApplyAsync(fixture, 15, 104));
        await Assert.ThrowsAsync<IOException>(() => fixture.Journal.SealAsync(
            fixture.Transfer.TransferId, fixture.Transfer.ProcessId, fixture.Transfer.StagePath,
            CancellationToken.None, fixture.Version));

        Assert.Equal(17u, await ApplyAsync(fixture, 19, 105));
        Assert.Equal(17u, await ApplyAsync(fixture, 19, 105));
        TransferJournalEntry sealedEntry = await fixture.Journal.SealAsync(
            fixture.Transfer.TransferId, fixture.Transfer.ProcessId, fixture.Transfer.StagePath,
            CancellationToken.None, fixture.Version);
        Assert.Equal(TransferJournalState.Sealed, sealedEntry.State);
        Assert.True(sealedEntry.SealedLength > 0);

        TransferJournalEntry inspecting = await fixture.Journal.TransitionAsync(
            fixture.Transfer.TransferId, TransferJournalState.Sealed, TransferJournalState.Inspecting,
            null, CancellationToken.None);
        Assert.Equal(TransferJournalState.Inspecting, inspecting.State);
    }

    [Fact]
    public async Task V20_retire_unexposed_uses_exact_background_delete_ack_and_replays_op16()
    {
        Fixture fixture = await CreateFixtureAsync(empty: false);
        Assert.Equal(6u, await ApplyAsync(fixture, 12, 201));
        Assert.Equal(7u, await ApplyAsync(fixture, 13, 202));

        Assert.Null(await ApplyAsync(fixture, 16, 203));
        TransferJournalEntry pending = await fixture.Journal.ReadAsync(
            fixture.Transfer.TransferId, CancellationToken.None);
        Assert.Equal(TransferJournalState.DiscardPending, pending.State);
        Assert.Equal(StagedDiscardKind.RetireUnexposed, pending.DiscardKind);
        Assert.Equal(StagedAttachmentStateV20.RetireUnexposedPending, pending.AttachmentStateV20);
        Assert.True(File.Exists(fixture.Transfer.StagePath));

        StagedDiscardRequest[] work = (await fixture.Journal.ReadDiscardPendingAsync(CancellationToken.None)).ToArray();
        StagedDiscardRequest cleanup = Assert.Single(work);
        Assert.Equal(StagedDiscardKind.RetireUnexposed, cleanup.Kind);
        Assert.Equal(fixture.Version, cleanup.Version);
        Assert.Equal(StagedDiscardStatus.Acknowledged,
            await fixture.Journal.CompleteDiscardAsync(cleanup, CancellationToken.None));
        Assert.False(File.Exists(fixture.Transfer.StagePath));

        Assert.Equal(12u, await ApplyAsync(fixture, 16, 203));
        TransferJournalEntry terminal = await fixture.Journal.ReadAsync(
            fixture.Transfer.TransferId, CancellationToken.None);
        Assert.Equal(StagedAttachmentStateV20.RetiredUnexposed, terminal.AttachmentStateV20);
        Assert.NotNull(terminal.DiscardAcknowledgedAtUtc);
    }

    [Fact]
    public async Task V20_retire_attached_private_requires_measured_zero_and_exact_ack()
    {
        Fixture empty = await CreateFixtureAsync(empty: true);
        await CompleteAttachmentAsync(empty, firstRequestId: 301);
        Assert.Null(await ApplyAsync(empty, 18, 305));
        StagedDiscardRequest pending = Assert.Single(
            await empty.Journal.ReadDiscardPendingAsync(CancellationToken.None));
        Assert.Equal(StagedDiscardKind.RetireAttachedPrivate, pending.Kind);
        Assert.Equal(StagedDiscardStatus.Acknowledged,
            await empty.Journal.CompleteDiscardAsync(pending, CancellationToken.None));
        Assert.Equal(15u, await ApplyAsync(empty, 18, 305));
        Assert.False(File.Exists(empty.Transfer.StagePath));

        Fixture nonempty = await CreateFixtureAsync(empty: false);
        await CompleteAttachmentAsync(nonempty, firstRequestId: 401);
        await Assert.ThrowsAsync<IOException>(() => ApplyAsync(nonempty, 18, 405));
        Assert.True(File.Exists(nonempty.Transfer.StagePath));
        Assert.Equal(TransferJournalState.Allocated,
            (await nonempty.Journal.ReadAsync(nonempty.Transfer.TransferId, CancellationToken.None)).State);
    }

    [Fact]
    public async Task V20_epoch_drain_replay_is_exact_and_does_not_reauthorize_a_different_tuple()
    {
        Fixture fixture = await CreateFixtureAsync(empty: false);
        StagedTransferJournal journal = fixture.Journal;
        Guid driver = fixture.DriverInstanceId;
        string directory = fixture.JournalDirectory;

        Assert.False(await journal.DrainDriverInstanceV20Async(driver, 501, 601, CancellationToken.None));
        Assert.Equal(6u, await ApplyAsync(fixture, 12, 501));
        Assert.Equal(7u, await ApplyAsync(fixture, 13, 502));
        Assert.Null(await ApplyAsync(fixture, 16, 503));
        StagedDiscardRequest cleanup = Assert.Single(
            await journal.ReadDiscardPendingAsync(CancellationToken.None));
        Assert.Equal(StagedDiscardStatus.Acknowledged,
            await journal.CompleteDiscardAsync(cleanup, CancellationToken.None));
        Assert.True(await journal.DrainDriverInstanceV20Async(driver, 504, 604, CancellationToken.None));
        await Assert.ThrowsAsync<IOException>(() => ApplyAsync(fixture, 19, 505));
        var restarted = new StagedTransferJournal(directory);
        Assert.Equal(StagedDriverEpochReconcileV20.DrainReplayOnly,
            await restarted.ReconcileDriverInstanceV20Async(driver, RequiredCapabilities, CancellationToken.None));
        Assert.False(await restarted.DrainDriverInstanceV20Async(driver, 503, 604, CancellationToken.None));
        Assert.False(await restarted.DrainDriverInstanceV20Async(driver, 504, 605, CancellationToken.None));
        Assert.True(await restarted.DrainDriverInstanceV20Async(driver, 504, 604, CancellationToken.None));

        Guid nextDriver = Guid.NewGuid();
        Assert.Equal(StagedDriverEpochReconcileV20.Active,
            await restarted.ReconcileDriverInstanceV20Async(nextDriver, RequiredCapabilities, CancellationToken.None));
        Assert.Equal(StagedDriverEpochReconcileV20.Active,
            await restarted.ReconcileDriverInstanceV20Async(nextDriver, RequiredCapabilities, CancellationToken.None));
    }

    [Fact]
    public async Task V20_epoch_rejects_unpaired_drain_receipts_without_rewriting_them()
    {
        DateTimeOffset accepted = new(2026, 10, 11, 12, 0, 0, TimeSpan.Zero);
        DateTimeOffset drained = accepted.AddSeconds(1);
        var malformed = new[]
        {
            new EpochRecord(Guid.NewGuid(), 77UL, null, accepted, null),
            new EpochRecord(Guid.NewGuid(), null, 88UL, accepted, null),
            new EpochRecord(Guid.NewGuid(), 77UL, 88UL, accepted, null),
            new EpochRecord(Guid.NewGuid(), null, null, accepted, drained),
            new EpochRecord(Guid.NewGuid(), 77UL, 88UL, accepted, accepted.AddTicks(-1)),
            new EpochRecord(Guid.NewGuid(), 0UL, 88UL, accepted, drained),
            new EpochRecord(Guid.NewGuid(), 77UL, 88UL, accepted,
                new DateTimeOffset(2026, 10, 11, 9, 0, 0, TimeSpan.FromHours(-3))),
        };

        for (int index = 0; index < malformed.Length; index++)
        {
            string directory = Path.Combine(_workspace.Root, $"malformed-epoch-{index}");
            // Let the journal create its directory with the same protected
            // owner and ACL used by production before the malformed file is
            // written. The bytes below stay malformed and are never rewritten.
            var journal = new StagedTransferJournal(directory);
            string path = Path.Combine(directory, "driver-epoch.state");
            string exactBytes = JsonSerializer.Serialize(malformed[index]);
            await File.WriteAllTextAsync(path, exactBytes);
            Guid requestedDriver = malformed[index].DriverInstanceId;

            await Assert.ThrowsAsync<InvalidDataException>(() =>
                journal.ReconcileDriverInstanceV20Async(requestedDriver, RequiredCapabilities, CancellationToken.None));
            await Assert.ThrowsAsync<InvalidDataException>(() =>
                journal.DrainDriverInstanceV20Async(requestedDriver, 999, 1000, CancellationToken.None));
            Assert.Equal(exactBytes, await File.ReadAllTextAsync(path));
        }
    }

    private async Task<Fixture> CreateFixtureAsync(bool empty)
    {
        string directory = Path.Combine(_workspace.Root, $"journal-{Guid.NewGuid():N}");
        var journal = new StagedTransferJournal(directory);
        string destinationDirectory = Path.Combine(_workspace.Root, "destination");
        string stageDirectory = Path.Combine(_workspace.Root, "stage");
        Directory.CreateDirectory(destinationDirectory);
        Directory.CreateDirectory(stageDirectory);
        string destination = Path.Combine(destinationDirectory, "document.txt");
        Guid id = Guid.NewGuid();
        string stage = Path.Combine(stageDirectory, id.ToString("N") + ".txt");
        if (empty) await File.WriteAllBytesAsync(stage, []);
        else await File.WriteAllTextAsync(stage, "positive v20 fixture");
        var transfer = new StagedTransfer(id, stage, destination, DestinationKind.Cloud,
            "word.exe", 1234, 1)
        {
            RequestorSid = RequestorSid,
            RequestorProcessCreationTime = ProcessCreationTime
        };
        Guid driver = Guid.NewGuid();
        Assert.Equal(StagedDriverEpochReconcileV20.Active,
            await journal.ReconcileDriverInstanceV20Async(driver, RequiredCapabilities, CancellationToken.None));
        StagedStageIdentity parentDirectory = StagedStageFile.ReadDirectoryIdentity(destinationDirectory);
        TransferJournalEntry entry = await journal.CreateAsync(transfer, CancellationToken.None,
            allocationDisposition: 2, allocationReferenceId: null, allocationReferenceKind: 0,
            driverInstanceId: driver, parentDirectoryIdentity: parentDirectory);
        var version = new StagedVersionIdentity(id, entry.DestinationGeneration, entry.StageIdentity!);
        return new Fixture(journal, directory, transfer, version, driver, parentDirectory);
    }

    private static Task<uint?> ApplyAsync(Fixture fixture, uint operation, ulong requestId) =>
        fixture.Journal.ApplyAttachmentV20Async(new StagedAttachmentRequestV20(operation, requestId,
            fixture.Version, fixture.DriverInstanceId, fixture.ParentDirectoryIdentity,
            fixture.Transfer.DestinationPath, fixture.Transfer.ProcessId),
            ownerIsLive: true, commitPolicyAllowed: true, CancellationToken.None);

    private static async Task CompleteAttachmentAsync(Fixture fixture, ulong firstRequestId)
    {
        Assert.Equal(6u, await ApplyAsync(fixture, 12, firstRequestId));
        Assert.Equal(7u, await ApplyAsync(fixture, 13, firstRequestId + 1));
        Assert.Equal(16u, await ApplyAsync(fixture, 15, firstRequestId + 2));
    }

    private sealed record Fixture(StagedTransferJournal Journal, string JournalDirectory, StagedTransfer Transfer,
        StagedVersionIdentity Version, Guid DriverInstanceId, StagedStageIdentity ParentDirectoryIdentity);

    private sealed record EpochRecord(Guid DriverInstanceId, ulong? DrainRequestId, ulong? DrainNonce,
        DateTimeOffset AcceptedAtUtc, DateTimeOffset? DrainedAtUtc);
}
