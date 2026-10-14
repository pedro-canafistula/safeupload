using SafeUpload.Agent.Core.Application;
using SafeUpload.Agent.Core.Infrastructure;
using SafeUpload.Agent.Core.Infrastructure.Extraction;
using SafeUpload.Agent.Service.Notifications;
using SafeUpload.Agent.Minifilter;
using System.Text.Json;
using SafeUpload.Agent.Core.Domain;
using SafeUpload.Agent.Service.Interception;

namespace SafeUpload.Agent.Tests;

public sealed class StagedAttachmentV20Tests : IDisposable
{
    private const string RequestorSid = "S-1-5-21-111-222-333-1000";
    private const long ProcessCreationTime = 638953632000000000;
    private const uint RequiredCapabilities = 0xbf;

    [Theory]
    [InlineData(0x1fu)]
    [InlineData(0x3fu)]
    public async Task Rename_receipt_profile_rejects_old_capabilities_before_accepting_an_epoch(uint oldCapabilities)
    {
        string directory = Path.Combine(_workspace.Root, "ordinary-empty-profile");
        var journal = new StagedTransferJournal(directory);
        Guid driver = Guid.NewGuid();
        Assert.Equal(StagedDriverEpochReconcileV20.Rejected,
            await journal.ReconcileDriverInstanceV20Async(driver, oldCapabilities, CancellationToken.None));
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

    [Theory]
    [InlineData("Clean replacement bytes.", StagedTransferOutcome.Released)]
    [InlineData("CPF: 529.982.247-25", StagedTransferOutcome.Blocked)]
    public async Task Rename_receipt_advances_occupied_generations_then_op19_seals_and_inspects(
        string content, StagedTransferOutcome outcome)
    {
        Fixture target = await CreateFixtureAsync(false, kind: DestinationKind.RemovableDrive);
        await CompleteAttachmentAsync(target, 1101);
        await ObserveAndSealAsync(target, 1104);
        Assert.Equal(StagedTransferOutcome.Released, await PublishAsync(target));
        string previousPublic = await File.ReadAllTextAsync(target.Transfer.DestinationPath);
        Assert.Equal(1, target.Version.DestinationGeneration);

        for (int expected = 2; expected <= 3; ++expected)
        {
            Fixture source = await CreateFixtureAsync(false, target, $"temporary-{expected}.tmp", content);
            await CompleteAttachmentAsync(source, (ulong)(expected * 1000));
            StagedRenameRequestV20 rename = RenameRequest(source, (ulong)(expected * 1000 + 10),
                target.Transfer.DestinationPath);
            await source.Journal.PrepareRenameAsync(source.Transfer.TransferId, rename.TransactionId,
                source.Transfer.ProcessId, rename.DestinationPath, false, CancellationToken.None, rename);
            TransferJournalEntry committed = await source.Journal.CompleteRenameAsync(source.Transfer.TransferId,
                rename.TransactionId, source.Transfer.ProcessId, rename.DestinationPath, true, CancellationToken.None, rename);
            StagedRenameReceiptV20 receipt = Assert.IsType<StagedRenameReceiptV20>(committed.LastRenameReceiptV20);
            Assert.Equal(rename, receipt.Source);
            Assert.Equal(1, receipt.Source.Version.DestinationGeneration);
            Assert.Equal(expected, receipt.DestinationGeneration);
            Assert.Equal(source.Transfer.DestinationPath, receipt.SourcePath);
            Assert.Equal(expected, committed.DestinationGeneration);
            Assert.Equal(previousPublic, await File.ReadAllTextAsync(target.Transfer.DestinationPath));

            // Reconstruct the op19 tuple from the adopted receipt. Allocation-time
            // generation/name is no longer valid; weakening op19 would fail here.
            await Assert.ThrowsAsync<IOException>(() => ApplyAsync(source, 19, rename.TransactionId + 1));
            Fixture adopted = source with { Transfer = committed.Transfer,
                Version = source.Version with { DestinationGeneration = receipt.DestinationGeneration } };
            await ObserveAndSealAsync(adopted, rename.TransactionId + 1);
            Assert.Equal(outcome, await PublishAsync(adopted));
            Assert.Equal(outcome == StagedTransferOutcome.Released ? content : previousPublic,
                await File.ReadAllTextAsync(target.Transfer.DestinationPath));
            if (outcome == StagedTransferOutcome.Blocked)
            {
                var blocked = await source.Journal.ReadAsync(source.Transfer.TransferId, CancellationToken.None);
                Assert.Equal(TransferJournalState.Blocked, blocked.State);
                Assert.Equal(StagedHandbackState.Verified, blocked.HandbackState);
                Assert.Equal(content, await File.ReadAllTextAsync(blocked.HandbackPath!));
            }
        }
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task Rename_receipt_uses_the_destination_watermark_even_when_its_name_is_absent(bool lowerTarget)
    {
        Fixture current = await CreateFixtureAsync(false);
        for (int index = 0; index < 3; ++index)
            current = await CreateFixtureAsync(false, current);
        Assert.Equal(4, current.Version.DestinationGeneration);
        Fixture source = lowerTarget ? current : await CreateFixtureAsync(false, current, "fresh-source.tmp");
        string destination = lowerTarget ? current.Transfer.DestinationPath + ".new" : current.Transfer.DestinationPath;
        Assert.False(File.Exists(destination));
        await CompleteAttachmentAsync(source, 4101);
        var rename = RenameRequest(source, 4110, destination);
        await source.Journal.PrepareRenameAsync(source.Transfer.TransferId, 4110, source.Transfer.ProcessId,
            destination, false, CancellationToken.None, rename);
        var committed = await source.Journal.CompleteRenameAsync(source.Transfer.TransferId, 4110,
            source.Transfer.ProcessId, destination, true, CancellationToken.None, rename);
        Assert.Equal(lowerTarget ? 1 : 5, committed.LastRenameReceiptV20!.DestinationGeneration);
        Fixture adopted = source with { Transfer = committed.Transfer,
            Version = source.Version with { DestinationGeneration = committed.DestinationGeneration } };
        await ObserveAndSealAsync(adopted, 4111);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task Rename_abort_or_commit_replays_the_stored_source_after_service_restart(bool commit)
    {
        Fixture target = await CreateFixtureAsync(false);
        Fixture source = await CreateFixtureAsync(false, target, "rename-source.tmp");
        await CompleteAttachmentAsync(source, 5101);
        var rename = RenameRequest(source, 5110, target.Transfer.DestinationPath);
        var prepared = await source.Journal.PrepareRenameAsync(source.Transfer.TransferId, 5110,
            source.Transfer.ProcessId, rename.DestinationPath, false, CancellationToken.None, rename);
        var restarted = new StagedTransferJournal(source.JournalDirectory);
        await restarted.RetainInterruptedAsync(CancellationToken.None);
        Assert.Equal(prepared, await restarted.ReadAsync(source.Transfer.TransferId, CancellationToken.None));
        await Assert.ThrowsAsync<IOException>(() => restarted.SealAsync(source.Transfer.TransferId,
            source.Transfer.ProcessId, source.Transfer.StagePath, CancellationToken.None, source.Version));
        var completed = await restarted.CompleteRenameAsync(source.Transfer.TransferId, 5110,
            source.Transfer.ProcessId, rename.DestinationPath, commit, CancellationToken.None, rename);
        var receipt = completed.LastRenameReceiptV20!;
        Assert.Equal(commit, receipt.Committed);
        Assert.Equal(source.Version, receipt.Source.Version);
        Assert.Equal(commit ? rename.DestinationPath : source.Transfer.DestinationPath, receipt.DestinationPath);
        Assert.Equal(commit ? 2 : source.Version.DestinationGeneration, completed.DestinationGeneration);
        if (!commit) Assert.Null(completed.NamespaceTombstones);
        restarted = new StagedTransferJournal(source.JournalDirectory);
        await restarted.RetainInterruptedAsync(CancellationToken.None);
        var recovered = await restarted.ReadAsync(source.Transfer.TransferId, CancellationToken.None);
        Assert.Equal(receipt, recovered.LastRenameReceiptV20);
        Assert.Equal(recovered, await restarted.CompleteRenameAsync(source.Transfer.TransferId, 5110,
            source.Transfer.ProcessId, rename.DestinationPath, commit, CancellationToken.None, rename));
        Assert.Equal(recovered.DestinationGeneration, receipt.DestinationGeneration);
        Fixture adopted = source with { Journal = restarted, Transfer = recovered.Transfer,
            Version = source.Version with { DestinationGeneration = receipt.DestinationGeneration } };
        await ObserveAndSealAsync(adopted, 5111);
    }

    [Fact]
    public async Task Cross_parent_rename_keeps_original_parent_evidence_and_remains_held_at_op19()
    {
        Fixture source = await CreateFixtureAsync(false);
        await CompleteAttachmentAsync(source, 8101);
        string parent = Path.Combine(_workspace.Root, "other-parent");
        Directory.CreateDirectory(parent);
        string destination = Path.Combine(parent, "moved.txt");
        var exact = RenameRequest(source, 8110, destination);
        await source.Journal.PrepareRenameAsync(source.Transfer.TransferId, 8110, source.Transfer.ProcessId,
            destination, false, CancellationToken.None, exact);
        var committed = await source.Journal.CompleteRenameAsync(source.Transfer.TransferId, 8110,
            source.Transfer.ProcessId, destination, true, CancellationToken.None, exact);
        Assert.Equal(source.ParentDirectoryIdentity, committed.ParentDirectoryIdentity);
        Assert.Equal(source.ParentDirectoryIdentity, committed.LastRenameReceiptV20!.Source.ParentDirectoryIdentity);
        Fixture adopted = source with { Transfer = committed.Transfer,
            Version = source.Version with { DestinationGeneration = committed.DestinationGeneration } };
        var refusal = await Assert.ThrowsAsync<IOException>(() => ApplyAsync(adopted, 19, 8111));
        Assert.True(StagedRequestRefusal.IsPermanent(refusal));
        await Assert.ThrowsAsync<IOException>(() => source.Journal.SealAsync(source.Transfer.TransferId,
            source.Transfer.ProcessId, source.Transfer.StagePath, CancellationToken.None, adopted.Version));
        Assert.Equal(committed, await source.Journal.ReadAsync(source.Transfer.TransferId, CancellationToken.None));
        Assert.False(File.Exists(destination));
    }

    [Theory]
    [InlineData("transaction")]
    [InlineData("transfer")]
    [InlineData("generation")]
    [InlineData("stage")]
    [InlineData("epoch")]
    [InlineData("parent")]
    [InlineData("view")]
    [InlineData("owner")]
    [InlineData("destination")]
    [InlineData("wire-name")]
    [InlineData("sealed")]
    public async Task Rename_commit_and_replay_refuse_each_altered_source_field(string field)
    {
        Fixture source = await CreateFixtureAsync(false);
        await CompleteAttachmentAsync(source, 6101);
        var exact = RenameRequest(source, 6110, source.Transfer.DestinationPath + ".renamed");
        var changed = field switch
        {
            "transaction" => exact with { TransactionId = exact.TransactionId + 1 },
            "transfer" => exact with { Version = exact.Version with { TransferId = Guid.NewGuid() } },
            "generation" => exact with { Version = exact.Version with { DestinationGeneration = 99 } },
            "stage" => exact with { Version = exact.Version with { StageIdentity = new(1, 2, 3) } },
            "epoch" => exact with { DriverInstanceId = Guid.NewGuid() },
            "parent" => exact with { ParentDirectoryIdentity = new(1, 2, 3) },
            "view" => exact with { ViewGeneration = exact.ViewGeneration + 1 },
            "owner" => exact with { OwnerProcessId = exact.OwnerProcessId + 1 },
            "destination" => exact with { DestinationPath = exact.DestinationPath + ".other" },
            "wire-name" => exact with { DestinationName = exact.DestinationName + ".other" },
            "sealed" => exact with { SealedVersion = true },
            _ => throw new ArgumentException(field)
        };
        var prepared = await source.Journal.PrepareRenameAsync(source.Transfer.TransferId, 6110,
            source.Transfer.ProcessId, exact.DestinationPath, false, CancellationToken.None, exact);
        IOException refused = await Assert.ThrowsAsync<IOException>(() => source.Journal.CompleteRenameAsync(
            source.Transfer.TransferId, 6110, source.Transfer.ProcessId, exact.DestinationPath, true,
            CancellationToken.None, changed));
        Assert.True(StagedRequestRefusal.IsPermanent(refused));
        Assert.Equal(prepared, await source.Journal.ReadAsync(source.Transfer.TransferId, CancellationToken.None));
        var committed = await source.Journal.CompleteRenameAsync(source.Transfer.TransferId, 6110,
            source.Transfer.ProcessId, exact.DestinationPath, true, CancellationToken.None, exact);
        await Assert.ThrowsAsync<IOException>(() => new StagedTransferJournal(source.JournalDirectory).CompleteRenameAsync(
            source.Transfer.TransferId, 6110, source.Transfer.ProcessId, exact.DestinationPath, true,
            CancellationToken.None, changed));
        Assert.Equal(committed, await source.Journal.ReadAsync(source.Transfer.TransferId, CancellationToken.None));
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task Rename_commit_write_failure_retries_only_unfinished_bookkeeping(bool afterReplacement)
    {
        Fixture target = await CreateFixtureAsync(false);
        Fixture source = await CreateFixtureAsync(false, target, "temporary.tmp");
        await CompleteAttachmentAsync(source, 7101);
        var exact = RenameRequest(source, 7110, target.Transfer.DestinationPath);
        bool injected = false;
        var journal = new StagedTransferJournal(source.JournalDirectory, writeObserver: (point, entry) =>
        {
            if (injected || entry.LastRenameReceiptV20 is null || point !=
                (afterReplacement ? StagedJournalWritePoint.AfterReplacement : StagedJournalWritePoint.BeforeReplacement)) return;
            injected = true;
            throw new IOException("injected rename persistence failure");
        });
        var prepared = await journal.PrepareRenameAsync(source.Transfer.TransferId, 7110,
            source.Transfer.ProcessId, exact.DestinationPath, false, CancellationToken.None, exact);
        var error = await Assert.ThrowsAsync<StagedJournalPersistenceException>(() => journal.CompleteRenameAsync(
            source.Transfer.TransferId, 7110, source.Transfer.ProcessId, exact.DestinationPath, true,
            CancellationToken.None, exact));
        Assert.True(injected);
        Assert.False(StagedRequestRefusal.IsPermanent(error));
        var restarted = new StagedTransferJournal(source.JournalDirectory);
        var durable = await restarted.ReadAsync(source.Transfer.TransferId, CancellationToken.None);
        Assert.Equal(afterReplacement, durable.LastRenameReceiptV20 is not null);
        if (!afterReplacement) Assert.Equal(prepared, durable);
        var committed = await restarted.CompleteRenameAsync(source.Transfer.TransferId, 7110,
            source.Transfer.ProcessId, exact.DestinationPath, true, CancellationToken.None, exact);
        Assert.Equal(2, committed.DestinationGeneration);
        Assert.Null(committed.NamespaceTombstones!.Previous);
        Assert.Equal(committed, await restarted.CompleteRenameAsync(source.Transfer.TransferId, 7110,
            source.Transfer.ProcessId, exact.DestinationPath, true, CancellationToken.None, exact));
    }

    private static StagedRenameRequestV20 RenameRequest(Fixture source, ulong transaction, string destination) =>
        new(transaction, source.Version, source.DriverInstanceId, source.ParentDirectoryIdentity, 42,
            source.Transfer.ProcessId, destination, false, destination);

    private static async Task ObserveAndSealAsync(Fixture fixture, ulong request)
    {
        Assert.Equal(17u, await ApplyAsync(fixture, 19, request));
        var entry = await fixture.Journal.SealAsync(fixture.Transfer.TransferId,
            fixture.Transfer.ProcessId, fixture.Transfer.StagePath, CancellationToken.None, fixture.Version);
        Assert.Equal(TransferJournalState.Sealed, entry.State);
        Assert.Equal(fixture.Version.DestinationGeneration, entry.DestinationGeneration);
    }

    private Task<StagedTransferOutcome> PublishAsync(Fixture fixture)
    {
        var inspector = new InspectionService(new LocalPolicyStore(_workspace.PolicyFile),
            new LocalQueueAuditSink(_workspace.QueueFile), ExtractorRegistry.CreateDefault(), new VerdictCache());
        var publisher = new StagedTransferPublisher(inspector, NotificationTestHub.Create(), fixture.Journal,
            Path.GetDirectoryName(fixture.Transfer.StagePath)!, new RenamePublicationGate(),
            handbackCopier: new RenameSnapshotCopier(_workspace.Root), sessionUserSidResolver: _ => RequestorSid);
        return publisher.PublishAsync(fixture.Transfer, CancellationToken.None);
    }

    private sealed class RenameSnapshotCopier(string root) : IStagedHandbackCopier
    {
        public async Task<string> CopyVerifiedAsync(StagedTransfer transfer, FileStream snapshot,
            long length, string sha256Hex, CancellationToken token)
        {
            string directory = Path.Combine(root, "handback");
            Directory.CreateDirectory(directory);
            string path = Path.Combine(directory, transfer.TransferId.ToString("N") + ".txt");
            snapshot.Position = 0;
            await using (var output = new FileStream(path, FileMode.CreateNew, FileAccess.Write, FileShare.None))
                await snapshot.CopyToAsync(output, token);
            using var proof = OpenVerifiedReadLease(transfer, path, length, sha256Hex);
            return path;
        }
        public IDisposable OpenVerifiedReadLease(StagedTransfer transfer, string path, long length, string sha256Hex)
        {
            var input = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read);
            try
            {
                string digest = Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(input));
                if (input.Length != length || digest != sha256Hex)
                    throw new IOException("The rename hand-back differs from its sealed snapshot.");
                input.Position = 0;
                return input;
            }
            catch { input.Dispose(); throw; }
        }
        public void CleanupUncommittedTemporary(StagedTransfer transfer) { }
    }

    private sealed class RenamePublicationGate : IStagedPublicationGate, IDisposable
    {
        public IDisposable Authorize(StagedTransfer transfer, string temporaryDestination, string digest) => this;
        public bool DisposeStage(Guid transferId, uint outcome, uint committedRenames) => false;
        public void Dispose() { }
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

    private async Task<Fixture> CreateFixtureAsync(bool empty, Fixture? previous = null,
        string name = "document.txt", string? content = null, DestinationKind kind = DestinationKind.Cloud)
    {
        string directory = previous?.JournalDirectory ?? Path.Combine(_workspace.Root, $"journal-{Guid.NewGuid():N}");
        var journal = previous?.Journal ?? new StagedTransferJournal(directory);
        string destinationDirectory = Path.Combine(_workspace.Root, "destination");
        string stageDirectory = Path.Combine(_workspace.Root, "stage");
        Directory.CreateDirectory(destinationDirectory);
        Directory.CreateDirectory(stageDirectory);
        string destination = Path.Combine(destinationDirectory, name);
        Guid id = Guid.NewGuid();
        string stage = Path.Combine(stageDirectory, id.ToString("N") + ".txt");
        if (empty) await File.WriteAllBytesAsync(stage, []);
        else await File.WriteAllTextAsync(stage, content ?? "positive v20 fixture");
        var transfer = new StagedTransfer(id, stage, destination, previous?.Transfer.Destination ?? kind,
            "word.exe", 1234, 1)
        {
            RequestorSid = RequestorSid,
            RequestorProcessCreationTime = ProcessCreationTime
        };
        Guid driver = previous?.DriverInstanceId ?? Guid.NewGuid();
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
