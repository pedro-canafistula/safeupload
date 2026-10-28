using System.Text.Json.Nodes;
using System.Security.AccessControl;
using SafeUpload.Agent.Service.Interception;

namespace SafeUpload.Agent.Tests;

public sealed class StagedAllocationRecoveryTests : IDisposable
{
    private readonly TestWorkspace _workspace = new();
    private const long MiB = 1024 * 1024;
    private string Stage => Path.Combine(_workspace.Root, "stage");
    private string Records => Path.Combine(Stage, ".space-reservations");
    private StagedSpaceBudget Budget()
    {
        StagedPrivateStorage.CreateDirectory(Stage);
        return new(Stage, new(true, 512 * MiB, 128 * MiB, 0), () => 2048 * MiB);
    }
    private StagedTransferJournal Journal() => new(Path.Combine(_workspace.Root, "journal"));
    public void Dispose() => _workspace.Dispose();

    [Fact]
    public async Task Hundreds_of_failed_allocations_recover_on_restart_once_then_same_and_other_users_save()
    {
        var budget = Budget(); Guid first = Guid.NewGuid();
        string path = Path.Combine(Stage, first.ToString("N") + ".txt");
        long capacity = budget.Reserve(first, "one", path);
        var template = JsonNode.Parse(File.ReadAllText(Path.Combine(Records, first.ToString("N") + ".json")))!;
        var templateSecurity = OperatingSystem.IsWindows()
            ? new FileInfo(Path.Combine(Records, first.ToString("N") + ".json")).GetAccessControl() : null;
        File.Delete(Path.Combine(Records, first.ToString("N") + ".json"));
        // Exact old-release shape produced after CREATE failed before backing
        // creation. Reproduce a population larger than both old metadata caps.
        for (int i = 0; i < 200; i++)
        {
            Guid id = Guid.NewGuid(); var old = template.DeepClone();
            old["Id"] = id; old["StagePath"] = Path.Combine(Stage, id.ToString("N") + ".txt");
            old["ContentReleased"] = true;
            string recordPath = Path.Combine(Records, id.ToString("N") + ".json");
            File.WriteAllText(recordPath, old.ToJsonString());
            if (templateSecurity is not null)
            {
                // SetAccessControl writes only modified sections. A freshly
                // read template is otherwise a no-op on Windows.
                var restored = new FileSecurity();
                restored.SetSecurityDescriptorBinaryForm(templateSecurity.GetSecurityDescriptorBinaryForm(),
                    AccessControlSections.Access | AccessControlSections.Owner | AccessControlSections.Group);
                new FileInfo(recordPath).SetAccessControl(restored);
            }
        }
        budget = Budget();
        Assert.Throws<StagedSpaceException>(() => budget.Reserve(Guid.NewGuid(), "one"));
        var journal = Journal();
        await budget.ReconcileAsync(journal, default); // Startup drain.
        Assert.Empty(Directory.GetFiles(Records));
        await budget.ReconcileAsync(journal, default); // Exactly-once credit: no second refund.
        budget = Budget();
        Assert.Equal(capacity, budget.Reserve(Guid.NewGuid(), "one"));
        Assert.Throws<StagedSpaceException>(() => budget.Reserve(Guid.NewGuid(), "one"));
        Assert.Equal(capacity, budget.Reserve(Guid.NewGuid(), "two"));
        Assert.Equal(2, Directory.GetFiles(Records).Length);
    }

    [Fact]
    public async Task Background_recovery_is_bounded_and_a_held_unknown_object_does_not_stop_other_users()
    {
        var budget = Budget(); Guid held = Guid.NewGuid();
        string stage = Path.Combine(Stage, held.ToString("N") + ".txt");
        budget.Reserve(held, "one", stage);
        File.WriteAllText(stage, "unknown identity must remain private and charged");
        Guid failed = Guid.NewGuid();
        budget.Reserve(failed, "two", Path.Combine(Stage, failed.ToString("N") + ".txt"));
        await budget.ReconcileAsync(Journal(), default, 1, (_, error) => throw new Exception("Unexpected recovery exception", error));
        Assert.Equal(2, Directory.GetFiles(Records).Length);
        await budget.ReconcileAsync(Journal(), default, 1);
        Assert.Single(Directory.GetFiles(Records));
        Assert.True(budget.ContentReservationPending(held));
        Assert.Throws<StagedSpaceException>(() => budget.Reserve(Guid.NewGuid(), "one"));
        Assert.True(budget.Reserve(Guid.NewGuid(), "two") >= 16 * MiB);
        Assert.Equal("unknown identity must remain private and charged", File.ReadAllText(stage));
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task Exact_kind5_abort_releases_sid_metadata_and_keeps_hot_or_packed_replay_accounted(bool packed)
    {
        var budget = Budget(); var journal = Journal(); Guid driver = Guid.NewGuid();
        journal.PrivateTemporaryAdmission = budget.RequireMetadataAdmission;
        journal.ArchiveGrowthAdmission = budget.RequireArchiveAdmission;
        journal.ArchiveStorageChanged = budget.RefreshArchiveStorage;
        for (int i = 0; i < 48; i++)
        {
            Guid id = Guid.NewGuid(); string stage = Path.Combine(Stage, id.ToString("N") + ".txt");
            budget.Reserve(id, "S-1-5-21-100", stage); File.WriteAllText(stage, "unattached private bytes");
            using (var file = StagedStageFile.Open(stage)) budget.RecordStage(id, stage, file.Identity);
            var transfer = new StagedTransfer(id, stage, Path.Combine(_workspace.Root, "public.txt"),
                SafeUpload.Agent.Core.Domain.DestinationKind.Cloud, "fixture", 42, 1)
                { RequestorSid = "S-1-5-21-100", RequestorProcessCreationTime = 123456 };
            var entry = await journal.CreateAsync(transfer, default, allocationDisposition: 3,
                allocationReferenceKind: 0, driverInstanceId: driver,
                parentDirectoryIdentity: StagedStageFile.ReadDirectoryIdentity(_workspace.Root));
            budget.Bind(entry);
            await budget.ReconcileAsync(journal, default);
            Assert.True(budget.ContentReservationPending(id)); // Absence of readers is insufficient.
            var discard = new StagedDiscardRequest(id, new(id, entry.DestinationGeneration, entry.StageIdentity!),
                StagedDiscardKind.UnattachedAllocation);
            await journal.BeginOrConfirmDiscardAsync(discard, default, 42, driver);
            await budget.ReconcileAsync(journal, default);
            Assert.True(budget.ContentReservationPending(id)); // No refund before exact ACK.
            await journal.CompleteDiscardAsync(discard, default);
            await budget.ReconcileAsync(journal, default);
            Assert.Empty(Directory.GetFiles(Records));
            Assert.False(File.Exists(stage + ".space"));
            if (packed) Assert.True(await journal.ArchiveCompletedAsync(await journal.ReadAsync(id, default), default));
            Assert.Equal(StagedDiscardStatus.Acknowledged, await journal.CompleteDiscardAsync(discard, default));
        }
        budget = new(Stage, new(true, 512 * MiB, 128 * MiB, 0), () => 2048 * MiB,
            new StagedTransferJournal(Path.Combine(_workspace.Root, "journal"), requireProtectedParent: false, deferArchiveLoad: true));
        budget.VerifyJournalInventory(Path.Combine(_workspace.Root, "journal"), journal);
        Assert.True(budget.Reserve(Guid.NewGuid(), "S-1-5-21-100") >= 16 * MiB);
        Assert.Throws<StagedSpaceException>(() => budget.Reserve(Guid.NewGuid(), "S-1-5-21-100"));
        Assert.True(budget.Reserve(Guid.NewGuid(), "S-1-5-21-200") >= 16 * MiB);
        Assert.False(File.Exists(Path.Combine(_workspace.Root, "public.txt")));
    }

    [Fact]
    public void Repeated_failed_seeds_have_no_retained_metadata_and_never_double_refund()
    {
        var budget = Budget(); long? first = null;
        for (int i = 0; i < 256; i++)
        {
            Guid id = Guid.NewGuid(); string stage = Path.Combine(Stage, id.ToString("N") + ".txt");
            long capacity = budget.Reserve(id, "one", stage);
            first ??= capacity; Assert.Equal(first, capacity);
            budget.RetireFailedAllocation(id); budget.RetireFailedAllocation(id);
            Assert.Empty(Directory.GetFiles(Records));
        }
        budget = Budget(); Assert.Equal(first, budget.Reserve(Guid.NewGuid(), "one"));
        Assert.Throws<StagedSpaceException>(() => budget.Reserve(Guid.NewGuid(), "one"));
        Assert.Equal(first, budget.Reserve(Guid.NewGuid(), "two"));
    }
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task Lost_initial_reply_stays_charged_until_exact_driver_abandonment_even_after_restart(bool restart)
    {
        const string sid = "S-1-5-21-100";
        var budget = Budget(); var journal = Journal(); Guid driver = Guid.NewGuid(), id = Guid.NewGuid();
        string stage = Path.Combine(Stage, id.ToString("N") + ".txt");
        budget.Reserve(id, sid, stage); File.WriteAllText(stage, "private bytes");
        var transfer = new StagedTransfer(id, stage, Path.Combine(_workspace.Root, "public.txt"),
            SafeUpload.Agent.Core.Domain.DestinationKind.Cloud, "fixture", 42, 1)
            { RequestorSid = sid, RequestorProcessCreationTime = 123456 };
        var entry = await journal.CreateAsync(transfer, default, allocationDisposition: 3,
            allocationReferenceKind: 0, driverInstanceId: driver,
            parentDirectoryIdentity: StagedStageFile.ReadDirectoryIdentity(_workspace.Root));
        budget.RecordStage(id, stage, entry.StageIdentity!); budget.Bind(entry);
        // The agent committed its reply tuple, but no adoption/abandonment
        // message arrives. Background accounting cannot invent that proof.
        byte[] grant = await File.ReadAllBytesAsync(stage + ".space");
        if (restart)
        {
            journal = Journal();
            budget = new(Stage, new(true, 512 * MiB, 128 * MiB, 0), () => 2048 * MiB, journal);
            await journal.RetainInterruptedAsync(default);
            entry = await journal.ReadAsync(id, default);
            Assert.Equal(TransferJournalState.Unsealed, entry.State);
        }
        await budget.ReconcileAsync(journal, default);
        Assert.True(budget.ContentReservationPending(id));
        Assert.Throws<StagedSpaceException>(() => budget.Reserve(Guid.NewGuid(), sid));
        Assert.Equal(grant, await File.ReadAllBytesAsync(stage + ".space"));
        Assert.Equal(entry, await journal.ReadAsync(id, default));

        // Existing kind-5 is sufficient only when the driver supplies this
        // exact abandonment proof. Timeout and restart do not supply it.
        var discard = new StagedDiscardRequest(id, StagedTransferJournal.VersionIdentity(entry), StagedDiscardKind.UnattachedAllocation);
        Assert.Equal(StagedDiscardStatus.Pending, await journal.BeginOrConfirmDiscardAsync(discard, default, 42, driver));
        await budget.ReconcileAsync(journal, default);
        Assert.True(budget.ContentReservationPending(id));
        Assert.Equal(StagedDiscardStatus.Acknowledged, await journal.CompleteDiscardAsync(discard, default));
        await budget.ReconcileAsync(journal, default);
        Assert.False(budget.ContentReservationPending(id)); Assert.Empty(Directory.GetFiles(Records));
        Assert.False(File.Exists(stage + ".space")); Assert.False(File.Exists(transfer.DestinationPath));
        Assert.Equal(StagedDiscardStatus.Acknowledged, await journal.CompleteDiscardAsync(discard, default));
        Assert.True(budget.Reserve(Guid.NewGuid(), sid) >= 16 * MiB);
    }

}
