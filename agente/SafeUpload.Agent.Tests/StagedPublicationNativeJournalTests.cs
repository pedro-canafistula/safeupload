#if SAFEUPLOAD_ADMISSION_EVIDENCE
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Text;
using System.Text.Json.Nodes;
using SafeUpload.Agent.Core.Domain;
using SafeUpload.Agent.Minifilter;
using SafeUpload.Agent.Service.Interception;

namespace SafeUpload.Agent.Tests;

// Actual private manifests/head writes with injected native receipts. These
// do not perform public rename or qualify protected callback/recovery behavior.
public sealed class StagedPublicationNativeJournalTests : IDisposable
{
    private readonly TestWorkspace _workspace = new();
    private readonly Guid _driver = Guid.NewGuid();
    private string JournalPath => Path.Combine(_workspace.Root, "journal");
    private string Parent => Path.Combine(_workspace.Root, "public");
    private string Stages => Path.Combine(_workspace.Root, "private");
    public void Dispose() => _workspace.Dispose();
    private StagedTransferJournal Journal() => new(JournalPath);
    private static SafeUploadStageIdentityV19 Wire(StagedStageIdentity id) => new()
    { VolumeSerialNumber = id.VolumeSerialNumber, FileIdHigh = id.FileIdHigh, FileIdLow = id.FileIdLow };

    private async Task<(StagedAllocationBindingV23 Binding, StagedAllocationReply Allocation, TransferJournalEntry Entry)> Allocate()
    {
        Directory.CreateDirectory(Parent);
        string root = Path.GetPathRoot(Parent)!; var volume = new StringBuilder(128);
        Assert.True(GetVolumeNameForVolumeMountPointW(root, volume, volume.Capacity));
        string name = volume.ToString(); Guid mount = Guid.Parse(name[(name.IndexOf('{') + 1)..name.IndexOf('}')]);
        var binding = new StagedAllocationBindingV23(Guid.NewGuid(), _driver, Guid.Empty, 2, 0, mount,
            StagedStageFile.ReadDirectoryIdentity(root), StagedStageFile.ReadDirectoryIdentity(Parent), false, "document.txt", null);
        var journal = Journal();
        await journal.ReconcileDriverInstanceV20Async(_driver, 0x3f, default);
        using var identity = WindowsIdentity.GetCurrent(); using var process = Process.GetCurrentProcess();
        var allocated = await new StagedTransferAllocator(Stages, journal).AllocateV23Async(Path.Combine(Parent, "document.txt"),
            DestinationKind.Cloud, process.ProcessName, process.Id, checked((uint)process.SessionId), identity.User!.Value,
            process.StartTime.ToFileTimeUtc(), binding, default);
        await File.WriteAllBytesAsync(allocated.Transfer.StagePath, new byte[37]);
        var version = new StagedVersionIdentity(allocated.Transfer.TransferId, allocated.DestinationGeneration, allocated.StageIdentity);
        foreach (var (operation, request) in new[] { (12u, 701ul), (13u, 702ul), (15u, 703ul), (19u, 704ul) })
            await journal.ApplyAttachmentV20Async(new(operation, request, version, _driver, binding.Parent,
                allocated.Transfer.DestinationPath, process.Id), true, true, default);
        var entry = await journal.SealAsync(allocated.Transfer.TransferId, process.Id, allocated.Transfer.StagePath, default, version);
        await journal.TransitionAsync(entry.Transfer.TransferId, TransferJournalState.Sealed, TransferJournalState.Inspecting, entry.Sha256Hex, default);
        entry = await journal.TransitionAsync(entry.Transfer.TransferId, TransferJournalState.Inspecting, TransferJournalState.Approved, entry.Sha256Hex, default);
        return (binding, allocated, entry);
    }

    private static BoundPublicationReplayRow Native(StagedAllocationBindingV23 binding, TransferJournalEntry entry, bool? accepted)
    {
        Guid nonce = Guid.NewGuid();
        var create = BoundPublicationV26.WithPayload(new()
        {
            Phase = BoundPublicationPhase.Create, TransferId = entry.Transfer.TransferId, DriverInstanceId = binding.DriverInstanceId,
            PermitNonce = nonce, CreateNonce = nonce, OperationId = Guid.NewGuid(), DestinationGeneration = entry.DestinationGeneration,
            MountManagerVolumeId = binding.MountManagerVolumeId, VolumeRootIdentity = Wire(binding.VolumeRoot), ParentIdentity = Wire(binding.Parent),
            StageIdentity = Wire(entry.StageIdentity!), MeasuredLength = entry.SealedLength!.Value, ExpectedMaxAllocated = entry.DestinationGeneration
        }, binding.CanonicalLeaf, ".safeupload-" + nonce.ToString("N") + ".pending", Convert.FromHexString(entry.Sha256Hex!));
        var temporary = Wire(new(entry.StageIdentity!.VolumeSerialNumber, 0, entry.StageIdentity.FileIdLow + 100));
        var rename = create; rename.Phase = BoundPublicationPhase.Rename; rename.PermitNonce = Guid.NewGuid();
        rename.OperationId = Guid.NewGuid(); rename.TemporaryIdentity = temporary;
        var facts = new BoundPublicationFactsRowV26
        {
            Create = create, Rename = rename, OriginalProcessId = 1234, OriginalSessionId = 1,
            OriginalProcessCreationTime = 123456, OriginalConnectionEpoch = 11, OsBootSequence = 42,
            TemporaryIdentity = temporary, CreateInformation = 2, ObservedEof = 37,
            Flags = BoundPublicationFacts.CreateConsumed | BoundPublicationFacts.CreateForwarded | BoundPublicationFacts.CreateResultKnown |
                BoundPublicationFacts.CreateAccepted | BoundPublicationFacts.TemporaryIdentityKnown | BoundPublicationFacts.DataFenced |
                BoundPublicationFacts.DataDrained | BoundPublicationFacts.FlushResultKnown | BoundPublicationFacts.FlushSucceeded |
                BoundPublicationFacts.RenameArmed | BoundPublicationFacts.RenameConsumed | BoundPublicationFacts.RenameForwarded |
                BoundPublicationFacts.TargetObservationKnown | BoundPublicationFacts.TargetAbsent
        };
        if (accepted is not null) facts.Flags |= BoundPublicationFacts.RenameResultKnown;
        if (accepted == true) facts.Flags |= BoundPublicationFacts.RenameAccepted;
        if (accepted == false) facts.RenameStatus = unchecked((int)0xc0000022);
        return new(facts);
    }

    private static BoundPublicationReplay Replay(BoundPublicationReplayRow row, ulong revision = 17) =>
        new(row.Facts.Create.DriverInstanceId, 11, revision, 42, [row]);
    private static async Task Begin(StagedTransferJournal journal, StagedTransferJournal.DestinationCommitTurn turn, BoundPublicationReplayRow row)
    {
        var f = row.Facts;
        await journal.BeginDestinationPublicationAsync(turn, f.Rename.OperationId, f.Create.TransferId,
            f.Create.DestinationGeneration, null, new(f.TemporaryIdentity.VolumeSerialNumber, f.TemporaryIdentity.FileIdHigh, f.TemporaryIdentity.FileIdLow),
            f.Create.MeasuredLength, Convert.ToHexString(f.Create.GetDigest()), default);
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    [InlineData(null)]
    public async Task Exact_native_result_is_durable_before_boolean_and_unknown_retains_the_intent(bool? accepted)
    {
        var fixture = await Allocate(); var row = Native(fixture.Binding, fixture.Entry, accepted); var journal = Journal();
        using (var turn = await journal.EnterDestinationCommitTurnAsync(fixture.Binding.Destination, StagedDestinationTurnPurpose.PhysicalCommit, default))
        {
            await Begin(journal, turn, row);
            await journal.RecordBoundPublicationNativeResultAsync(turn, Replay(row), row);
        }
        var head = (await Journal().ReadDestinationHeadAsync(fixture.Binding.Destination, default))!;
        var receipt = Assert.Single(head.PublicationNativeReceipts!);
        var actual = BoundPublicationV26.DecodeFactRow(Convert.FromBase64String(receipt.FactsBase64), receipt.DriverInstanceId, receipt.ConnectionEpoch, receipt.OsBootSequence);
        Assert.Equal(row.Facts.RenameStatus, actual.Facts.RenameStatus);
        Assert.Equal(accepted == true ? fixture.Entry.DestinationGeneration : 0, head.LatestPublished);
        Assert.Equal(accepted is null, head.PendingCommit is not null);
        if (accepted is not null) Assert.Equal(row.Facts.Create.CreateNonce, head.LastMutationResult!.PublicationCreateNonce);
        else Assert.Null(head.LastMutationResult);
    }

    [Theory]
    [InlineData("operation")]
    [InlineData("digest")]
    [InlineData("stage")]
    [InlineData("destination")]
    public async Task Changed_native_binding_never_commits_the_shared_head(string change)
    {
        var fixture = await Allocate(); var original = Native(fixture.Binding, fixture.Entry, true); var f = original.Facts;
        switch (change)
        {
            case "operation": f.Rename.OperationId = Guid.NewGuid(); break;
            case "digest":
                var digest = new byte[32]; digest[0] = 1;
                f.Create = BoundPublicationV26.WithPayload(f.Create, f.Create.GetDestinationLeaf(), f.Create.GetTemporaryLeaf(), digest);
                f.Rename = BoundPublicationV26.WithPayload(f.Rename, f.Rename.GetDestinationLeaf(), f.Rename.GetTemporaryLeaf(), digest); break;
            case "stage": f.Create.StageIdentity.FileIdLow++; f.Rename.StageIdentity = f.Create.StageIdentity; break;
            case "destination": f.Create.ParentIdentity.FileIdLow++; f.Rename.ParentIdentity = f.Create.ParentIdentity; break;
        }
        var changed = new BoundPublicationReplayRow(f); var journal = Journal();
        using var turn = await journal.EnterDestinationCommitTurnAsync(fixture.Binding.Destination, StagedDestinationTurnPurpose.PhysicalCommit, default);
        await Begin(journal, turn, original);
        await Assert.ThrowsAnyAsync<IOException>(() => journal.RecordBoundPublicationNativeResultAsync(turn, Replay(changed), changed));
        var head = (await Journal().ReadDestinationHeadAsync(fixture.Binding.Destination, default))!;
        Assert.Equal(0, head.LatestPublished); Assert.NotNull(head.PendingCommit); Assert.Empty(head.PublicationNativeReceipts ?? []);
    }

    [Fact]
    public async Task Boolean_only_completion_cannot_complete_a_bound_manifest()
    {
        var fixture = await Allocate(); var row = Native(fixture.Binding, fixture.Entry, true); var journal = Journal();
        using var turn = await journal.EnterDestinationCommitTurnAsync(fixture.Binding.Destination, StagedDestinationTurnPurpose.PhysicalCommit, default);
        await Begin(journal, turn, row); var f = row.Facts;
        await Assert.ThrowsAsync<IOException>(() => journal.RecordDestinationPublicationResultAsync(turn, f.Rename.OperationId,
            f.Create.TransferId, new(f.TemporaryIdentity.VolumeSerialNumber, f.TemporaryIdentity.FileIdHigh, f.TemporaryIdentity.FileIdLow), true));
        Assert.NotNull((await Journal().ReadDestinationHeadAsync(fixture.Binding.Destination, default))!.PendingCommit);
    }

    [Fact]
    public async Task Late_cleanup_after_manifest_compaction_preserves_newer_generation_and_final_native_status()
    {
        var fixture = await Allocate(); var row = Native(fixture.Binding, fixture.Entry, true); var journal = Journal();
        using (var turn = await journal.EnterDestinationCommitTurnAsync(fixture.Binding.Destination, StagedDestinationTurnPurpose.PhysicalCommit, default))
        { await Begin(journal, turn, row); await journal.RecordBoundPublicationNativeResultAsync(turn, Replay(row), row); }
        var later = await Allocate();
        File.Delete(Path.Combine(JournalPath, fixture.Entry.Transfer.TransferId.ToString("N") + ".json"));
        var facts = row.Facts; facts.Flags |= BoundPublicationFacts.LastCleanup;
        var closed = new BoundPublicationReplayRow(facts);
        using (var turn = await journal.EnterDestinationCommitTurnAsync(fixture.Binding.Destination, StagedDestinationTurnPurpose.Reconciliation, default))
            await journal.RecordBoundPublicationNativeResultAsync(turn, Replay(closed, 18), closed);
        var head = (await Journal().ReadDestinationHeadAsync(fixture.Binding.Destination, default))!;
        Assert.Equal(later.Entry.DestinationGeneration, head.CurrentSaveGeneration);
        Assert.Equal(later.Entry.Transfer.TransferId, head.CurrentSaveTransferId);
        Assert.Equal(fixture.Entry.DestinationGeneration, head.LatestPublished);
        Assert.Single(head.PublicationNativeReceipts!);
    }

    [Theory]
    [InlineData("status")]
    [InlineData("revision")]
    [InlineData("forget-result")]
    public async Task Final_native_facts_cannot_be_changed_or_forgotten_on_replay(string change)
    {
        var fixture = await Allocate(); var row = Native(fixture.Binding, fixture.Entry, false); var journal = Journal();
        using var turn = await journal.EnterDestinationCommitTurnAsync(fixture.Binding.Destination, StagedDestinationTurnPurpose.PhysicalCommit, default);
        await Begin(journal, turn, row); await journal.RecordBoundPublicationNativeResultAsync(turn, Replay(row), row);
        var f = row.Facts; ulong revision = 18;
        if (change == "status") f.RenameStatus = unchecked((int)0xc0000035);
        if (change == "revision") revision = 16;
        if (change == "forget-result") { f.Flags &= ~BoundPublicationFacts.RenameResultKnown; f.RenameStatus = 0; }
        var changed = new BoundPublicationReplayRow(f);
        await Assert.ThrowsAsync<IOException>(() => journal.RecordBoundPublicationNativeResultAsync(turn, Replay(changed, revision), changed));
        Assert.False((await Journal().ReadDestinationHeadAsync(fixture.Binding.Destination, default))!.LastMutationResult!.Succeeded);
    }

    [Fact]
    public async Task Corrupt_projection_or_missing_native_binding_is_rejected_after_restart()
    {
        var fixture = await Allocate(); var row = Native(fixture.Binding, fixture.Entry, true); var journal = Journal();
        using (var turn = await journal.EnterDestinationCommitTurnAsync(fixture.Binding.Destination, StagedDestinationTurnPurpose.PhysicalCommit, default))
        { await Begin(journal, turn, row); await journal.RecordBoundPublicationNativeResultAsync(turn, Replay(row), row); }
        string path = Assert.Single(Directory.GetFiles(JournalPath, "destination-*.state"));
        string original = await File.ReadAllTextAsync(path);
        var json = JsonNode.Parse(original)!; json["LastMutationResult"]!["Succeeded"] = false;
        await File.WriteAllTextAsync(path, json.ToJsonString());
        await Assert.ThrowsAsync<InvalidDataException>(() => Journal().ReadDestinationHeadAsync(fixture.Binding.Destination, default));
        json = JsonNode.Parse(original)!; json["LastMutationResult"]!.AsObject().Remove("PublicationCreateNonce");
        await File.WriteAllTextAsync(path, json.ToJsonString());
        await Assert.ThrowsAsync<InvalidDataException>(() => Journal().ReadDestinationHeadAsync(fixture.Binding.Destination, default));
    }

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern bool GetVolumeNameForVolumeMountPointW(string path, StringBuilder name, int length);
}
#endif
