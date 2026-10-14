#if SAFEUPLOAD_ADMISSION_EVIDENCE
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Text;
using Microsoft.Win32.SafeHandles;
using SafeUpload.Agent.Core.Domain;
using SafeUpload.Agent.Service.Interception;
using SafeUpload.Agent.Service.Notifications;

namespace SafeUpload.Agent.Tests;

// Real Windows filesystem integration, without a loaded filter. These prove
// service allocation transactions; protected publication/Verifier remain
// separate VM gates.
public sealed class StagedBoundAllocationIntegrationTests : IDisposable
{
    private readonly TestWorkspace _workspace = new();
    private readonly Guid _driver = Guid.NewGuid();
    private string Parent => Path.Combine(_workspace.Root, "public");
    private string Stages => Path.Combine(_workspace.Root, "private");
    private string Journal => Path.Combine(_workspace.Root, "journal");
    public void Dispose() => _workspace.Dispose();

    private StagedAllocationBindingV23 Binding(string leaf, uint disposition, bool present, Guid? reservation = null)
    {
        Directory.CreateDirectory(Parent);
        string root = Path.GetPathRoot(Parent)!;
        var volume = new StringBuilder(128);
        Assert.True(GetVolumeNameForVolumeMountPointW(root, volume, volume.Capacity));
        string text = volume.ToString();
        Guid volumeId = Guid.Parse(text[(text.IndexOf('{') + 1)..text.IndexOf('}')]);
        StagedStageIdentity? target = null;
        if (present) { using var file = StagedStageFile.Open(Path.Combine(Parent, leaf)); target = file.Identity; }
        return new(reservation ?? Guid.NewGuid(), _driver, Guid.Empty, disposition, 0, volumeId,
            StagedStageFile.ReadDirectoryIdentity(root), StagedStageFile.ReadDirectoryIdentity(Parent),
            false, leaf, target);
    }

    private Task<StagedAllocationReply> Allocate(StagedTransferAllocator allocator,
        StagedAllocationBindingV23 binding, string? locator = null, StagedAllocationSecuritySnapshot? security = null, bool metadataMissing = false)
    {
        using var identity = WindowsIdentity.GetCurrent();
        using var process = Process.GetCurrentProcess();
        return allocator.AllocateV23Async(locator ?? Path.Combine(Parent, binding.CanonicalLeaf), DestinationKind.Cloud,
            process.ProcessName, process.Id, checked((uint)process.SessionId), identity.User!.Value,
            process.StartTime.ToFileTimeUtc(), binding, CancellationToken.None, metadataMissing ? null : security ?? WriterMetadataFixture.Current(binding));
    }

    [Fact]
    public async Task Missing_carrier_is_refused_before_backing_or_durable_claim()
    {
        var binding = Binding("missing.txt", 2, false);
        var journal = new StagedTransferJournal(Journal);
        await Assert.ThrowsAsync<InvalidDataException>(() => Allocate(new(Stages, journal), binding, metadataMissing: true));
        Assert.Null(await journal.FindBoundAllocationAsync(binding.ReservationId, CancellationToken.None));
        Assert.Empty(Directory.EnumerateFiles(Stages));
        var historical = StagedAllocationSecuritySnapshot.Create(Guid.NewGuid(), binding, 1, 0x10000,
            SecuritySnapshotFixture.Descriptor(), SecuritySnapshotFixture.Descriptor());
        await Assert.ThrowsAsync<InvalidDataException>(() => Allocate(new(Stages, journal), binding, security: historical));
        Assert.Empty(Directory.EnumerateFiles(Stages));
    }

    [Fact]
    public async Task Empty_kernel_completion_precedes_exposure_and_ordinary_seal_and_replay_cannot_bypass_it()
    {
        var binding = Binding("empty-seal.txt", 2, false);
        var journal = new StagedTransferJournal(Journal);
        Assert.Equal(StagedDriverEpochReconcileV20.Active,
            await journal.ReconcileDriverInstanceV20Async(_driver, 0x1bf, CancellationToken.None));
        var reply = await Allocate(new(Stages, journal), binding);
        var pending = await journal.ReadAsync(binding.ReservationId, CancellationToken.None);
        var version = StagedTransferJournal.VersionIdentity(pending);
        Task<uint?> Apply(uint operation, ulong request) => journal.ApplyAttachmentV20Async(
            new(operation, request, version, _driver, binding.Parent, reply.Transfer.DestinationPath, reply.Transfer.ProcessId),
            ownerIsLive: true, commitPolicyAllowed: true, CancellationToken.None);
        Assert.Equal(StageV20WireResult.AttachPrepared, await Apply(12, 101));
        Assert.Equal(StageV20WireResult.AttachCommitted, await Apply(13, 102));
        Assert.Equal("seed_completion_unproved", (await Assert.ThrowsAsync<IOException>(() => Apply(15, 103))).Message);
        var completion = KernelCompletionFixture(pending);
        await journal.CompleteBoundSeedAsync(version, completion, CancellationToken.None);
        Assert.Equal(StageV20WireResult.CompletionPermitted, await Apply(15, 103));
        var permitted = await journal.ReadAsync(binding.ReservationId, CancellationToken.None);
        await SeedProvenanceFixture.WriteAsync(Journal, permitted with { SeedCompletion = null });
        Assert.Equal("seed_completion_unproved", (await Assert.ThrowsAsync<IOException>(() => Apply(15, 103))).Message);
        await SeedProvenanceFixture.WriteAsync(Journal, permitted);
        Assert.Equal(StageV20WireResult.HandleLifetimeObserved, await Apply(19, 104));
        var sealedEntry = await journal.SealAsync(binding.ReservationId, reply.Transfer.ProcessId,
            reply.Transfer.StagePath, CancellationToken.None, version);
        Assert.Equal(TransferJournalState.Sealed, sealedEntry.State);
        Assert.Equal(0, sealedEntry.SealedLength);
        Assert.Equal(Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(Array.Empty<byte>())), sealedEntry.Sha256Hex);
        Assert.False(File.Exists(reply.Transfer.DestinationPath)); // Publication remains a separate gate.
    }

    [Fact]
    public async Task Bound_allocation_does_not_open_a_second_public_data_reader()
    {
        Directory.CreateDirectory(Parent);
        string path = Path.Combine(Parent, "exclusive.txt");
        File.WriteAllText(path, "old public bytes");
        var binding = Binding("exclusive.txt", 1, true);
        using var writer = CreateFileW(path, 2, 0, IntPtr.Zero, 3, 0x80, IntPtr.Zero);
        Assert.False(writer.IsInvalid);
        var journal = new StagedTransferJournal(Journal);
        var reply = await Allocate(new(Stages, journal), binding);
        Assert.Empty(File.ReadAllBytes(reply.Transfer.StagePath));
        var entry = await journal.ReadAsync(binding.ReservationId, CancellationToken.None);
        Assert.Null(entry.SeedCompletion);
        Assert.Equal(binding.PublicTarget, entry.SeedProvenance!.PublicSource);
        Assert.Equal("seed_coherence_unproved", (await Assert.ThrowsAsync<IOException>(() => journal.CompleteBoundSeedAsync(
            StagedTransferJournal.VersionIdentity(entry), KernelCompletionFixture(entry), CancellationToken.None))).Message);
        writer.Dispose();
        Assert.Equal("old public bytes", File.ReadAllText(path));
    }

    [Fact]
    public async Task Partial_kernel_seed_is_retained_and_never_replayed_as_an_empty_allocation()
    {
        var binding = Binding("partial.txt", 2, false);
        var journal = new StagedTransferJournal(Journal);
        var reply = await Allocate(new(Stages, journal), binding);
        File.WriteAllText(reply.Transfer.StagePath, "partial private seed");
        await Assert.ThrowsAsync<IOException>(() => Allocate(new(Stages, new StagedTransferJournal(Journal)), binding));
        Assert.Equal("partial private seed", File.ReadAllText(reply.Transfer.StagePath));
        var entry = await journal.ReadAsync(binding.ReservationId, CancellationToken.None);
        Assert.Null(entry.SeedCompletion);
        Assert.Equal("seed_completion_unproved", (await Assert.ThrowsAsync<IOException>(() => journal.SealAsync(
            binding.ReservationId, entry.Transfer.ProcessId, entry.Transfer.StagePath, CancellationToken.None))).Message);
        Assert.False(File.Exists(reply.Transfer.DestinationPath));
    }

    [Theory]
    [InlineData(48)] // original allocation RequestId
    [InlineData(56)] // connection epoch
    [InlineData(64)] // authority revision
    [InlineData(72)] // snapshot
    public async Task Restart_cannot_refresh_immutable_carrier_for_a_committed_reservation(int changedField)
    {
        var binding = Binding("restart.txt", 2, false);
        var security = WriterMetadataFixture.Current(binding);
        var journal = new StagedTransferJournal(Journal);
        var first = await Allocate(new(Stages, journal), binding, security: security);
        byte[] envelope = Convert.FromHexString(security.WriterMetadataEnvelopeHex!); envelope[changedField] ^= 1;
        var changed = StagedAllocationSecuritySnapshot.FromWriterMetadata(
            SafeUpload.Agent.Minifilter.WriterMetadataV27.DecodeEnvelope(envelope));
        var reopened = new StagedTransferJournal(Journal);
        await Assert.ThrowsAsync<IOException>(() => Allocate(new(Stages, reopened), binding, security: changed));
        Assert.Equal(security, await reopened.ReadBoundAllocationSecurityAsync(binding.ReservationId, CancellationToken.None));
        Assert.True(File.Exists(first.Transfer.StagePath));
    }

    [Fact]
    public async Task Durable_captured_unproven_authority_cannot_be_rewritten_to_allow_export()
    {
        Directory.CreateDirectory(Parent); File.WriteAllText(Path.Combine(Parent, "authority.txt"), "old bytes");
        var binding = Binding("authority.txt", 1, true); var journal = new StagedTransferJournal(Journal);
        var reply = await Allocate(new(Stages, journal), binding);
        var entry = await journal.ReadAsync(binding.ReservationId, CancellationToken.None);
        var seed = entry.SeedProvenance!;
        var proof = seed.ExportEvidence!;
        await SeedProvenanceFixture.WriteAsync(Journal, entry with { SeedProvenance = seed with
        { ExportEvidence = proof with { ReadAuthority = StagedSeedAuthority.Allowed, RecipientAuthority = StagedSeedAuthority.Allowed } } });
        await Assert.ThrowsAsync<InvalidDataException>(() => new StagedTransferJournal(Journal).ReadAsync(
            binding.ReservationId, CancellationToken.None));
        Assert.True(File.Exists(reply.Transfer.StagePath));
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task Seed_completion_persistence_fault_retains_exact_private_object_without_recopy(bool afterReplacement)
    {
        var binding = Binding("completion.txt", 2, false); bool injected = false;
        var journal = new StagedTransferJournal(Journal, false, 100, (point, entry) =>
        {
            if (!injected && entry.SeedCompletion is not null &&
                point == (afterReplacement ? StagedJournalWritePoint.AfterReplacement : StagedJournalWritePoint.BeforeReplacement))
            { injected = true; throw new IOException("Interrupted seed completion persistence"); }
        });
        var reply = await Allocate(new(Stages, journal), binding);
        var pending = await journal.ReadAsync(binding.ReservationId, CancellationToken.None);
        var completion = KernelCompletionFixture(pending);
        await Assert.ThrowsAsync<StagedJournalPersistenceException>(() => journal.CompleteBoundSeedAsync(
            StagedTransferJournal.VersionIdentity(pending), completion, CancellationToken.None));
        Assert.True(injected);
        var reopened = new StagedTransferJournal(Journal);
        var entry = await reopened.ReadAsync(binding.ReservationId, CancellationToken.None);
        Assert.Equal(afterReplacement, entry.SeedCompletion is not null);
        Assert.Empty(File.ReadAllBytes(entry.Transfer.StagePath));
        Assert.Equal(afterReplacement ? null : "seed_export_unproven", StagedSeedExport.Failure(entry));
        var replay = await Allocate(new(Stages, reopened), binding);
        Assert.Equal(reply.StageIdentity, replay.StageIdentity);
        if (!afterReplacement)
            Assert.Equal("seed_completion_unproved", (await Assert.ThrowsAsync<IOException>(() => reopened.SealAsync(
                binding.ReservationId, entry.Transfer.ProcessId, entry.Transfer.StagePath, CancellationToken.None))).Message);
        await reopened.CompleteBoundSeedAsync(StagedTransferJournal.VersionIdentity(entry), completion, CancellationToken.None);
        var completed = await reopened.ReadAsync(binding.ReservationId, CancellationToken.None);
        Assert.Equal(completion, completed.SeedCompletion);
        await Assert.ThrowsAsync<IOException>(() => reopened.CompleteBoundSeedAsync(
            StagedTransferJournal.VersionIdentity(entry), completion with { ReceiptId = Guid.NewGuid() }, CancellationToken.None));
        Assert.False(File.Exists(entry.Transfer.DestinationPath));
    }

    // Models the future authenticated kernel receipt for storage controls only.
    // No native source read, coherence or loaded-driver claim is made here.
    private static StagedSeedCompletion KernelCompletionFixture(TransferJournalEntry entry) =>
        new(StagedTransferJournal.VersionIdentity(entry), 0)
        {
            FormatVersion = 2, ReceiptId = Guid.NewGuid(), DriverInstanceId = entry.DriverInstanceId!.Value,
            Binding = entry.BoundAllocation, Metadata = entry.AllocationSecurity,
            Origin = entry.SeedProvenance!.Origin, Predecessor = entry.SeedProvenance.Predecessor,
            EofSet = true, Flushed = true, Revalidated = true
        };

    [Theory]
    [InlineData(0u)]
    [InlineData(2u)]
    [InlineData(3u)]
    [InlineData(5u)]
    public async Task Absent_target_begins_without_prior_bytes(uint disposition)
    {
        var binding = Binding("new.txt", disposition, false);
        var journal = new StagedTransferJournal(Journal);
        var reply = await Allocate(new(Stages, journal), binding);
        var entry = await journal.ReadAsync(reply.Transfer.TransferId, CancellationToken.None);
        Assert.Equal(StagedSeedOrigin.None, entry.SeedProvenance!.Origin);
        Assert.False(entry.SeedProvenance.ContainsPriorBytes);
        Assert.Null(entry.SeedCompletion);
        Assert.Equal("seed_export_unproven", StagedSeedExport.Failure(entry));
        Assert.Equal("seed_completion_unproved", (await Assert.ThrowsAsync<IOException>(() => journal.SealAsync(
            binding.ReservationId, entry.Transfer.ProcessId, entry.Transfer.StagePath, CancellationToken.None))).Message);
        entry = await journal.CompleteBoundSeedAsync(StagedTransferJournal.VersionIdentity(entry),
            KernelCompletionFixture(entry), CancellationToken.None);
        Assert.Null(StagedSeedExport.Failure(entry));
        Assert.Equal(0, entry.SeedCompletion!.Length);
        Assert.Equal(TransferJournalState.Allocated, entry.State); // Ordinary seal still required, including empty.
        Assert.False(File.Exists(reply.Transfer.DestinationPath));
    }

    [Theory]
    [InlineData(true, false)]
    [InlineData(true, true)]
    [InlineData(false, false)]
    public async Task Private_successors_preserve_public_provenance_without_inventing_export_evidence(bool publicSeed, bool missing)
    {
        Directory.CreateDirectory(Parent);
        if (publicSeed) File.WriteAllText(Path.Combine(Parent, "chain.txt"), "prior public bytes");
        var binding = Binding("chain.txt", publicSeed ? 1u : 2u, publicSeed);
        var journal = new StagedTransferJournal(Journal); var allocator = new StagedTransferAllocator(Stages, journal);
        var first = await Allocate(allocator, binding);
        Assert.Empty(File.ReadAllBytes(first.Transfer.StagePath));
        // Model a retained historical predecessor explicitly: V23 allocation
        // now returns an empty candidate and does not copy the public source.
        File.WriteAllText(first.Transfer.StagePath, publicSeed ? "prior public bytes" : "new writer bytes");
        var parent = await journal.ReadAsync(first.Transfer.TransferId, CancellationToken.None);
        if (missing) parent = parent with { SeedProvenance = null, SeedCompletion = null };
        await SaveMeasuredFixture(parent);
        if (missing)
        {
            // A captured bound seed whose provenance disappeared is corrupt,
            // not a new inheritable allocation with synthesized restrictions.
            var preserving = binding with { ReservationId = Guid.NewGuid(), ParentTransferId = parent.Transfer.TransferId,
                ReferenceKind = 1, Disposition = 1 };
            await Assert.ThrowsAsync<InvalidDataException>(() => new StagedTransferJournal(Journal)
                .ReadAsync(parent.Transfer.TransferId, CancellationToken.None));
            await Assert.ThrowsAsync<InvalidDataException>(() => Allocate(allocator, preserving));
            Assert.Equal("prior public bytes", File.ReadAllText(parent.Transfer.StagePath));
            return;
        }
        for (int i = 0; i < 2; i++)
        {
            binding = binding with { ReservationId = Guid.NewGuid(), ParentTransferId = parent.Transfer.TransferId,
                ReferenceKind = 1, Disposition = 1 };
            var next = await Allocate(allocator, binding);
            var child = await journal.ReadAsync(next.Transfer.TransferId, CancellationToken.None);
            Assert.Equal(StagedSeedOrigin.PrivatePredecessor, child.SeedProvenance!.Origin);
            Assert.Equal(StagedTransferJournal.VersionIdentity(parent), child.SeedProvenance.Predecessor);
            Assert.Equal(publicSeed, child.SeedProvenance.ContainsPriorBytes);
            Assert.Equal("seed_export_unproven", child.SeedProvenance.InheritedRestriction);
            Assert.Equal("seed_export_unproven", StagedSeedExport.Failure(child));
            Assert.Null(child.SeedCompletion);
            Assert.Empty(File.ReadAllBytes(child.Transfer.StagePath));
            Assert.Equal("seed_coherence_unproved", (await Assert.ThrowsAsync<IOException>(() => journal.CompleteBoundSeedAsync(
                StagedTransferJournal.VersionIdentity(child), KernelCompletionFixture(child), CancellationToken.None))).Message);
            if (!missing && publicSeed) Assert.Equal(first.Transfer.TransferId, child.SeedProvenance.SourceBinding!.ReservationId);
            await SaveMeasuredFixture(child); parent = child;
        }
        var sealedChild = await journal.ReadAsync(parent.Transfer.TransferId, CancellationToken.None);
        var blocked = sealedChild with { State = TransferJournalState.Blocked, StateHistory = [],
            Sha256Hex = Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(File.ReadAllBytes(parent.Transfer.StagePath))),
            BlockedPolicyVersion = 1 };
        await SeedProvenanceFixture.WriteAsync(Journal, blocked);
        var checkedEntry = await new StagedTransferJournal(Journal).EnforceSeedExportAsync(parent.Transfer.TransferId, CancellationToken.None);
        Assert.Equal(StagedHandbackState.Failed, checkedEntry.HandbackState); // Incomplete seeds never export, even without prior bytes.
        Assert.True(File.Exists(parent.Transfer.StagePath));
    }

    // Only models a measured seal receipt. No loaded driver or native lifetime claim.
    private Task SaveMeasuredFixture(TransferJournalEntry entry) => SeedProvenanceFixture.WriteAsync(Journal,
        entry with { State = TransferJournalState.Sealed, StateHistory = [], SealedOnce = true,
            SealedLength = new FileInfo(entry.Transfer.StagePath).Length });

    [Fact]
    public async Task Seed_intent_survives_failed_head_claim_before_bytes_and_never_exposes_an_incomplete_copy()
    {
        Directory.CreateDirectory(Parent); File.WriteAllText(Path.Combine(Parent, "seed.txt"), "old source bytes");
        var binding = Binding("seed.txt", 1, true); var journal = new StagedTransferJournal(Journal);
        string head = Path.Combine(Journal, "destination-" + binding.Destination.StorageKey + ".state");
        Directory.CreateDirectory(head);
        await Assert.ThrowsAsync<IOException>(() => Allocate(new(Stages, journal), binding));
        var intent = await journal.ReadAsync(binding.ReservationId, CancellationToken.None);
        Assert.Equal(StagedSeedOrigin.ExistingPublic, intent.SeedProvenance!.Origin);
        Assert.Null(intent.SeedCompletion); Assert.Equal(0, new FileInfo(intent.Transfer.StagePath).Length);
        Assert.Equal("seed_export_unproven", StagedSeedExport.Failure(intent));
        Directory.Delete(head);
        var replay = await Allocate(new(Stages, new StagedTransferJournal(Journal)), binding);
        Assert.Equal(intent.StageIdentity, replay.StageIdentity);
        Assert.Equal("seed_completion_unproved", (await Assert.ThrowsAsync<IOException>(() => journal.SealAsync(
            binding.ReservationId, intent.Transfer.ProcessId, intent.Transfer.StagePath, CancellationToken.None))).Message);
        Assert.Empty(File.ReadAllBytes(intent.Transfer.StagePath));
        Assert.True(File.Exists(intent.Transfer.StagePath));
        Assert.Equal("old source bytes", File.ReadAllText(intent.Transfer.DestinationPath));
    }

    [Fact]
    public async Task Security_snapshot_is_committed_before_reply_and_exact_replay_survives_restart()
    {
        var binding = Binding("save.txt", 2, false);
        byte[] construction = SecuritySnapshotFixture.Descriptor(), stored = construction.ToArray();
        stored[2] &= 0xf7;
        var snapshot = WriterMetadataFixture.Current(binding, construction, stored);
        var journal = new StagedTransferJournal(Journal);
        var first = await Allocate(new(Stages, journal), binding, security: snapshot);
        var entry = await journal.ReadAsync(binding.ReservationId, CancellationToken.None);
        Assert.Equal(snapshot.Reference(), entry.AllocationSecurity);
        var reopened = new StagedTransferJournal(Journal);
        Assert.Equal(snapshot, await reopened.ReadBoundAllocationSecurityAsync(binding.ReservationId, CancellationToken.None));
        Assert.Equal(first, await Allocate(new(Stages, reopened), binding, security: snapshot));
        await Assert.ThrowsAsync<InvalidDataException>(() => Allocate(new(Stages, reopened), binding, metadataMissing: true));
        await Assert.ThrowsAsync<InvalidDataException>(() => Allocate(new(Stages, reopened), binding,
            security: snapshot with { AssignmentRevision = 2 }));
        Assert.Equal(entry, await reopened.ReadAsync(binding.ReservationId, CancellationToken.None));
    }

    [Fact]
    public async Task Full_descriptor_pair_fits_private_storage_without_expanding_the_manifest_bound()
    {
        var binding = Binding("large.txt", 2, false);
        byte[] descriptor = SecuritySnapshotFixture.Descriptor(duplicateAces: 3150);
        var snapshot = WriterMetadataFixture.Current(binding, descriptor, descriptor);
        Assert.True(snapshot.Encode().Length > 128 * 1024);
        var journal = new StagedTransferJournal(Journal);
        await Allocate(new(Stages, journal), binding, security: snapshot);
        Assert.True(new FileInfo(Path.Combine(Journal, binding.ReservationId.ToString("N") + ".json")).Length < 128 * 1024);
        var reopened = new StagedTransferJournal(Journal);
        Assert.Equal(snapshot, await reopened.ReadBoundAllocationSecurityAsync(binding.ReservationId, CancellationToken.None));
        await reopened.CompactAsync(DateTimeOffset.UtcNow.AddHours(1), CancellationToken.None);
        Assert.Equal(snapshot, await reopened.ReadBoundAllocationSecurityAsync(binding.ReservationId, CancellationToken.None));
    }

    [Fact]
    public async Task Unreferenced_flushed_security_record_is_private_and_compacted_after_retention()
    {
        var binding = Binding("orphan.txt", 2, false);
        byte[] descriptor = SecuritySnapshotFixture.Descriptor();
        var snapshot = WriterMetadataFixture.Current(binding, descriptor, descriptor);
        var journal = new StagedTransferJournal(Journal);
        string path = Path.Combine(Journal, snapshot.SnapshotId.ToString("N") + ".security");
        File.WriteAllBytes(path, snapshot.Encode()); // Simulate flush followed by a crash before manifest commit.
        Assert.Equal(0, await journal.CompactAsync(DateTimeOffset.UtcNow.AddHours(-1), CancellationToken.None));
        Assert.True(File.Exists(path));
        Assert.Equal(0, await journal.CompactAsync(DateTimeOffset.UtcNow.AddHours(1), CancellationToken.None));
        Assert.False(File.Exists(path));
        Assert.Empty(Directory.EnumerateFiles(Journal, "*.json"));
    }

    [Theory]
    [InlineData("missing")]
    [InlineData("changed")]
    [InlineData("replaced-binding")]
    public async Task Missing_or_changed_security_cannot_be_recovered_as_allocation_authority(string change)
    {
        var binding = Binding("save.txt", 2, false);
        byte[] descriptor = SecuritySnapshotFixture.Descriptor();
        var snapshot = WriterMetadataFixture.Current(binding, descriptor, descriptor);
        var journal = new StagedTransferJournal(Journal);
        var reply = await Allocate(new(Stages, journal), binding, security: snapshot);
        string path = Path.Combine(Journal, snapshot.SnapshotId.ToString("N") + ".security");
        if (change == "missing") File.Delete(path);
        else
        {
            byte[] bytes = File.ReadAllBytes(path);
            bytes[change == "changed" ? bytes.Length - 1 : 80] ^= 1;
            File.WriteAllBytes(path, bytes);
        }
        var reopened = new StagedTransferJournal(Journal);
        await Assert.ThrowsAsync<InvalidDataException>(() => reopened.ReadAsync(binding.ReservationId, CancellationToken.None));
        await Assert.ThrowsAsync<InvalidDataException>(() => Allocate(new(Stages, reopened), binding, security: snapshot));
        Assert.True(File.Exists(reply.Transfer.StagePath));
    }

    [Theory]
    [InlineData(1u, true)]
    [InlineData(3u, true)]
    [InlineData(0u, false)]
    [InlineData(4u, false)]
    [InlineData(5u, false)]
    public async Task Existing_target_dispositions_persist_seed_intent_and_return_only_an_empty_candidate(
        uint disposition, bool copied)
    {
        Directory.CreateDirectory(Parent);
        byte[] original = Enumerable.Range(0, 65539).Select(i => (byte)(i % 251)).ToArray();
        File.WriteAllBytes(Path.Combine(Parent, "save.txt"), original);
        var binding = Binding("save.txt", disposition, true);
        var journal = new StagedTransferJournal(Journal);
        var first = await Allocate(new(Stages, journal), binding);
        Assert.Empty(File.ReadAllBytes(first.Transfer.StagePath));
        Assert.Equal(original, File.ReadAllBytes(first.Transfer.DestinationPath));
        var manifest = await journal.ReadAsync(first.Transfer.TransferId, CancellationToken.None);
        Assert.Equal(binding, manifest.BoundAllocation);
        Assert.Equal(copied ? StagedSeedOrigin.ExistingPublic : StagedSeedOrigin.None, manifest.SeedProvenance!.Origin);
        Assert.Equal(copied, manifest.SeedProvenance.ContainsPriorBytes);
        Assert.Equal(copied ? binding.PublicTarget : null, manifest.SeedProvenance.PublicSource);
        if (copied)
        {
            Assert.Equal(StagedSeedAuthority.Unproven, manifest.SeedProvenance.ExportEvidence!.ReadAuthority);
            Assert.Equal(StagedSeedAuthority.Unproven, manifest.SeedProvenance.ExportEvidence.RecipientAuthority);
        }
        else Assert.Null(manifest.SeedProvenance.ExportEvidence);
        Assert.Null(manifest.SeedCompletion);
        Assert.Equal("seed_export_unproven", StagedSeedExport.Failure(manifest));
        if (copied)
            Assert.Equal("seed_coherence_unproved", (await Assert.ThrowsAsync<IOException>(() => journal.CompleteBoundSeedAsync(
                StagedTransferJournal.VersionIdentity(manifest), KernelCompletionFixture(manifest), CancellationToken.None))).Message);
        Assert.Equal(23u, manifest.AllocationExtensionVersion);
        Assert.Equal(first.StageIdentity, manifest.StageIdentity);
        var head = await journal.ReadDestinationHeadAsync(binding.Destination, CancellationToken.None);
        Assert.Equal(first.Transfer.TransferId, head!.CurrentSaveTransferId);
        Assert.Equal(first.DestinationGeneration, head.MaxAllocated);
        var reopened = new StagedTransferJournal(Journal);
        var replay = await Allocate(new(Stages, reopened), binding);
        Assert.Equal(first, replay);
    }

    [Fact]
    public async Task Saved_allocation_replay_requires_the_live_owner_lifetime_and_session()
    {
        var binding = Binding("owned.txt", 2, false);
        var journal = new StagedTransferJournal(Journal);
        var allocated = await Allocate(new(Stages, journal), binding);
        using var process = Process.GetCurrentProcess();
        var live = SessionResolver.GetRequiredProcessIdentity(process.Id);
        Assert.Equal(live.CreationTimeFileTime, allocated.Transfer.RequestorProcessCreationTime);
        MinifilterInterceptor.RequireBoundWriterIdentity(allocated.Transfer, process.Id);
        Assert.Throws<IOException>(() => MinifilterInterceptor.RequireBoundWriterIdentity(
            allocated.Transfer with { RequestorProcessCreationTime = live.CreationTimeFileTime - 1 }, process.Id));
        Assert.Throws<IOException>(() => MinifilterInterceptor.RequireBoundWriterIdentity(
            allocated.Transfer with { SessionId = live.SessionId + 1 }, process.Id));
        Assert.Throws<IOException>(() => MinifilterInterceptor.RequireBoundWriterIdentity(
            allocated.Transfer with { RequestorSid = "S-1-0-0" }, process.Id));
        Assert.Throws<IOException>(() => MinifilterInterceptor.RequireBoundWriterIdentity(
            allocated.Transfer with { ProcessId = process.Id + 1 }, process.Id));
        var saved = await journal.ReadAsync(binding.ReservationId, CancellationToken.None);
        Assert.Equal(TransferJournalState.Allocated, saved.State);
        Assert.Equal(allocated.StageIdentity, saved.StageIdentity);
        Assert.True(File.Exists(saved.Transfer.StagePath));
        Assert.False(File.Exists(Path.Combine(Parent, binding.CanonicalLeaf)));
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task Delete_high_water_includes_retained_bound_manifest_even_after_head_loss(bool nativeScheduled)
    {
        Directory.CreateDirectory(Parent);
        File.WriteAllText(Path.Combine(Parent, "save.txt"), "approved source");
        var binding = Binding("save.txt", 1, true);
        var journal = new StagedTransferJournal(Journal);
        var save = await Allocate(new(Stages, journal), binding);
        File.Delete(Path.Combine(Journal, "destination-" + binding.Destination.StorageKey + ".state"));
        var native = new StagedPublicDeleteBinding(Guid.NewGuid(), Guid.NewGuid(), _driver, 11,
            binding.PublicTarget!, save.Transfer.ProcessId, save.Transfer.RequestorProcessCreationTime!.Value,
            save.Transfer.SessionId!.Value, save.Transfer.RequestorSid!, 42, binding.MountManagerVolumeId);
        using var turn = await journal.EnterDestinationCommitTurnAsync(binding.Destination,
            StagedDestinationTurnPurpose.Allocation, CancellationToken.None);
        var prepared = nativeScheduled
            ? await journal.BeginNativeDeleteOnCloseCreateAsync(turn, native, Guid.NewGuid(),
                save.Transfer.DestinationPath, retainedManifestHighWater: 0, CancellationToken.None)
            : await journal.AdmitPublicDeleteAsync(turn, native, save.Transfer.DestinationPath,
                retainedManifestHighWater: 0, CancellationToken.None);
        Assert.Equal(save.DestinationGeneration + 1, prepared.Generation);
        Assert.Equal(nativeScheduled ? StagedPublicDeleteState.AcceptedUnresolved : StagedPublicDeleteState.Admitted, prepared.State);
        var head = (await journal.ReadDestinationHeadAsync(binding.Destination, CancellationToken.None))!;
        Assert.Equal(prepared.Generation, head.MaxAllocated);
        Assert.Equal(binding, (await journal.ReadAsync(binding.ReservationId, CancellationToken.None)).BoundAllocation);
    }

    [Fact]
    public async Task Renamed_parent_and_replaced_locator_cannot_select_different_seed_bytes()
    {
        Directory.CreateDirectory(Parent);
        File.WriteAllText(Path.Combine(Parent, "save.txt"), "original approved source");
        var binding = Binding("save.txt", 1, true);
        Directory.Move(Parent, Path.Combine(_workspace.Root, "renamed-original"));
        Directory.CreateDirectory(Parent);
        File.WriteAllText(Path.Combine(Parent, "save.txt"), "replacement locator bytes");
        var journal = new StagedTransferJournal(Journal);
        var result = await Allocate(new(Stages, journal), binding);
        await journal.ValidateAllocationReplyAsync(new(result.Transfer.TransferId, result.DestinationGeneration,
            result.StageIdentity), binding.ReservationId, CancellationToken.None);
        Assert.Empty(File.ReadAllBytes(result.Transfer.StagePath));
        var entry = await journal.ReadAsync(binding.ReservationId, CancellationToken.None);
        Assert.Equal(binding, entry.SeedProvenance!.SourceBinding);
        Assert.Null(entry.SeedCompletion);
        Assert.Equal("original approved source", File.ReadAllText(Path.Combine(_workspace.Root, "renamed-original", "save.txt")));
        Assert.Equal("replacement locator bytes", File.ReadAllText(Path.Combine(Parent, "save.txt")));
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task Native_false_no_op_preserves_exact_bytes_and_independent_create_on_close(bool scheduledOnClose)
    {
        Directory.CreateDirectory(Parent);
        string path = Path.Combine(Parent, "native-clear.txt");
        byte[] original = Encoding.UTF8.GetBytes("original public bytes");
        File.WriteAllBytes(path, original);
        var binding = Binding("native-clear.txt", 1, true);
        var destination = binding.Destination;
        using var parent = StagedDestinationDirectory.Open(binding);
        var observation = StagedDestinationNameObserver.Observe(parent.VolumeRoot, parent.Parent,
            destination, CancellationToken.None);
        var journal = new StagedTransferJournal(Journal);
        using (var bind = await journal.EnterDestinationCommitTurnAsync(destination,
                   StagedDestinationTurnPurpose.Allocation, CancellationToken.None))
        {
            var head = await journal.CapturePublicOpenHeadAsync(bind, binding.PublicTarget!, path,
                observation, CancellationToken.None);
            Assert.Equal(0, head.MaxAllocated); Assert.Empty(head.Deletes);
        }
        StagedPublicDeleteBinding? scheduled = null;
        Guid createOperation = Guid.NewGuid();
        if (scheduledOnClose)
        {
            using var process = Process.GetCurrentProcess();
            using var user = WindowsIdentity.GetCurrent();
            scheduled = new(Guid.NewGuid(), Guid.NewGuid(), _driver, 11, binding.PublicTarget!, process.Id,
                process.StartTime.ToFileTimeUtc(), checked((uint)process.SessionId), user.User!.Value, 42,
                binding.MountManagerVolumeId);
            using var turn = await journal.EnterDestinationCommitTurnAsync(destination,
                StagedDestinationTurnPurpose.Allocation, CancellationToken.None);
            await journal.BeginNativeDeleteOnCloseCreateAsync(turn, scheduled, createOperation,
                path, 0, CancellationToken.None);
        }
        using (var regular = CreateFileW(path, 0x10000, 7, IntPtr.Zero, 3, 0x80, IntPtr.Zero))
        {
            Assert.False(regular.IsInvalid, $"Checked DELETE open failed: {Marshal.GetLastWin32Error()}");
            using var creator = scheduledOnClose
                ? CreateFileW(path, 0x10000, 7, IntPtr.Zero, 3, 0x04000080, IntPtr.Zero) : null;
            if (creator is not null)
            {
                Assert.False(creator.IsInvalid, $"Native on-close CREATE failed: {Marshal.GetLastWin32Error()}");
                using var accepted = await journal.EnterDestinationCommitTurnAsync(destination,
                    StagedDestinationTurnPurpose.Reconciliation, CancellationToken.None);
                await journal.RecordNativeDeleteOnCloseCreateResultAsync(accepted, scheduled!, createOperation, true, true);
            }
            var before = (await journal.ReadDestinationHeadAsync(destination, CancellationToken.None))!;
            Guid operation = Guid.NewGuid();
            using (var turn = await journal.EnterDestinationCommitTurnAsync(destination,
                       StagedDestinationTurnPurpose.Reconciliation, CancellationToken.None))
            {
                var checkedName = StagedDestinationNameObserver.Observe(parent.VolumeRoot, parent.Parent,
                    destination, CancellationToken.None);
                Assert.Equal(binding.PublicTarget, checkedName.PublicIdentity);
                await journal.BeginPublicDeleteClearAsync(turn, operation, binding.PublicTarget!,
                    CancellationToken.None, checkedName);
                byte clear = 0;
                bool result = SetFileInformationByHandle(regular, 4, ref clear, 1);
                int error = Marshal.GetLastWin32Error();
                await journal.RecordPublicDeleteClearResultAsync(turn, operation, binding.PublicTarget!, result);
                Assert.True(result, $"Native FALSE/no-op failed: {error}");
            }
            var after = (await new StagedTransferJournal(Journal).ReadDestinationHeadAsync(destination, CancellationToken.None))!;
            Assert.Equal(before.MaxAllocated, after.MaxAllocated); Assert.Equal(before.Deletes, after.Deletes);
            Assert.Equal(before.CommittedDelete, after.CommittedDelete); Assert.Null(after.PendingCommit);
            using var bytes = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
            byte[] observed = new byte[original.Length];
            bytes.ReadExactly(observed); Assert.Equal(original, observed); Assert.Equal(original.Length, bytes.Length);
            if (creator is not null)
            {
                bytes.Dispose(); creator.Dispose(); // Another original reader/DELETE handle still retains the link.
                var retained = StagedDestinationNameObserver.Observe(parent.VolumeRoot, parent.Parent,
                    destination, CancellationToken.None);
                Assert.Equal(binding.PublicTarget, retained.PublicIdentity);
            }
        }
        Assert.Equal(!scheduledOnClose, File.Exists(path));
        var finalName = StagedDestinationNameObserver.Observe(parent.VolumeRoot, parent.Parent,
            destination, CancellationToken.None);
        Assert.Equal(scheduledOnClose ? null : binding.PublicTarget, finalName.PublicIdentity);
        if (!scheduledOnClose)
        {
            using var exact = StagedStageFile.Open(path);
            Assert.Equal(binding.PublicTarget, exact.Identity); Assert.Equal(original, File.ReadAllBytes(path));
        }
    }

    [Fact]
    public async Task Replaced_public_identity_and_false_absence_never_create_a_manifest()
    {
        Directory.CreateDirectory(Parent);
        string path = Path.Combine(Parent, "save.txt");
        File.WriteAllText(path, "original");
        var existing = Binding("save.txt", 1, true);
        File.Move(path, Path.Combine(Parent, "retained-original.txt"));
        File.WriteAllText(path, "different identity");
        var journal = new StagedTransferJournal(Journal);
        var allocator = new StagedTransferAllocator(Stages, journal);
        await Assert.ThrowsAsync<IOException>(() => Allocate(allocator, existing));
        Assert.Null(await journal.FindBoundAllocationAsync(existing.ReservationId, CancellationToken.None));
        var absent = Binding("new.txt", 2, false);
        File.WriteAllText(Path.Combine(Parent, "new.txt"), "");
        await Assert.ThrowsAsync<IOException>(() => Allocate(allocator, absent));
        Assert.Null(await journal.FindBoundAllocationAsync(absent.ReservationId, CancellationToken.None));
        Assert.Empty(Directory.GetFiles(Stages));
    }

    [Fact]
    public async Task Manifest_before_failed_head_claim_replays_the_same_private_identity_and_generation()
    {
        var binding = Binding("empty.txt", 2, false);
        var journal = new StagedTransferJournal(Journal);
        string blockedHead = Path.Combine(Journal, "destination-" + binding.Destination.StorageKey + ".state");
        Directory.CreateDirectory(blockedHead); // Real native head-commit failure after the manifest flush.
        await Assert.ThrowsAsync<IOException>(() => Allocate(new(Stages, journal), binding));
        var candidate = await journal.ReadAsync(binding.ReservationId, CancellationToken.None);
        Assert.Equal(TransferJournalState.Allocated, candidate.State);
        Assert.True(File.Exists(candidate.Transfer.StagePath));
        Assert.Equal(0, new FileInfo(candidate.Transfer.StagePath).Length);
        await Assert.ThrowsAsync<IOException>(() => journal.ValidateAllocationReplyAsync(
            new(candidate.Transfer.TransferId, candidate.DestinationGeneration, candidate.StageIdentity!),
            binding.ReservationId, CancellationToken.None));
        Directory.Delete(blockedHead);
        var reopened = new StagedTransferJournal(Journal);
        var replay = await Allocate(new(Stages, reopened), binding);
        Assert.Equal(candidate.StageIdentity, replay.StageIdentity);
        Assert.Equal(candidate.DestinationGeneration, replay.DestinationGeneration);
        var head = await reopened.ReadDestinationHeadAsync(binding.Destination, CancellationToken.None);
        Assert.Equal(binding.ReservationId, head!.CurrentSaveTransferId);
        Assert.Equal(candidate.DestinationGeneration, head.MaxAllocated);
    }

    [Fact]
    public async Task Overtaken_manifest_candidate_remains_private_and_never_rolls_back_the_head()
    {
        var first = Binding("empty.txt", 2, false);
        var journal = new StagedTransferJournal(Journal);
        string blockedHead = Path.Combine(Journal, "destination-" + first.Destination.StorageKey + ".state");
        Directory.CreateDirectory(blockedHead);
        var allocator = new StagedTransferAllocator(Stages, journal);
        await Assert.ThrowsAsync<IOException>(() => Allocate(allocator, first));
        var candidate = await journal.ReadAsync(first.ReservationId, CancellationToken.None);
        Directory.Delete(blockedHead);
        var newer = await Allocate(allocator, first with { ReservationId = Guid.NewGuid() });
        Assert.True(newer.DestinationGeneration > candidate.DestinationGeneration);
        await Assert.ThrowsAsync<IOException>(() => Allocate(allocator, first));
        Assert.True(File.Exists(candidate.Transfer.StagePath));
        var head = await journal.ReadDestinationHeadAsync(first.Destination, CancellationToken.None);
        Assert.Equal(newer.Transfer.TransferId, head!.CurrentSaveTransferId);
        Assert.Equal(newer.DestinationGeneration, head.MaxAllocated);
    }

    [Fact]
    public async Task Concurrent_guid_reuse_cannot_delete_a_different_destination_candidate()
    {
        var first = Binding("first.txt", 2, false);
        var second = first with { CanonicalLeaf = "second.txt" };
        var journal = new StagedTransferJournal(Journal);
        var allocator = new StagedTransferAllocator(Stages, journal);
        async Task<StagedAllocationReply?> Attempt(StagedAllocationBindingV23 binding)
        {
            try { return await Allocate(allocator, binding); }
            catch (IOException) { return null; }
        }
        var replies = await Task.WhenAll(Attempt(first), Attempt(second));
        var winner = Assert.Single(replies, r => r is not null)!;
        using var held = StagedStageFile.Open(winner.Transfer.StagePath);
        Assert.Equal(winner.StageIdentity, held.Identity);
        Assert.Equal(0, held.Stream.Length);
        Assert.Single(Directory.GetFiles(Stages));
        var saved = await journal.ReadAsync(first.ReservationId, CancellationToken.None);
        Assert.Equal(winner.Transfer, saved.Transfer);
    }

    [Fact]
    public async Task Waiting_destination_continuation_leaves_unrelated_work_free_and_drains_before_port_close()
    {
        using var continuations = new StagedRequestContinuations(CancellationToken.None);
        var entered = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var unrelated = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var stopped = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        continuations.Dispatch(async token =>
        {
            entered.SetResult();
            try { await Task.Delay(Timeout.InfiniteTimeSpan, token); }
            finally { stopped.SetResult(); }
        });
        await entered.Task.WaitAsync(TimeSpan.FromSeconds(10));
        continuations.Dispatch(_ => { unrelated.SetResult(); return Task.CompletedTask; });
        await unrelated.Task.WaitAsync(TimeSpan.FromSeconds(10));
        Assert.False(stopped.Task.IsCompleted);
        await continuations.DrainAsync().WaitAsync(TimeSpan.FromSeconds(10));
        Assert.True(stopped.Task.IsCompleted);
        Assert.Throws<InvalidOperationException>(() => continuations.Dispatch(_ => Task.CompletedTask));
    }

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetVolumeNameForVolumeMountPointW(string root, StringBuilder volume, int size);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern SafeFileHandle CreateFileW(string path, uint access, uint share, IntPtr security,
        uint disposition, uint flags, IntPtr template);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool SetFileInformationByHandle(SafeFileHandle file, int informationClass,
        ref byte information, uint size);
}
#endif
