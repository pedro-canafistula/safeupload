using SafeUpload.Agent.Core.Domain;
using SafeUpload.Agent.Core.Application;
using SafeUpload.Agent.Core.Infrastructure;
using SafeUpload.Agent.Core.Infrastructure.Extraction;
using SafeUpload.Agent.Service.Interception;
using SafeUpload.Agent.Service.Notifications;
using StageDisposeOutcome = SafeUpload.Agent.Minifilter.StageDisposeOutcome;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Security.Cryptography;
using System.Runtime.InteropServices;
using System.Text;
using SafeUpload.Agent.Minifilter;

namespace SafeUpload.Agent.Tests;

public sealed class StagedTransferAllocatorTests : IDisposable
{
    private readonly TestWorkspace _workspace = new();

    public void Dispose() => _workspace.Dispose();

    [Fact]
    public void Bound_allocation_marker_is_opaque_and_cannot_fall_back_to_v20_or_image_text()
    {
        SafeUploadRequest request = MakeAllocateRequest(Contract.StageBoundAllocationVersion,
            RequestFlags.StageV19Reply, new byte[124]);
        Assert.True(request.UsesStageBinaryPayload);
        Assert.False(request.TryReadStagePayload<SafeUploadStageAllocateV19>(
            Operation.StageAllocate, out _));
        Assert.Throws<InvalidOperationException>(() => request.GetImageName());
#if !SAFEUPLOAD_ADMISSION_EVIDENCE
        Assert.False(request.HasKnownFlags);
        Assert.Null(typeof(SafeUploadRequest).Assembly.GetType(
            "SafeUpload.Agent.Minifilter.SafeUploadStageAllocateV23"));
        Assert.Null(typeof(SafeUploadRequest).GetMethod("TryReadBoundAllocationV23"));
        Assert.Null(typeof(StagedTransferAllocator).GetMethod("AllocateV23Async",
            System.Reflection.BindingFlags.Instance | System.Reflection.BindingFlags.NonPublic));
        Assert.Null(typeof(StagedTransferAllocator).Assembly.GetType(
            "SafeUpload.Agent.Service.Interception.StagedDestinationDirectory"));
        Assert.Null(typeof(StagedTransferAllocator).Assembly.GetType(
            "SafeUpload.Agent.Service.Interception.StagedRequestContinuations"));
#endif
    }

    [Fact]
    public void V19_allocate_marker_with_legacy_reserved_value_is_rejected_before_text_decode()
    {
        SafeUploadRequest request = MakeAllocateRequest(3, RequestFlags.StageV19Reply,
            Encoding.Unicode.GetBytes("not-a-text-fallback"));

        // Run() applies HasKnownFlags before operation dispatch. The marker
        // also makes ImageName opaque, so even an accidental legacy route
        // cannot decode the bytes as a process name.
        Assert.False(request.HasKnownFlags);
        Assert.True(request.UsesStageV19BinaryPayload);
        Assert.False(request.TryReadStagePayload<SafeUploadStageAllocateV19>(
            Operation.StageAllocate, out _));
        Assert.Throws<InvalidOperationException>(() => request.GetImageName());
    }

    [Fact]
    public void V19_allocate_reserved_value_without_marker_is_denied_by_typed_parser()
    {
        byte[] payload = EncodeStageAllocatePayload();
        SafeUploadRequest request = MakeAllocateRequest(Contract.StageExtensionVersion,
            RequestFlags.None, payload);

        // The dispatcher selects the typed branch by Reserved=19. The typed
        // parser requires the reply marker and refuses to expose this as text.
        Assert.True(request.HasKnownFlags);
        Assert.True(request.UsesStageV19BinaryPayload);
        Assert.False(request.TryReadStagePayload<SafeUploadStageAllocateV19>(
            Operation.StageAllocate, out _));
        Assert.Throws<InvalidOperationException>(() => request.GetImageName());
    }

    [Fact]
    public void Legacy_allocate_request_remains_text_decodable()
    {
        const string imageName = "notepad.exe";
        SafeUploadRequest request = MakeAllocateRequest(0, RequestFlags.None,
            Encoding.Unicode.GetBytes(imageName));

        Assert.True(request.HasKnownFlags);
        Assert.False(request.UsesStageV19BinaryPayload);
        Assert.Equal(imageName, request.GetImageName());
        Assert.False(request.TryReadStagePayload<SafeUploadStageAllocateV19>(
            Operation.StageAllocate, out _));
    }

    [Fact]
    public void V19_allocate_request_is_read_only_through_typed_payload_parser()
    {
        Guid reservation = Guid.NewGuid();
        Guid driverInstance = Guid.NewGuid();
        SafeUploadRequest request = MakeAllocateRequest(Contract.StageExtensionVersion,
            RequestFlags.StageV19Reply, EncodeStageAllocatePayload(reservation, driverInstance));

        Assert.True(request.HasKnownFlags);
        Assert.True(request.UsesStageV19BinaryPayload);
        Assert.True(request.TryReadStagePayload<SafeUploadStageAllocateV19>(
            Operation.StageAllocate, out SafeUploadStageAllocateV19 payload));
        Assert.Equal(reservation, payload.AllocationReservationId);
        Assert.Equal(driverInstance, payload.DriverInstanceId);
        Assert.Throws<InvalidOperationException>(() => request.GetImageName());
    }

    [Fact]
    public void V20_typed_allocate_rejects_the_old_v19_profile_marker()
    {
        var oldPayload = new SafeUploadStageAllocateV19
        {
            Version = 19,
            StructSize = Contract.StageAllocateV19Size,
            AllocationReservationId = Guid.NewGuid(),
            DriverInstanceId = Guid.NewGuid(),
        };
        Span<byte> oldBytes = stackalloc byte[Contract.StageAllocateV19Size];
        MemoryMarshal.Write(oldBytes, in oldPayload);
        SafeUploadRequest request = MakeAllocateRequest(19, RequestFlags.StageV19Reply,
            oldBytes.ToArray());

        Assert.False(request.HasKnownFlags);
        Assert.False(request.TryReadStagePayload<SafeUploadStageAllocateV19>(
            Operation.StageAllocate, out _));
        Assert.Throws<InvalidOperationException>(() => request.GetImageName());
    }

    [Fact]
    public void V20_typed_allocate_rejects_nonzero_data_after_payload_or_path()
    {
        Guid reservation = Guid.NewGuid();
        Guid driverInstance = Guid.NewGuid();
        byte[] payload = EncodeStageAllocatePayload(reservation, driverInstance);
        int imageOffset = checked((int)Marshal.OffsetOf<SafeUploadRequest>(nameof(SafeUploadRequest.ImageName)));
        int pathOffset = checked((int)Marshal.OffsetOf<SafeUploadRequest>(nameof(SafeUploadRequest.Path)));

        SafeUploadRequest imageTail = MakeAllocateRequest(Contract.StageExtensionVersion,
            RequestFlags.StageV19Reply, payload);
        Span<byte> imageBytes = MemoryMarshal.AsBytes(MemoryMarshal.CreateSpan(ref imageTail, 1));
        imageBytes[imageOffset + payload.Length + 1] = 0x5a;
        Assert.False(imageTail.TryReadStagePayload<SafeUploadStageAllocateV19>(
            Operation.StageAllocate, out _));

        SafeUploadRequest pathTail = MakeAllocateRequest(Contract.StageExtensionVersion,
            RequestFlags.StageV19Reply, payload);
        Span<byte> pathBytes = MemoryMarshal.AsBytes(MemoryMarshal.CreateSpan(ref pathTail, 1));
        pathBytes[pathOffset + checked((int)pathTail.PathLength) + 1] = 0x5a;
        Assert.False(pathTail.TryReadStagePayload<SafeUploadStageAllocateV19>(
            Operation.StageAllocate, out _));
    }

    [Fact]
    public void V20_marker_on_an_ordinary_operation_is_rejected_before_image_text_decode()
    {
        SafeUploadRequest request = MakeAllocateRequest(Contract.StageExtensionVersion,
            RequestFlags.None, [0x01, 0x7f, 0x00, 0xff]);
        request.Operation = Operation.Create;

        Assert.False(request.HasKnownFlags);
        Assert.True(request.UsesStageBinaryPayload);
        Assert.Throws<InvalidOperationException>(() => request.GetImageName());
    }

    private static SafeUploadRequest MakeAllocateRequest(uint reserved, RequestFlags flags,
        byte[] imageNameBytes)
    {
        var request = new SafeUploadRequest
        {
            Version = Contract.Version,
            StructSize = Contract.RequestSize,
            RequestId = 1,
            Operation = Operation.StageAllocate,
            RequestorProcessId = 1234,
            Flags = (uint)flags,
            PathLength = (uint)Encoding.Unicode.GetByteCount(@"C:\stage-target.txt"),
            ImageNameLength = (uint)imageNameBytes.Length,
            Reserved = reserved,
        };
        Span<byte> requestBytes = MemoryMarshal.AsBytes(MemoryMarshal.CreateSpan(ref request, 1));
        int pathOffset = checked((int)Marshal.OffsetOf<SafeUploadRequest>(nameof(SafeUploadRequest.Path)));
        int imageNameOffset = checked((int)Marshal.OffsetOf<SafeUploadRequest>(nameof(SafeUploadRequest.ImageName)));
        Encoding.Unicode.GetBytes(@"C:\stage-target.txt").AsSpan().CopyTo(requestBytes.Slice(pathOffset));
        imageNameBytes.AsSpan().CopyTo(requestBytes.Slice(imageNameOffset));
        return request;
    }

    private static byte[] EncodeStageAllocatePayload(Guid? reservation = null,
        Guid? driverInstance = null)
    {
        var payload = new SafeUploadStageAllocateV19
        {
            Version = Contract.StageExtensionVersion,
            StructSize = Contract.StageAllocateV19Size,
            AllocationReservationId = reservation ?? Guid.NewGuid(),
            DriverInstanceId = driverInstance ?? Guid.NewGuid(),
        };
        Span<byte> bytes = stackalloc byte[Contract.StageAllocateV19Size];
        MemoryMarshal.Write(bytes, in payload);
        return bytes.ToArray();
    }

    [Fact]
    public async Task Allocation_is_journaled_before_the_stage_name_is_returned()
    {
        string root = Path.Combine(_workspace.Root, "stage");
        var journal = new StagedTransferJournal(Path.Combine(_workspace.Root, "journal"));
        var allocator = new StagedTransferAllocator(root, journal);
        string destination = Path.Combine(_workspace.Root, "destination", "report.txt");

        var first = await allocator.AllocateAsync(destination, DestinationKind.Cloud,
            "word.exe", 17, 2, CancellationToken.None);
        var second = await allocator.AllocateAsync(destination, DestinationKind.Cloud,
            "word.exe", 17, 2, CancellationToken.None);

        Assert.NotEqual(first.TransferId, second.TransferId);
        Assert.NotEqual(first.StagePath, second.StagePath);
        Assert.Equal(".txt", Path.GetExtension(first.StagePath));
        Assert.StartsWith(root + Path.DirectorySeparatorChar, first.StagePath,
            StringComparison.OrdinalIgnoreCase);
        Assert.True(File.Exists(first.StagePath));
        Assert.Equal(0, new FileInfo(first.StagePath).Length);
        Assert.False(File.Exists(destination));
        var entry = await journal.ReadAsync(first.TransferId, CancellationToken.None);
        Assert.Equal(TransferJournalState.Allocated, entry.State);
        Assert.Equal(first, entry.Transfer);
    }

    [Fact]
    public async Task Allocation_persists_requestor_sid_and_process_creation_time()
    {
        string root = Path.Combine(_workspace.Root, "stage");
        var journal = new StagedTransferJournal(Path.Combine(_workspace.Root, "journal"));
        var allocator = new StagedTransferAllocator(root, journal);
        string sid = "S-1-5-21-111-222-333-1000";

        StagedTransfer transfer = await allocator.AllocateAsync(
            Path.Combine(_workspace.Root, "destination", "bound.txt"), DestinationKind.Cloud,
            "word.exe", 17, 2, 2, null, CancellationToken.None,
            requestorSid: sid, requestorProcessCreationTime: 638953632000000000);

        TransferJournalEntry entry = await journal.ReadAsync(transfer.TransferId, CancellationToken.None);
        Assert.Equal(sid, entry.Transfer.RequestorSid);
        Assert.Equal<long?>(638953632000000000, entry.Transfer.RequestorProcessCreationTime);
    }

    [Fact]
    public async Task V19_stable_allocation_reservation_replays_the_same_exact_stage_under_concurrency()
    {
        string root = Path.Combine(_workspace.Root, "stage");
        string destination = Path.Combine(_workspace.Root, "destination", "replay.txt");
        Directory.CreateDirectory(Path.GetDirectoryName(destination)!);
        var journal = new StagedTransferJournal(Path.Combine(_workspace.Root, "journal"));
        var allocator = new StagedTransferAllocator(root, journal);
        const string sid = "S-1-5-21-111-222-333-1000";
        const long creation = 638953632000000000;
        Guid driverInstance = Guid.NewGuid();
        var intent = new StagedAllocationIntentV19(Guid.NewGuid(), Guid.Empty, 5, 0, driverInstance);

        Task<StagedAllocationReply> first = allocator.AllocateV19Async(destination,
            DestinationKind.Cloud, "word", 17, 2, intent, null, null, sid, creation,
            CancellationToken.None);
        Task<StagedAllocationReply> retry = allocator.AllocateV19Async(destination,
            DestinationKind.Cloud, "word", 17, 2, intent, null, null, sid, creation,
            CancellationToken.None);
        StagedAllocationReply[] replies = await Task.WhenAll(first, retry);

        Assert.Equal(replies[0].Transfer.TransferId, replies[1].Transfer.TransferId);
        Assert.Equal(replies[0].Transfer.StagePath, replies[1].Transfer.StagePath);
        Assert.Equal(replies[0].DestinationGeneration, replies[1].DestinationGeneration);
        Assert.Equal(replies[0].StageIdentity, replies[1].StageIdentity);
        TransferJournalEntry entry = await journal.ReadAsync(intent.ReservationId, CancellationToken.None);
        Assert.Equal(TransferJournalState.Allocated, entry.State);
        Assert.Equal(driverInstance, entry.DriverInstanceId);
        Assert.Equal(0, replies[0].InitialLength);

        await Assert.ThrowsAsync<IOException>(() => allocator.AllocateV19Async(destination,
            DestinationKind.Cloud, "word", 17, 2, intent with { DriverInstanceId = Guid.NewGuid() },
            null, null, sid, creation, CancellationToken.None));
        await Assert.ThrowsAsync<IOException>(() => allocator.AllocateV19Async(destination,
            DestinationKind.Cloud, "word", 17, 2, intent with { Disposition = 4 },
            null, null, sid, creation, CancellationToken.None));
    }

    [Fact]
    public async Task Backing_file_has_its_own_private_acl_and_restart_removes_extra_grants()
    {
        if (!OperatingSystem.IsWindows()) return;
        string root = Path.Combine(_workspace.Root, "stage");
        var journal = new StagedTransferJournal(Path.Combine(_workspace.Root, "journal"));
        var allocator = new StagedTransferAllocator(root, journal);
        var transfer = await allocator.AllocateAsync(Path.Combine(_workspace.Root, "report.txt"),
            DestinationKind.Cloud, "word.exe", 17, 2, CancellationToken.None);
        var file = new FileInfo(transfer.StagePath);
        var security = file.GetAccessControl();
        Assert.True(security.AreAccessRulesProtected);
        var everyone = new SecurityIdentifier(WellKnownSidType.WorldSid, null);
        security.AddAccessRule(new FileSystemAccessRule(everyone,
            FileSystemRights.Read, AccessControlType.Allow));
        file.SetAccessControl(security);
        _ = new StagedTransferAllocator(root, journal);
        security = file.GetAccessControl();
        Assert.True(security.AreAccessRulesProtected);
        using var identity = WindowsIdentity.GetCurrent();
        var owner = identity.User ?? throw new InvalidOperationException("Test identity has no SID.");
        var rules = security.GetAccessRules(true, true, typeof(SecurityIdentifier))
            .Cast<FileSystemAccessRule>().ToArray();
        Assert.NotEmpty(rules);
        Assert.All(rules, rule => {
            Assert.Equal(AccessControlType.Allow, rule.AccessControlType);
            Assert.False(rule.IsInherited);
            var sid = (SecurityIdentifier)rule.IdentityReference;
            Assert.True(sid.Equals(owner) || sid.IsWellKnown(WellKnownSidType.LocalSystemSid));
        });
    }

    [Fact]
    public async Task Allocation_rejects_a_destination_inside_the_stage_root()
    {
        string root = Path.Combine(_workspace.Root, "stage");
        var allocator = new StagedTransferAllocator(root,
            new StagedTransferJournal(Path.Combine(_workspace.Root, "journal")));

        await Assert.ThrowsAsync<ArgumentException>(() => allocator.AllocateAsync(
            Path.Combine(root, "escape.txt"), DestinationKind.Cloud,
            "word.exe", 17, null, CancellationToken.None));
    }

    [Fact]
    public async Task Later_open_copies_the_sealed_version_without_changing_it()
    {
        string root = Path.Combine(_workspace.Root, "stage");
        var journal = new StagedTransferJournal(Path.Combine(_workspace.Root, "journal"));
        var allocator = new StagedTransferAllocator(root, journal);
        string destination = Path.Combine(_workspace.Root, "destination", "report.txt");
        var first = await allocator.AllocateAsync(destination, DestinationKind.Cloud,
            "word.exe", 17, 2, CancellationToken.None);
        await File.WriteAllTextAsync(first.StagePath, "approved version");
        await journal.TransitionAsync(first.TransferId, TransferJournalState.Allocated,
            TransferJournalState.Sealed, null, CancellationToken.None);

        var second = await allocator.AllocateAsync(destination, DestinationKind.Cloud,
            "word.exe", 17, 2, 1, first, CancellationToken.None);
        Assert.NotEqual(first.TransferId, second.TransferId);
        Assert.Equal("approved version", await File.ReadAllTextAsync(second.StagePath));
        await File.AppendAllTextAsync(second.StagePath, " plus changes");
        Assert.Equal("approved version", await File.ReadAllTextAsync(first.StagePath));
        Assert.Equal(TransferJournalState.Allocated,
            (await journal.ReadAsync(second.TransferId, CancellationToken.None)).State);
    }

    [Fact]
    public async Task V19_create_after_discard_commits_exact_ancestry_before_backing_and_replays_reservation()
    {
        string root = Path.Combine(_workspace.Root, "stage");
        string journalPath = Path.Combine(_workspace.Root, "journal");
        string destination = Path.Combine(_workspace.Root, "destination", "report.txt");
        Directory.CreateDirectory(Path.GetDirectoryName(destination)!);
        var journal = new StagedTransferJournal(journalPath);
        var allocator = new StagedTransferAllocator(root, journal);
        const int processId = 17;
        const uint sessionId = 2;
        const string sid = "S-1-5-21-111-222-333-1000";
        const long creation = 638953632000000000;
        Guid driverInstanceId = Guid.NewGuid();
        Assert.Equal(StagedDriverEpochReconcileV20.Active,
            await journal.ReconcileDriverInstanceV20Async(driverInstanceId, 0x1bf, CancellationToken.None));

        StagedAllocationReply v1Reply = await allocator.AllocateV19Async(destination,
            DestinationKind.Cloud, "word.exe", processId, sessionId,
            new StagedAllocationIntentV19(Guid.NewGuid(), Guid.Empty, 2, 0, driverInstanceId),
            null, null, sid, creation, CancellationToken.None);
        TransferJournalEntry v1Allocated = await journal.ReadAsync(v1Reply.Transfer.TransferId, CancellationToken.None);
        var v1Identity = new StagedVersionIdentity(v1Reply.Transfer.TransferId,
            v1Reply.DestinationGeneration, v1Reply.StageIdentity);
        Assert.Equal(v1Identity, new StagedVersionIdentity(v1Allocated.Transfer.TransferId,
            v1Allocated.DestinationGeneration, v1Allocated.StageIdentity!));
        await CompleteV20AttachmentAsync(journal, v1Reply.Transfer, v1Identity,
            driverInstanceId, 1000);
        TransferJournalEntry v1 = await LegacyStagedJournalFixture.SealEmptyAsync(journal, _workspace.Root, v1Identity.TransferId, processId,
            v1Reply.Transfer.StagePath, CancellationToken.None, v1Identity);
        Assert.Equal(TransferJournalState.LegacyEmptyHeld, v1.State);

        StagedAllocationReply v2Reply = await allocator.AllocateV19Async(destination,
            DestinationKind.Cloud, "word.exe", processId, sessionId,
            new StagedAllocationIntentV19(Guid.NewGuid(), v1Identity.TransferId, 1, 1, driverInstanceId),
            v1.Transfer, null, sid, creation, CancellationToken.None);
        TransferJournalEntry v2Allocated = await journal.ReadAsync(v2Reply.Transfer.TransferId, CancellationToken.None);
        Assert.Equal(v1Identity, v2Allocated.ParentVersionIdentity);
        await File.WriteAllTextAsync(v2Reply.Transfer.StagePath, "private V2 bytes");
        var v2Identity = new StagedVersionIdentity(v2Reply.Transfer.TransferId,
            v2Reply.DestinationGeneration, v2Reply.StageIdentity);
        await CompleteV20AttachmentAsync(journal, v2Reply.Transfer, v2Identity,
            driverInstanceId, 1010);
        TransferJournalEntry v2 = await LegacyStagedJournalFixture.SealEmptyAsync(journal, _workspace.Root, v2Identity.TransferId, processId,
            v2Reply.Transfer.StagePath, CancellationToken.None, v2Identity);
        Assert.Equal(TransferJournalState.Sealed, v2.State);
        Assert.Equal(driverInstanceId, v2.DriverInstanceId);
        Assert.Equal(StagedAttachmentStateV20.HandleObserved, v2.AttachmentStateV20);
        Assert.Equal((ulong?)1012, v2.CompletionPermitRequestIdV20);
        Assert.Equal((ulong?)1013, v2.HandleObservedRequestIdV20);

        Guid reservationId = Guid.NewGuid();
        StagedStageIdentity parentDirectory = StagedStageFile.ReadDirectoryIdentity(
            Path.GetDirectoryName(destination)!);
        var createAfter = new StagedCreateAfterDiscardRequest(reservationId, v2Identity,
            parentDirectory, 5, destination, DestinationKind.Cloud, processId, sessionId, sid, creation,
            driverInstanceId);
        Guid mixedReservationId = Guid.NewGuid();
        var mixedLegacyRequest = createAfter with
        {
            ReservationId = mixedReservationId,
            DriverInstanceId = null
        };
        byte[] v1BeforeMixedRequest = await File.ReadAllBytesAsync(Path.Combine(journalPath,
            v1Identity.TransferId.ToString("N") + ".json"));
        byte[] v2BeforeMixedRequest = await File.ReadAllBytesAsync(Path.Combine(journalPath,
            v2Identity.TransferId.ToString("N") + ".json"));
        byte[] v2StageBeforeMixedRequest = await File.ReadAllBytesAsync(v2Reply.Transfer.StagePath);
        await Assert.ThrowsAsync<IOException>(() => allocator.CreateAfterPrivateDiscardAsync(
            mixedLegacyRequest, CancellationToken.None));
        Assert.Equal(v1BeforeMixedRequest, await File.ReadAllBytesAsync(Path.Combine(journalPath,
            v1Identity.TransferId.ToString("N") + ".json")));
        Assert.Equal(v2BeforeMixedRequest, await File.ReadAllBytesAsync(Path.Combine(journalPath,
            v2Identity.TransferId.ToString("N") + ".json")));
        Assert.Equal(v2StageBeforeMixedRequest, await File.ReadAllBytesAsync(v2Reply.Transfer.StagePath));
        Assert.False(File.Exists(Path.Combine(journalPath, mixedReservationId.ToString("N") + ".json")));
        Assert.False(File.Exists(Path.Combine(root, mixedReservationId.ToString("N") + ".txt")));
        Assert.False(File.Exists(destination));

        StagedAllocationReply v3Reply = await allocator.CreateAfterPrivateDiscardAsync(createAfter,
            CancellationToken.None);
        TransferJournalEntry v2Pending = await journal.ReadAsync(v2Identity.TransferId, CancellationToken.None);
        TransferJournalEntry v3Allocated = await journal.ReadAsync(reservationId, CancellationToken.None);
        var v3Identity = new StagedVersionIdentity(reservationId, v3Reply.DestinationGeneration,
            v3Reply.StageIdentity);
        await File.WriteAllTextAsync(v3Reply.Transfer.StagePath, "attached V3 bytes");
        Assert.Equal(TransferJournalState.DiscardPending, v2Pending.State);
        Assert.Equal(v2Identity.TransferId, v2Pending.DiscardReservationId);
        Assert.Equal(reservationId, v2Pending.CreateAfterReservationId);
        Assert.Equal(TransferJournalState.Allocated, v3Allocated.State);
        Assert.Equal(v1Identity, v3Allocated.ParentVersionIdentity);
        Assert.Equal(v2Identity, v3Allocated.DeleteVersionIdentity);
        Assert.Equal(driverInstanceId, v3Allocated.DriverInstanceId);
        Assert.Equal(v2Identity.TransferId, v3Allocated.AllocationReferenceId);
        Assert.Equal(1u, v3Allocated.AllocationReferenceKind);
        Assert.Equal(0, v3Reply.InitialLength);
        Assert.False(File.Exists(destination));

        // The old cleanup is exact and off-thread. The current V3 claim is
        // durable before either V1/V2 stage can disappear.
        var v2Cleanup = new StagedDiscardRequest(v2Identity.TransferId, v2Identity,
            StagedDiscardKind.PrivateVersion);
        Assert.Equal(StagedDiscardStatus.Pending,
            await journal.BeginOrConfirmDiscardAsync(v2Cleanup, CancellationToken.None, processId));
        var v1Cleanup = new StagedDiscardRequest(reservationId, v1Identity,
            StagedDiscardKind.EmptyHeldPredecessor);
        await Assert.ThrowsAsync<IOException>(() => journal.BeginOrConfirmDiscardAsync(
            v1Cleanup, CancellationToken.None, processId));
        Assert.Equal(StagedDiscardStatus.Acknowledged,
            await journal.CompleteDiscardAsync(v2Cleanup, CancellationToken.None));
        journal = new StagedTransferJournal(journalPath);
        Assert.Equal(0, await journal.CompactAsync(DateTimeOffset.UtcNow.AddDays(1), CancellationToken.None));
        allocator = new StagedTransferAllocator(root, journal);
        await Assert.ThrowsAsync<IOException>(() => journal.BeginOrConfirmDiscardAsync(
            v1Cleanup, CancellationToken.None, processId));
        TransferJournalEntry unretiredV3 = await journal.ReadAsync(reservationId, CancellationToken.None);
        Assert.Null(unretiredV3.DiscardKind);
        Assert.Null(unretiredV3.DiscardRequestedAtUtc);
        Assert.Null(unretiredV3.HandleObservedRequestIdV20);
        TransferJournalEntry retainedV1 = await journal.ReadAsync(v1Identity.TransferId,
            CancellationToken.None);
        Assert.Equal(TransferJournalState.LegacyEmptyHeld, retainedV1.State);
        Assert.Equal(v1Identity, new StagedVersionIdentity(retainedV1.Transfer.TransferId,
            retainedV1.DestinationGeneration, retainedV1.StageIdentity!));
        Assert.Null(retainedV1.DiscardRequestedAtUtc);
        Assert.Null(retainedV1.DiscardAcknowledgedAtUtc);
        Assert.True(File.Exists(v1Reply.Transfer.StagePath));
        await CompleteV20AttachmentAsync(journal, v3Reply.Transfer, v3Identity,
            driverInstanceId, 1020);
        TransferJournalEntry observedV3 = await journal.ReadAsync(reservationId,
            CancellationToken.None);
        Assert.Equal(driverInstanceId, observedV3.DriverInstanceId);
        Assert.Equal(StagedAttachmentStateV20.HandleObserved, observedV3.AttachmentStateV20);
        Assert.Equal((ulong?)1022, observedV3.CompletionPermitRequestIdV20);
        Assert.Equal((ulong?)1023, observedV3.HandleObservedRequestIdV20);
        Assert.Equal(StagedDiscardStatus.Pending,
            await journal.BeginOrConfirmDiscardAsync(v1Cleanup, CancellationToken.None, processId));
        await Assert.ThrowsAsync<IOException>(() => journal.BeginOrConfirmDiscardAsync(
            new StagedDiscardRequest(reservationId, v3Identity,
                StagedDiscardKind.UnattachedAllocation), CancellationToken.None, processId, driverInstanceId));
        Assert.Equal(StagedDiscardStatus.Acknowledged,
            await journal.CompleteDiscardAsync(v1Cleanup, CancellationToken.None));

        await File.WriteAllTextAsync(destination, "keep public replacement");
        StagedAllocationReply replay = await allocator.CreateAfterPrivateDiscardAsync(createAfter,
            CancellationToken.None);
        Assert.Equal(v3Reply.Transfer.TransferId, replay.Transfer.TransferId);
        Assert.Equal(v3Reply.DestinationGeneration, replay.DestinationGeneration);
        Assert.Equal(v3Reply.StageIdentity, replay.StageIdentity);
        Assert.Equal(v3Reply.Transfer.StagePath, replay.Transfer.StagePath);
        Assert.Equal("keep public replacement", await File.ReadAllTextAsync(destination));
    }

    [Fact]
    public async Task Legacy_v19_create_after_preserves_all_legacy_chain_and_rejects_mixed_epoch_request()
    {
        string stageRoot = Path.Combine(_workspace.Root, "stage");
        string journalRoot = Path.Combine(_workspace.Root, "journal");
        string destination = Path.Combine(_workspace.Root, "destination", "legacy-create-after.txt");
        Directory.CreateDirectory(Path.GetDirectoryName(destination)!);
        const int processId = 17;
        const uint sessionId = 2;
        const string sid = "S-1-5-21-111-222-333-1000";
        const long creation = 638953632000000000;
        var journal = new StagedTransferJournal(journalRoot);
        var allocator = new StagedTransferAllocator(stageRoot, journal);

        StagedAllocationReply v1Reply = await allocator.AllocateV19Async(destination,
            DestinationKind.Cloud, "word.exe", processId, sessionId, 2, null,
            CancellationToken.None, requestorSid: sid, requestorProcessCreationTime: creation);
        var v1Identity = new StagedVersionIdentity(v1Reply.Transfer.TransferId,
            v1Reply.DestinationGeneration, v1Reply.StageIdentity);
        TransferJournalEntry v1 = await LegacyStagedJournalFixture.SealEmptyAsync(journal, _workspace.Root, v1Identity.TransferId, processId,
            v1Reply.Transfer.StagePath, CancellationToken.None, v1Identity);
        Assert.Equal(TransferJournalState.LegacyEmptyHeld, v1.State);
        Assert.Null(v1.DriverInstanceId);
        Assert.Equal(StagedAttachmentStateV20.None, v1.AttachmentStateV20);

        StagedAllocationReply v2Reply = await allocator.AllocateV19Async(destination,
            DestinationKind.Cloud, "word.exe", processId, sessionId, 1, v1Reply.Transfer,
            CancellationToken.None, requestorSid: sid, requestorProcessCreationTime: creation);
        await File.WriteAllTextAsync(v2Reply.Transfer.StagePath, "legacy private V2 bytes");
        var v2Identity = new StagedVersionIdentity(v2Reply.Transfer.TransferId,
            v2Reply.DestinationGeneration, v2Reply.StageIdentity);
        TransferJournalEntry v2 = await journal.ReadAsync(v2Identity.TransferId, CancellationToken.None);
        Assert.Equal(v1Identity, v2.ParentVersionIdentity);
        Assert.Null(v2.DriverInstanceId);
        Assert.Equal(StagedAttachmentStateV20.None, v2.AttachmentStateV20);

        StagedStageIdentity parentDirectory = StagedStageFile.ReadDirectoryIdentity(
            Path.GetDirectoryName(destination)!);
        Guid reservationId = Guid.NewGuid();
        var mixedRequest = new StagedCreateAfterDiscardRequest(reservationId, v2Identity,
            parentDirectory, 5, destination, DestinationKind.Cloud, processId, sessionId,
            sid, creation, Guid.NewGuid());
        byte[] v1ManifestBefore = await File.ReadAllBytesAsync(Path.Combine(journalRoot,
            v1Identity.TransferId.ToString("N") + ".json"));
        byte[] v2ManifestBefore = await File.ReadAllBytesAsync(Path.Combine(journalRoot,
            v2Identity.TransferId.ToString("N") + ".json"));
        byte[] v1StageBefore = await File.ReadAllBytesAsync(v1Reply.Transfer.StagePath);
        byte[] v2StageBefore = await File.ReadAllBytesAsync(v2Reply.Transfer.StagePath);

        await Assert.ThrowsAsync<IOException>(() => allocator.CreateAfterPrivateDiscardAsync(
            mixedRequest, CancellationToken.None));
        Assert.Equal(v1ManifestBefore, await File.ReadAllBytesAsync(Path.Combine(journalRoot,
            v1Identity.TransferId.ToString("N") + ".json")));
        Assert.Equal(v2ManifestBefore, await File.ReadAllBytesAsync(Path.Combine(journalRoot,
            v2Identity.TransferId.ToString("N") + ".json")));
        Assert.Equal(v1StageBefore, await File.ReadAllBytesAsync(v1Reply.Transfer.StagePath));
        Assert.Equal(v2StageBefore, await File.ReadAllBytesAsync(v2Reply.Transfer.StagePath));
        Assert.False(File.Exists(Path.Combine(journalRoot, reservationId.ToString("N") + ".json")));
        Assert.False(File.Exists(Path.Combine(stageRoot, reservationId.ToString("N") + ".txt")));
        Assert.False(File.Exists(destination));

        var legacyRequest = mixedRequest with { DriverInstanceId = null };
        StagedAllocationReply v3Reply = await allocator.CreateAfterPrivateDiscardAsync(
            legacyRequest, CancellationToken.None);
        TransferJournalEntry v2Pending = await journal.ReadAsync(v2Identity.TransferId,
            CancellationToken.None);
        TransferJournalEntry v3 = await journal.ReadAsync(reservationId, CancellationToken.None);
        Assert.Equal(TransferJournalState.DiscardPending, v2Pending.State);
        Assert.Equal(reservationId, v2Pending.CreateAfterReservationId);
        Assert.Equal(TransferJournalState.Allocated, v3.State);
        Assert.Equal(v1Identity, v3.ParentVersionIdentity);
        Assert.Equal(v2Identity, v3.DeleteVersionIdentity);
        Assert.Null(v3.DriverInstanceId);
        Assert.Equal(StagedAttachmentStateV20.None, v3.AttachmentStateV20);
        Assert.Equal(v3Reply.StageIdentity, v3.StageIdentity);
        Assert.False(File.Exists(destination));
    }

    [Theory]
    [InlineData("missing")]
    [InlineData("pending")]
    [InlineData("wrong-receipt-tuple")]
    public async Task V20_create_after_requires_exact_op19_before_any_journal_mutation(string receiptShape)
    {
        string stageRoot = Path.Combine(_workspace.Root, "stage");
        string journalRoot = Path.Combine(_workspace.Root, "journal");
        string destination = Path.Combine(_workspace.Root, "destination", $"{receiptShape}.txt");
        Directory.CreateDirectory(Path.GetDirectoryName(destination)!);
        const int processId = 17;
        const uint sessionId = 2;
        const string sid = "S-1-5-21-111-222-333-1000";
        const long creation = 638953632000000000;
        Guid driverInstanceId = Guid.NewGuid();
        var journal = new StagedTransferJournal(journalRoot);
        var allocator = new StagedTransferAllocator(stageRoot, journal);
        Assert.Equal(StagedDriverEpochReconcileV20.Active,
            await journal.ReconcileDriverInstanceV20Async(driverInstanceId, 0x1bf, CancellationToken.None));

        StagedAllocationReply v1Reply = await allocator.AllocateV19Async(destination,
            DestinationKind.Cloud, "word.exe", processId, sessionId,
            new StagedAllocationIntentV19(Guid.NewGuid(), Guid.Empty, 2, 0, driverInstanceId),
            null, null, sid, creation, CancellationToken.None);
        var v1Identity = new StagedVersionIdentity(v1Reply.Transfer.TransferId,
            v1Reply.DestinationGeneration, v1Reply.StageIdentity);
        await CompleteV20AttachmentAsync(journal, v1Reply.Transfer, v1Identity,
            driverInstanceId, 1900);
        TransferJournalEntry v1 = await LegacyStagedJournalFixture.SealEmptyAsync(journal, _workspace.Root, v1Identity.TransferId, processId,
            v1Reply.Transfer.StagePath, CancellationToken.None, v1Identity);
        Assert.Equal(TransferJournalState.LegacyEmptyHeld, v1.State);

        StagedAllocationReply v2Reply = await allocator.AllocateV19Async(destination,
            DestinationKind.Cloud, "word.exe", processId, sessionId,
            new StagedAllocationIntentV19(Guid.NewGuid(), v1Identity.TransferId, 1, 1, driverInstanceId),
            v1.Transfer, null, sid, creation, CancellationToken.None);
        var v2Identity = new StagedVersionIdentity(v2Reply.Transfer.TransferId,
            v2Reply.DestinationGeneration, v2Reply.StageIdentity);
        TransferJournalEntry v2Allocated = await journal.ReadAsync(v2Identity.TransferId,
            CancellationToken.None);
        StagedStageIdentity parentDirectory = v2Allocated.ParentDirectoryIdentity!;
        Task<uint?> ApplyV2(uint operation, ulong requestId, StagedVersionIdentity? version = null) =>
            journal.ApplyAttachmentV20Async(new StagedAttachmentRequestV20(operation, requestId,
                version ?? v2Identity, driverInstanceId, parentDirectory, destination, processId),
                ownerIsLive: true, commitPolicyAllowed: true, CancellationToken.None);

        Assert.Equal(6u, await ApplyV2(12, 2001));
        Assert.Equal(7u, await ApplyV2(13, 2002));
        if (receiptShape != "missing")
            Assert.Equal(16u, await ApplyV2(15, 2003));
        byte[] v1ManifestBytes = await File.ReadAllBytesAsync(Path.Combine(journalRoot,
            v1Identity.TransferId.ToString("N") + ".json"));
        byte[] v2ManifestBytes = await File.ReadAllBytesAsync(Path.Combine(journalRoot,
            v2Identity.TransferId.ToString("N") + ".json"));
        byte[] v1StageBytes = await File.ReadAllBytesAsync(v1Reply.Transfer.StagePath);
        byte[] v2StageBytes = await File.ReadAllBytesAsync(v2Reply.Transfer.StagePath);
        if (receiptShape == "wrong-receipt-tuple")
        {
            await Assert.ThrowsAsync<IOException>(() => ApplyV2(19, 2003));
            StagedVersionIdentity wrongVersion = v2Identity with
            {
                StageIdentity = v2Identity.StageIdentity with
                {
                    FileIdLow = v2Identity.StageIdentity.FileIdLow ^ 1
                }
            };
            await Assert.ThrowsAsync<IOException>(() => ApplyV2(19, 2004, wrongVersion));
            Assert.Equal(v1ManifestBytes, await File.ReadAllBytesAsync(Path.Combine(journalRoot,
                v1Identity.TransferId.ToString("N") + ".json")));
            Assert.Equal(v2ManifestBytes, await File.ReadAllBytesAsync(Path.Combine(journalRoot,
                v2Identity.TransferId.ToString("N") + ".json")));
        }

        TransferJournalEntry beforeV1 = await journal.ReadAsync(v1Identity.TransferId, CancellationToken.None);
        TransferJournalEntry beforeV2 = await journal.ReadAsync(v2Identity.TransferId, CancellationToken.None);
        Assert.Equal(receiptShape == "missing"
            ? StagedAttachmentStateV20.Committed
            : StagedAttachmentStateV20.CompletionPermitted, beforeV2.AttachmentStateV20);
        Assert.Null(beforeV2.HandleObservedRequestIdV20);

        Guid reservationId = Guid.NewGuid();
        var createAfter = new StagedCreateAfterDiscardRequest(reservationId, v2Identity,
            parentDirectory, 5, destination, DestinationKind.Cloud, processId, sessionId,
            sid, creation, driverInstanceId);
        await Assert.ThrowsAsync<IOException>(() => allocator.CreateAfterPrivateDiscardAsync(
            createAfter, CancellationToken.None));

        TransferJournalEntry afterV1 = await journal.ReadAsync(v1Identity.TransferId, CancellationToken.None);
        TransferJournalEntry afterV2 = await journal.ReadAsync(v2Identity.TransferId, CancellationToken.None);
        Assert.Equal(TransferJournalState.LegacyEmptyHeld, afterV1.State);
        Assert.Null(afterV1.DiscardKind);
        Assert.Null(afterV1.DiscardRequestedAtUtc);
        Assert.Null(afterV1.DiscardAcknowledgedAtUtc);
        Assert.Equal(beforeV2.State, afterV2.State);
        Assert.Equal(beforeV2.AttachmentStateV20, afterV2.AttachmentStateV20);
        Assert.Null(afterV2.DiscardKind);
        Assert.Null(afterV2.DiscardRequestedAtUtc);
        Assert.Null(afterV2.CreateAfterReservationId);
        Assert.Equal(v1ManifestBytes, await File.ReadAllBytesAsync(Path.Combine(journalRoot,
            v1Identity.TransferId.ToString("N") + ".json")));
        Assert.Equal(v2ManifestBytes, await File.ReadAllBytesAsync(Path.Combine(journalRoot,
            v2Identity.TransferId.ToString("N") + ".json")));
        Assert.Equal(v1StageBytes, await File.ReadAllBytesAsync(v1Reply.Transfer.StagePath));
        Assert.Equal(v2StageBytes, await File.ReadAllBytesAsync(v2Reply.Transfer.StagePath));
        Assert.False(File.Exists(Path.Combine(journalRoot, reservationId.ToString("N") + ".json")));
        Assert.False(File.Exists(Path.Combine(stageRoot, reservationId.ToString("N") + ".txt")));
        Assert.False(File.Exists(destination));
    }

    [Theory]
    [InlineData("identityless")]
    [InlineData("different-epoch")]
    public async Task V20_create_after_rejects_identityless_or_different_epoch_v1_before_child_intent(
        string parentEpochShape)
    {
        string journalRoot = Path.Combine(_workspace.Root, "journal");
        string stageRoot = Path.Combine(_workspace.Root, "stage");
        string destination = Path.Combine(_workspace.Root, "destination", $"{parentEpochShape}.txt");
        Directory.CreateDirectory(Path.GetDirectoryName(destination)!);
        Directory.CreateDirectory(stageRoot);
        const int processId = 17;
        const uint sessionId = 2;
        const string sid = "S-1-5-21-111-222-333-1000";
        const long creation = 638953632000000000;
        Guid oldDriver = Guid.NewGuid();
        Guid currentDriver = Guid.NewGuid();
        var journal = new StagedTransferJournal(journalRoot);
        if (parentEpochShape == "different-epoch")
            Assert.Equal(StagedDriverEpochReconcileV20.Active,
                await journal.ReconcileDriverInstanceV20Async(oldDriver, 0x1bf, CancellationToken.None));

        Guid v1Id = Guid.NewGuid();
        string v1Stage = Path.Combine(stageRoot, v1Id.ToString("N") + ".txt");
        await File.WriteAllBytesAsync(v1Stage, []);
        var v1Transfer = new StagedTransfer(v1Id, v1Stage, destination, DestinationKind.Cloud,
            "word.exe", processId, sessionId)
        {
            RequestorSid = sid,
            RequestorProcessCreationTime = creation
        };
        StagedStageIdentity parentDirectory = StagedStageFile.ReadDirectoryIdentity(
            Path.GetDirectoryName(destination)!);
        TransferJournalEntry v1Created = await journal.CreateAsync(v1Transfer, CancellationToken.None,
            allocationDisposition: parentEpochShape == "identityless" ? null : 2,
            allocationReferenceId: null,
            allocationReferenceKind: parentEpochShape == "identityless" ? null : 0,
            driverInstanceId: parentEpochShape == "identityless" ? null : oldDriver,
            parentDirectoryIdentity: parentEpochShape == "identityless" ? null : parentDirectory);
        var v1Identity = new StagedVersionIdentity(v1Id, v1Created.DestinationGeneration,
            v1Created.StageIdentity!);
        if (parentEpochShape == "different-epoch")
            await CompleteV20AttachmentAsync(journal, v1Transfer, v1Identity, oldDriver, 2000);
        TransferJournalEntry v1 = await LegacyStagedJournalFixture.SealEmptyAsync(journal, _workspace.Root, v1Id, processId, v1Stage,
            CancellationToken.None, v1Identity);
        Assert.Equal(TransferJournalState.LegacyEmptyHeld, v1.State);

        // A current v20 followup must fail before it creates a successor
        // allocation manifest when the V1 is legacy or belongs to another
        // driver epoch.
        Guid rejectedV2Id = Guid.NewGuid();
        string rejectedV2Stage = Path.Combine(stageRoot, rejectedV2Id.ToString("N") + ".txt");
        await File.WriteAllBytesAsync(rejectedV2Stage, []);
        var rejectedV2 = v1Transfer with { TransferId = rejectedV2Id, StagePath = rejectedV2Stage };
        await Assert.ThrowsAsync<IOException>(() => journal.CreateAsync(rejectedV2,
            CancellationToken.None, parentTransferId: v1Id, allocationDisposition: 1,
            allocationReferenceId: v1Id, allocationReferenceKind: 1,
            driverInstanceId: currentDriver, parentDirectoryIdentity: parentDirectory));
        await Assert.ThrowsAsync<FileNotFoundException>(() => journal.ReadAsync(rejectedV2Id,
            CancellationToken.None));

        // Recreate a pre-fix V2 manifest to exercise the deeper CREATE_AFTER
        // guard. Its exact parent tuple exists, but its v20 driver binding
        // cannot be accepted because V1 is legacy or from oldDriver.
        Guid v2Id = Guid.NewGuid();
        string v2Stage = Path.Combine(stageRoot, v2Id.ToString("N") + ".txt");
        await File.WriteAllTextAsync(v2Stage, "legacy V2 bytes");
        var v2Transfer = v1Transfer with { TransferId = v2Id, StagePath = v2Stage };
        TransferJournalEntry v2Created = await journal.CreateAsync(v2Transfer, CancellationToken.None,
            parentTransferId: v1Id);
        var v2Identity = new StagedVersionIdentity(v2Id, v2Created.DestinationGeneration,
            v2Created.StageIdentity!);
        await LegacyStagedJournalFixture.SealEmptyAsync(journal, _workspace.Root, v2Id, processId, v2Stage, CancellationToken.None, v2Identity);

        string v2ManifestPath = Path.Combine(journalRoot, v2Id.ToString("N") + ".json");
        JsonObject v2Manifest = JsonNode.Parse(await File.ReadAllTextAsync(v2ManifestPath))!.AsObject();
        v2Manifest["CreateReservationId"] = v2Id.ToString("D");
        v2Manifest["AllocationDisposition"] = 5;
        v2Manifest["AllocationReferenceId"] = v1Id.ToString("D");
        v2Manifest["AllocationReferenceKind"] = 1;
        v2Manifest["DriverInstanceId"] = currentDriver.ToString("D");
        v2Manifest["ParentDirectoryIdentity"] = JsonSerializer.SerializeToNode(parentDirectory);
        // Keep this child independently eligible for the CREATE_AFTER path so
        // the assertions below reach the intended V1 epoch mismatch. The
        // exact V2 op15/op19 receipts are valid for its own current tuple.
        v2Manifest["AttachmentStateV20"] = (uint)StagedAttachmentStateV20.HandleObserved;
        v2Manifest["AttachPrepareRequestIdV20"] = 3001;
        v2Manifest["AttachCommitRequestIdV20"] = 3002;
        v2Manifest["AttachCommitResultV20"] = 7;
        v2Manifest["CompletionPermitRequestIdV20"] = 3003;
        v2Manifest["HandleObservedRequestIdV20"] = 3004;
        await File.WriteAllTextAsync(v2ManifestPath, v2Manifest.ToJsonString());

        Guid v3Reservation = Guid.NewGuid();
        var request = new StagedCreateAfterDiscardRequest(v3Reservation, v2Identity,
            parentDirectory, 5, destination, DestinationKind.Cloud, processId, sessionId,
            sid, creation, currentDriver);
        var v3Transfer = new StagedTransfer(v3Reservation,
            Path.Combine(stageRoot, v3Reservation.ToString("N") + ".txt"), destination,
            DestinationKind.Cloud, "word.exe", processId, sessionId)
        {
            RequestorSid = sid,
            RequestorProcessCreationTime = creation
        };
        await Assert.ThrowsAsync<IOException>(() => journal.CreateAfterPrivateDiscardIntentAsync(
            request, v3Transfer, CancellationToken.None));
        var rejectedParentCleanup = new StagedDiscardRequest(v2Id, v1Identity,
            StagedDiscardKind.EmptyHeldPredecessor);
        await Assert.ThrowsAsync<IOException>(() => journal.BeginOrConfirmDiscardAsync(
            rejectedParentCleanup, CancellationToken.None, processId, currentDriver));

        TransferJournalEntry unchangedV2 = await journal.ReadAsync(v2Id, CancellationToken.None);
        TransferJournalEntry unchangedV1 = await journal.ReadAsync(v1Id, CancellationToken.None);
        Assert.Equal(TransferJournalState.Sealed, unchangedV2.State);
        Assert.Null(unchangedV2.DiscardRequestedAtUtc);
        Assert.Null(unchangedV2.CreateAfterReservationId);
        Assert.Equal(TransferJournalState.LegacyEmptyHeld, unchangedV1.State);
        Assert.Null(unchangedV1.DiscardRequestedAtUtc);
        Assert.Null(unchangedV1.DiscardAcknowledgedAtUtc);
        Assert.Null(unchangedV1.DiscardKind);
        await Assert.ThrowsAsync<FileNotFoundException>(() => journal.ReadAsync(v3Reservation,
            CancellationToken.None));
        Assert.True(File.Exists(v1Stage));
        Assert.True(File.Exists(v2Stage));
    }

    [Theory]
    [InlineData(StagedDiscardKind.PrivateVersion)]
    [InlineData(StagedDiscardKind.UnattachedAllocation)]
    public async Task Direct_emptyheld_parent_cleanup_requires_terminal_child_ack_and_survives_restart_compaction(
        StagedDiscardKind childDisposition)
    {
        string root = Path.Combine(_workspace.Root, "stage");
        string journalPath = Path.Combine(_workspace.Root, "journal");
        string destination = Path.Combine(_workspace.Root, "destination", "direct-empty-parent.txt");
        Directory.CreateDirectory(Path.GetDirectoryName(destination)!);
        const int processId = 17;
        const uint sessionId = 2;
        const string sid = "S-1-5-21-111-222-333-1000";
        const long creation = 638953632000000000;
        Guid driverInstance = Guid.NewGuid();
        var journal = new StagedTransferJournal(journalPath);
        var allocator = new StagedTransferAllocator(root, journal);

        StagedAllocationReply v1Reply = await allocator.AllocateV19Async(destination,
            DestinationKind.Cloud, "word.exe", processId, sessionId,
            new StagedAllocationIntentV19(Guid.NewGuid(), Guid.Empty, 2, 0, driverInstance),
            null, null, sid, creation, CancellationToken.None);
        var v1Identity = new StagedVersionIdentity(v1Reply.Transfer.TransferId,
            v1Reply.DestinationGeneration, v1Reply.StageIdentity);
        await CompleteV20AttachmentAsync(journal, v1Reply.Transfer, v1Identity,
            driverInstance, 1200);
        TransferJournalEntry v1 = await LegacyStagedJournalFixture.SealEmptyAsync(journal, _workspace.Root, v1Identity.TransferId, processId,
            v1Reply.Transfer.StagePath, CancellationToken.None, v1Identity);
        Assert.Equal(TransferJournalState.LegacyEmptyHeld, v1.State);

        Guid v2Reservation = Guid.NewGuid();
        StagedAllocationReply v2Reply = await allocator.AllocateV19Async(destination,
            DestinationKind.Cloud, "word.exe", processId, sessionId,
            new StagedAllocationIntentV19(v2Reservation, v1Identity.TransferId, 1, 1, driverInstance),
            v1.Transfer, null, sid, creation, CancellationToken.None);
        TransferJournalEntry v2 = await journal.ReadAsync(v2Reservation, CancellationToken.None);
        Assert.Equal(v1Identity, v2.ParentVersionIdentity);
        Assert.Equal(v2Reply.StageIdentity, v2.StageIdentity);
        Assert.Equal(TransferJournalState.Allocated, v2.State);
        if (childDisposition == StagedDiscardKind.PrivateVersion)
        {
            await CompleteV20AttachmentAsync(journal, v2Reply.Transfer,
                new StagedVersionIdentity(v2Reservation, v2.DestinationGeneration, v2.StageIdentity!),
                driverInstance, 1210);
        }


        await Assert.ThrowsAsync<IOException>(() => journal.BeginOrConfirmDiscardAsync(
            new StagedDiscardRequest(v2Reservation, v1Identity,
                StagedDiscardKind.EmptyHeldPredecessor), CancellationToken.None,
            processId, driverInstance));

        var v2Cleanup = new StagedDiscardRequest(v2Reservation,
            new StagedVersionIdentity(v2Reservation, v2.DestinationGeneration, v2.StageIdentity!),
            childDisposition);
        Assert.Equal(StagedDiscardStatus.Pending,
            await journal.BeginOrConfirmDiscardAsync(v2Cleanup, CancellationToken.None,
                processId, driverInstance));
        Assert.Equal(StagedDiscardStatus.Acknowledged,
            await journal.CompleteDiscardAsync(v2Cleanup, CancellationToken.None));

        await Assert.ThrowsAsync<IOException>(() => journal.BeginOrConfirmDiscardAsync(
            new StagedDiscardRequest(v1Identity.TransferId, v1Identity,
                StagedDiscardKind.OwnerExitEmpty), CancellationToken.None, processId, driverInstance));
        await Assert.ThrowsAsync<FileNotFoundException>(() => journal.BeginOrConfirmDiscardAsync(
            new StagedDiscardRequest(Guid.NewGuid(), v1Identity,
                StagedDiscardKind.EmptyHeldPredecessor), CancellationToken.None, processId, driverInstance));

        // This unit fixture does not observe a real process exit. It retains
        // the saved nonzero owner PID and exact V2 reservation through service
        // restart, and verifies that the old cleanup keeps its exact proof.
        // Ordinary max+1 allocation no longer waits on this legacy chain.
        var v1Cleanup = new StagedDiscardRequest(v2Reservation, v1Identity,
            StagedDiscardKind.EmptyHeldPredecessor);
        await Assert.ThrowsAsync<IOException>(() => journal.BeginOrConfirmDiscardAsync(
            v1Cleanup with { Version = v1Identity with { DestinationGeneration = v1Identity.DestinationGeneration + 1 } },
            CancellationToken.None, processId, driverInstance));
        Assert.Equal(StagedDiscardStatus.Pending,
            await journal.BeginOrConfirmDiscardAsync(v1Cleanup, CancellationToken.None,
                processId, driverInstance));
        journal = new StagedTransferJournal(journalPath);
        Assert.Equal(0, await journal.CompactAsync(DateTimeOffset.UtcNow.AddDays(1), CancellationToken.None));
        StagedDiscardRequest pending = Assert.Single(await journal.ReadDiscardPendingAsync(CancellationToken.None));
        Assert.Equal(v1Cleanup, pending);
        allocator = new StagedTransferAllocator(root, journal);

        Assert.Equal(StagedDiscardStatus.Acknowledged,
            await journal.CompleteDiscardAsync(v1Cleanup, CancellationToken.None));
        journal = new StagedTransferJournal(journalPath);
        Assert.Equal(0, await journal.CompactAsync(DateTimeOffset.UtcNow.AddDays(1), CancellationToken.None));
        Assert.Equal(v1Identity, new StagedVersionIdentity(v1Identity.TransferId,
            (await journal.ReadAsync(v1Identity.TransferId, CancellationToken.None)).DestinationGeneration,
            (await journal.ReadAsync(v1Identity.TransferId, CancellationToken.None)).StageIdentity!));

        allocator = new StagedTransferAllocator(root, journal);
        StagedAllocationReply successor = await allocator.AllocateV19Async(destination,
            DestinationKind.Cloud, "word.exe", processId, sessionId,
            new StagedAllocationIntentV19(Guid.NewGuid(), Guid.Empty, 5, 0, driverInstance),
            null, null, sid, creation, CancellationToken.None);
        Assert.True(successor.DestinationGeneration > v2.DestinationGeneration);
        Assert.Equal(2, await journal.CompactAsync(DateTimeOffset.UtcNow.AddDays(1), CancellationToken.None));
        await Assert.ThrowsAsync<FileNotFoundException>(() => journal.ReadAsync(v1Identity.TransferId,
            CancellationToken.None));
        await Assert.ThrowsAsync<FileNotFoundException>(() => journal.ReadAsync(v2Reservation,
            CancellationToken.None));
        Assert.Equal(successor.DestinationGeneration,
            (await journal.ReadAsync(successor.Transfer.TransferId, CancellationToken.None)).DestinationGeneration);
    }

    [Theory]
    [InlineData(StagedDiscardKind.OwnerExitEmpty)]
    [InlineData(StagedDiscardKind.DriverUnloadEmpty)]
    public async Task Direct_emptyheld_successor_must_be_exactly_retired_before_its_parent(
        StagedDiscardKind childCleanupKind)
    {
        string root = Path.Combine(_workspace.Root, "stage");
        string destination = Path.Combine(_workspace.Root, "destination", "direct-empty-child.txt");
        Directory.CreateDirectory(Path.GetDirectoryName(destination)!);
        const int processId = 17;
        const uint sessionId = 2;
        const string sid = "S-1-5-21-111-222-333-1000";
        const long creation = 638953632000000000;
        Guid driverInstance = Guid.NewGuid();
        var journal = new StagedTransferJournal(Path.Combine(_workspace.Root, "journal"));
        var allocator = new StagedTransferAllocator(root, journal);

        StagedAllocationReply v1Reply = await allocator.AllocateV19Async(destination,
            DestinationKind.Cloud, "word.exe", processId, sessionId,
            new StagedAllocationIntentV19(Guid.NewGuid(), Guid.Empty, 2, 0, driverInstance),
            null, null, sid, creation, CancellationToken.None);
        var v1Identity = new StagedVersionIdentity(v1Reply.Transfer.TransferId,
            v1Reply.DestinationGeneration, v1Reply.StageIdentity);
        await CompleteV20AttachmentAsync(journal, v1Reply.Transfer, v1Identity,
            driverInstance, 1300);
        TransferJournalEntry v1 = await LegacyStagedJournalFixture.SealEmptyAsync(journal, _workspace.Root, v1Identity.TransferId, processId,
            v1Reply.Transfer.StagePath, CancellationToken.None, v1Identity);
        Assert.Equal(TransferJournalState.LegacyEmptyHeld, v1.State);

        Guid v2Reservation = Guid.NewGuid();
        StagedAllocationReply v2Reply = await allocator.AllocateV19Async(destination,
            DestinationKind.Cloud, "word.exe", processId, sessionId,
            new StagedAllocationIntentV19(v2Reservation, v1Identity.TransferId, 1, 1, driverInstance),
            v1.Transfer, null, sid, creation, CancellationToken.None);
        var v2Identity = new StagedVersionIdentity(v2Reservation,
            v2Reply.DestinationGeneration, v2Reply.StageIdentity);
        await CompleteV20AttachmentAsync(journal, v2Reply.Transfer, v2Identity,
            driverInstance, 1310);
        TransferJournalEntry v2 = await LegacyStagedJournalFixture.SealEmptyAsync(journal, _workspace.Root, v2Reservation, processId,
            v2Reply.Transfer.StagePath, CancellationToken.None, v2Identity);
        Assert.Equal(TransferJournalState.LegacyEmptyHeld, v2.State);

        var v2Cleanup = new StagedDiscardRequest(v2Reservation, v2Identity,
            childCleanupKind);
        Assert.Equal(StagedDiscardStatus.Pending,
            await journal.BeginOrConfirmDiscardAsync(v2Cleanup, CancellationToken.None,
                processId, driverInstance));
        Assert.Equal(StagedDiscardStatus.Acknowledged,
            await journal.CompleteDiscardAsync(v2Cleanup, CancellationToken.None));

        var v1Cleanup = new StagedDiscardRequest(v2Reservation, v1Identity,
            StagedDiscardKind.EmptyHeldPredecessor);
        await Assert.ThrowsAsync<IOException>(() => journal.BeginOrConfirmDiscardAsync(
            v1Cleanup, CancellationToken.None, processId + 1, driverInstance));
        await Assert.ThrowsAsync<IOException>(() => journal.BeginOrConfirmDiscardAsync(
            v1Cleanup, CancellationToken.None, processId, Guid.NewGuid()));
        await Assert.ThrowsAsync<IOException>(() => journal.BeginOrConfirmDiscardAsync(
            v1Cleanup with { Version = v1Identity with
                { StageIdentity = v1Identity.StageIdentity with
                    { FileIdLow = v1Identity.StageIdentity.FileIdLow ^ 1 } } },
            CancellationToken.None, processId, driverInstance));
        Assert.Equal(StagedDiscardStatus.Pending,
            await journal.BeginOrConfirmDiscardAsync(v1Cleanup, CancellationToken.None,
                processId, driverInstance));
        Assert.Equal(StagedDiscardStatus.Acknowledged,
            await journal.CompleteDiscardAsync(v1Cleanup, CancellationToken.None));
        Assert.False(File.Exists(v1Reply.Transfer.StagePath));
        Assert.False(File.Exists(v2Reply.Transfer.StagePath));

        StagedAllocationReply next = await allocator.AllocateV19Async(destination,
            DestinationKind.Cloud, "word.exe", processId, sessionId,
            new StagedAllocationIntentV19(Guid.NewGuid(), Guid.Empty, 5, 0, driverInstance),
            null, null, sid, creation, CancellationToken.None);
        Assert.True(next.DestinationGeneration > v2Identity.DestinationGeneration);
    }

    [Theory]
    [InlineData("sid")]
    [InlineData("process-creation")]
    [InlineData("driver-epoch")]
    public async Task Direct_emptyheld_cleanup_rejects_mismatched_child_writer_or_epoch(string mutation)
    {
        string root = Path.Combine(_workspace.Root, "stage");
        string journalRoot = Path.Combine(_workspace.Root, "journal");
        string destination = Path.Combine(_workspace.Root, "destination", "direct-child-metadata.txt");
        Directory.CreateDirectory(Path.GetDirectoryName(destination)!);
        const int processId = 17;
        const uint sessionId = 2;
        const string sid = "S-1-5-21-111-222-333-1000";
        const long creation = 638953632000000000;
        Guid driverInstance = Guid.NewGuid();
        var journal = new StagedTransferJournal(journalRoot);
        var allocator = new StagedTransferAllocator(root, journal);

        StagedAllocationReply v1Reply = await allocator.AllocateV19Async(destination,
            DestinationKind.Cloud, "word.exe", processId, sessionId,
            new StagedAllocationIntentV19(Guid.NewGuid(), Guid.Empty, 2, 0, driverInstance),
            null, null, sid, creation, CancellationToken.None);
        var v1Identity = new StagedVersionIdentity(v1Reply.Transfer.TransferId,
            v1Reply.DestinationGeneration, v1Reply.StageIdentity);
        await CompleteV20AttachmentAsync(journal, v1Reply.Transfer, v1Identity,
            driverInstance, 1400);
        TransferJournalEntry sealedV1 = await LegacyStagedJournalFixture.SealEmptyAsync(journal, _workspace.Root, v1Identity.TransferId, processId,
            v1Reply.Transfer.StagePath, CancellationToken.None, v1Identity);

        Guid v2Reservation = Guid.NewGuid();
        StagedAllocationReply v2Reply = await allocator.AllocateV19Async(destination,
            DestinationKind.Cloud, "word.exe", processId, sessionId,
            new StagedAllocationIntentV19(v2Reservation, v1Identity.TransferId, 1, 1, driverInstance),
            sealedV1.Transfer, null,
            sid, creation, CancellationToken.None);
        var v2Identity = new StagedVersionIdentity(v2Reservation, v2Reply.DestinationGeneration,
            v2Reply.StageIdentity);
        await CompleteV20AttachmentAsync(journal, v2Reply.Transfer, v2Identity,
            driverInstance, 1410);
        var v2Cleanup = new StagedDiscardRequest(v2Reservation, v2Identity,
            StagedDiscardKind.PrivateVersion);
        Assert.Equal(StagedDiscardStatus.Pending, await journal.BeginOrConfirmDiscardAsync(
            v2Cleanup, CancellationToken.None, processId, driverInstance));
        Assert.Equal(StagedDiscardStatus.Acknowledged,
            await journal.CompleteDiscardAsync(v2Cleanup, CancellationToken.None));

        string childManifest = Path.Combine(journalRoot, v2Reservation.ToString("N") + ".json");
        JsonObject document = JsonNode.Parse(await File.ReadAllTextAsync(childManifest))!.AsObject();
        Guid cleanupEpoch = driverInstance;
        if (mutation == "sid")
            document["Transfer"]!["RequestorSid"] = "S-1-5-21-999-888-777-1000";
        else if (mutation == "process-creation")
            document["Transfer"]!["RequestorProcessCreationTime"] = creation + 1;
        else
        {
            cleanupEpoch = Guid.NewGuid();
            document["DriverInstanceId"] = cleanupEpoch.ToString("D");
        }
        await File.WriteAllTextAsync(childManifest, document.ToJsonString());

        journal = new StagedTransferJournal(journalRoot);
        var v1Cleanup = new StagedDiscardRequest(v2Reservation, v1Identity,
            StagedDiscardKind.EmptyHeldPredecessor);
        await Assert.ThrowsAsync<IOException>(() => journal.BeginOrConfirmDiscardAsync(
            v1Cleanup, CancellationToken.None, processId, cleanupEpoch));
        Assert.True(File.Exists(v1Reply.Transfer.StagePath));
        Assert.False(File.Exists(v2Reply.Transfer.StagePath));
        Assert.Null((await journal.ReadAsync(v1Identity.TransferId, CancellationToken.None))
            .DiscardAcknowledgedAtUtc);
    }

    [Fact]
    public async Task Direct_released_successor_requires_gate_confirmed_disposal_before_parent_ack()
    {
        string root = Path.Combine(_workspace.Root, "stage");
        string destination = Path.Combine(_workspace.Root, "destination", "direct-released-child.txt");
        Directory.CreateDirectory(Path.GetDirectoryName(destination)!);
        const int processId = 17;
        const uint sessionId = 2;
        const string sid = "S-1-5-21-111-222-333-1000";
        const long creation = 638953632000000000;
        Guid driverInstance = Guid.NewGuid();
        var journal = new StagedTransferJournal(Path.Combine(_workspace.Root, "journal"));
        var allocator = new StagedTransferAllocator(root, journal);

        StagedAllocationReply v1Reply = await allocator.AllocateV19Async(destination,
            DestinationKind.Cloud, "word.exe", processId, sessionId,
            new StagedAllocationIntentV19(Guid.NewGuid(), Guid.Empty, 2, 0, driverInstance),
            null, null, sid, creation, CancellationToken.None);
        var v1Identity = new StagedVersionIdentity(v1Reply.Transfer.TransferId,
            v1Reply.DestinationGeneration, v1Reply.StageIdentity);
        await CompleteV20AttachmentAsync(journal, v1Reply.Transfer, v1Identity,
            driverInstance, 1500);
        TransferJournalEntry v1 = await LegacyStagedJournalFixture.SealEmptyAsync(journal, _workspace.Root, v1Identity.TransferId, processId,
            v1Reply.Transfer.StagePath, CancellationToken.None, v1Identity);

        Guid v2Reservation = Guid.NewGuid();
        StagedAllocationReply v2Reply = await allocator.AllocateV19Async(destination,
            DestinationKind.Cloud, "word.exe", processId, sessionId,
            new StagedAllocationIntentV19(v2Reservation, v1Identity.TransferId, 1, 1, driverInstance),
            v1.Transfer, null, sid, creation, CancellationToken.None);
        await File.WriteAllTextAsync(v2Reply.Transfer.StagePath, "approved private V2 bytes");
        var v2Identity = new StagedVersionIdentity(v2Reservation,
            v2Reply.DestinationGeneration, v2Reply.StageIdentity);
        await CompleteV20AttachmentAsync(journal, v2Reply.Transfer, v2Identity,
            driverInstance, 1510);
        await LegacyStagedJournalFixture.SealEmptyAsync(journal, _workspace.Root, v2Reservation, processId, v2Reply.Transfer.StagePath,
            CancellationToken.None, v2Identity);
        string digest = Convert.ToHexString(SHA256.HashData(
            await File.ReadAllBytesAsync(v2Reply.Transfer.StagePath))).ToLowerInvariant();
        await journal.TransitionAsync(v2Reservation, TransferJournalState.Sealed,
            TransferJournalState.Inspecting, null, CancellationToken.None);
        await journal.TransitionAsync(v2Reservation, TransferJournalState.Inspecting,
            TransferJournalState.Approved, digest, CancellationToken.None);
        await journal.TransitionAsync(v2Reservation, TransferJournalState.Approved,
            TransferJournalState.Publishing, null, CancellationToken.None);
        TransferJournalEntry released = await journal.TransitionAsync(v2Reservation,
            TransferJournalState.Publishing, TransferJournalState.Released,
            null, CancellationToken.None);
        Assert.False(released.StageDeleted);

        var v1Cleanup = new StagedDiscardRequest(v2Reservation, v1Identity,
            StagedDiscardKind.EmptyHeldPredecessor);
        Assert.Equal(StagedDiscardStatus.Pending,
            await journal.BeginOrConfirmDiscardAsync(v1Cleanup, CancellationToken.None,
                processId, driverInstance));

        StagedTransferPublisher heldPublisher = CreateDisposalPublisher(journal, root,
            held: true, out DisposalGate heldGate);
        await heldPublisher.DisposeReleasedStageAsync(v2Reservation, CancellationToken.None);
        Assert.Equal(new[] { (v2Reservation, StageDisposeOutcome.Released) }, heldGate.Disposals);
        Assert.True(File.Exists(v2Reply.Transfer.StagePath));
        Assert.False((await journal.ReadAsync(v2Reservation, CancellationToken.None)).StageDeleted);
        await Assert.ThrowsAsync<IOException>(() => journal.CompleteDiscardAsync(v1Cleanup,
            CancellationToken.None));
        Assert.True(File.Exists(v1Reply.Transfer.StagePath));
        Assert.Null((await journal.ReadAsync(v1Identity.TransferId, CancellationToken.None))
            .DiscardAcknowledgedAtUtc);

        // Kind-2 completion consumes the durable receipt from the ordinary
        // publisher path; it never bypasses the driver's held-stage gate.
        StagedTransferPublisher releasedPublisher = CreateDisposalPublisher(journal, root,
            held: false, out DisposalGate releasedGate);
        await releasedPublisher.DisposeReleasedStageAsync(v2Reservation, CancellationToken.None);
        Assert.Equal(new[] { (v2Reservation, StageDisposeOutcome.Released) }, releasedGate.Disposals);
        Assert.True((await journal.ReadAsync(v2Reservation, CancellationToken.None)).StageDeleted);
        Assert.False(File.Exists(v2Reply.Transfer.StagePath));
        Assert.Equal(StagedDiscardStatus.Acknowledged,
            await journal.CompleteDiscardAsync(v1Cleanup, CancellationToken.None));
        Assert.False(File.Exists(v1Reply.Transfer.StagePath));
    }

    private StagedTransferPublisher CreateDisposalPublisher(StagedTransferJournal journal,
        string stageRoot, bool held, out DisposalGate gate)
    {
        gate = new DisposalGate(held);
        var inspector = new InspectionService(
            new LocalPolicyStore(_workspace.PolicyFile),
            new LocalQueueAuditSink(_workspace.QueueFile),
            ExtractorRegistry.CreateDefault(), new VerdictCache());
        return new StagedTransferPublisher(inspector, NotificationTestHub.Create(), journal,
            stageRoot, gate);
    }

    private static async Task CompleteV20AttachmentAsync(StagedTransferJournal journal,
        StagedTransfer transfer, StagedVersionIdentity version, Guid driverInstanceId,
        ulong firstRequestId)
    {
        Assert.Equal(StagedDriverEpochReconcileV20.Active,
            await journal.ReconcileDriverInstanceV20Async(driverInstanceId, 0x1bf, CancellationToken.None));
        TransferJournalEntry current = await journal.ReadAsync(version.TransferId, CancellationToken.None);
        Assert.Equal(version, new StagedVersionIdentity(current.Transfer.TransferId,
            current.DestinationGeneration, current.StageIdentity!));
        Assert.Equal(driverInstanceId, current.DriverInstanceId);
        StagedStageIdentity parentDirectoryIdentity = current.ParentDirectoryIdentity ??
            StagedStageFile.ReadDirectoryIdentity(Path.GetDirectoryName(transfer.DestinationPath)!);

        Task<uint?> Apply(uint operation, ulong requestId) => journal.ApplyAttachmentV20Async(
            new StagedAttachmentRequestV20(operation, requestId, version, driverInstanceId,
                parentDirectoryIdentity, transfer.DestinationPath, transfer.ProcessId),
            ownerIsLive: true, commitPolicyAllowed: true, CancellationToken.None);

        Assert.Equal(6u, await Apply(12, firstRequestId));
        Assert.Equal(7u, await Apply(13, firstRequestId + 1));
        Assert.Equal(16u, await Apply(15, firstRequestId + 2));
        Assert.Equal(17u, await Apply(19, firstRequestId + 3));
    }

    private sealed class DisposalGate(bool held) : IStagedPublicationGate, IDisposable
    {
        public readonly List<(Guid TransferId, uint Outcome)> Disposals = [];
        public IDisposable Authorize(StagedTransfer transfer, string temporaryDestination, string digest) => this;
        public bool DisposeStage(Guid transferId, uint outcome, uint committedRenames)
        {
            Disposals.Add((transferId, outcome));
            return held;
        }
        public void Dispose() { }
    }

    [Fact]
    public async Task Direct_released_successor_replacement_blocks_parent_cleanup_without_deleting_replacement()
    {
        string root = Path.Combine(_workspace.Root, "stage");
        string destination = Path.Combine(_workspace.Root, "destination", "direct-released-replacement.txt");
        Directory.CreateDirectory(Path.GetDirectoryName(destination)!);
        const int processId = 17;
        const uint sessionId = 2;
        const string sid = "S-1-5-21-111-222-333-1000";
        const long creation = 638953632000000000;
        Guid driverInstance = Guid.NewGuid();
        var journal = new StagedTransferJournal(Path.Combine(_workspace.Root, "journal"));
        var allocator = new StagedTransferAllocator(root, journal);

        StagedAllocationReply v1Reply = await allocator.AllocateV19Async(destination,
            DestinationKind.Cloud, "word.exe", processId, sessionId,
            new StagedAllocationIntentV19(Guid.NewGuid(), Guid.Empty, 2, 0, driverInstance),
            null, null, sid, creation, CancellationToken.None);
        var v1Identity = new StagedVersionIdentity(v1Reply.Transfer.TransferId,
            v1Reply.DestinationGeneration, v1Reply.StageIdentity);
        await CompleteV20AttachmentAsync(journal, v1Reply.Transfer, v1Identity,
            driverInstance, 1600);
        TransferJournalEntry v1 = await LegacyStagedJournalFixture.SealEmptyAsync(journal, _workspace.Root, v1Identity.TransferId, processId,
            v1Reply.Transfer.StagePath, CancellationToken.None, v1Identity);

        Guid v2Reservation = Guid.NewGuid();
        StagedAllocationReply v2Reply = await allocator.AllocateV19Async(destination,
            DestinationKind.Cloud, "word.exe", processId, sessionId,
            new StagedAllocationIntentV19(v2Reservation, v1Identity.TransferId, 1, 1, driverInstance),
            v1.Transfer, null, sid, creation, CancellationToken.None);
        await File.WriteAllTextAsync(v2Reply.Transfer.StagePath, "approved private V2 bytes");
        var v2Identity = new StagedVersionIdentity(v2Reservation,
            v2Reply.DestinationGeneration, v2Reply.StageIdentity);
        await CompleteV20AttachmentAsync(journal, v2Reply.Transfer, v2Identity,
            driverInstance, 1610);
        await LegacyStagedJournalFixture.SealEmptyAsync(journal, _workspace.Root, v2Reservation, processId, v2Reply.Transfer.StagePath,
            CancellationToken.None, v2Identity);
        string digest = Convert.ToHexString(SHA256.HashData(
            await File.ReadAllBytesAsync(v2Reply.Transfer.StagePath))).ToLowerInvariant();
        await journal.TransitionAsync(v2Reservation, TransferJournalState.Sealed,
            TransferJournalState.Inspecting, null, CancellationToken.None);
        await journal.TransitionAsync(v2Reservation, TransferJournalState.Inspecting,
            TransferJournalState.Approved, digest, CancellationToken.None);
        await journal.TransitionAsync(v2Reservation, TransferJournalState.Approved,
            TransferJournalState.Publishing, null, CancellationToken.None);
        await journal.TransitionAsync(v2Reservation, TransferJournalState.Publishing,
            TransferJournalState.Released, null, CancellationToken.None);

        var v1Cleanup = new StagedDiscardRequest(v2Reservation, v1Identity,
            StagedDiscardKind.EmptyHeldPredecessor);
        Assert.Equal(StagedDiscardStatus.Pending,
            await journal.BeginOrConfirmDiscardAsync(v1Cleanup, CancellationToken.None,
                processId, driverInstance));
        File.Delete(v2Reply.Transfer.StagePath);
        await File.WriteAllTextAsync(v2Reply.Transfer.StagePath, "replacement object must remain private");

        StagedTransferPublisher publisher = CreateDisposalPublisher(journal, root,
            held: false, out DisposalGate gate);
        await publisher.DisposeReleasedStageAsync(v2Reservation, CancellationToken.None);
        Assert.Equal(new[] { (v2Reservation, StageDisposeOutcome.Released) }, gate.Disposals);
        await Assert.ThrowsAsync<IOException>(() => journal.CompleteDiscardAsync(
            v1Cleanup, CancellationToken.None));
        Assert.Equal("replacement object must remain private",
            await File.ReadAllTextAsync(v2Reply.Transfer.StagePath));
        Assert.True(File.Exists(v1Reply.Transfer.StagePath));
        Assert.Null((await journal.ReadAsync(v1Identity.TransferId, CancellationToken.None))
            .DiscardAcknowledgedAtUtc);
    }

    [Fact]
    public async Task V19_create_after_rejects_wrong_delete_identity_and_changed_parent_directory()
    {
        string root = Path.Combine(_workspace.Root, "stage");
        string destination = Path.Combine(_workspace.Root, "destination", "report.txt");
        Directory.CreateDirectory(Path.GetDirectoryName(destination)!);
        var journal = new StagedTransferJournal(Path.Combine(_workspace.Root, "journal"));
        var allocator = new StagedTransferAllocator(root, journal);
        var parent = await allocator.AllocateV19Async(destination, DestinationKind.Cloud, "word.exe",
            17, 2, 2, null, CancellationToken.None, requestorSid: "S-1-5-21-111-222-333-1000",
            requestorProcessCreationTime: 638953632000000000);
        TransferJournalEntry parentEmpty = await LegacyStagedJournalFixture.SealEmptyAsync(journal, _workspace.Root, parent.Transfer.TransferId, 17,
            parent.Transfer.StagePath, CancellationToken.None, new StagedVersionIdentity(
                parent.Transfer.TransferId, parent.DestinationGeneration, parent.StageIdentity));
        var child = await allocator.AllocateV19Async(destination, DestinationKind.Cloud, "word.exe",
            17, 2, 1, parentEmpty.Transfer, CancellationToken.None,
            requestorSid: "S-1-5-21-111-222-333-1000",
            requestorProcessCreationTime: 638953632000000000);
        await File.WriteAllTextAsync(child.Transfer.StagePath, "V2");
        TransferJournalEntry sealedChild = await LegacyStagedJournalFixture.SealEmptyAsync(journal, _workspace.Root, child.Transfer.TransferId, 17,
            child.Transfer.StagePath, CancellationToken.None, new StagedVersionIdentity(
                child.Transfer.TransferId, child.DestinationGeneration, child.StageIdentity));
        var exact = new StagedVersionIdentity(child.Transfer.TransferId, child.DestinationGeneration,
            child.StageIdentity);
        StagedStageIdentity directoryIdentity = StagedStageFile.ReadDirectoryIdentity(
            Path.GetDirectoryName(destination)!);
        var wrongIdentity = new StagedCreateAfterDiscardRequest(Guid.NewGuid(),
            exact with { StageIdentity = new StagedStageIdentity(0, 123, 456) }, directoryIdentity,
            5, destination, DestinationKind.Cloud, 17, 2, "S-1-5-21-111-222-333-1000",
            638953632000000000);
        await Assert.ThrowsAsync<ArgumentException>(() => allocator.CreateAfterPrivateDiscardAsync(
            wrongIdentity with { DeleteVersion = exact, Disposition = 2 }, CancellationToken.None));
        await Assert.ThrowsAsync<IOException>(() => allocator.CreateAfterPrivateDiscardAsync(
            wrongIdentity, CancellationToken.None));
        Assert.Equal(TransferJournalState.Sealed,
            (await journal.ReadAsync(sealedChild.Transfer.TransferId, CancellationToken.None)).State);

        string movedDirectory = Path.GetDirectoryName(destination)! + ".old";
        Directory.Move(Path.GetDirectoryName(destination)!, movedDirectory);
        Directory.CreateDirectory(Path.GetDirectoryName(destination)!);
        var changedParent = new StagedCreateAfterDiscardRequest(Guid.NewGuid(), exact,
            directoryIdentity, 5, destination, DestinationKind.Cloud, 17, 2,
            "S-1-5-21-111-222-333-1000", 638953632000000000);
        await Assert.ThrowsAsync<IOException>(() => allocator.CreateAfterPrivateDiscardAsync(
            changedParent, CancellationToken.None));
        Assert.True(File.Exists(Path.Combine(movedDirectory, Path.GetFileName(destination))) == false);
    }

    private async Task<(StagedTransferAllocator Allocator, StagedTransferJournal Journal,
        StagedTransfer Owner, string Source, string Root)> RenamedOccupiedSlotAsync()
    {
        string root = Path.Combine(_workspace.Root, "stage");
        var journal = new StagedTransferJournal(Path.Combine(_workspace.Root, "journal"));
        var allocator = new StagedTransferAllocator(root, journal);
        string source = Path.Combine(_workspace.Root, "report.txt");
        await File.WriteAllTextAsync(source, "old public bytes");
        var owner = await allocator.AllocateAsync(source, DestinationKind.Cloud,
            "word.exe", 17, 2, 1, null, CancellationToken.None);
        await File.WriteAllTextAsync(owner.StagePath, "prior private bytes");
        string target = Path.Combine(_workspace.Root, "renamed.txt");
        await journal.PrepareRenameAsync(owner.TransferId, 93, 17, target, false, CancellationToken.None);
        await journal.CompleteRenameAsync(owner.TransferId, 93, 17, target, true, CancellationToken.None);
        return (allocator, journal, owner, source, root);
    }

    [Fact]
    public async Task Committed_private_tombstone_creates_empty_view_without_reading_or_changing_public_slot()
    {
        var (allocator, journal, owner, source, root) = await RenamedOccupiedSlotAsync();
        await Assert.ThrowsAsync<IOException>(() => allocator.AllocateAsync(source,
            DestinationKind.Cloud, "word.exe", 17, 2, 2, null, CancellationToken.None));
        var next = await allocator.AllocateAsync(source, DestinationKind.Cloud,
            "word.exe", 17, 2, 2, null, CancellationToken.None, owner.TransferId);
        Assert.Equal(0, new FileInfo(next.StagePath).Length);
        Assert.Equal("old public bytes", await File.ReadAllTextAsync(source));
        Assert.Equal("prior private bytes", await File.ReadAllTextAsync(owner.StagePath));
        var entry = await journal.ReadAsync(next.TransferId, CancellationToken.None);
        Assert.True(entry.DestinationGeneration > 2);
        Assert.Equal(TransferJournalState.Allocated, entry.State);
        await Assert.ThrowsAsync<IOException>(() => allocator.AllocateAsync(source,
            DestinationKind.Cloud, "word.exe", 17, 2, 2, null, CancellationToken.None, owner.TransferId));
        Assert.Equal(2, Directory.GetFiles(root).Length);
    }

    [Theory]
    [InlineData(18, 2, false)]
    [InlineData(17, 3, false)]
    [InlineData(17, 2, true)]
    public async Task Tombstone_reuse_rejects_other_writer_session_or_unknown_owner(
        int processId, uint sessionId, bool unknownOwner)
    {
        var (allocator, journal, owner, source, root) = await RenamedOccupiedSlotAsync();
        await Assert.ThrowsAsync<IOException>(() => allocator.AllocateAsync(source,
            DestinationKind.Cloud, "word.exe", processId, sessionId, 2, null,
            CancellationToken.None, unknownOwner ? Guid.NewGuid() : owner.TransferId));
        Assert.Single(Directory.GetFiles(root));
        Assert.Single(await journal.ReadPendingAsync(CancellationToken.None));
        Assert.Equal("old public bytes", await File.ReadAllTextAsync(source));
        Assert.Equal("prior private bytes", await File.ReadAllTextAsync(owner.StagePath));
    }

    [Fact]
    public async Task Concurrent_tombstone_claims_commit_only_one_new_generation()
    {
        var (allocator, journal, owner, source, root) = await RenamedOccupiedSlotAsync();
        async Task<StagedTransfer?> TryClaimAsync()
        {
            try
            {
                return await allocator.AllocateAsync(source, DestinationKind.Cloud,
                    "word.exe", 17, 2, 2, null, CancellationToken.None, owner.TransferId);
            }
            catch (IOException) { return null; }
        }
        var results = await Task.WhenAll(TryClaimAsync(), TryClaimAsync());
        var winner = Assert.Single(results.OfType<StagedTransfer>());
        Assert.Equal(0, new FileInfo(winner.StagePath).Length);
        Assert.Equal(2, Directory.GetFiles(root).Length);
        Assert.Equal(2, (await journal.ReadPendingAsync(CancellationToken.None)).Count);
        Assert.Equal("old public bytes", await File.ReadAllTextAsync(source));
    }

    [Theory]
    [InlineData(0)]
    [InlineData(1)]
    [InlineData(511)]
    [InlineData(4095)]
    [InlineData(65535)]
    [InlineData(65536)]
    [InlineData(65537)]
    public async Task Noncached_seed_preserves_exact_bytes_and_partial_sector_length(int length)
    {
        string root = Path.Combine(_workspace.Root, "stage");
        var journal = new StagedTransferJournal(Path.Combine(_workspace.Root, "journal"));
        var allocator = new StagedTransferAllocator(root, journal);
        string destination = Path.Combine(_workspace.Root, "report.txt");
        byte[] content = Enumerable.Range(0, length).Select(i => (byte)(i * 17)).ToArray();
        await File.WriteAllBytesAsync(destination, content);
        var stage = await allocator.AllocateAsync(destination, DestinationKind.Cloud,
            "word.exe", 17, 2, 1, null, CancellationToken.None);
        Assert.Equal(content, await File.ReadAllBytesAsync(stage.StagePath));
        Assert.Equal(length, new FileInfo(stage.StagePath).Length);
        Assert.Equal(content, await File.ReadAllBytesAsync(destination));
    }

    [Fact]
    public async Task Existing_destination_is_seeded_for_open_and_truncated_for_overwrite()
    {
        string root = Path.Combine(_workspace.Root, "stage");
        var journal = new StagedTransferJournal(Path.Combine(_workspace.Root, "journal"));
        var allocator = new StagedTransferAllocator(root, journal);
        string destination = Path.Combine(_workspace.Root, "destination", "report.txt");
        Directory.CreateDirectory(Path.GetDirectoryName(destination)!);
        await File.WriteAllTextAsync(destination, "already there");

        var opened = await allocator.AllocateAsync(destination, DestinationKind.Cloud,
            "word.exe", 17, 2, 1, null, CancellationToken.None);
        Assert.Equal("already there", await File.ReadAllTextAsync(opened.StagePath));
        var overwritten = await allocator.AllocateAsync(destination, DestinationKind.Cloud,
            "word.exe", 17, 2, 4, null, CancellationToken.None);
        Assert.Equal(0, new FileInfo(overwritten.StagePath).Length);
        Assert.Equal("already there", await File.ReadAllTextAsync(destination));
        await Assert.ThrowsAsync<IOException>(() => allocator.AllocateAsync(destination,
            DestinationKind.Cloud, "word.exe", 17, 2, 2, null, CancellationToken.None));
    }

    [Theory]
    [InlineData(1)]
    [InlineData(3)]
    public async Task Oversized_source_is_rejected_without_stage_manifest_or_destination_changes(uint disposition)
    {
        const long maximum = 16 * 1024 * 1024;
        string root = Path.Combine(_workspace.Root, "stage");
        string journalRoot = Path.Combine(_workspace.Root, "journal");
        var allocator = new StagedTransferAllocator(root, new StagedTransferJournal(journalRoot));
        string destination = Path.Combine(_workspace.Root, "large.txt");
        await using (var source = File.Create(destination)) source.SetLength(maximum + 1);

        await Assert.ThrowsAsync<IOException>(() => allocator.AllocateAsync(destination,
            DestinationKind.Cloud, "word.exe", 17, 2, disposition, null, CancellationToken.None));

        Assert.Empty(Directory.EnumerateFiles(root));
        Assert.Empty(Directory.EnumerateFiles(journalRoot));
        Assert.Equal(maximum + 1, new FileInfo(destination).Length);
    }

    [Fact]
    public async Task Exact_maximum_seed_preserves_its_final_byte_and_truncation_needs_no_seed()
    {
        const int maximum = 16 * 1024 * 1024;
        string root = Path.Combine(_workspace.Root, "stage");
        var allocator = new StagedTransferAllocator(root,
            new StagedTransferJournal(Path.Combine(_workspace.Root, "journal")));
        string destination = Path.Combine(_workspace.Root, "boundary.txt");
        await using (var source = File.Create(destination))
        {
            source.SetLength(maximum);
            source.Position = maximum - 1;
            source.WriteByte(0x5a);
        }
        var copied = await allocator.AllocateAsync(destination, DestinationKind.Cloud,
            "word.exe", 17, 2, 1, null, CancellationToken.None);
        Assert.Equal(maximum, new FileInfo(copied.StagePath).Length);
        await using (var stage = File.OpenRead(copied.StagePath))
        {
            stage.Position = maximum - 1;
            Assert.Equal(0x5a, stage.ReadByte());
        }
        await using (var source = File.OpenWrite(destination)) source.SetLength(maximum + 1L);
        var empty = await allocator.AllocateAsync(destination, DestinationKind.Cloud,
            "word.exe", 17, 2, 4, null, CancellationToken.None);
        Assert.Equal(0, new FileInfo(empty.StagePath).Length);
        Assert.Equal(maximum + 1L, new FileInfo(destination).Length);
    }

    [Fact]
    public async Task Oversized_prior_private_version_is_preserved_without_creating_a_followup()
    {
        const long maximum = 16 * 1024 * 1024;
        string root = Path.Combine(_workspace.Root, "stage");
        string journalRoot = Path.Combine(_workspace.Root, "journal");
        var journal = new StagedTransferJournal(journalRoot);
        var allocator = new StagedTransferAllocator(root, journal);
        string destination = Path.Combine(_workspace.Root, "private-large.txt");
        var prior = await allocator.AllocateAsync(destination, DestinationKind.Cloud,
            "word.exe", 17, 2, CancellationToken.None);
        await using (var source = File.OpenWrite(prior.StagePath)) source.SetLength(maximum + 1);
        var sealedEntry = await journal.TransitionAsync(prior.TransferId, TransferJournalState.Allocated,
            TransferJournalState.Sealed, null, CancellationToken.None);

        await Assert.ThrowsAsync<IOException>(() => allocator.AllocateAsync(destination,
            DestinationKind.Cloud, "word.exe", 17, 2, 1, prior, CancellationToken.None));

        Assert.Single(Directory.EnumerateFiles(root));
        Assert.Single(Directory.EnumerateFiles(journalRoot));
        Assert.Equal(maximum + 1, new FileInfo(prior.StagePath).Length);
        Assert.Equal(sealedEntry, await journal.ReadAsync(prior.TransferId, CancellationToken.None));
        Assert.False(File.Exists(destination));
    }
}
