using System.Security.Principal;
using System.Text.Json.Nodes;
using SafeUpload.Agent.Core.Application;
using SafeUpload.Agent.Core.Contracts;
using SafeUpload.Agent.Core.Domain;
using SafeUpload.Agent.Core.Infrastructure;
using SafeUpload.Agent.Core.Infrastructure.Extraction;
using SafeUpload.Agent.Service.Interception;
using SafeUpload.Agent.Service.Notifications;

namespace SafeUpload.Agent.Tests;

public sealed class StagedHandbackTests : IDisposable
{
    private const string TestRequestorSid = "S-1-5-21-111-222-333-1000";
    private readonly TestWorkspace _workspace = new();
    private readonly string _stagingRoot;
    private readonly string _journalRoot;
    private readonly NotificationHub _notifications = NotificationTestHub.Create();

    public StagedHandbackTests()
    {
        // The copier creates the hand-back directories owned by SYSTEM, which the agent service (SYSTEM) may always do. A test
        // process may do it only with SeRestorePrivilege enabled: the builder's SSH session has it enabled, a CI runner's
        // elevated token holds it disabled ("This security ID may not be assigned as the owner of this object").
        TestPrivileges.TryEnable("SeRestorePrivilege");
        _stagingRoot = Path.Combine(_workspace.Root, "staging");
        _journalRoot = Path.Combine(_workspace.Root, "journal");
        Directory.CreateDirectory(_stagingRoot);
    }

    public void Dispose() => _workspace.Dispose();

    [Fact]
    public async Task Verified_handback_is_idempotent_across_restart_and_cleanup_waits_for_window_close()
    {
        IPolicyStore policy = await PolicyAsync(allowJustification: true);
        var journal = new StagedTransferJournal(_journalRoot);
        var transfer = CreateBlockedCandidate(journal, "CPF: 529.982.247-25", sessionId: 7);
        Directory.CreateDirectory(Path.GetDirectoryName(transfer.DestinationPath)!);
        await File.WriteAllTextAsync(transfer.DestinationPath, "protected baseline");
        var firstCopy = new RecordingHandbackCopier(Path.Combine(_workspace.Root, "profile"));
        var publisher = Publisher(journal, policy, new StagedJustifications(), firstCopy);

        Assert.Equal(StagedTransferOutcome.Blocked,
            await publisher.PublishAsync(transfer, CancellationToken.None));
        TransferJournalEntry blocked = await journal.ReadAsync(transfer.TransferId, CancellationToken.None);
        Assert.True(blocked.HandbackState == StagedHandbackState.Verified,
            "Hand-back state " + blocked.HandbackState + ": " + blocked.HandbackFailureReason);
        Assert.Equal(1, firstCopy.CopyCount);
        Assert.False(blocked.JustificationWindowClosed);
        Assert.True(File.Exists(transfer.StagePath));
        Assert.Equal("protected baseline", await File.ReadAllTextAsync(transfer.DestinationPath));
        Assert.Equal("CPF: 529.982.247-25", await File.ReadAllTextAsync(blocked.HandbackPath!));
        Assert.Equal(Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(
            await File.ReadAllBytesAsync(transfer.StagePath))), blocked.Sha256Hex);

        var restartedJournal = new StagedTransferJournal(_journalRoot);
        var afterRestartCopy = new RecordingHandbackCopier(Path.Combine(_workspace.Root, "profile"));
        var restartedPublisher = Publisher(restartedJournal, policy,
            new StagedJustifications(), afterRestartCopy);
        await restartedPublisher.RecoverBlockedAsync(
            await restartedJournal.ReadAsync(transfer.TransferId, CancellationToken.None),
            CancellationToken.None);
        Assert.Equal(0, afterRestartCopy.CopyCount);
        Assert.True(File.Exists(transfer.StagePath));

        blocked = await restartedJournal.ReadAsync(transfer.TransferId, CancellationToken.None);
        await restartedJournal.CloseJustificationWindowAsync(transfer.TransferId,
            blocked.JustificationExpiresAtUtc!.Value.AddTicks(1), CancellationToken.None);
        await restartedPublisher.ProcessBlockedCleanupAsync(
            await restartedJournal.ReadAsync(transfer.TransferId, CancellationToken.None),
            CancellationToken.None);

        TransferJournalEntry cleaned = await restartedJournal.ReadAsync(
            transfer.TransferId, CancellationToken.None);
        Assert.True(cleaned.JustificationWindowClosed);
        Assert.True(cleaned.StageDeleted);
        Assert.False(File.Exists(transfer.StagePath));
        Assert.Equal(0, afterRestartCopy.CopyCount);
    }

    [Fact]
    public async Task Copy_failure_is_audited_retains_staging_and_never_reports_a_verified_path()
    {
        IPolicyStore policy = await PolicyAsync(allowJustification: true);
        var journal = new StagedTransferJournal(_journalRoot);
        var transfer = CreateBlockedCandidate(journal, "CPF: 529.982.247-25", sessionId: 7);
        var copier = new RecordingHandbackCopier(Path.Combine(_workspace.Root, "profile"), fail: true);
        using var subscription = _notifications.Subscribe(7, TestRequestorSid);
        var publisher = Publisher(journal, policy, new StagedJustifications(), copier);

        Assert.Equal(StagedTransferOutcome.Blocked,
            await publisher.PublishAsync(transfer, CancellationToken.None));
        TransferJournalEntry blocked = await journal.ReadAsync(transfer.TransferId, CancellationToken.None);
        Assert.Equal(StagedHandbackState.Failed, blocked.HandbackState);
        Assert.Null(blocked.HandbackPath);
        Assert.True(File.Exists(transfer.StagePath));
        Assert.False(File.Exists(transfer.DestinationPath));
        Assert.Equal(2, (await new LocalQueueAuditSink(_workspace.QueueFile)
            .ReadRecentAsync(10, CancellationToken.None)).Count);
        var transferNotifications = new List<TransferNotification>();
        while (subscription.Reader.TryRead(out AgentNotification? notification))
            if (notification is TransferNotification transferNotification)
                transferNotifications.Add(transferNotification);
        var blockedNotification = Assert.Single(transferNotifications,
            notification => notification.Phase == TransferPhase.Blocked);
        Assert.Equal(blocked.Sha256Hex, blockedNotification.SnapshotSha256Hex);
        Assert.False(blockedNotification.HandbackVerified);
        Assert.Null(blockedNotification.HandbackPath);
        Assert.DoesNotContain(transferNotifications,
            notification => notification.Phase == TransferPhase.Released);
        await Assert.ThrowsAsync<IOException>(() => journal.TransitionAsync(transfer.TransferId,
            TransferJournalState.Blocked, TransferJournalState.Inspecting, null,
            CancellationToken.None, closeJustificationWindow: true));
    }

    [Fact]
    public async Task Reused_session_still_hands_back_to_the_requestor_and_delivers_nothing_to_the_session()
    {
        IPolicyStore policy = await PolicyAsync(allowJustification: true);
        var journal = new StagedTransferJournal(_journalRoot);
        var transfer = CreateBlockedCandidate(journal, "CPF: 529.982.247-25", sessionId: 7);
        var copier = new RecordingHandbackCopier(Path.Combine(_workspace.Root, "profile"));
        using var subscription = _notifications.Subscribe(7, TestRequestorSid);
        var publisher = new StagedTransferPublisher(new InspectionService(policy,
                new LocalQueueAuditSink(_workspace.QueueFile), ExtractorRegistry.CreateDefault(),
                new VerdictCache()), _notifications, journal, _stagingRoot,
            new TestPublicationGate(), new StagedJustifications(), policyStore: policy,
            handbackCopier: copier, sessionUserSidResolver: _ => "S-1-5-21-999-888-777-1000");

        Assert.Equal(StagedTransferOutcome.Blocked,
            await publisher.PublishAsync(transfer, CancellationToken.None));
        TransferJournalEntry blocked = await journal.ReadAsync(transfer.TransferId, CancellationToken.None);

        // The hand-back follows the requestor SID persisted at allocation, never the
        // session's current user; the session's new user receives nothing.
        Assert.Equal(StagedHandbackState.Verified, blocked.HandbackState);
        Assert.Equal(1, copier.CopyCount);
        Assert.NotNull(blocked.HandbackPath);
        Assert.DoesNotContain(DrainTransfers(subscription),
            notification => notification.Phase == TransferPhase.Blocked);
        Assert.Contains(await new LocalQueueAuditSink(_workspace.QueueFile)
                .ReadRecentAsync(10, CancellationToken.None),
            audit => audit.Verdict == Verdict.Blocked);
    }

    [Fact]
    public async Task Legacy_manifest_without_requestor_sid_is_never_handed_back_automatically()
    {
        IPolicyStore policy = await PolicyAsync(allowJustification: true);
        var journal = new StagedTransferJournal(_journalRoot);
        var transfer = CreateBlockedCandidate(journal, "CPF: 529.982.247-25", sessionId: 7,
            requestorSid: null);
        var copier = new RecordingHandbackCopier(Path.Combine(_workspace.Root, "profile"));
        using var subscription = _notifications.Subscribe(7, TestRequestorSid);
        var publisher = Publisher(journal, policy, new StagedJustifications(), copier);

        Assert.Equal(StagedTransferOutcome.Blocked,
            await publisher.PublishAsync(transfer, CancellationToken.None));
        TransferJournalEntry blocked = await journal.ReadAsync(transfer.TransferId, CancellationToken.None);

        Assert.Equal(StagedHandbackState.Failed, blocked.HandbackState);
        Assert.Equal("requestor_identity_unavailable", blocked.HandbackFailureReason);
        Assert.Equal(0, copier.CopyCount);
        Assert.True(File.Exists(transfer.StagePath));
        Assert.DoesNotContain(DrainTransfers(subscription),
            notification => notification.Phase == TransferPhase.Blocked);
        Assert.Contains(await new LocalQueueAuditSink(_workspace.QueueFile)
                .ReadRecentAsync(10, CancellationToken.None),
            audit => audit.Verdict == Verdict.Blocked);
    }

    [Fact]
    public async Task Recovery_with_a_reused_session_keeps_the_verified_handback_without_recopy()
    {
        IPolicyStore policy = await PolicyAsync(allowJustification: false);
        var journal = new StagedTransferJournal(_journalRoot);
        var transfer = CreateBlockedCandidate(journal, "CPF: 529.982.247-25", sessionId: 7);
        var copier = new RecordingHandbackCopier(Path.Combine(_workspace.Root, "profile"));
        var owner = _notifications.Subscribe(7, TestRequestorSid);
        using var ownerLifetime = owner;
        using var newSessionUser = _notifications.Subscribe(7, "S-1-5-21-999-888-777-1000");
        var initialPublisher = Publisher(journal, policy, new StagedJustifications(), copier);
        Assert.Equal(StagedTransferOutcome.Blocked,
            await initialPublisher.PublishAsync(transfer, CancellationToken.None));
        TransferJournalEntry verified = await journal.ReadAsync(transfer.TransferId, CancellationToken.None);
        Assert.Equal(StagedHandbackState.Verified, verified.HandbackState);
        _ = DrainTransfers(owner).ToArray();
        _ = DrainTransfers(newSessionUser).ToArray();

        var recoveredPublisher = new StagedTransferPublisher(new InspectionService(policy,
                new LocalQueueAuditSink(_workspace.QueueFile), ExtractorRegistry.CreateDefault(),
                new VerdictCache()), _notifications, journal, _stagingRoot,
            new TestPublicationGate(), new StagedJustifications(), policyStore: policy,
            handbackCopier: copier, sessionUserSidResolver: _ => "S-1-5-21-999-888-777-1000");
        await recoveredPublisher.RecoverBlockedAsync(verified, CancellationToken.None);
        TransferJournalEntry retained = await journal.ReadAsync(transfer.TransferId, CancellationToken.None);

        // Session reuse neither redirects nor invalidates a hand-back bound to the requestor SID.
        Assert.Equal(StagedHandbackState.Verified, retained.HandbackState);
        Assert.Equal(verified.HandbackPath, retained.HandbackPath);
        Assert.Equal(1, copier.CopyCount);
        Assert.DoesNotContain(DrainTransfers(newSessionUser), notification => notification.Phase == TransferPhase.Blocked);
        Assert.DoesNotContain(await new LocalQueueAuditSink(_workspace.QueueFile)
                .ReadRecentAsync(10, CancellationToken.None),
            audit => audit.NotInspectedReason == "requestor_identity_unavailable");
    }

    [Fact]
    public async Task Cleanup_reverification_of_changed_copy_retains_staging_without_recopy_loops()
    {
        IPolicyStore policy = await PolicyAsync(allowJustification: true);
        var journal = new StagedTransferJournal(_journalRoot);
        var transfer = CreateBlockedCandidate(journal, "CPF: 529.982.247-25", sessionId: 7);
        var copier = new RecordingHandbackCopier(Path.Combine(_workspace.Root, "profile"));
        var publisher = Publisher(journal, policy, new StagedJustifications(), copier);
        Assert.Equal(StagedTransferOutcome.Blocked,
            await publisher.PublishAsync(transfer, CancellationToken.None));
        TransferJournalEntry blocked = await journal.ReadAsync(transfer.TransferId, CancellationToken.None);
        await File.WriteAllTextAsync(blocked.HandbackPath!, "changed after verified copy");
        await journal.CloseJustificationWindowAsync(transfer.TransferId,
            blocked.JustificationExpiresAtUtc!.Value.AddTicks(1), CancellationToken.None);

        await publisher.ProcessBlockedCleanupAsync(
            await journal.ReadAsync(transfer.TransferId, CancellationToken.None), CancellationToken.None);
        TransferJournalEntry retained = await journal.ReadAsync(transfer.TransferId, CancellationToken.None);
        await publisher.ProcessBlockedCleanupAsync(retained, CancellationToken.None);
        await publisher.RecoverBlockedAsync(retained, CancellationToken.None);

        Assert.Equal(StagedHandbackState.Failed, retained.HandbackState);
        Assert.Equal("handback_reverification_failed", retained.HandbackFailureReason);
        Assert.Null(retained.HandbackPath);
        Assert.False(retained.StageDeleted);
        Assert.True(File.Exists(transfer.StagePath));
        Assert.Equal(1, copier.CopyCount);
        Assert.Single((await new LocalQueueAuditSink(_workspace.QueueFile)
            .ReadRecentAsync(20, CancellationToken.None)), audit =>
            audit.Verdict == Verdict.Retained && audit.NotInspectedReason == "handback_reverification_failed");
    }

    [Fact]
    public async Task Failed_copy_removes_its_uncommitted_temp_by_handle()
    {
        if (!OperatingSystem.IsWindows()) return;
        using WindowsIdentity identity = WindowsIdentity.GetCurrent();
        SecurityIdentifier user = identity.User ?? throw new InvalidOperationException("Test user SID missing.");
        string profile = Path.Combine(_workspace.Root, "cancel-profile");
        Directory.CreateDirectory(profile);
        var copier = new StagedHandbackCopier(await EmptyScopePolicyAsync(),
            new TestHandbackEnvironment(user, profile));
        string sourcePath = _workspace.WriteText("cancel-source.txt", "sealed snapshot");
        var transfer = new StagedTransfer(Guid.NewGuid(), sourcePath,
            Path.Combine(_workspace.Root, "protected", "report.txt"),
            DestinationKind.RemovableDrive, "explorer.exe", 1234, 7)
        { RequestorSid = user.Value };
        using var cancellation = new CancellationTokenSource();
        await using var source = new CancelDuringCopyFileStream(sourcePath, cancellation);
        string digest = Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(
            await File.ReadAllBytesAsync(sourcePath)));

        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => copier.CopyVerifiedAsync(
            transfer, source, source.Length, digest, cancellation.Token));

        string blockedDirectory = Path.Combine(profile, "SafeUpload", "_bloqueados");
        Assert.True(Directory.Exists(blockedDirectory));
        Assert.Empty(Directory.EnumerateFiles(blockedDirectory, ".safeupload-*.tmp"));
    }

    [Fact]
    public void File_acl_descriptor_is_explicit_and_contains_only_the_user_and_system()
    {
        var user = new SecurityIdentifier(WellKnownSidType.BuiltinUsersSid, null);
        Assert.Equal($"O:SYD:P(A;;FR;;;{user.Value})(A;;FA;;;SY)",
            StagedHandbackCopier.BuildFileSecurityDescriptorSddl(user));
        Assert.Equal($"O:SYD:P(A;;FR;;;{user.Value})(A;;FA;;;SY)",
            StagedHandbackCopier.BuildDirectorySecurityDescriptorSddl(user));
    }

    [Theory]
    [InlineData("policy")]
    [InlineData("sync")]
    public async Task Protected_or_known_sync_roots_are_refused_before_directory_creation(string scopeKind)
    {
        if (!OperatingSystem.IsWindows()) return;
        using WindowsIdentity identity = WindowsIdentity.GetCurrent();
        SecurityIdentifier user = identity.User ?? throw new InvalidOperationException("Test user SID missing.");
        string profile = Path.Combine(_workspace.Root, "refusal-profile");
        Directory.CreateDirectory(profile);
        string safeUpload = Path.Combine(profile, "SafeUpload");
        Directory.CreateDirectory(safeUpload);
        var policy = new LocalPolicyStore(_workspace.PolicyFile);
        await policy.LoadAsync(CancellationToken.None);
        string[] syncRoots = [];
        JsonObject scopeDocument = JsonNode.Parse(await File.ReadAllTextAsync(_workspace.PolicyFile))!.AsObject();
        scopeDocument["monitoredScopes"]!["destinationPaths"] = new JsonArray();
        await File.WriteAllTextAsync(_workspace.PolicyFile, scopeDocument.ToJsonString());
        if (scopeKind == "policy")
        {
            JsonObject document = JsonNode.Parse(await File.ReadAllTextAsync(_workspace.PolicyFile))!.AsObject();
            document["monitoredScopes"]!["destinationPaths"] = new JsonArray(JsonValue.Create(safeUpload));
            await File.WriteAllTextAsync(_workspace.PolicyFile, document.ToJsonString());
        }
        else syncRoots = [safeUpload];

        var copier = new StagedHandbackCopier(policy,
            new TestHandbackEnvironment(user, profile, syncRoots));
        string sourcePath = _workspace.WriteText("scope-source.txt", "sealed snapshot");
        var transfer = new StagedTransfer(Guid.NewGuid(), sourcePath,
            Path.Combine(_workspace.Root, "protected", "report.txt"),
            DestinationKind.RemovableDrive, "explorer.exe", 1234, 7)
        { RequestorSid = user.Value };
        string digest = Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(
            await File.ReadAllBytesAsync(sourcePath)));
        await using var source = new FileStream(sourcePath, FileMode.Open, FileAccess.Read,
            FileShare.Read, 4096, FileOptions.Asynchronous);

        await Assert.ThrowsAsync<IOException>(() => copier.CopyVerifiedAsync(
            transfer, source, source.Length, digest, CancellationToken.None));
        Assert.False(Directory.Exists(Path.Combine(safeUpload, "_bloqueados")));
    }

    [Theory]
    [InlineData("policy")]
    [InlineData("sync")]
    public async Task Unresolvable_registered_scope_fails_closed_before_directory_creation(string scopeKind)
    {
        if (!OperatingSystem.IsWindows()) return;
        using WindowsIdentity identity = WindowsIdentity.GetCurrent();
        SecurityIdentifier user = identity.User ?? throw new InvalidOperationException("Test user SID missing.");
        string profile = Path.Combine(_workspace.Root, "unresolved-profile");
        Directory.CreateDirectory(profile);
        string missingRoot = Path.Combine(profile, "missing-registered-root");
        var policy = new LocalPolicyStore(_workspace.PolicyFile);
        await policy.LoadAsync(CancellationToken.None);
        JsonObject document = JsonNode.Parse(await File.ReadAllTextAsync(_workspace.PolicyFile))!.AsObject();
        document["monitoredScopes"]!["destinationPaths"] = scopeKind == "policy"
            ? new JsonArray(JsonValue.Create(missingRoot)) : new JsonArray();
        await File.WriteAllTextAsync(_workspace.PolicyFile, document.ToJsonString());
        string[] syncRoots = scopeKind == "sync" ? [missingRoot] : [];
        var copier = new StagedHandbackCopier(policy,
            new TestHandbackEnvironment(user, profile, syncRoots));
        string sourcePath = _workspace.WriteText("missing-scope-source.txt", "sealed snapshot");
        var transfer = new StagedTransfer(Guid.NewGuid(), sourcePath,
            Path.Combine(_workspace.Root, "protected", "report.txt"),
            DestinationKind.RemovableDrive, "explorer.exe", 1234, 7)
        { RequestorSid = user.Value };
        string digest = Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(
            await File.ReadAllBytesAsync(sourcePath)));
        await using var source = new FileStream(sourcePath, FileMode.Open, FileAccess.Read,
            FileShare.Read, 4096, FileOptions.Asynchronous);

        await Assert.ThrowsAnyAsync<IOException>(() => copier.CopyVerifiedAsync(
            transfer, source, source.Length, digest, CancellationToken.None));
        Assert.False(Directory.Exists(Path.Combine(profile, "SafeUpload")));
    }

    [Fact]
    public async Task Extended_length_sync_root_alias_is_matched_by_directory_identity()
    {
        if (!OperatingSystem.IsWindows()) return;
        using WindowsIdentity identity = WindowsIdentity.GetCurrent();
        SecurityIdentifier user = identity.User ?? throw new InvalidOperationException("Test user SID missing.");
        string profile = Path.Combine(_workspace.Root, "alias-profile");
        string safeUpload = Path.Combine(profile, "SafeUpload");
        Directory.CreateDirectory(safeUpload);
        string alias = "\\\\?\\" + Path.GetFullPath(safeUpload);
        Assert.True(StagedHandbackCopier.DirectoryPathsHaveSameIdentity(safeUpload, alias));
        var copier = new StagedHandbackCopier(await EmptyScopePolicyAsync(),
            new TestHandbackEnvironment(user, profile, [alias]));
        string sourcePath = _workspace.WriteText("alias-source.txt", "sealed snapshot");
        var transfer = new StagedTransfer(Guid.NewGuid(), sourcePath,
            Path.Combine(_workspace.Root, "protected", "report.txt"),
            DestinationKind.RemovableDrive, "explorer.exe", 1234, 7)
        { RequestorSid = user.Value };
        string digest = Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(
            await File.ReadAllBytesAsync(sourcePath)));
        await using var source = new FileStream(sourcePath, FileMode.Open, FileAccess.Read,
            FileShare.Read, 4096, FileOptions.Asynchronous);

        await Assert.ThrowsAsync<IOException>(() => copier.CopyVerifiedAsync(
            transfer, source, source.Length, digest, CancellationToken.None));
        Assert.False(Directory.Exists(Path.Combine(safeUpload, "_bloqueados")));
    }

    [Fact]
    public async Task Existing_handback_name_is_verified_read_only_and_never_overwritten()
    {
        if (!OperatingSystem.IsWindows()) return;
        using WindowsIdentity identity = WindowsIdentity.GetCurrent();
        SecurityIdentifier user = identity.User ?? throw new InvalidOperationException("Test user SID missing.");
        string profile = Path.Combine(_workspace.Root, "test-profile");
        Directory.CreateDirectory(profile);
        var copier = new StagedHandbackCopier(await EmptyScopePolicyAsync(),
            new TestHandbackEnvironment(user, profile));
        string sourcePath = _workspace.WriteText("sealed.txt", "sealed snapshot");
        var transfer = new StagedTransfer(Guid.NewGuid(), sourcePath,
            Path.Combine(_workspace.Root, "protected", "report.txt"),
            DestinationKind.RemovableDrive, "explorer.exe", 1234, 7)
        { RequestorSid = user.Value };
        string digest = Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(
            await File.ReadAllBytesAsync(sourcePath)));
        string returned;
        await using (var source = new FileStream(sourcePath, FileMode.Open, FileAccess.Read,
                         FileShare.Read, 4096, FileOptions.Asynchronous))
        {
            returned = await copier.CopyVerifiedAsync(transfer, source, source.Length,
                digest, CancellationToken.None);
        }
        Assert.Equal("sealed snapshot", await File.ReadAllTextAsync(returned));

        await using (var adoptSource = new FileStream(sourcePath, FileMode.Open, FileAccess.Read,
                         FileShare.Read, 4096, FileOptions.Asynchronous))
        {
            string adopted = await copier.CopyVerifiedAsync(transfer, adoptSource,
                adoptSource.Length, digest, CancellationToken.None);
            Assert.Equal(returned, adopted);
        }

        await Assert.ThrowsAsync<UnauthorizedAccessException>(() => File.WriteAllTextAsync(returned,
            "user cannot modify the SYSTEM-owned hand-back"));
        Assert.Equal("sealed snapshot", await File.ReadAllTextAsync(returned));
        await File.WriteAllTextAsync(sourcePath, "different source bytes");
        string changedDigest = Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(
            await File.ReadAllBytesAsync(sourcePath)));
        await using var retrySource = new FileStream(sourcePath, FileMode.Open, FileAccess.Read,
            FileShare.Read, 4096, FileOptions.Asynchronous);
        await Assert.ThrowsAsync<IOException>(() => copier.CopyVerifiedAsync(
            transfer, retrySource, retrySource.Length, changedDigest, CancellationToken.None));
        Assert.Equal("sealed snapshot", await File.ReadAllTextAsync(returned));
    }

    [Fact]
    public async Task Reparse_component_is_refused_when_unprivileged_test_host_can_create_one()
    {
        if (!OperatingSystem.IsWindows()) return;
        using WindowsIdentity identity = WindowsIdentity.GetCurrent();
        SecurityIdentifier user = identity.User ?? throw new InvalidOperationException("Test user SID missing.");
        string profile = Path.Combine(_workspace.Root, "reparse-profile");
        Directory.CreateDirectory(profile);
        string outside = Path.Combine(_workspace.Root, "outside");
        Directory.CreateDirectory(outside);
        try
        {
            Directory.CreateSymbolicLink(Path.Combine(profile, "SafeUpload"), outside);
        }
        catch (Exception error) when (error is UnauthorizedAccessException or IOException or PlatformNotSupportedException)
        {
            return; // Windows may disable unprivileged symlink creation on the builder.
        }

        var copier = new StagedHandbackCopier(await EmptyScopePolicyAsync(),
            new TestHandbackEnvironment(user, profile));
        string sourcePath = _workspace.WriteText("reparse-source.txt", "sealed snapshot");
        var transfer = new StagedTransfer(Guid.NewGuid(), sourcePath,
            Path.Combine(_workspace.Root, "protected", "report.txt"),
            DestinationKind.RemovableDrive, "explorer.exe", 1234, 7)
        { RequestorSid = user.Value };
        string digest = Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(
            await File.ReadAllBytesAsync(sourcePath)));
        await using var source = new FileStream(sourcePath, FileMode.Open, FileAccess.Read,
            FileShare.Read, 4096, FileOptions.Asynchronous);
        await Assert.ThrowsAsync<IOException>(() => copier.CopyVerifiedAsync(
            transfer, source, source.Length, digest, CancellationToken.None));
        Assert.Empty(Directory.EnumerateFileSystemEntries(outside));
    }

    private async Task<IPolicyStore> PolicyAsync(bool allowJustification)
    {
        var store = new LocalPolicyStore(_workspace.PolicyFile);
        await store.LoadAsync(CancellationToken.None);
        JsonObject policy = JsonNode.Parse(await File.ReadAllTextAsync(_workspace.PolicyFile))!.AsObject();
        policy["overrideAllowed"] = allowJustification;
        policy["monitoredScopes"]!["destinationPaths"] = new JsonArray();
        await File.WriteAllTextAsync(_workspace.PolicyFile, policy.ToJsonString());
        return store;
    }

    private async Task<IPolicyStore> EmptyScopePolicyAsync()
    {
        var store = new LocalPolicyStore(_workspace.PolicyFile);
        await store.LoadAsync(CancellationToken.None);
        JsonObject policy = JsonNode.Parse(await File.ReadAllTextAsync(_workspace.PolicyFile))!.AsObject();
        policy["monitoredScopes"]!["destinationPaths"] = new JsonArray();
        await File.WriteAllTextAsync(_workspace.PolicyFile, policy.ToJsonString());
        return store;
    }

    private StagedTransfer CreateBlockedCandidate(StagedTransferJournal journal,
        string contents, uint? sessionId, string? requestorSid = TestRequestorSid)
    {
        string stage = Path.Combine(_stagingRoot, Guid.NewGuid().ToString("N") + ".txt");
        File.WriteAllText(stage, contents);
        string destination = Path.Combine(_workspace.Root, "protected", Path.GetFileName(stage));
        var transfer = new StagedTransfer(Guid.NewGuid(), stage, destination,
            DestinationKind.RemovableDrive, "explorer.exe", 4321, sessionId)
        { RequestorSid = requestorSid };
        journal.CreateAsync(transfer, CancellationToken.None).GetAwaiter().GetResult();
        journal.TransitionAsync(transfer.TransferId, TransferJournalState.Allocated,
            TransferJournalState.Sealed, null, CancellationToken.None).GetAwaiter().GetResult();
        return transfer;
    }

    private StagedTransferPublisher Publisher(StagedTransferJournal journal, IPolicyStore policy,
        StagedJustifications justifications, IStagedHandbackCopier copier) =>
        new(new InspectionService(policy, new LocalQueueAuditSink(_workspace.QueueFile),
                ExtractorRegistry.CreateDefault(), new VerdictCache()),
            _notifications, journal, _stagingRoot, new TestPublicationGate(),
            justifications, policyStore: policy, handbackCopier: copier,
            sessionUserSidResolver: _ => TestRequestorSid);

    private sealed class RecordingHandbackCopier(string profile, bool fail = false) : IStagedHandbackCopier
    {
        public int CopyCount { get; private set; }

        public async Task<string> CopyVerifiedAsync(StagedTransfer transfer, FileStream sealedSnapshot,
            long length, string sha256Hex, CancellationToken token)
        {
            CopyCount++;
            if (fail) throw new IOException("Injected hand-back copy failure.");
            string directory = Path.Combine(profile, "SafeUpload", "_bloqueados");
            Directory.CreateDirectory(directory);
            string path = Path.Combine(directory, transfer.TransferId.ToString("N") +
                Path.GetExtension(transfer.DestinationPath));
            if (File.Exists(path)) throw new IOException("The fake copier does not overwrite.");
            sealedSnapshot.Position = 0;
            await using (var output = new FileStream(path, FileMode.CreateNew, FileAccess.Write,
                FileShare.None, 4096, FileOptions.Asynchronous | FileOptions.WriteThrough))
            {
                await sealedSnapshot.CopyToAsync(output, token);
                output.Flush(flushToDisk: true);
                if (output.Length != length) throw new IOException("Length mismatch in fake copy.");
            }
            string digest = Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(
                await File.ReadAllBytesAsync(path, token)));
            if (!string.Equals(digest, sha256Hex, StringComparison.OrdinalIgnoreCase))
                throw new IOException("Digest mismatch in fake copy.");
            return path;
        }

        public IDisposable OpenVerifiedReadLease(StagedTransfer transfer, string handbackPath,
            long length, string sha256Hex)
        {
            var stream = new FileStream(handbackPath, FileMode.Open, FileAccess.Read,
                FileShare.Read, 4096, FileOptions.SequentialScan);
            try
            {
                string digest = Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(stream));
                if (stream.Length != length || !string.Equals(digest, sha256Hex,
                        StringComparison.OrdinalIgnoreCase))
                    throw new IOException("The fake hand-back changed after verification.");
                stream.Position = 0;
                return stream;
            }
            catch
            {
                stream.Dispose();
                throw;
            }
        }

        public void CleanupUncommittedTemporary(StagedTransfer transfer) { }
    }

    private sealed class TestHandbackEnvironment(SecurityIdentifier user, string profile,
        string[]? syncRoots = null)
        : IStagedHandbackEnvironment
    {
        public void RequireServiceIdentity() { }
        public SecurityIdentifier ResolveUser(uint? sessionId) => user;
        public string ResolveProfilePath(SecurityIdentifier userSid) => profile;
        public IEnumerable<string> KnownSyncRoots(string profilePath, SecurityIdentifier userSid) =>
            syncRoots ?? Array.Empty<string>();
    }

    private sealed class TestPublicationGate : IStagedPublicationGate, IDisposable
    {
        public IDisposable Authorize(StagedTransfer transfer, string temporaryDestination, string digest) => this;
        public void Dispose() { }
    }

    private static IEnumerable<TransferNotification> DrainTransfers(NotificationSubscription subscription)
    {
        while (subscription.Reader.TryRead(out AgentNotification? notification))
            if (notification is TransferNotification transfer) yield return transfer;
    }

    private sealed class CancelDuringCopyFileStream(string path, CancellationTokenSource cancellation)
        : FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read)
    {
        public override Task CopyToAsync(Stream destination, int bufferSize,
            CancellationToken cancellationToken)
        {
            cancellation.Cancel();
            return base.CopyToAsync(destination, bufferSize, cancellation.Token);
        }
    }
}
