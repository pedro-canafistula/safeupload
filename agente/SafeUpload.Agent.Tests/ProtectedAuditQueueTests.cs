using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text.Json;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging.Abstractions;
using SafeUpload.Agent.Core.Domain;
using SafeUpload.Agent.Core.Infrastructure;
using SafeUpload.Agent.Service.Diagnostics;

namespace SafeUpload.Agent.Tests;

public sealed class ProtectedAuditQueueTests : IDisposable
{
    private readonly TestWorkspace _workspace = new();
    private string FilePath => Path.Combine(_workspace.Root, "protected", "queue.jsonl");
    private readonly SecurityIdentifier _users = new(WellKnownSidType.BuiltinUsersSid, null);
    private QueueStorageProtection Protection(string? path = null)
    {
        using var identity = WindowsIdentity.GetCurrent();
        return new(path ?? FilePath, identity.User!); // Test-only owner; never changes machine state.
    }
    private LocalQueueAuditSink Sink() => new(FilePath, Protection());
    private static AuditEvent Event() => new(Guid.NewGuid(), DateTimeOffset.UtcNow, "SYNTHETIC", "SYNTHETIC",
        "ordinary.txt", ".txt", 1, Verdict.Approved, [], [], "synthetic", 42, "synthetic", null, 1, 0, false);
    private static AuditOverride Override(Guid id) => new(id, "business reason", DateTimeOffset.UtcNow, "SYNTHETIC", "SYNTHETIC");

    [Fact]
    public void Service_registration_always_selects_the_protected_default_constructor()
    {
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddSingleton("an unrelated registered string");
        SafeUpload.Agent.Service.Program.ConfigureAuditStorage(services);
        using var provider = services.BuildServiceProvider();
        Assert.True(provider.GetRequiredService<LocalQueueAuditSink>().EnforcesProtectedStorage);
    }

    [Theory]
    [InlineData("recent")] [InlineData("matching")] [InlineData("pending")]
    [InlineData("overrides")] [InlineData("integrity")] [InlineData("temporaries")]
    [InlineData("classification")]
    public async Task Read_only_queries_do_not_create_a_missing_protected_directory(string operation)
    {
        var sink = Sink();
        switch (operation)
        {
            case "recent": Assert.Empty(await sink.ReadRecentAsync(10, default)); break;
            case "matching": Assert.Empty(await sink.ReadRecentMatchingAsync(10, _ => true, default)); break;
            case "pending": Assert.Empty(await sink.ReadPendingAsync(10, default)); break;
            case "overrides": Assert.Empty(await sink.ReadPendingOverridesAsync(10, default)); break;
            case "integrity": Assert.False((await sink.InspectIntegrityAsync(default)).FileExists); break;
            case "temporaries": Assert.False((await sink.InspectTemporaryFilesAsync(default)).DirectoryExists); break;
            case "classification": Assert.False((await sink.ClassifyTemporaryFilesAsync(default)).DirectoryExists); break;
        }
        Assert.False(Directory.Exists(Path.GetDirectoryName(FilePath)));
    }

    [Fact]
    public async Task First_write_and_restart_preserve_protected_events_overrides_and_receipts()
    {
        var item = Event(); var requested = Override(item.EventId);
        await Sink().WriteAsync(item, default);
        await Sink().RecordOverrideAsync(requested, default);
        var protection = Protection();
        var fileAcl = new FileInfo(FilePath).GetAccessControl();
        Assert.True(fileAcl.AreAccessRulesProtected);
        protection.Verify(fileAcl, directory: false);
        protection.Verify(new DirectoryInfo(Path.GetDirectoryName(FilePath)!).GetAccessControl(), directory: true);
        Assert.Equal(JsonSerializer.Serialize(item), JsonSerializer.Serialize(Assert.Single(await Sink().ReadPendingAsync(10, default))));
        Assert.Equal(requested, Assert.Single(await Sink().ReadPendingOverridesAsync(10, default)));
        await Sink().MarkDispatchedAsync([item.EventId], default);
        Assert.Empty(await Sink().ReadPendingAsync(10, default));
        Assert.Single(await Sink().ReadPendingOverridesAsync(10, default));
        await Sink().MarkOverridesDispatchedAsync([requested], default);
        Assert.Empty(await Sink().ReadPendingOverridesAsync(10, default));
        Assert.True(Assert.Single(await Sink().ReadRecentAsync(10, default)).Dispatched);
        Assert.Empty(Directory.GetFiles(Path.GetDirectoryName(FilePath)!, "*.tmp"));
        var confirmedAcl = new FileInfo(FilePath).GetAccessControl();
        protection.Verify(confirmedAcl, directory: false);
        Assert.True(confirmedAcl.AreAccessRulesProtected);
        Assert.Equal(3, confirmedAcl.GetAccessRules(true, true, typeof(SecurityIdentifier)).Count);
    }

    [Theory]
    [InlineData("event")] [InlineData("override")] [InlineData("recent")]
    [InlineData("matching")] [InlineData("pending")] [InlineData("overrides")]
    [InlineData("confirm")] [InlineData("confirm-override")] [InlineData("integrity")]
    public async Task Existing_exposed_queue_is_rejected_without_reading_rewriting_or_repairing_it(string operation)
    {
        var item = Event(); var requested = Override(item.EventId);
        var sink = Sink();
        await sink.WriteAsync(item, default);
        await sink.RecordOverrideAsync(requested, default);
        var security = new FileInfo(FilePath).GetAccessControl();
        security.AddAccessRule(new FileSystemAccessRule(_users, FileSystemRights.Read, AccessControlType.Allow));
        new FileInfo(FilePath).SetAccessControl(security);
        byte[] bytes = await File.ReadAllBytesAsync(FilePath);
        string descriptor = new FileInfo(FilePath).GetAccessControl().GetSecurityDescriptorSddlForm(AccessControlSections.All);
        await Assert.ThrowsAsync<UnauthorizedAccessException>(() => operation switch
        {
            "event" => sink.WriteAsync(Event(), default), "override" => sink.RecordOverrideAsync(requested, default),
            "recent" => sink.ReadRecentAsync(10, default), "matching" => sink.ReadRecentMatchingAsync(10, _ => true, default),
            "pending" => sink.ReadPendingAsync(10, default), "overrides" => sink.ReadPendingOverridesAsync(10, default),
            "confirm" => sink.MarkDispatchedAsync([item.EventId], default), "confirm-override" => sink.MarkOverridesDispatchedAsync([requested], default),
            _ => sink.InspectIntegrityAsync(default)
        });
        Assert.Equal(bytes, await File.ReadAllBytesAsync(FilePath));
        Assert.Equal(descriptor, new FileInfo(FilePath).GetAccessControl().GetSecurityDescriptorSddlForm(AccessControlSections.All));
        Assert.Empty(Directory.GetFiles(Path.GetDirectoryName(FilePath)!, "*.tmp"));
    }

    [Fact]
    public async Task Secure_legacy_inheritance_is_accepted_without_normalizing_its_descriptor()
    {
        var protection = Protection();
        protection.PrepareParent(create: true);
        var item = Event();
        await new LocalQueueAuditSink(FilePath).WriteAsync(item, default); // Prior writer inherited the protected parent's ACL.
        var acl = new FileInfo(FilePath).GetAccessControl();
        Assert.False(acl.AreAccessRulesProtected);
        string descriptor = acl.GetSecurityDescriptorSddlForm(AccessControlSections.All);
        Assert.Equal(JsonSerializer.Serialize(item), JsonSerializer.Serialize(Assert.Single(await Sink().ReadPendingAsync(10, default))));
        Assert.Equal(descriptor, new FileInfo(FilePath).GetAccessControl().GetSecurityDescriptorSddlForm(AccessControlSections.All));
        await Sink().MarkDispatchedAsync([item.EventId], default);
        protection.Verify(new FileInfo(FilePath).GetAccessControl(), directory: false);
        int ruleCount = new FileInfo(FilePath).GetAccessControl().GetAccessRules(true, true, typeof(SecurityIdentifier)).Count;
        // Repeated ReplaceFile merges must not accumulate ever more redundant grants.
        for (int i = 0; i < 3; i++)
        {
            await Sink().MarkDispatchedAsync([item.EventId], default);
            Assert.Equal(ruleCount, new FileInfo(FilePath).GetAccessControl().GetAccessRules(true, true, typeof(SecurityIdentifier)).Count);
        }
        await Sink().WriteAsync(Event(), default);
        Assert.Single(await Sink().ReadPendingAsync(10, default));
    }

    [Fact]
    public async Task Cancellation_after_private_temp_creation_preserves_data_and_allows_retry()
    {
        var item = Event();
        await Sink().WriteAsync(item, default);
        byte[] before = await File.ReadAllBytesAsync(FilePath);
        using var cancellation = new CancellationTokenSource();
        var protection = Protection();
        var sink = new LocalQueueAuditSink(FilePath, protection, temporary =>
        {
            var output = new FileInfo(temporary).Create(FileMode.CreateNew, FileSystemRights.FullControl,
                FileShare.None, 4096, FileOptions.Asynchronous, protection.FileSecurity());
            cancellation.Cancel();
            return output;
        });
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => sink.MarkDispatchedAsync([item.EventId], cancellation.Token));
        Assert.Equal(before, await File.ReadAllBytesAsync(FilePath));
        Assert.Empty(Directory.GetFiles(Path.GetDirectoryName(FilePath)!, "*.tmp"));
        await sink.MarkDispatchedAsync([item.EventId], default);
        Assert.Empty(await sink.ReadPendingAsync(10, default));
    }

    [Fact]
    public async Task Exposed_confirmation_temp_is_rejected_before_copy_and_only_owned_temp_is_removed()
    {
        var item = Event();
        await Sink().WriteAsync(item, default);
        byte[] before = await File.ReadAllBytesAsync(FilePath);
        string unrelated = FilePath + ".unrelated.tmp";
        await File.WriteAllTextAsync(unrelated, "synthetic evidence");
        var protection = Protection();
        var sink = new LocalQueueAuditSink(FilePath, protection, temporary =>
        {
            var acl = protection.FileSecurity();
            acl.AddAccessRule(new FileSystemAccessRule(_users, FileSystemRights.Read, AccessControlType.Allow));
            return new FileInfo(temporary).Create(FileMode.CreateNew, FileSystemRights.FullControl,
                FileShare.None, 4096, FileOptions.Asynchronous, acl);
        });
        await Assert.ThrowsAsync<UnauthorizedAccessException>(() => sink.MarkDispatchedAsync([item.EventId], default));
        Assert.Equal(before, await File.ReadAllBytesAsync(FilePath));
        Assert.Equal(new[] { unrelated }, Directory.GetFiles(Path.GetDirectoryName(FilePath)!, "*.tmp"));
        Assert.Equal("synthetic evidence", await File.ReadAllTextAsync(unrelated));
    }

    [Fact]
    public async Task Truncated_tail_does_not_swallow_the_next_protected_append_after_restart()
    {
        var first = Event(); var next = Event();
        await Sink().WriteAsync(first, default);
        await File.AppendAllTextAsync(FilePath, "{\"eventId\":");
        byte[] before = await File.ReadAllBytesAsync(FilePath);
        await Sink().WriteAsync(next, default);
        byte[] after = await File.ReadAllBytesAsync(FilePath);
        Assert.Equal(before, after.Take(before.Length).ToArray());
        Assert.Equal(new[] { first.EventId, next.EventId }, (await Sink().ReadPendingAsync(10, default)).Select(e => e.EventId));
        Protection().Verify(new FileInfo(FilePath).GetAccessControl(), directory: false);
    }

    [Fact]
    public async Task Descriptor_drift_during_confirmation_preserves_queue_bytes_and_removes_only_its_own_temp()
    {
        var item = Event();
        await Sink().WriteAsync(item, default);
        byte[] before = await File.ReadAllBytesAsync(FilePath);
        var protection = Protection();
        var sink = new LocalQueueAuditSink(FilePath, protection, temporary =>
        {
            var output = new FileInfo(temporary).Create(FileMode.CreateNew, FileSystemRights.FullControl,
                FileShare.None, 4096, FileOptions.Asynchronous, protection.FileSecurity());
            var acl = new FileInfo(FilePath).GetAccessControl();
            acl.AddAccessRule(new FileSystemAccessRule(_users, FileSystemRights.Read, AccessControlType.Allow));
            new FileInfo(FilePath).SetAccessControl(acl);
            return output;
        });
        await Assert.ThrowsAsync<UnauthorizedAccessException>(() => sink.MarkDispatchedAsync([item.EventId], default));
        Assert.Equal(before, await File.ReadAllBytesAsync(FilePath));
        Assert.Empty(Directory.GetFiles(Path.GetDirectoryName(FilePath)!, "*.tmp"));
    }

    [Fact]
    public async Task Unsafe_parent_is_not_repaired_and_health_does_not_claim_a_successful_empty_read()
    {
        var inner = Sink();
        await inner.WriteAsync(Event(), default);
        string parent = Path.GetDirectoryName(FilePath)!;
        var acl = new DirectoryInfo(parent).GetAccessControl();
        acl.AddAccessRule(new FileSystemAccessRule(_users, FileSystemRights.Modify,
            InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit, PropagationFlags.None, AccessControlType.Allow));
        new DirectoryInfo(parent).SetAccessControl(acl);
        string before = new DirectoryInfo(parent).GetAccessControl().GetSecurityDescriptorSddlForm(AccessControlSections.All);
        var health = new AuditQueueHealth();
        var monitored = new MonitoredAuditSink(inner, health, NullLogger<MonitoredAuditSink>.Instance);
        await Assert.ThrowsAsync<UnauthorizedAccessException>(() => monitored.ReadPendingAsync(10, default));
        Assert.True(health.Read().Degraded);
        Assert.Equal("access_denied", health.Read().Operations.Single(e => e.Operation == "ReadPending").FailureKind);
        await Assert.ThrowsAsync<UnauthorizedAccessException>(() => inner.InspectTemporaryFilesAsync(default));
        await Assert.ThrowsAsync<UnauthorizedAccessException>(() => inner.ClassifyTemporaryFilesAsync(default));
        Assert.Equal(before,
            new DirectoryInfo(parent).GetAccessControl().GetSecurityDescriptorSddlForm(AccessControlSections.All));
    }

    [Fact]
    public async Task Hard_linked_queue_is_rejected_without_modifying_either_name()
    {
        await Sink().WriteAsync(Event(), default);
        byte[] before = await File.ReadAllBytesAsync(FilePath);
        string alias = Path.Combine(_workspace.Root, "outside-alias.jsonl");
        if (!CreateHardLink(alias, FilePath, IntPtr.Zero)) throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error());
        await Assert.ThrowsAsync<UnauthorizedAccessException>(() => Sink().ReadPendingAsync(10, default));
        await Assert.ThrowsAsync<UnauthorizedAccessException>(() => Sink().WriteAsync(Event(), default));
        Assert.Equal(before, await File.ReadAllBytesAsync(FilePath));
        Assert.Equal(before, await File.ReadAllBytesAsync(alias));
    }

    [Theory]
    [InlineData(WellKnownSidType.LocalSystemSid)]
    [InlineData(WellKnownSidType.BuiltinAdministratorsSid)]
    public void Production_file_descriptor_accepts_only_the_declared_trusted_owners(WellKnownSidType owner)
    {
        var protection = new QueueStorageProtection(FilePath);
        var acl = protection.FileSecurity();
        acl.SetOwner(new SecurityIdentifier(owner, null));
        protection.Verify(acl, directory: false);
        Assert.Equal(2, acl.GetAccessRules(true, true, typeof(SecurityIdentifier)).Count);
    }

    [Theory]
    [InlineData("owner")] [InlineData("extra-ace")] [InlineData("deny")]
    [InlineData("rights")]
    public void Security_model_rejects_untrusted_owner_or_nonexact_grants_without_changing_the_descriptor(string mutation)
    {
        var protection = new QueueStorageProtection(FilePath); // Production policy; descriptor stays in memory.
        var acl = protection.FileSecurity();
        switch (mutation)
        {
            case "owner": acl.SetOwner(_users); break;
            case "extra-ace": acl.AddAccessRule(new FileSystemAccessRule(_users, FileSystemRights.Read, AccessControlType.Allow)); break;
            case "deny": acl.AddAccessRule(new FileSystemAccessRule(_users, FileSystemRights.Write, AccessControlType.Deny)); break;
            case "rights": acl.SetAccessRule(new FileSystemAccessRule(new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null), FileSystemRights.Read, AccessControlType.Allow)); break;
        }
        string before = acl.GetSecurityDescriptorSddlForm(AccessControlSections.All);
        Assert.Throws<UnauthorizedAccessException>(() => protection.Verify(acl, directory: false));
        Assert.Equal(before, acl.GetSecurityDescriptorSddlForm(AccessControlSections.All));
    }

    [DllImport("kernel32.dll", EntryPoint = "CreateHardLinkW", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CreateHardLink(string name, string existing, IntPtr security);
    public void Dispose() => _workspace.Dispose();
}
