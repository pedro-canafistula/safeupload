using System.Security.AccessControl;
using System.Security.Principal;
using SafeUpload.Agent.Service.Interception;

namespace SafeUpload.Agent.Tests;

[Trait("Category", "NativeWindows")]
public sealed class StagedPrivateStorageNativeTests : IDisposable
{
    private readonly TestWorkspace _workspace = new();
    public void Dispose() => _workspace.Dispose();

    [Fact]
    public void Private_creation_excludes_inherited_mutators_without_changing_the_parent_or_existing_unsafe_objects()
    {
        using var identity = WindowsIdentity.GetCurrent(); var owner = identity.User!;
        var directory = new DirectoryInfo(_workspace.Root);
        var broad = directory.GetAccessControl();
        broad.AddAccessRule(new FileSystemAccessRule(new SecurityIdentifier(WellKnownSidType.WorldSid, null),
            FileSystemRights.Modify, InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit,
            PropagationFlags.None, AccessControlType.Allow));
        directory.SetAccessControl(broad);
        byte[] parent = directory.GetAccessControl().GetSecurityDescriptorBinaryForm();
        string missingParent = Path.Combine(_workspace.Root, "missing-parent");
        Assert.Throws<DirectoryNotFoundException>(() => StagedPrivateStorage.CreateDirectory(Path.Combine(missingParent, "private")));
        Assert.False(Directory.Exists(missingParent));
        string stage = Path.Combine(_workspace.Root, "private");
        StagedPrivateStorage.CreateDirectory(stage);
        RequirePrivate(StagedPrivateSecurity.ReadDirectory(stage), owner);
        string path = Path.Combine(stage, "metadata");
        using (var output = StagedPrivateStorage.CreateFile(path))
        {
            output.WriteByte(42); output.Flush(true);
            RequirePrivate(StagedPrivateSecurity.ReadFile(path), owner); // READ_CONTROL despite exclusive data sharing.
            Assert.Throws<IOException>(() => File.OpenRead(path));
        }
        Assert.Equal(new byte[] { 42 }, File.ReadAllBytes(path));
        byte[] fileSecurity = StagedPrivateSecurity.ReadFile(path).GetSecurityDescriptorBinaryForm();
        Assert.Throws<IOException>(() => StagedPrivateStorage.CreateFile(path));
        Assert.Equal(new byte[] { 42 }, File.ReadAllBytes(path));
        Assert.Equal(fileSecurity, StagedPrivateSecurity.ReadFile(path).GetSecurityDescriptorBinaryForm());
        string unsafeRoot = Path.Combine(_workspace.Root, "inherited"); Directory.CreateDirectory(unsafeRoot);
        byte[] existing = new DirectoryInfo(unsafeRoot).GetAccessControl().GetSecurityDescriptorBinaryForm();
        Assert.Throws<UnauthorizedAccessException>(() => StagedPrivateStorage.CreateDirectory(unsafeRoot));
        Assert.Throws<UnauthorizedAccessException>(() => new StagedSpaceBudget(unsafeRoot,
            new(true, 512L << 20, 128L << 20, 0), () => 2L << 30));
        Assert.Equal(existing, new DirectoryInfo(unsafeRoot).GetAccessControl().GetSecurityDescriptorBinaryForm());
        Assert.Equal(parent, directory.GetAccessControl().GetSecurityDescriptorBinaryForm());
    }

    [Fact]
    public async Task Budget_creates_root_ledger_and_grant_with_private_descriptors_before_reopen_or_restart()
    {
        const string sid = "S-1-5-21-100";
        string root = Path.Combine(_workspace.Root, "new-stage"); Guid id = Guid.NewGuid();
        var options = new StagedSpaceOptions(true, 512L << 20, 128L << 20, 0);
        var budget = new StagedSpaceBudget(root, options, () => 2L << 30);
        using var identity = WindowsIdentity.GetCurrent();
        RequirePrivate(StagedPrivateSecurity.ReadDirectory(root), identity.User!);
        RequirePrivate(StagedPrivateSecurity.ReadDirectory(Path.Combine(root, ".space-reservations")), identity.User!);
        string stage = Path.Combine(root, id.ToString("N") + ".txt");
        budget.Reserve(id, sid, stage);
        using (var file = StagedPrivateStorage.CreateFile(stage)) { file.WriteByte(42); file.Flush(true); }
        using (var file = StagedStageFile.Open(stage)) budget.RecordStage(id, stage, file.Identity);
        var journal = new StagedTransferJournal(Path.Combine(_workspace.Root, "journal"));
        var transfer = new StagedTransfer(id, stage, Path.Combine(_workspace.Root, "public.txt"),
            SafeUpload.Agent.Core.Domain.DestinationKind.Cloud, "fixture", 17, 1) { RequestorSid = sid };
        budget.Bind(await journal.CreateAsync(transfer, default));
        RequirePrivate(StagedPrivateSecurity.ReadFile(stage + ".space"), identity.User!);
        RequirePrivate(StagedPrivateSecurity.ReadFile(Path.Combine(root, ".space-reservations", id.ToString("N") + ".json")), identity.User!);
        var restarted = new StagedSpaceBudget(root, options, () => 2L << 30);
        Assert.True(restarted.ContentReservationPending(id));
        Assert.False(File.Exists(transfer.DestinationPath));
    }

    private static void RequirePrivate(FileSystemSecurity security, SecurityIdentifier owner)
    {
        Assert.True(security.AreAccessRulesProtected);
        Assert.Equal(owner, security.GetOwner(typeof(SecurityIdentifier)));
        StagedTransferJournal.RequireNoUntrustedWriters(security, owner);
        var rules = security.GetAccessRules(true, true, typeof(SecurityIdentifier)).Cast<FileSystemAccessRule>().ToArray();
        var expectedSids = new[] { owner.Value, "S-1-5-18", "S-1-5-32-544" }.Distinct().Order().ToArray();
        Assert.Equal(expectedSids, rules.Select(rule => rule.IdentityReference.Value).Distinct().Order().ToArray());
        Assert.All(rules, rule => Assert.False(rule.IsInherited));
        Assert.All(rules, rule => Assert.Equal(FileSystemRights.FullControl, rule.FileSystemRights));
        Assert.All(rules, rule => Assert.Equal(AccessControlType.Allow, rule.AccessControlType));
        Assert.All(rules, rule => Assert.Equal(PropagationFlags.None, rule.PropagationFlags));
        var inheritance = security is DirectorySecurity
            ? InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit : InheritanceFlags.None;
        Assert.All(rules, rule => Assert.Equal(inheritance, rule.InheritanceFlags));
    }
}
