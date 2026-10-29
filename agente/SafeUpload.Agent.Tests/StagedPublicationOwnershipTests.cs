using System.Security.AccessControl;
using System.Security.Principal;
using SafeUpload.Agent.Service.Interception;

namespace SafeUpload.Agent.Tests;

// M2 MVP metadata (owner 2026-10-29): the saving user owns a new file; an edit keeps the existing owner and DACL.
public sealed class StagedPublicationOwnershipTests : IDisposable
{
    private readonly TestWorkspace _workspace = new();
    public void Dispose() => _workspace.Dispose();

    private static readonly SecurityIdentifier Users = new(WellKnownSidType.BuiltinUsersSid, null);
    private static readonly SecurityIdentifier Guests = new(WellKnownSidType.BuiltinGuestsSid, null);

    [Fact]
    public void New_file_descriptor_names_the_owner_and_leaves_the_dacl_absent_never_null()
    {
        var descriptor = new RawSecurityDescriptor(StagedPublicationOwnership.NewFile(Users), 0);
        Assert.Equal(Users, descriptor.Owner);
        // Absent (inherit from the parent), not a NULL DACL that would grant everyone access.
        Assert.Equal(0, (int)(descriptor.ControlFlags & ControlFlags.DiscretionaryAclPresent));
        Assert.Null(descriptor.DiscretionaryAcl);
        Assert.Null(descriptor.SystemAcl);
    }

    [Fact]
    public void Preserve_keeps_owner_group_dacl_and_protection_and_drops_the_sacl()
    {
        var dacl = new RawAcl(GenericAcl.AclRevision, 1);
        dacl.InsertAce(0, new CommonAce(AceFlags.None, AceQualifier.AccessAllowed, 0x120089, Guests, false, null));
        var source = new RawSecurityDescriptor(ControlFlags.SelfRelative | ControlFlags.DiscretionaryAclPresent |
            ControlFlags.DiscretionaryAclProtected, Users, Guests, null, dacl);
        byte[] bytes = new byte[source.BinaryLength]; source.GetBinaryForm(bytes, 0);
        var kept = new RawSecurityDescriptor(StagedPublicationOwnership.Preserve(bytes), 0);
        Assert.Equal(Users, kept.Owner); Assert.Equal(Guests, kept.Group);
        Assert.NotEqual(0, (int)(kept.ControlFlags & ControlFlags.DiscretionaryAclProtected));
        var ace = Assert.IsType<CommonAce>(Assert.Single(kept.DiscretionaryAcl!));
        Assert.Equal(Guests, ace.SecurityIdentifier); Assert.Equal(0x120089, ace.AccessMask);
    }

    [Fact]
    public void Preserve_refuses_a_descriptor_without_a_dacl_instead_of_inventing_one()
    {
        var source = new RawSecurityDescriptor(ControlFlags.SelfRelative, Users, null, null, null);
        byte[] bytes = new byte[source.BinaryLength]; source.GetBinaryForm(bytes, 0);
        Assert.Throws<IOException>(() => StagedPublicationOwnership.Preserve(bytes));
    }

    [Fact]
    public void Native_new_file_is_owned_by_the_named_user_and_resolves_creator_owner_through_inheritance()
    {
        if (!OperatingSystem.IsWindows()) return;
        using var self = WindowsIdentity.GetCurrent();
        string parent = Path.Combine(_workspace.Root, "protected");
        var parentSecurity = new DirectorySecurity();
        parentSecurity.SetAccessRuleProtection(true, false);
        parentSecurity.AddAccessRule(new FileSystemAccessRule(self.User!, FileSystemRights.FullControl,
            InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit, PropagationFlags.None, AccessControlType.Allow));
        parentSecurity.AddAccessRule(new FileSystemAccessRule(new SecurityIdentifier(WellKnownSidType.CreatorOwnerSid, null),
            FileSystemRights.Modify, InheritanceFlags.ObjectInherit, PropagationFlags.InheritOnly, AccessControlType.Allow));
        new DirectoryInfo(parent).Create(parentSecurity);
        string path = Path.Combine(parent, "new.txt");
        // The test process owns itself, so no privilege is needed; the service names another user with SeRestorePrivilege.
        using (var output = StagedDestinationFile.CreateUnbuffered(path, StagedPublicationOwnership.NewFile(self.User!))) { }
        var stored = new FileInfo(path).GetAccessControl(AccessControlSections.Owner | AccessControlSections.Access);
        Assert.Equal(self.User, stored.GetOwner(typeof(SecurityIdentifier)));
        var rules = stored.GetAccessRules(true, true, typeof(SecurityIdentifier)).Cast<FileSystemAccessRule>().ToArray();
        Assert.All(rules, rule => Assert.True(rule.IsInherited));
        // CREATOR OWNER became the actual owner, as for a native create by that user.
        Assert.Contains(rules, rule => rule.IdentityReference.Equals(self.User) &&
            (rule.FileSystemRights & FileSystemRights.Modify) == FileSystemRights.Modify);
        Assert.DoesNotContain(rules, rule => rule.IdentityReference.Value == "S-1-3-0");
    }

    [Fact]
    public void Native_edit_keeps_the_existing_owner_and_explicit_ace_on_the_replacement()
    {
        if (!OperatingSystem.IsWindows()) return;
        using var self = WindowsIdentity.GetCurrent();
        string parent = Path.Combine(_workspace.Root, "edit");
        Directory.CreateDirectory(parent);
        string destination = Path.Combine(parent, "doc.txt");
        File.WriteAllText(destination, "old");
        var existing = new FileInfo(destination).GetAccessControl();
        existing.AddAccessRule(new FileSystemAccessRule(Guests, FileSystemRights.Read, AccessControlType.Allow));
        new FileInfo(destination).SetAccessControl(existing);
        byte[]? descriptor = StagedPublicationOwnership.Descriptor(destination, Users.Value);
        Assert.NotNull(descriptor);
        string replacement = Path.Combine(parent, "doc.pending");
        using (var output = StagedDestinationFile.CreateUnbuffered(replacement, descriptor)) { }
        var stored = new FileInfo(replacement).GetAccessControl(AccessControlSections.Owner | AccessControlSections.Access);
        // The existing owner wins over the requestor for an edit.
        Assert.Equal(self.User, stored.GetOwner(typeof(SecurityIdentifier)));
        Assert.Contains(stored.GetAccessRules(true, false, typeof(SecurityIdentifier)).Cast<FileSystemAccessRule>(),
            rule => rule.IdentityReference.Equals(Guests) && (rule.FileSystemRights & FileSystemRights.Read) == FileSystemRights.Read);
    }
}
