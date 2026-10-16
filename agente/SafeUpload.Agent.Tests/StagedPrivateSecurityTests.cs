using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Principal;
using SafeUpload.Agent.Service.Interception;

namespace SafeUpload.Agent.Tests;

public sealed class StagedPrivateSecurityTests : IDisposable
{
    private readonly TestWorkspace _workspace = new();
    public void Dispose() => _workspace.Dispose();

    [Fact]
    public void Startup_acl_reads_require_no_data_access_and_coexist_with_exclusive_backing_handles()
    {
        if (!OperatingSystem.IsWindows()) return;
        string path = _workspace.WriteText("retained.stage", "private bytes");
        var expected = new FileInfo(path).GetAccessControl();
        using var backing = new FileStream(path, FileMode.Open, FileAccess.ReadWrite, FileShare.None);
        var actual = StagedPrivateSecurity.ReadFile(path);
        const AccessControlSections sections = AccessControlSections.Owner | AccessControlSections.Group | AccessControlSections.Access;
        Assert.Equal(expected.GetSecurityDescriptorSddlForm(sections), actual.GetSecurityDescriptorSddlForm(sections));
        Assert.Equal(backing.Length, new FileInfo(path).Length);
        Assert.NotNull(StagedPrivateSecurity.ReadDirectory(_workspace.Root).GetOwner(typeof(SecurityIdentifier)));
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void Startup_acl_reads_reject_reparse_and_hard_link_files_without_touching_the_target(bool hardLink)
    {
        if (!OperatingSystem.IsWindows()) return;
        string target = _workspace.WriteText("outside.txt", "unchanged");
        string link = Path.Combine(_workspace.Root, "private.stage");
        if (hardLink) Assert.True(CreateHardLink(link, target, IntPtr.Zero));
        else File.CreateSymbolicLink(link, target);
        Assert.Throws<IOException>(() => StagedPrivateSecurity.ReadFile(link));
        Assert.Equal("unchanged", File.ReadAllText(target).TrimStart('\uFEFF'));
    }

    [Fact]
    public void Startup_acl_reads_reject_a_directory_junction_and_wrong_object_type()
    {
        if (!OperatingSystem.IsWindows()) return;
        string link = Path.Combine(_workspace.Root, "linked-directory");
        Directory.CreateSymbolicLink(link, _workspace.Root);
        try { Assert.Throws<IOException>(() => StagedPrivateSecurity.ReadDirectory(link)); }
        finally { Directory.Delete(link); }
        Assert.Throws<IOException>(() => StagedPrivateSecurity.ReadFile(_workspace.Root));
        Assert.Throws<IOException>(() => StagedPrivateSecurity.ReadDirectory(_workspace.WriteText("file", "x")));
    }

    [Fact]
    public async Task Existing_private_journal_reinitializes_without_losing_its_manifest_or_acl()
    {
        if (!OperatingSystem.IsWindows()) return;
        string directory = Path.Combine(_workspace.Root, "journal");
        var journal = new StagedTransferJournal(directory);
        var transfer = new StagedTransfer(Guid.NewGuid(),
            Path.Combine(_workspace.Root, "private.stage"), Path.Combine(_workspace.Root, "public.txt"),
            SafeUpload.Agent.Core.Domain.DestinationKind.RemovableDrive, "notepad.exe", 123, 1);
        File.WriteAllText(transfer.StagePath, "private bytes");
        await journal.CreateAsync(transfer, CancellationToken.None);
        string manifest = Path.Combine(directory, transfer.TransferId.ToString("N") + ".json");
        byte[] original = File.ReadAllBytes(manifest);
        var acl = StagedPrivateSecurity.ReadDirectory(directory).GetSecurityDescriptorBinaryForm();
        var restarted = new StagedTransferJournal(directory);
        Assert.Equal(transfer, (await restarted.ReadAsync(transfer.TransferId, CancellationToken.None)).Transfer);
        Assert.Equal(original, File.ReadAllBytes(manifest));
        Assert.Equal(acl, StagedPrivateSecurity.ReadDirectory(directory).GetSecurityDescriptorBinaryForm());
    }

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CreateHardLink(string link, string existing, IntPtr reserved);
}
