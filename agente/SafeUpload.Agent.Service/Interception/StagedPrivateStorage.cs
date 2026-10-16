using System.Security.AccessControl;
using System.Security.Principal;

namespace SafeUpload.Agent.Service.Interception;

// Creation, not ACL recovery. Existing objects remain subject to the same
// custody checks; never normalize an inherited/untrusted descriptor to pass.
internal static class StagedPrivateStorage
{
    internal static void CreateDirectory(string path)
    {
        path = Path.GetFullPath(path);
        for (string? ancestor = path; ancestor is not null; ancestor = Path.GetDirectoryName(ancestor))
            if ((Directory.Exists(ancestor) || File.Exists(ancestor)) &&
                (File.GetAttributes(ancestor) & FileAttributes.ReparsePoint) != 0)
                throw new IOException("Private storage path contains a reparse point.");
        if (!Directory.Exists(path))
        {
            // Only this leaf receives a validated descriptor. Do not silently
            // create an inherited, unvalidated chain of production ancestors.
            string? parent = Path.GetDirectoryName(path);
            if (parent is null || !Directory.Exists(parent))
                throw new DirectoryNotFoundException("Private storage requires an existing parent directory.");
            if (OperatingSystem.IsWindows())
                new DirectoryInfo(path).Create(DirectorySecurity());
            else Directory.CreateDirectory(path);
        }
        if (!OperatingSystem.IsWindows()) return;
        using var identity = WindowsIdentity.GetCurrent();
        var owner = identity.User ?? throw new UnauthorizedAccessException("Missing private storage owner.");
        var security = StagedPrivateSecurity.ReadDirectory(path);
        if (owner.IsWellKnown(WellKnownSidType.LocalSystemSid))
            StagedTransferJournal.RequireTrustedOwner(security, "private storage directory");
        StagedTransferJournal.RequireNoUntrustedWriters(security, owner);
        if (!security.AreAccessRulesProtected)
            throw new UnauthorizedAccessException("Private storage directory DACL is not protected.");
    }

    internal static FileStream CreateFile(string path) => OperatingSystem.IsWindows()
        ? new FileInfo(path).Create(FileMode.CreateNew, FileSystemRights.FullControl,
            FileShare.None, 4096, FileOptions.WriteThrough, FileSecurity())
        : new FileStream(path, FileMode.CreateNew, FileAccess.ReadWrite, FileShare.None, 4096, FileOptions.WriteThrough);

    private static DirectorySecurity DirectorySecurity()
    {
        var security = new DirectorySecurity();
        Configure(security, directory: true);
        return security;
    }

    internal static FileSecurity FileSecurity()
    {
        var security = new FileSecurity();
        Configure(security, directory: false);
        return security;
    }

    private static void Configure(FileSystemSecurity security, bool directory)
    {
        using var identity = WindowsIdentity.GetCurrent();
        var owner = identity.User ?? throw new UnauthorizedAccessException("Missing private storage owner.");
        security.SetAccessRuleProtection(true, false);
        security.SetOwner(owner);
        StagedTransferJournal.AddPrivateRules(security, owner, inherit: directory);
    }
}
