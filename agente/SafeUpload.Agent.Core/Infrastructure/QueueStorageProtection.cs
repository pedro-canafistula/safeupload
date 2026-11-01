using System.Runtime.Versioning;
using System.Security.AccessControl;
using System.Security.Principal;

namespace SafeUpload.Agent.Core.Infrastructure;

/// <summary>Trust policy for the service queue. Never repairs an existing descriptor or replaces untrusted data.</summary>
[SupportedOSPlatform("windows")]
internal sealed class QueueStorageProtection
{
    private readonly SecurityIdentifier[] _trusted;
    private readonly SecurityIdentifier _creator;
    internal string FilePath { get; }

    internal QueueStorageProtection(string file) : this(file, null) { }

    // Owned temporary test trees only. Production always has exactly SYSTEM/Administrators.
    internal QueueStorageProtection(string file, SecurityIdentifier? testOwner)
    {
        FilePath = Path.GetFullPath(file);
        var system = new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null);
        var administrators = new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null);
        _creator = testOwner ?? system;
        _trusted = new[] { system, administrators, _creator }.Distinct().ToArray();
    }

    internal bool PrepareParent(bool create)
    {
        string directory = Path.GetDirectoryName(FilePath)!;
        // No links in any existing ancestor; an inaccessible ancestor is an error, not absence.
        bool exists = false;
        for (string? path = directory; path is not null; path = Path.GetDirectoryName(path))
        {
            try
            {
                var attributes = File.GetAttributes(path);
                if ((attributes & FileAttributes.ReparsePoint) != 0 || (attributes & FileAttributes.Directory) == 0)
                    throw Rejected();
                if (path == directory) exists = true;
            }
            catch (FileNotFoundException) { }
            catch (DirectoryNotFoundException) { }
        }
        if (!exists)
        {
            if (!create) return false;
            try { new DirectoryInfo(directory).Create(DirectorySecurity()); }
            catch (IOException) when (Directory.Exists(directory)) { /* Verify the concurrent creator below. */ }
        }
        RejectLeaf(File.GetAttributes(directory), directory: true);
        Verify(new DirectoryInfo(directory).GetAccessControl(), directory: true);
        return true;
    }

    internal bool QueueExists()
    {
        if (!PrepareParent(create: false)) return false;
        try { RejectLeaf(File.GetAttributes(FilePath), directory: false); return true; }
        catch (FileNotFoundException) { return false; }
        catch (DirectoryNotFoundException) { return false; }
    }

    internal FileSecurity FileSecurity()
    {
        var security = new FileSecurity();
        security.SetAccessRuleProtection(true, false);
        security.SetOwner(_creator);
        foreach (var sid in _trusted)
            security.AddAccessRule(new FileSystemAccessRule(sid, FileSystemRights.FullControl, AccessControlType.Allow));
        return security;
    }

    private DirectorySecurity DirectorySecurity()
    {
        var security = new DirectorySecurity();
        security.SetAccessRuleProtection(true, false);
        security.SetOwner(_creator);
        foreach (var sid in _trusted)
            security.AddAccessRule(new FileSystemAccessRule(sid, FileSystemRights.FullControl,
                InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit, PropagationFlags.None, AccessControlType.Allow));
        return security;
    }

    internal void Verify(FileSystemSecurity security, bool directory)
    {
        if (security.GetOwner(typeof(SecurityIdentifier)) is not SecurityIdentifier owner || !_trusted.Contains(owner) ||
            directory && !security.AreAccessRulesProtected) throw Rejected();
        var rules = security.GetAccessRules(true, true, typeof(SecurityIdentifier));
        if (directory && rules.Count != _trusted.Length) throw Rejected();
        var seen = new HashSet<SecurityIdentifier>();
        var inheritance = directory ? InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit : InheritanceFlags.None;
        foreach (FileSystemAccessRule rule in rules)
        {
            if (rule.IdentityReference is not SecurityIdentifier sid || !_trusted.Contains(sid) ||
                rule.AccessControlType != AccessControlType.Allow || rule.FileSystemRights != FileSystemRights.FullControl ||
                rule.InheritanceFlags != inheritance || rule.PropagationFlags != PropagationFlags.None || directory && rule.IsInherited)
                throw Rejected();
            if (!seen.Add(sid) && directory) throw Rejected();
        }
        if (!seen.SetEquals(_trusted)) throw Rejected();
        // Legacy queue files may inherit only these trusted ACEs from the verified protected directory.
        // Accept them without changing their ACL; new files are protected at creation.
        // ReplaceFile may retain both explicit and inherited identical trusted grants.
        // These redundant file ACEs add no principal or permission and remain acceptable.
    }

    internal static void RejectLeaf(FileAttributes attributes, bool directory)
    {
        if ((attributes & FileAttributes.ReparsePoint) != 0 || ((attributes & FileAttributes.Directory) != 0) != directory)
            throw Rejected();
    }

    internal static UnauthorizedAccessException Rejected() =>
        new("Audit queue storage is not trusted. Administrative review required.");
}
