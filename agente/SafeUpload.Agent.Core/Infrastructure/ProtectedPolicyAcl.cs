using System.Security.AccessControl;
using System.Security.Principal;

namespace SafeUpload.Agent.Core.Infrastructure;

/// <summary>
/// Enforces the policy file's machine-trust boundary before any JSON is read.
/// Local administrators and SYSTEM are trusted by the MVP owner decision, so
/// they receive full control. Standard users receive no ACE; protected DACLs
/// prevent inherited write access from ProgramData or a caller-created parent.
/// Existing mismatches are refused instead of repaired and immediately loaded:
/// a file exposed to a standard user may already contain a weakened policy.
/// </summary>
internal static class ProtectedPolicyAcl
{
    private static readonly SecurityIdentifier SystemSid =
        new(WellKnownSidType.LocalSystemSid, null);
    private static readonly SecurityIdentifier AdministratorsSid =
        new(WellKnownSidType.BuiltinAdministratorsSid, null);

    public static void EnsureDirectory(string policyFile)
    {
        string directory = Path.GetDirectoryName(Path.GetFullPath(policyFile))
            ?? throw new PolicyFileAclRejectedException("Policy file has no parent directory.");

        RejectReparseAncestors(directory);
        if (!Directory.Exists(directory))
        {
            try
            {
                new DirectoryInfo(directory).Create(CreateDirectorySecurity());
            }
            catch (IOException) when (Directory.Exists(directory))
            {
                // A concurrent creator is accepted only after exact read-back below.
            }
        }

        if (!Directory.Exists(directory) ||
            (File.GetAttributes(directory) & FileAttributes.ReparsePoint) != 0)
        {
            throw new PolicyFileAclRejectedException("SafeUpload policy directory is missing or is a reparse point.");
        }

        Verify(new DirectoryInfo(directory).GetAccessControl(), directory: true, "SafeUpload policy directory");
    }

    public static void VerifyPolicyFile(string policyFile)
    {
        string fullPath = Path.GetFullPath(policyFile);
        FileAttributes attributes;
        try
        {
            attributes = File.GetAttributes(fullPath);
        }
        catch (FileNotFoundException ex)
        {
            throw new PolicyFileAclRejectedException("SafeUpload policy file disappeared before ACL verification.", ex);
        }
        catch (DirectoryNotFoundException ex)
        {
            throw new PolicyFileAclRejectedException("SafeUpload policy file parent disappeared before ACL verification.", ex);
        }

        if ((attributes & FileAttributes.Directory) != 0 || (attributes & FileAttributes.ReparsePoint) != 0)
        {
            throw new PolicyFileAclRejectedException("SafeUpload policy file is a directory or reparse point.");
        }

        Verify(new FileInfo(fullPath).GetAccessControl(), directory: false, "policy.json");
    }

    public static FileSecurity CreatePolicyFileSecurity()
    {
        var security = new FileSecurity();
        security.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);
        security.SetOwner(SystemSid);
        security.AddAccessRule(new FileSystemAccessRule(SystemSid, FileSystemRights.FullControl,
            InheritanceFlags.None, PropagationFlags.None, AccessControlType.Allow));
        security.AddAccessRule(new FileSystemAccessRule(AdministratorsSid, FileSystemRights.FullControl,
            InheritanceFlags.None, PropagationFlags.None, AccessControlType.Allow));
        return security;
    }

    private static DirectorySecurity CreateDirectorySecurity()
    {
        var security = new DirectorySecurity();
        security.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);
        security.SetOwner(SystemSid);
        const InheritanceFlags children = InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit;
        security.AddAccessRule(new FileSystemAccessRule(SystemSid, FileSystemRights.FullControl,
            children, PropagationFlags.None, AccessControlType.Allow));
        security.AddAccessRule(new FileSystemAccessRule(AdministratorsSid, FileSystemRights.FullControl,
            children, PropagationFlags.None, AccessControlType.Allow));
        return security;
    }

    private static void Verify(FileSystemSecurity security, bool directory, string objectName)
    {
        SecurityIdentifier? owner = security.GetOwner(typeof(SecurityIdentifier)) as SecurityIdentifier;
        if (owner is null || (!SystemSid.Equals(owner) && !AdministratorsSid.Equals(owner)) ||
            !security.AreAccessRulesProtected)
        {
            throw new PolicyFileAclRejectedException($"{objectName} owner or protected DACL is invalid.");
        }

        AuthorizationRuleCollection rules = security.GetAccessRules(
            includeExplicit: true, includeInherited: true, targetType: typeof(SecurityIdentifier));
        if (rules.Count != 2)
        {
            throw new PolicyFileAclRejectedException($"{objectName} DACL must contain only SYSTEM and Administrators.");
        }

        bool system = false;
        bool administrators = false;
        InheritanceFlags expectedInheritance = directory
            ? InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit
            : InheritanceFlags.None;
        foreach (FileSystemAccessRule rule in rules)
        {
            if (rule.AccessControlType != AccessControlType.Allow || rule.IsInherited ||
                rule.FileSystemRights != FileSystemRights.FullControl ||
                rule.InheritanceFlags != expectedInheritance || rule.PropagationFlags != PropagationFlags.None ||
                rule.IdentityReference is not SecurityIdentifier sid)
            {
                throw new PolicyFileAclRejectedException($"{objectName} contains a non-exact or inherited ACE.");
            }

            if (SystemSid.Equals(sid) && !system) system = true;
            else if (AdministratorsSid.Equals(sid) && !administrators) administrators = true;
            else throw new PolicyFileAclRejectedException($"{objectName} contains an unexpected trustee.");
        }

        if (!system || !administrators)
        {
            throw new PolicyFileAclRejectedException($"{objectName} is missing a required trustee.");
        }
    }

    private static void RejectReparseAncestors(string path)
    {
        for (string? cursor = path; cursor is not null; cursor = Path.GetDirectoryName(cursor))
        {
            if (!Directory.Exists(cursor)) continue;
            if ((File.GetAttributes(cursor) & FileAttributes.ReparsePoint) != 0)
            {
                throw new PolicyFileAclRejectedException("SafeUpload policy path contains a reparse point.");
            }
        }
    }
}

internal sealed class PolicyFileAclRejectedException : UnauthorizedAccessException
{
    public PolicyFileAclRejectedException(string message) : base(message) { }
    public PolicyFileAclRejectedException(string message, Exception innerException) : base(message, innerException) { }
}
