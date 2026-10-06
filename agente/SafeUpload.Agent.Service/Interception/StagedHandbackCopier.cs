using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text;
using Microsoft.Win32;
using Microsoft.Win32.SafeHandles;
using SafeUpload.Agent.Core.Application;

namespace SafeUpload.Agent.Service.Interception;

public interface IStagedHandbackCopier
{
    Task<string> CopyVerifiedAsync(StagedTransfer transfer, FileStream sealedSnapshot,
        long length, string sha256Hex, CancellationToken token);

    /// <summary>Verifies and locks a committed copy against writes and deletion.</summary>
    IDisposable OpenVerifiedReadLease(StagedTransfer transfer, string handbackPath,
        long length, string sha256Hex);

    /// <summary>Deletes only this transfer's constrained service temporary, if present.</summary>
    void CleanupUncommittedTemporary(StagedTransfer transfer);
}

internal interface IStagedHandbackEnvironment
{
    void RequireServiceIdentity();
    SecurityIdentifier ResolveUser(uint? sessionId);
    string ResolveProfilePath(SecurityIdentifier userSid);
    IEnumerable<string> KnownSyncRoots(string profile, SecurityIdentifier userSid);
}

/// <summary>
/// Copies a blocked immutable snapshot into the owning user's profile using
/// relative NT opens. Every opened directory is checked before it is used as
/// the RootDirectory for the next operation.
/// </summary>
internal sealed class StagedHandbackCopier : IStagedHandbackCopier
{
    private readonly IPolicyStore _policyStore;
    private readonly IStagedHandbackEnvironment _environment;
    private const uint GenericRead = 0x80000000;
    private const uint GenericWrite = 0x40000000;
    private const uint DeleteAccess = 0x00010000;
    private const uint ReadControl = 0x00020000;
    private const uint WriteOwnerAccess = 0x00080000;
    private const uint FileReadAttributes = 0x00000080;
    private const uint FileTraverse = 0x00000020;
    private const uint Synchronize = 0x00100000;
    private const uint FileGenericRead = 0x00120089;
    private const uint ShareRead = 0x00000001;
    private const uint ShareReadWrite = 0x00000003;
    private const uint OpenExisting = 1; // NT FILE_OPEN (NtCreateFile CreateDisposition)
    private const uint Win32OpenExisting = 3; // CreateFile OPEN_EXISTING; 1 there is CREATE_NEW
    private const uint CreateNew = 2;
    private const uint DirectoryFile = 0x00000001;
    private const uint NonDirectoryFile = 0x00000040;
    private const uint SynchronousNonAlert = 0x00000020;
    private const uint OpenReparsePoint = 0x00200000;
    private const uint FileAttributeDirectory = 0x00000010;
    private const uint FileAttributeReparsePoint = 0x00000400;
    private const uint BackupIntent = 0x00004000;
    private const uint FileFlagBackupSemantics = 0x02000000;
    private const int FileRenameInfoEx = 22;
    private const int FileRenameInformationExClass = 65;
    private const int FileDispositionInfo = 4;
    private const int FileDispositionInfoEx = 21;
    private const uint FileRenameNoReplace = 0;
    private const uint FileDispositionDelete = 0x00000001;
    private const int SecurityInformationOwner = 0x00000001;
    private const int SecurityInformationDacl = 0x00000004;
    private const int SeFileObject = 1;
    private const int TokenUser = 1;
    private const int TokenSessionId = 12;
    private const int ErrorInsufficientBuffer = 122;
    private const int ErrorFileNotFound = 2;
    private const int ErrorPathNotFound = 3;

    public StagedHandbackCopier(IPolicyStore policyStore)
        : this(policyStore, new WindowsHandbackEnvironment()) { }

    internal StagedHandbackCopier(IPolicyStore policyStore,
        IStagedHandbackEnvironment environment)
    {
        _policyStore = policyStore ?? throw new ArgumentNullException(nameof(policyStore));
        _environment = environment ?? throw new ArgumentNullException(nameof(environment));
    }

    public async Task<string> CopyVerifiedAsync(StagedTransfer transfer, FileStream sealedSnapshot,
        long length, string sha256Hex, CancellationToken token)
    {
        ArgumentNullException.ThrowIfNull(transfer);
        ArgumentNullException.ThrowIfNull(sealedSnapshot);
        if (!OperatingSystem.IsWindows()) throw new PlatformNotSupportedException(
            "Staged hand-back requires Windows handle-relative file operations.");
        if (length < 0 || sha256Hex.Length != 64 || !sha256Hex.All(Uri.IsHexDigit))
            throw new ArgumentException("The sealed snapshot evidence is invalid.");

        _environment.RequireServiceIdentity();
        SecurityIdentifier userSid = RequireBoundSessionUser(transfer);
        string profile = _environment.ResolveProfilePath(userSid);
        string directoryPath = Path.Combine(profile, "SafeUpload", "_bloqueados");

        sealedSnapshot.Position = 0;
        string sourceDigest = Convert.ToHexString(
            await System.Security.Cryptography.SHA256.HashDataAsync(sealedSnapshot, token).ConfigureAwait(false));
        if (sealedSnapshot.Length != length || !string.Equals(sourceDigest, sha256Hex,
                StringComparison.OrdinalIgnoreCase))
            throw new IOException("The staged snapshot no longer matches its sealed digest.");
        sealedSnapshot.Position = 0;

        HashSet<DirectoryIdentity> registeredRoots = await EnsureOutsideProtectedAndSyncedTreesAsync(
            directoryPath, profile, userSid, token)
            .ConfigureAwait(false);
        string extension = SafeExtension(transfer.DestinationPath);
        string leaf = transfer.TransferId.ToString("N") + extension;
        string verifiedPath = Path.Combine(directoryPath, leaf);
        if (verifiedPath.Length > 511)
            throw new IOException("The verified hand-back path exceeds the journal path limit.");
        using VerifiedDirectory directory = OpenBlockedDirectory(profile, userSid, createDirectories: true);
        EnsureDestinationAncestorsOutsideRegisteredRoots(directory, registeredRoots);

        using (SafeFileHandle? existing = TryOpenRelativeFile(directory.Handle, leaf, GenericRead |
                   FileReadAttributes | ReadControl | Synchronize, ShareRead))
        {
            if (existing is not null)
            {
                VerifyFile(existing, userSid, length, sha256Hex);
                _ = RequireBoundSessionUser(transfer);
                return verifiedPath;
            }
        }

        string temporary = ".safeupload-" + transfer.TransferId.ToString("N") + ".tmp";
        DeleteExistingServiceTemporary(directory.Handle, temporary, userSid);
        SafeFileHandle temporaryHandle = CreateRelativeFile(directory.Handle, temporary,
            userSid, GenericRead | GenericWrite | DeleteAccess | FileReadAttributes | ReadControl |
            Synchronize);
        bool committed = false;
        bool deleteMarked = false;
        void DeleteUncommittedTemporary()
        {
            if (!committed && !deleteMarked && !temporaryHandle.IsClosed)
            {
                MarkDeleteByHandle(temporaryHandle);
                deleteMarked = true;
            }
        }
        try
        {
            if (!DuplicateHandle(GetCurrentProcess(), temporaryHandle, GetCurrentProcess(),
                    out SafeFileHandle outputHandle, 0, false, 2))
                throw new IOException("Could not open the hand-back output stream.",
                    new Win32Exception(Marshal.GetLastWin32Error()));
            using (outputHandle)
            using (var output = new FileStream(outputHandle, FileAccess.ReadWrite,
                       64 * 1024, isAsync: false))
            {
                try
                {
                    await sealedSnapshot.CopyToAsync(output, 64 * 1024, token).ConfigureAwait(false);
                    output.Flush(flushToDisk: true);
                    VerifyFile(output.SafeFileHandle, userSid, length, sha256Hex);
                    _ = RequireBoundSessionUser(transfer);
                    RenameRelativeNoReplace(output.SafeFileHandle, directory.Handle, leaf);
                    VerifyFile(output.SafeFileHandle, userSid, length, sha256Hex);
                    _ = RequireBoundSessionUser(transfer);
                    committed = true;
                }
                finally { DeleteUncommittedTemporary(); }
            }
        }
        finally
        {
            try { DeleteUncommittedTemporary(); }
            finally { temporaryHandle.Dispose(); }
        }

        // Reopen the committed name through the same verified directory handle.
        using SafeFileHandle committedFile = OpenRelativeFile(directory.Handle, leaf,
            GenericRead | FileReadAttributes | ReadControl | Synchronize, ShareRead);
        VerifyFile(committedFile, userSid, length, sha256Hex);
        return verifiedPath;
    }

    public IDisposable OpenVerifiedReadLease(StagedTransfer transfer, string handbackPath,
        long length, string sha256Hex)
    {
        ArgumentNullException.ThrowIfNull(transfer);
        if (!OperatingSystem.IsWindows()) throw new PlatformNotSupportedException(
            "Staged hand-back requires Windows handle-relative file operations.");
        _environment.RequireServiceIdentity();
        SecurityIdentifier userSid = RequireBoundSessionUser(transfer);
        string profile = _environment.ResolveProfilePath(userSid);
        string leaf = transfer.TransferId.ToString("N") + SafeExtension(transfer.DestinationPath);
        string expectedPath = Path.Combine(profile, "SafeUpload", "_bloqueados", leaf);
        if (!string.Equals(Path.GetFullPath(handbackPath), Path.GetFullPath(expectedPath),
                StringComparison.OrdinalIgnoreCase))
            throw new IOException("The verified hand-back path does not match its transfer identity.");

        VerifiedDirectory directory = OpenBlockedDirectory(profile, userSid, createDirectories: false);
        SafeFileHandle? file = null;
        try
        {
            file = OpenRelativeFile(directory.Handle, leaf,
                GenericRead | FileReadAttributes | ReadControl | Synchronize, ShareRead);
            VerifyFile(file, userSid, length, sha256Hex);
            return new VerifiedHandbackLease(file, directory);
        }
        catch
        {
            file?.Dispose();
            directory.Dispose();
            throw;
        }
    }

    public void CleanupUncommittedTemporary(StagedTransfer transfer)
    {
        if (!OperatingSystem.IsWindows()) throw new PlatformNotSupportedException(
            "Staged hand-back requires Windows handle-relative file operations.");
        _environment.RequireServiceIdentity();
        SecurityIdentifier userSid = RequireBoundSessionUser(transfer);
        string profile = _environment.ResolveProfilePath(userSid);
        try
        {
            using VerifiedDirectory directory = OpenBlockedDirectory(profile, userSid,
                createDirectories: false);
            DeleteExistingServiceTemporary(directory.Handle,
                ".safeupload-" + transfer.TransferId.ToString("N") + ".tmp", userSid);
        }
        catch (DirectoryNotFoundException)
        {
            // No directory means there is no recoverable temporary object.
        }
    }

    private SecurityIdentifier RequireBoundSessionUser(StagedTransfer transfer)
    {
        if (transfer.SessionId is null || string.IsNullOrWhiteSpace(transfer.RequestorSid))
            throw new UnauthorizedAccessException("The staged transfer has no bound requestor identity.");
        SecurityIdentifier expected;
        try { expected = new SecurityIdentifier(transfer.RequestorSid); }
        catch (ArgumentException error)
        {
            throw new UnauthorizedAccessException("The staged transfer requestor SID is invalid.", error);
        }
        if (expected.IsWellKnown(WellKnownSidType.LocalSystemSid))
            throw new UnauthorizedAccessException("A hand-back cannot be routed to the SYSTEM account.");
        SecurityIdentifier actual = _environment.ResolveUser(transfer.SessionId);
        if (!expected.Equals(actual))
            throw new UnauthorizedAccessException("The current session SID does not own this staged transfer.");
        return expected;
    }

    private async Task<HashSet<DirectoryIdentity>> EnsureOutsideProtectedAndSyncedTreesAsync(
        string target, string profile, SecurityIdentifier userSid, CancellationToken token)
    {
        if (!Directory.Exists(profile))
            throw new IOException("The owning user's profile directory is unavailable.");
        HashSet<DirectoryIdentity> targetAncestors = OpenDirectoryAncestors(target,
            allowMissingSuffix: true);
        var registeredRoots = new HashSet<DirectoryIdentity>();
        var policy = await _policyStore.LoadAsync(token).ConfigureAwait(false);
        foreach (string scope in policy.MonitoredScopes.DestinationPaths)
        {
            DirectoryIdentity identity = OpenDirectoryIdentity(scope);
            registeredRoots.Add(identity);
            if (targetAncestors.Contains(identity))
                throw new IOException("The hand-back location falls inside a protected policy scope.");
        }
        foreach (string syncRoot in _environment.KnownSyncRoots(profile, userSid))
        {
            DirectoryIdentity identity = OpenDirectoryIdentity(syncRoot);
            registeredRoots.Add(identity);
            if (targetAncestors.Contains(identity))
                throw new IOException("The hand-back location falls inside a known sync root.");
        }
        return registeredRoots;
    }

    private static void EnsureDestinationAncestorsOutsideRegisteredRoots(
        VerifiedDirectory destination, HashSet<DirectoryIdentity> registeredRoots)
    {
        foreach (SafeFileHandle component in destination.Components)
            if (registeredRoots.Contains(GetDirectoryIdentity(component)))
                throw new IOException("The opened hand-back location falls inside a protected or synced tree.");
    }

    internal static bool DirectoryPathsHaveSameIdentity(string first, string second)
    {
        if (!OperatingSystem.IsWindows()) throw new PlatformNotSupportedException();
        return OpenDirectoryIdentity(first) == OpenDirectoryIdentity(second);
    }

    private static DirectoryIdentity OpenDirectoryIdentity(string path)
    {
        using VerifiedDirectory directory = OpenExistingDirectoryPath(path);
        return GetDirectoryIdentity(directory.Handle);
    }

    private static HashSet<DirectoryIdentity> OpenDirectoryAncestors(string path,
        bool allowMissingSuffix)
    {
        using VerifiedDirectory directory = OpenExistingDirectoryPath(path, allowMissingSuffix);
        return directory.Components.Select(GetDirectoryIdentity).ToHashSet();
    }

    private static VerifiedDirectory OpenExistingDirectoryPath(string path,
        bool allowMissingSuffix = false)
    {
        if (string.IsNullOrWhiteSpace(path) || !Path.IsPathFullyQualified(path))
            throw new IOException("A policy scope or sync root is not fully qualified.");
        string fullPath = Path.GetFullPath(path);
        string volumeRoot = Path.GetPathRoot(fullPath)
            ?? throw new IOException("A policy scope or sync root has no local volume root.");
        if (!IsLocalVolumeRoot(volumeRoot))
            throw new IOException("A policy scope or sync root is not on a local volume.");
        SafeFileHandle root = OpenVolumeRoot(volumeRoot);
        var components = new List<SafeFileHandle> { root };
        try
        {
            string relative = Path.GetRelativePath(volumeRoot, fullPath);
            string[] names = relative == "." ? [] : relative.Split(Path.DirectorySeparatorChar,
                StringSplitOptions.RemoveEmptyEntries);
            bool missing = false;
            foreach (string name in names)
            {
                if (missing) break;
                SafeFileHandle? next = TryOpenIdentityDirectory(components[^1], name);
                if (next is null)
                {
                    if (!allowMissingSuffix)
                        throw new DirectoryNotFoundException("A policy scope or sync root could not be resolved.");
                    missing = true;
                    continue;
                }
                VerifyDirectory(next);
                components.Add(next);
            }
            return new VerifiedDirectory(components);
        }
        catch
        {
            for (int index = components.Count - 1; index >= 0; index--)
                components[index].Dispose();
            throw;
        }
    }

    private static SafeFileHandle? TryOpenIdentityDirectory(SafeFileHandle parent, string component)
    {
        int status = NtCreateRelative(out SafeFileHandle handle,
            FileReadAttributes | FileTraverse | Synchronize, parent, component,
            IntPtr.Zero, OpenExisting,
            DirectoryFile | SynchronousNonAlert | OpenReparsePoint | BackupIntent, ShareReadWrite);
        if (status >= 0) return handle;
        handle.Dispose();
        uint error = RtlNtStatusToDosError(status);
        if (error is ErrorFileNotFound or ErrorPathNotFound) return null;
        throw NtIOException("A policy scope or sync root could not be resolved safely.", status);
    }

    private static bool IsLocalVolumeRoot(string root) =>
        (root.Length == 3 && char.IsAsciiLetter(root[0]) && root[1] == ':' && root[2] == '\\') ||
        (root.Length == 7 && root.StartsWith("\\\\?\\", StringComparison.Ordinal) &&
         char.IsAsciiLetter(root[4]) && root[5] == ':' && root[6] == '\\');

    private static string SafeExtension(string destinationPath)
    {
        string extension = Path.GetExtension(destinationPath);
        return extension.Length is > 1 and <= 17 && extension[0] == '.' &&
            extension[1..].All(character => char.IsLetterOrDigit(character))
            ? extension : string.Empty;
    }

    private static IEnumerable<string> KnownSyncRoots(string profile, SecurityIdentifier userSid)
    {
        // The user profile is not accessed via SYSTEM's HKCU. Read the hive
        // mounted for the owning SID and the machine Cloud Files registrations.
        foreach (string basePath in new[]
                 {
                     Path.Combine(profile, "OneDrive"), Path.Combine(profile, "Dropbox"),
                     Path.Combine(profile, "Google Drive")
                 })
            if (Directory.Exists(basePath)) yield return basePath;
        if (Directory.Exists(profile))
        {
            foreach (string businessOneDrive in Directory.EnumerateDirectories(profile, "OneDrive - *"))
                yield return businessOneDrive;
        }

        using RegistryKey user = Registry.Users.OpenSubKey(userSid.Value)
            ?? throw new IOException("The owning user's registry hive is unavailable.");
        using RegistryKey? oneDrive = user.OpenSubKey(
            @"Software\Microsoft\OneDrive\Accounts", writable: false);
        if (oneDrive is not null)
        {
            foreach (string account in oneDrive.GetSubKeyNames())
            {
                using RegistryKey? key = oneDrive.OpenSubKey(account, writable: false);
                if (key?.GetValue("UserFolder") is string path) yield return NormalizeSyncRoot(path, profile);
            }
        }

        using RegistryKey? driveFs = user.OpenSubKey(
            @"Software\Google\DriveFS\Accounts", writable: false);
        if (driveFs is not null)
        {
            foreach (string account in driveFs.GetSubKeyNames())
            {
                using RegistryKey? key = driveFs.OpenSubKey(account, writable: false);
                if (key?.GetValue("mount_point") is string path) yield return NormalizeSyncRoot(path, profile);
            }
        }

        using RegistryKey? dropbox = user.OpenSubKey(@"Software\Dropbox", writable: false);
        if (dropbox is not null)
        {
            foreach (string valueName in new[] { "Path", "DropboxPath", "UserFolder" })
                if (dropbox.GetValue(valueName) is string path) yield return NormalizeSyncRoot(path, profile);
        }

        using RegistryKey? cloudRoots = Registry.LocalMachine.OpenSubKey(
            @"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\SyncRootManager", writable: false);
        if (cloudRoots is null) yield break;
        foreach (string provider in cloudRoots.GetSubKeyNames())
        {
            using RegistryKey? roots = cloudRoots.OpenSubKey(provider + "\\UserSyncRoots", writable: false);
            if (roots?.GetValue(userSid.Value) is string path) yield return NormalizeSyncRoot(path, profile);
        }
    }

    private static string NormalizeSyncRoot(string value, string profile)
    {
        string expanded = value.Replace("%USERPROFILE%", profile, StringComparison.OrdinalIgnoreCase);
        expanded = Environment.ExpandEnvironmentVariables(expanded);
        if (!Path.IsPathFullyQualified(expanded))
            throw new IOException("A registered sync root could not be resolved safely.");
        return Path.GetFullPath(expanded);
    }

    private static string ResolveProfilePath(SecurityIdentifier userSid)
    {
        using RegistryKey key = Registry.LocalMachine.OpenSubKey(
            @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\" + userSid.Value,
            writable: false) ?? throw new IOException("The owning user's profile is not registered.");
        string profile = key.GetValue("ProfileImagePath") as string
            ?? throw new IOException("The owning user's profile path is missing.");
        if (!Path.IsPathFullyQualified(Environment.ExpandEnvironmentVariables(profile)))
            throw new IOException("The owning user's profile path is not absolute.");
        profile = Path.GetFullPath(Environment.ExpandEnvironmentVariables(profile));
        string root = Path.GetPathRoot(profile)
            ?? throw new IOException("The owning user's profile is not on a local volume.");
        var drive = new DriveInfo(root);
        if (drive.DriveType != DriveType.Fixed || !drive.IsReady || drive.DriveFormat != "NTFS")
            throw new IOException("The owning user's profile must be on a ready local NTFS volume.");
        return Path.TrimEndingDirectorySeparator(profile);
    }

    private static SecurityIdentifier ResolveSessionUser(uint? sessionId)
    {
        if (sessionId is null || !WTSQueryUserToken(sessionId.Value, out SafeAccessTokenHandle token))
            throw new IOException("The owning Windows session could not be resolved.",
                new Win32Exception(Marshal.GetLastWin32Error()));
        using (token)
        {
            uint actualSession = ReadTokenUInt32(token, TokenSessionId);
            if (actualSession != sessionId.Value)
                throw new UnauthorizedAccessException("The resolved token belongs to another session.");
            _ = GetTokenInformation(token, TokenUser, IntPtr.Zero, 0, out uint required);
            int error = Marshal.GetLastWin32Error();
            if (error != ErrorInsufficientBuffer || required == 0 || required > 64 * 1024)
                throw new IOException("The owning user's SID could not be read.", new Win32Exception(error));
            int length = checked((int)required);
            IntPtr buffer = Marshal.AllocHGlobal(length);
            try
            {
                if (!GetTokenInformation(token, TokenUser, buffer, required, out _))
                    throw new IOException("The owning user's SID could not be read.",
                        new Win32Exception(Marshal.GetLastWin32Error()));
                IntPtr sid = Marshal.ReadIntPtr(buffer);
                return new SecurityIdentifier(sid);
            }
            finally { Marshal.FreeHGlobal(buffer); }
        }
    }

    private static uint ReadTokenUInt32(SafeAccessTokenHandle token, int infoClass)
    {
        IntPtr buffer = Marshal.AllocHGlobal(sizeof(uint));
        try
        {
            if (!GetTokenInformation(token, infoClass, buffer, sizeof(uint), out _))
                throw new IOException("The owning session identity could not be verified.",
                    new Win32Exception(Marshal.GetLastWin32Error()));
            return unchecked((uint)Marshal.ReadInt32(buffer));
        }
        finally { Marshal.FreeHGlobal(buffer); }
    }

    private static VerifiedDirectory OpenBlockedDirectory(string profile, SecurityIdentifier userSid,
        bool createDirectories)
    {
        string volumeRoot = Path.GetPathRoot(profile)!;
        SafeFileHandle current = OpenVolumeRoot(volumeRoot);
        var components = new List<SafeFileHandle> { current };

        try
        {
            VerifyDirectory(current);
            string[] profileComponents = Path.GetRelativePath(volumeRoot, profile)
                .Split(Path.DirectorySeparatorChar, StringSplitOptions.RemoveEmptyEntries);
            for (int index = 0; index < profileComponents.Length; index++)
            {
                SafeFileHandle next = OpenExistingDirectory(current, profileComponents[index],
                    writable: index == profileComponents.Length - 1);
                current = next;
                components.Add(current);
                VerifyDirectory(current);
            }
            VerifyProfileOwner(current, userSid);

            foreach (string component in new[] { "SafeUpload", "_bloqueados" })
            {
                SafeFileHandle next = createDirectories
                    ? OpenOrCreatePrivateDirectory(current, component, userSid)
                    : OpenExistingPrivateDirectory(current, component, userSid);
                current = next;
                components.Add(current);
                VerifyDirectory(current);
                VerifyPrivateAcl(current, userSid);
            }
            return new VerifiedDirectory(components);
        }
        catch
        {
            for (int index = components.Count - 1; index >= 0; index--)
                components[index].Dispose();
            throw;
        }
    }

    private static SafeFileHandle OpenVolumeRoot(string volumeRoot)
    {
        SafeFileHandle handle = CreateFile(volumeRoot,
            FileReadAttributes | FileTraverse | Synchronize, ShareReadWrite, IntPtr.Zero,
            Win32OpenExisting, FileFlagBackupSemantics | OpenReparsePoint, IntPtr.Zero);
        if (!handle.IsInvalid) return handle;
        var error = new Win32Exception(Marshal.GetLastWin32Error());
        handle.Dispose();
        throw new IOException("The profile volume root could not be opened safely.", error);
    }

    private static SafeFileHandle OpenExistingDirectory(SafeFileHandle parent, string component,
        bool writable) =>
        TryOpenRelativeDirectory(parent, component, writable) ??
        throw new DirectoryNotFoundException("The registered user profile contains a missing component.");

    private static SafeFileHandle OpenOrCreatePrivateDirectory(SafeFileHandle parent,
        string component, SecurityIdentifier userSid)
    {
        SafeFileHandle? opened = TryOpenRelativeDirectory(parent, component, writable: true,
            ownerChange: true);
        if (opened is null)
        {
            IntPtr descriptor = CreateSecurityDescriptor(userSid, directory: true);
            try
            {
                opened = CreateRelativeDirectory(parent, component, descriptor);
            }
            catch (IOException)
            {
                // A user may win the name race; reopen relative and validate
                // the object that now occupies this component.
                SafeFileHandle? raced = TryOpenRelativeDirectory(parent, component, writable: true,
                    ownerChange: true);
                if (raced is null) throw;
                opened = raced;
            }
            finally { if (descriptor != IntPtr.Zero) LocalFree(descriptor); }
        }
        try
        {
            VerifyDirectory(opened);
            HardenKnownPrivateDirectoryAcl(opened, userSid);
            VerifyPrivateAcl(opened, userSid);
            return opened;
        }
        catch
        {
            opened.Dispose();
            throw;
        }
    }

    private static SafeFileHandle OpenExistingPrivateDirectory(SafeFileHandle parent,
        string component, SecurityIdentifier userSid)
    {
        SafeFileHandle opened = TryOpenRelativeDirectory(parent, component, writable: true) ??
            throw new DirectoryNotFoundException("The committed hand-back directory disappeared.");
        try
        {
            VerifyDirectory(opened);
            VerifyPrivateAcl(opened, userSid);
            return opened;
        }
        catch
        {
            opened.Dispose();
            throw;
        }
    }

    private static SafeFileHandle? TryOpenRelativeDirectory(SafeFileHandle parent, string name,
        bool writable, bool ownerChange = false)
    {
        uint access = (writable ? GenericRead | GenericWrite : 0) |
            (ownerChange ? WriteOwnerAccess : 0) |
            FileReadAttributes | ReadControl | FileTraverse | Synchronize;
        int status = NtCreateRelative(out SafeFileHandle handle, access, parent, name,
            IntPtr.Zero, OpenExisting, DirectoryFile | SynchronousNonAlert | OpenReparsePoint | BackupIntent,
            ShareReadWrite);
        if (status >= 0) return handle;
        handle.Dispose();
        uint error = RtlNtStatusToDosError(status);
        if (error is ErrorFileNotFound or ErrorPathNotFound) return null;
        throw NtIOException("Could not open a profile directory component.", status);
    }

    private static SafeFileHandle CreateRelativeDirectory(SafeFileHandle parent,
        string name, IntPtr securityDescriptor)
    {
        int status = NtCreateRelative(out SafeFileHandle handle, GenericRead | GenericWrite |
            FileReadAttributes | ReadControl | FileTraverse | Synchronize, parent, name,
            securityDescriptor, CreateNew, DirectoryFile | SynchronousNonAlert | OpenReparsePoint | BackupIntent,
            ShareReadWrite);
        if (status < 0)
        {
            handle.Dispose();
            throw NtIOException("Could not create a user hand-back directory.", status);
        }
        return handle;
    }

    private static SafeFileHandle CreateRelativeFile(SafeFileHandle parent, string name,
        SecurityIdentifier userSid, uint access)
    {
        IntPtr descriptor = CreateSecurityDescriptor(userSid, directory: false);
        try
        {
            int status = NtCreateRelative(out SafeFileHandle handle, access, parent, name,
                descriptor, CreateNew, NonDirectoryFile | SynchronousNonAlert | OpenReparsePoint | BackupIntent,
                ShareRead);
            if (status < 0)
            {
                handle.Dispose();
                throw NtIOException("Could not create a new hand-back file.", status);
            }
            try
            {
                VerifyFileIdentity(handle, userSid);
                return handle;
            }
            catch
            {
                handle.Dispose();
                throw;
            }
        }
        finally { LocalFree(descriptor); }
    }

    private static SafeFileHandle? TryOpenRelativeFile(SafeFileHandle parent, string name, uint access,
        uint shareAccess)
    {
        int status = NtCreateRelative(out SafeFileHandle handle, access, parent, name,
            IntPtr.Zero, OpenExisting, NonDirectoryFile | SynchronousNonAlert | OpenReparsePoint | BackupIntent,
            shareAccess);
        if (status >= 0) return handle;
        handle.Dispose();
        uint error = RtlNtStatusToDosError(status);
        if (error is ErrorFileNotFound or ErrorPathNotFound) return null;
        throw NtIOException("Could not inspect an existing hand-back name.", status);
    }

    private static SafeFileHandle OpenRelativeFile(SafeFileHandle parent, string name, uint access,
        uint shareAccess) =>
        TryOpenRelativeFile(parent, name, access, shareAccess) ??
        throw new FileNotFoundException("The committed hand-back file disappeared.", name);

    private static void DeleteExistingServiceTemporary(SafeFileHandle directory, string name,
        SecurityIdentifier userSid)
    {
        using SafeFileHandle? existing = TryOpenRelativeFile(directory, name,
            DeleteAccess | FileReadAttributes | ReadControl | Synchronize, ShareRead);
        if (existing is null) return;
        VerifyFileIdentity(existing, userSid);
        VerifyTemporaryAcl(existing, userSid);
        MarkDeleteByHandle(existing);
    }

    private static void VerifyTemporaryAcl(SafeFileHandle handle, SecurityIdentifier userSid)
    {
        SecurityDescriptor descriptor = ReadSecurityDescriptor(handle);
        SecurityIdentifier systemSid = new(WellKnownSidType.LocalSystemSid, null);
        if (descriptor.Owner is null || !systemSid.Equals(descriptor.Owner) ||
            (descriptor.Control & (ushort)ControlFlags.DiscretionaryAclProtected) == 0 ||
            descriptor.Dacl is null || descriptor.Dacl.Count != 2)
            throw new UnauthorizedAccessException("The service temporary file is not protected.");
        var expected = new Dictionary<string, HashSet<int>>(StringComparer.Ordinal)
        {
            [userSid.Value] = [(int)FileGenericRead, (int)FileSystemRights.FullControl],
            [systemSid.Value] = [(int)FileSystemRights.FullControl]
        };
        var seen = new HashSet<string>(StringComparer.Ordinal);
        foreach (GenericAce ace in descriptor.Dacl)
        {
            if (ace is not CommonAce common || common.AceQualifier != AceQualifier.AccessAllowed ||
                common.AceFlags != AceFlags.None || common.SecurityIdentifier is not { } sid ||
                !expected.TryGetValue(sid.Value, out HashSet<int>? rights) ||
                !rights.Contains(common.AccessMask) || !seen.Add(sid.Value))
                throw new UnauthorizedAccessException("The service temporary file contains an unapproved ACE.");
        }
        if (seen.Count != expected.Count)
            throw new UnauthorizedAccessException("The service temporary file ACL is incomplete.");
    }

    private static void MarkDeleteByHandle(SafeFileHandle file)
    {
        byte[] extended = BitConverter.GetBytes(FileDispositionDelete);
        if (SetFileInformationByHandle(file, FileDispositionInfoEx, extended, extended.Length)) return;

        // Older Windows builds can lack FILE_DISPOSITION_INFO_EX. Both paths
        // mark the open object itself, never a path that could be substituted.
        byte[] legacy = BitConverter.GetBytes(1);
        if (!SetFileInformationByHandle(file, FileDispositionInfo, legacy, legacy.Length))
            throw new IOException("Could not delete the uncommitted hand-back temporary by handle.",
                new Win32Exception(Marshal.GetLastWin32Error()));
    }

    private static void VerifyDirectory(SafeFileHandle handle)
    {
        ByHandleFileInformation info = GetFileInformation(handle);
        if ((info.Attributes & FileAttributeDirectory) == 0 ||
            (info.Attributes & FileAttributeReparsePoint) != 0)
            throw new IOException("A profile path component is not a plain directory.");
    }

    private static void VerifyProfileOwner(SafeFileHandle handle, SecurityIdentifier userSid)
    {
        SecurityDescriptor descriptor = ReadSecurityDescriptor(handle);
        // Windows creates profile directories owned by SYSTEM (verified on 19045: C:\Users\<user> has
        // owner S-1-5-18). ProfileList is HKLM, so the path is admin-controlled; the owner check only
        // has to exclude a directory owned by some other standard user.
        SecurityIdentifier? owner = descriptor.Owner;
        if (owner is null || !(userSid.Equals(owner) || owner.IsWellKnown(WellKnownSidType.LocalSystemSid) ||
                owner.IsWellKnown(WellKnownSidType.BuiltinAdministratorsSid)))
            throw new UnauthorizedAccessException("The registered profile directory has an untrusted owner.");
    }

    private static void VerifyPrivateAcl(SafeFileHandle handle, SecurityIdentifier userSid)
    {
        SecurityDescriptor descriptor = ReadSecurityDescriptor(handle);
        SecurityIdentifier systemSid = new(WellKnownSidType.LocalSystemSid, null);
        if (descriptor.Owner is null || !systemSid.Equals(descriptor.Owner) ||
            (descriptor.Control & (ushort)ControlFlags.DiscretionaryAclProtected) == 0 ||
            descriptor.Dacl is null || descriptor.Dacl.Count != 2)
            throw new UnauthorizedAccessException("The hand-back directory ACL is not explicitly private.");
        var expected = new Dictionary<string, int>(StringComparer.Ordinal)
        {
            [userSid.Value] = (int)FileGenericRead,
            [systemSid.Value] = (int)FileSystemRights.FullControl
        };
        foreach (GenericAce ace in descriptor.Dacl)
        {
            if (ace is not CommonAce common || common.AceQualifier != AceQualifier.AccessAllowed ||
                common.SecurityIdentifier is not { } sid || !expected.Remove(sid.Value, out int rights) ||
                common.AccessMask != rights)
                throw new UnauthorizedAccessException("The hand-back ACL contains an unapproved ACE.");
            if (common.AceFlags != AceFlags.None)
                throw new UnauthorizedAccessException("The hand-back ACL contains inherited or propagating ACE flags.");
        }
        if (expected.Count != 0)
            throw new UnauthorizedAccessException("The hand-back ACL omits the owning user or SYSTEM.");
    }

    private static void HardenKnownPrivateDirectoryAcl(SafeFileHandle handle,
        SecurityIdentifier userSid)
    {
        SecurityDescriptor descriptor = ReadSecurityDescriptor(handle);
        SecurityIdentifier systemSid = new(WellKnownSidType.LocalSystemSid, null);
        if ((descriptor.Control & (ushort)ControlFlags.DiscretionaryAclProtected) == 0 ||
            descriptor.Dacl is null || descriptor.Dacl.Count != 2 || descriptor.Owner is null ||
            (!descriptor.Owner.Equals(userSid) && !descriptor.Owner.Equals(systemSid)))
            throw new UnauthorizedAccessException("The existing hand-back directory is not a recognized private directory.");

        var expected = new Dictionary<string, HashSet<int>>(StringComparer.Ordinal)
        {
            [userSid.Value] = [(int)FileGenericRead, (int)FileSystemRights.FullControl],
            [systemSid.Value] = [(int)FileSystemRights.FullControl]
        };
        var seen = new HashSet<string>(StringComparer.Ordinal);
        const AceFlags oldInheritance = AceFlags.ContainerInherit | AceFlags.ObjectInherit;
        foreach (GenericAce ace in descriptor.Dacl)
        {
            if (ace is not CommonAce common || common.AceQualifier != AceQualifier.AccessAllowed ||
                (common.AceFlags != AceFlags.None && common.AceFlags != oldInheritance) ||
                common.SecurityIdentifier is not { } sid ||
                !expected.TryGetValue(sid.Value, out HashSet<int>? rights) ||
                !rights.Contains(common.AccessMask) || !seen.Add(sid.Value))
                throw new UnauthorizedAccessException("The existing hand-back directory ACL is not recognized.");
        }
        if (seen.Count != expected.Count)
            throw new UnauthorizedAccessException("The existing hand-back directory ACL is incomplete.");

        bool alreadyHardened = descriptor.Owner.Equals(systemSid) &&
            descriptor.Dacl.Cast<GenericAce>().All(ace => ace is CommonAce common &&
                common.AceFlags == AceFlags.None && common.SecurityIdentifier is { } sid &&
                common.AccessMask == (sid.Equals(userSid) ? (int)FileGenericRead :
                    (int)FileSystemRights.FullControl));
        if (alreadyHardened) return;
        ApplyPrivateAcl(handle, userSid, directory: true);
    }

    private static void ApplyPrivateAcl(SafeFileHandle handle, SecurityIdentifier userSid,
        bool directory)
    {
        IntPtr descriptor = CreateSecurityDescriptor(userSid, directory);
        try
        {
            if (!GetSecurityDescriptorOwner(descriptor, out IntPtr owner, out _) ||
                !GetSecurityDescriptorDacl(descriptor, out _, out IntPtr dacl, out _))
                throw new IOException("Could not read the new hand-back security descriptor.",
                    new Win32Exception(Marshal.GetLastWin32Error()));
            int result = SetSecurityInfo(handle, SeFileObject,
                SecurityInformationOwner | SecurityInformationDacl | unchecked((int)0x80000000),
                owner, IntPtr.Zero, dacl, IntPtr.Zero);
            if (result != 0)
                throw new IOException("Could not harden the existing hand-back directory.",
                    new Win32Exception(result));
        }
        finally { LocalFree(descriptor); }
    }

    private static void VerifyFile(SafeFileHandle handle, SecurityIdentifier userSid,
        long expectedLength, string expectedSha256)
    {
        VerifyFileIdentity(handle, userSid);
        var info = GetFileInformation(handle);
        long length = ((long)info.SizeHigh << 32) | info.SizeLow;
        if (length != expectedLength)
            throw new IOException("The hand-back file length does not match the sealed snapshot.");
        if (!DuplicateHandle(GetCurrentProcess(), handle, GetCurrentProcess(), out SafeFileHandle duplicate,
                0, false, 2))
            throw new IOException("Could not open an independent hand-back verification reader.",
                new Win32Exception(Marshal.GetLastWin32Error()));
        using (duplicate)
        using (var stream = new FileStream(duplicate, FileAccess.Read, 64 * 1024, isAsync: false))
        {
            stream.Position = 0;
            string digest = Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(stream));
            if (!string.Equals(digest, expectedSha256, StringComparison.OrdinalIgnoreCase))
                throw new IOException("The hand-back file digest does not match the sealed snapshot.");
            VerifyPrivateAcl(handle, userSid);
        }
    }

    private static void VerifyFileIdentity(SafeFileHandle handle, SecurityIdentifier userSid)
    {
        ByHandleFileInformation info = GetFileInformation(handle);
        if ((info.Attributes & (FileAttributeDirectory | FileAttributeReparsePoint)) != 0 || info.LinkCount != 1)
            throw new IOException("The hand-back file is a reparse point, directory, or has multiple links.");
        SecurityDescriptor descriptor = ReadSecurityDescriptor(handle);
        if (descriptor.Owner?.IsWellKnown(WellKnownSidType.LocalSystemSid) != true)
            throw new UnauthorizedAccessException("The hand-back file is not owned by SYSTEM.");
    }

    private static void RenameRelativeNoReplace(SafeFileHandle file, SafeFileHandle directory,
        string finalName)
    {
        // FILE_RENAME_INFORMATION through NtSetInformationFile: kernel32's SetFileInformationByHandle
        // rejects a non-null RootDirectory for renames (ERROR_INVALID_PARAMETER, verified on the builder),
        // and a handle-relative target is the point. Flags 0 = no replace (STATUS_OBJECT_NAME_COLLISION).
        byte[] name = Encoding.Unicode.GetBytes(finalName);
        int nameOffset = IntPtr.Size == 8 ? 20 : 12;
        int headerSize = IntPtr.Size == 8 ? 24 : 16;
        byte[] buffer = new byte[checked(headerSize + name.Length)];
        BitConverter.GetBytes(FileRenameNoReplace).CopyTo(buffer, 0);
        if (IntPtr.Size == 8) BitConverter.GetBytes(directory.DangerousGetHandle().ToInt64()).CopyTo(buffer, 8);
        else BitConverter.GetBytes(directory.DangerousGetHandle().ToInt32()).CopyTo(buffer, 4);
        BitConverter.GetBytes(name.Length).CopyTo(buffer, nameOffset - sizeof(uint));
        name.CopyTo(buffer, nameOffset);
        int status = NtSetInformationFile(file, out IoStatusBlock _, buffer, buffer.Length,
            FileRenameInformationExClass);
        if (status < 0)
            throw new IOException("Could not commit the verified hand-back file without replacement.",
                new Win32Exception(checked((int)RtlNtStatusToDosError(status))));
    }

    private static IntPtr CreateSecurityDescriptor(SecurityIdentifier userSid, bool directory)
    {
        string sddl = BuildSecurityDescriptorSddl(userSid, directory);
        if (!ConvertStringSecurityDescriptorToSecurityDescriptor(sddl, 1,
                out IntPtr descriptor, out _))
            throw new IOException("Could not construct the private hand-back ACL.",
                new Win32Exception(Marshal.GetLastWin32Error()));
        return descriptor;
    }

    internal static string BuildFileSecurityDescriptorSddl(SecurityIdentifier userSid) =>
        BuildSecurityDescriptorSddl(userSid, directory: false);

    internal static string BuildDirectorySecurityDescriptorSddl(SecurityIdentifier userSid) =>
        BuildSecurityDescriptorSddl(userSid, directory: true);

    private static string BuildSecurityDescriptorSddl(SecurityIdentifier userSid, bool directory)
    {
        string sid = userSid.Value;
        _ = directory; // Each child receives its own explicit ACL at creation.
        return $"O:SYD:P(A;;FR;;;{sid})(A;;FA;;;SY)";
    }

    private static SecurityDescriptor ReadSecurityDescriptor(SafeFileHandle handle)
    {
        int result = GetSecurityInfo(handle, SeFileObject,
            SecurityInformationOwner | SecurityInformationDacl,
            out _, out _, out _, out _, out IntPtr descriptor);
        if (result != 0) throw new IOException("Could not read hand-back security information.",
            new Win32Exception(result));
        try
        {
            if (!GetSecurityDescriptorControl(descriptor, out ushort control, out _))
                throw new IOException("Could not validate the hand-back security descriptor.",
                    new Win32Exception(Marshal.GetLastWin32Error()));
            uint length = GetSecurityDescriptorLength(descriptor);
            if (length == 0 || length > 64 * 1024)
                throw new IOException("Could not validate the hand-back security descriptor.");
            byte[] bytes = new byte[checked((int)length)];
            Marshal.Copy(descriptor, bytes, 0, bytes.Length);
            var raw = new RawSecurityDescriptor(bytes, 0);
            return new SecurityDescriptor(raw.Owner is null ? null : new SecurityIdentifier(raw.Owner.Value),
                raw.DiscretionaryAcl, control);
        }
        finally { LocalFree(descriptor); }
    }

    private static ByHandleFileInformation GetFileInformation(SafeFileHandle handle)
    {
        if (!GetFileInformationByHandle(handle, out var info))
            throw new IOException("Could not identify a hand-back path component.",
                new Win32Exception(Marshal.GetLastWin32Error()));
        return info;
    }

    private static DirectoryIdentity GetDirectoryIdentity(SafeFileHandle handle)
    {
        if (!GetFileInformationByHandleEx(handle, 18, out FileIdInfo info,
                checked((uint)Marshal.SizeOf<FileIdInfo>())))
            throw new IOException("Could not resolve a directory's volume and file identity.",
                new Win32Exception(Marshal.GetLastWin32Error()));
        return new DirectoryIdentity(info.VolumeSerialNumber,
            new FileId128(info.FileId.Low, info.FileId.High));
    }

    private static IOException NtIOException(string message, int status) =>
        new(message, new Win32Exception(checked((int)RtlNtStatusToDosError(status))));

    private sealed class WindowsHandbackEnvironment : IStagedHandbackEnvironment
    {
        public void RequireServiceIdentity()
        {
            using WindowsIdentity caller = WindowsIdentity.GetCurrent();
            if (caller.User?.IsWellKnown(WellKnownSidType.LocalSystemSid) != true)
                throw new UnauthorizedAccessException("Staged hand-back must run as LocalSystem.");
        }

        public SecurityIdentifier ResolveUser(uint? sessionId) => ResolveSessionUser(sessionId);
        public string ResolveProfilePath(SecurityIdentifier userSid) =>
            StagedHandbackCopier.ResolveProfilePath(userSid);
        public IEnumerable<string> KnownSyncRoots(string profile, SecurityIdentifier userSid) =>
            StagedHandbackCopier.KnownSyncRoots(profile, userSid);
    }

    private sealed record SecurityDescriptor(SecurityIdentifier? Owner, RawAcl? Dacl, ushort Control);
    private readonly record struct DirectoryIdentity(ulong VolumeSerialNumber, FileId128 FileId);
    private readonly record struct FileId128(ulong Low, ulong High);
    [StructLayout(LayoutKind.Sequential)]
    private struct NativeFileId128
    {
        public ulong Low;
        public ulong High;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct FileIdInfo
    {
        public ulong VolumeSerialNumber;
        public NativeFileId128 FileId;
    }

    private sealed class VerifiedHandbackLease(SafeFileHandle file, VerifiedDirectory directory) : IDisposable
    {
        private SafeFileHandle? _file = file;
        private VerifiedDirectory? _directory = directory;

        public void Dispose()
        {
            Interlocked.Exchange(ref _file, null)?.Dispose();
            Interlocked.Exchange(ref _directory, null)?.Dispose();
        }
    }

    private sealed class VerifiedDirectory(IReadOnlyList<SafeFileHandle> components) : IDisposable
    {
        public SafeFileHandle Handle { get; } = components[^1];
        public IReadOnlyList<SafeFileHandle> Components { get; } = components;
        public void Dispose()
        {
            for (int index = Components.Count - 1; index >= 0; index--)
                Components[index].Dispose();
        }
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct IoStatusBlock { public IntPtr Status; public UIntPtr Information; }

    [StructLayout(LayoutKind.Sequential)]
    private struct UnicodeString { public ushort Length; public ushort MaximumLength; public IntPtr Buffer; }

    [StructLayout(LayoutKind.Sequential)]
    private struct ObjectAttributes
    {
        public uint Length;
        public IntPtr RootDirectory;
        public IntPtr ObjectName;
        public uint Attributes;
        public IntPtr SecurityDescriptor;
        public IntPtr SecurityQualityOfService;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct ByHandleFileInformation
    {
        public uint Attributes;
        public System.Runtime.InteropServices.ComTypes.FILETIME CreationTime;
        public System.Runtime.InteropServices.ComTypes.FILETIME LastAccessTime;
        public System.Runtime.InteropServices.ComTypes.FILETIME LastWriteTime;
        public uint VolumeSerialNumber;
        public uint SizeHigh;
        public uint SizeLow;
        public uint LinkCount;
        public uint FileIndexHigh;
        public uint FileIndexLow;
    }

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern SafeFileHandle CreateFile(string path, uint access, uint share,
        IntPtr security, uint disposition, uint flags, IntPtr template);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetFileInformationByHandle(SafeFileHandle file,
        out ByHandleFileInformation information);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetFileInformationByHandleEx(SafeFileHandle file,
        int informationClass, out FileIdInfo information, uint bufferSize);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool SetFileInformationByHandle(SafeFileHandle file,
        int informationClass, byte[] information, int size);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool DuplicateHandle(IntPtr sourceProcess, SafeFileHandle source,
        IntPtr targetProcess, out SafeFileHandle target, uint desiredAccess,
        [MarshalAs(UnmanagedType.Bool)] bool inheritHandle, uint options);

    [DllImport("kernel32.dll")]
    private static extern IntPtr GetCurrentProcess();

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr LocalFree(IntPtr memory);

    [DllImport("advapi32.dll", EntryPoint = "ConvertStringSecurityDescriptorToSecurityDescriptorW",
        CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool ConvertStringSecurityDescriptorToSecurityDescriptor(
        string descriptor, uint revision, out IntPtr result, out uint size);

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern int GetSecurityInfo(SafeFileHandle handle, int objectType,
        int securityInformation, out IntPtr owner, out IntPtr group, out IntPtr dacl,
        out IntPtr sacl, out IntPtr securityDescriptor);

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern int SetSecurityInfo(SafeFileHandle handle, int objectType,
        int securityInformation, IntPtr owner, IntPtr group, IntPtr dacl, IntPtr sacl);

    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetSecurityDescriptorOwner(IntPtr descriptor,
        out IntPtr owner, out int ownerDefaulted);

    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetSecurityDescriptorDacl(IntPtr descriptor,
        out int daclPresent, out IntPtr dacl, out int daclDefaulted);

    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetSecurityDescriptorControl(IntPtr descriptor,
        out ushort control, out uint revision);

    [DllImport("advapi32.dll")]
    private static extern uint GetSecurityDescriptorLength(IntPtr descriptor);

    [DllImport("wtsapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool WTSQueryUserToken(uint sessionId, out SafeAccessTokenHandle token);

    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetTokenInformation(SafeAccessTokenHandle token, int informationClass,
        IntPtr information, uint informationLength, out uint returnLength);

    [DllImport("ntdll.dll")]
    private static extern int NtCreateFile(out SafeFileHandle fileHandle, uint desiredAccess,
        ref ObjectAttributes objectAttributes, out IoStatusBlock ioStatusBlock,
        IntPtr allocationSize, uint fileAttributes, uint shareAccess, uint createDisposition,
        uint createOptions, IntPtr eaBuffer, uint eaLength);

    [DllImport("ntdll.dll")]
    private static extern uint RtlNtStatusToDosError(int status);

    [DllImport("ntdll.dll")]
    private static extern int NtSetInformationFile(SafeFileHandle fileHandle,
        out IoStatusBlock ioStatusBlock, byte[] fileInformation, int length, int fileInformationClass);

    private static int NtCreateRelative(out SafeFileHandle handle, uint access,
        SafeFileHandle parent, string name, IntPtr securityDescriptor, uint disposition, uint options,
        uint shareAccess)
    {
        byte[] nameBytes = Encoding.Unicode.GetBytes(name);
        if (nameBytes.Length > ushort.MaxValue - 2) throw new IOException("A path component is too long.");
        IntPtr nameBuffer = Marshal.AllocHGlobal(nameBytes.Length + sizeof(char));
        IntPtr unicodePointer = IntPtr.Zero;
        try
        {
            Marshal.Copy(nameBytes, 0, nameBuffer, nameBytes.Length);
            Marshal.WriteInt16(nameBuffer, nameBytes.Length, 0);
            var unicode = new UnicodeString
            {
                Length = checked((ushort)nameBytes.Length),
                MaximumLength = checked((ushort)(nameBytes.Length + sizeof(char))),
                Buffer = nameBuffer
            };
            unicodePointer = Marshal.AllocHGlobal(Marshal.SizeOf<UnicodeString>());
            Marshal.StructureToPtr(unicode, unicodePointer, false);
            var attributes = new ObjectAttributes
            {
                Length = checked((uint)Marshal.SizeOf<ObjectAttributes>()),
                RootDirectory = parent.DangerousGetHandle(),
                ObjectName = unicodePointer,
                Attributes = 0x40, // OBJ_CASE_INSENSITIVE
                SecurityDescriptor = securityDescriptor
            };
            return NtCreateFile(out handle, access, ref attributes, out _,
                IntPtr.Zero, 0, shareAccess, disposition, options, IntPtr.Zero, 0);
        }
        finally
        {
            if (unicodePointer != IntPtr.Zero) Marshal.FreeHGlobal(unicodePointer);
            Marshal.FreeHGlobal(nameBuffer);
        }
    }
}
