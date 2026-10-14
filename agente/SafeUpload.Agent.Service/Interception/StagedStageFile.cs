using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using Microsoft.Win32.SafeHandles;

namespace SafeUpload.Agent.Service.Interception;

/// <summary>
/// The identity captured for a private stage file before its name is returned
/// to the writer. Windows uses volume serial + FILE_ID_INFO. The non-Windows
/// path exists only so the Windows-targeted service tests can exercise state
/// transitions on developer hosts; production is Windows-only.
/// </summary>
public sealed record StagedStageIdentity(ulong VolumeSerialNumber, ulong FileIdHigh, ulong FileIdLow);

/// <summary>
/// Opens a private stage without following its final reparse point and without
/// sharing write access. The same handle supplies identity and EOF length, so
/// seal classification cannot combine metadata from different path objects.
/// </summary>
internal sealed class StagedStageFile : IDisposable
{
    private const uint GenericRead = 0x80000000;
    private const uint DeleteAccess = 0x00010000;
    private const uint FileReadAttributes = 0x00000080;
    private const uint Synchronize = 0x00100000;
    private const uint ShareRead = 0x00000001;
    private const uint ShareWrite = 0x00000002;
    private const uint ShareDelete = 0x00000004;
    private const uint OpenExisting = 3;
    private const uint OpenReparsePoint = 0x00200000;
    private const uint BackupSemantics = 0x02000000;
    private const uint SequentialScan = 0x08000000;
    private const uint AttributeDirectory = 0x00000010;
    private const uint AttributeReparsePoint = 0x00000400;
    private const int FileIdInfoClass = 18;
    private const int FileDispositionInfoClass = 4;

    private StagedStageFile(FileStream stream, StagedStageIdentity identity)
        => (Stream, Identity) = (stream, identity);

    public FileStream Stream { get; }
    public StagedStageIdentity Identity { get; }

    public static StagedStageFile Open(string path, bool allowWriters = false)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(path);
        path = Path.GetFullPath(path);
        return OperatingSystem.IsWindows() ? OpenWindows(path, allowWriters) : OpenPortable(path, allowWriters);
    }

    /// <summary>
    /// Reads the identity and length of a private stage that a kernel writer
    /// may hold open. The driver keeps a writable stage backing open with no
    /// sharing while a writer is attached, so any data-access open fails with a
    /// sharing violation (m2t5boot7: every attach PREPARE refused, every save
    /// denied). Share modes govern data and delete access only: this handle
    /// requests FILE_READ_ATTRIBUTES alone, never reads or locks the bytes, and
    /// keeps the no-follow, regular-file, single-link and FILE_ID_INFO checks.
    /// </summary>
    public static (StagedStageIdentity Identity, long Length) ReadAttachedMetadata(string path)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(path);
        path = Path.GetFullPath(path);
        if (!OperatingSystem.IsWindows())
        {
            using StagedStageFile portable = OpenPortable(path, allowWriters: true);
            return (portable.Identity, portable.Stream.Length);
        }
        using SafeFileHandle handle = CreateFile(path, FileReadAttributes | Synchronize,
            ShareRead | ShareWrite | ShareDelete, IntPtr.Zero, OpenExisting, OpenReparsePoint, IntPtr.Zero);
        if (handle.IsInvalid)
        {
            var error = new Win32Exception(Marshal.GetLastWin32Error());
            throw error.NativeErrorCode switch
            {
                2 => new FileNotFoundException("Private stage was not found.", path),
                3 => new DirectoryNotFoundException("Private stage directory was not found."),
                5 => new UnauthorizedAccessException("Private stage could not be opened.", error),
                _ => new IOException("Private stage could not be opened.", error)
            };
        }
        if (!GetFileInformationByHandle(handle, out ByHandleFileInformation basic))
            throw new IOException("Private stage identity could not be read.",
                new Win32Exception(Marshal.GetLastWin32Error()));
        if ((basic.Attributes & (AttributeDirectory | AttributeReparsePoint)) != 0 || basic.LinkCount != 1)
            throw StagedRequestRefusal.Create("Private stage must be a single-link regular file without reparse points.");
        if (!GetFileInformationByHandleEx(handle, FileIdInfoClass, out FileIdInfo fileId,
                checked((uint)Marshal.SizeOf<FileIdInfo>())))
            throw new IOException("Private stage FILE_ID_INFO could not be read.",
                new Win32Exception(Marshal.GetLastWin32Error()));
        if (!GetFileSizeEx(handle, out long length))
            throw new IOException("Private stage length could not be read.",
                new Win32Exception(Marshal.GetLastWin32Error()));
        return (new StagedStageIdentity(fileId.VolumeSerialNumber, fileId.FileId.High, fileId.FileId.Low), length);
    }

    /// <summary>Reads a no-follow identity for the existing destination parent directory.</summary>
    public static StagedStageIdentity ReadDirectoryIdentity(string path)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(path);
        path = Path.GetFullPath(path);
        if (!Directory.Exists(path)) throw new DirectoryNotFoundException(path);
        for (string? current = path; current is not null; current = Path.GetDirectoryName(current))
        {
            if (Directory.Exists(current) && (File.GetAttributes(current) & FileAttributes.ReparsePoint) != 0)
                throw StagedRequestRefusal.Create("The destination parent contains a reparse point.");
        }
        return OperatingSystem.IsWindows() ? ReadWindowsDirectoryIdentity(path) : ReadPortableDirectoryIdentity(path);
    }

    /// <summary>
    /// Deletes only the exact stage object named by the manifest. Windows
    /// uses a no-follow handle with DELETE access and no sharing, then marks
    /// that handle for deletion; a replacement at the same path is never
    /// unlinked. Success means the path is absent after the handle closes.
    /// </summary>
    public static bool TryDeleteExactAndConfirmAbsent(string path, StagedStageIdentity expected,
        out Exception? failure, long? expectedLength = null)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(path);
        ArgumentNullException.ThrowIfNull(expected);
        path = Path.GetFullPath(path);
        failure = null;
        if (!OperatingSystem.IsWindows())
        {
            try
            {
                using var stage = OpenPortable(path, allowWriters: false);
                if (stage.Identity != expected || (expectedLength is { } exactLength &&
                    stage.Stream.Length != exactLength)) return false;
                stage.Dispose();
                File.Delete(path);
                return IsPathAbsent(path, out failure);
            }
            catch (FileNotFoundException) { return true; }
            catch (DirectoryNotFoundException) { return true; }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
            { failure = ex; return false; }
        }

        SafeFileHandle handle = CreateFile(path, GenericRead | DeleteAccess, 0,
            IntPtr.Zero, OpenExisting, OpenReparsePoint | SequentialScan, IntPtr.Zero);
        if (handle.IsInvalid)
        {
            int error = Marshal.GetLastWin32Error();
            handle.Dispose();
            if (error is 2 or 3) return true;
            failure = new IOException("The exact private stage could not be opened for deletion.",
                new Win32Exception(error));
            return false;
        }

        try
        {
            if (!TryReadFileIdentity(handle, requireSingleLink: true, out var actual) || actual != expected ||
                (expectedLength is { } exactLength &&
                 (!GetFileSizeEx(handle, out long actualLength) || actualLength != exactLength)))
                return false;
            var disposition = new FileDispositionInformation { DeleteFile = true };
            if (!SetFileInformationByHandle(handle, FileDispositionInfoClass, ref disposition,
                    Marshal.SizeOf<FileDispositionInformation>()))
            {
                failure = new IOException("The exact private stage could not be marked for deletion.",
                    new Win32Exception(Marshal.GetLastWin32Error()));
                return false;
            }
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            failure = ex;
            return false;
        }
        finally { handle.Dispose(); }

        return IsPathAbsent(path, out failure);
    }

    /// <summary>
    /// Confirms absence without treating access errors or an unknown object as
    /// successful cleanup. Callers that only have a legacy manifest without an
    /// identity may use this to accept an already-absent path, never to delete.
    /// </summary>
    public static bool TryConfirmAbsent(string path, out Exception? failure)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(path);
        return IsPathAbsent(Path.GetFullPath(path), out failure);
    }

    /// <summary>
    /// Removes a reservation-derived stage file that has no journal manifest.
    /// This is used only before an allocation reply exists, while the private
    /// staging directory is service-owned. It first opens without following
    /// the final reparse point and then deletes only the same single-link ID.
    /// </summary>
    public static bool TryDeleteUnjournaled(string path, out Exception? failure)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(path);
        path = Path.GetFullPath(path);
        failure = null;
        if (IsPathAbsent(path, out failure)) return true;
        if (failure is not null) return false;
        try
        {
            StagedStageIdentity identity;
            using (StagedStageFile stage = Open(path)) identity = stage.Identity;
            return TryDeleteExactAndConfirmAbsent(path, identity, out failure);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or
                                   System.ComponentModel.Win32Exception)
        {
            failure = ex;
            return false;
        }
    }

    private static StagedStageIdentity ReadWindowsDirectoryIdentity(string path)
    {
        using SafeFileHandle handle = CreateFile(path, FileReadAttributes,
            ShareRead | ShareDelete, IntPtr.Zero, OpenExisting,
            OpenReparsePoint | BackupSemantics, IntPtr.Zero);
        if (handle.IsInvalid) throw new IOException("The destination parent identity could not be opened.",
            new Win32Exception(Marshal.GetLastWin32Error()));
        if (!GetFileInformationByHandle(handle, out ByHandleFileInformation basic))
            throw new IOException("The destination parent identity could not be read.",
                new Win32Exception(Marshal.GetLastWin32Error()));
        if ((basic.Attributes & AttributeDirectory) == 0 || (basic.Attributes & AttributeReparsePoint) != 0)
            throw StagedRequestRefusal.Create("The destination parent must be a directory without reparse points.");
        if (!GetFileInformationByHandleEx(handle, FileIdInfoClass, out FileIdInfo fileId,
                checked((uint)Marshal.SizeOf<FileIdInfo>())))
            throw new IOException("The destination parent identity could not be verified.",
                new Win32Exception(Marshal.GetLastWin32Error()));
        return new StagedStageIdentity(fileId.VolumeSerialNumber, fileId.FileId.High, fileId.FileId.Low);
    }

    private static StagedStageIdentity ReadPortableDirectoryIdentity(string path)
    {
        long created = Directory.GetCreationTimeUtc(path).Ticks;
        byte[] digest = SHA256.HashData(Encoding.UTF8.GetBytes(Path.GetFullPath(path) + "\0" + created));
        return new StagedStageIdentity(0, BitConverter.ToUInt64(digest, 0), BitConverter.ToUInt64(digest, 8));
    }

    private static bool IsPathAbsent(string path, out Exception? failure)
    {
        failure = null;
        try { _ = File.GetAttributes(path); return false; }
        catch (FileNotFoundException) { return true; }
        catch (DirectoryNotFoundException) { return true; }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        { failure = ex; return false; }
    }

    private static bool TryReadFileIdentity(SafeFileHandle handle, bool requireSingleLink,
        out StagedStageIdentity identity)
    {
        identity = null!;
        if (!GetFileInformationByHandle(handle, out ByHandleFileInformation basic) ||
            (basic.Attributes & (AttributeDirectory | AttributeReparsePoint)) != 0 ||
            (requireSingleLink && basic.LinkCount != 1) ||
            !GetFileInformationByHandleEx(handle, FileIdInfoClass, out FileIdInfo fileId,
                checked((uint)Marshal.SizeOf<FileIdInfo>())))
            return false;
        identity = new StagedStageIdentity(fileId.VolumeSerialNumber,
            fileId.FileId.High, fileId.FileId.Low);
        return true;
    }

    private static StagedStageFile OpenWindows(string path, bool allowWriters)
    {
        uint share = ShareRead | ShareDelete | (allowWriters ? ShareWrite : 0);
        SafeFileHandle handle = CreateFile(path, GenericRead, share,
            IntPtr.Zero, OpenExisting, OpenReparsePoint | SequentialScan, IntPtr.Zero);
        if (handle.IsInvalid)
        {
            var error = new Win32Exception(Marshal.GetLastWin32Error());
            handle.Dispose();
            throw error.NativeErrorCode switch
            {
                2 => new FileNotFoundException("Private stage was not found.", path),
                3 => new DirectoryNotFoundException("Private stage directory was not found."),
                5 => new UnauthorizedAccessException("Private stage could not be opened.", error),
                _ => new IOException("Private stage could not be opened.", error)
            };
        }

        try
        {
            if (!GetFileInformationByHandle(handle, out ByHandleFileInformation basic))
                throw new IOException("Private stage identity could not be read.",
                    new Win32Exception(Marshal.GetLastWin32Error()));
            if ((basic.Attributes & (AttributeDirectory | AttributeReparsePoint)) != 0 || basic.LinkCount != 1)
                throw StagedRequestRefusal.Create("Private stage must be a single-link regular file without reparse points.");
            if (!GetFileInformationByHandleEx(handle, FileIdInfoClass, out FileIdInfo fileId,
                    checked((uint)Marshal.SizeOf<FileIdInfo>())))
                throw new IOException("Private stage FILE_ID_INFO could not be read.",
                    new Win32Exception(Marshal.GetLastWin32Error()));

            var identity = new StagedStageIdentity(fileId.VolumeSerialNumber,
                fileId.FileId.High, fileId.FileId.Low);
            return new StagedStageFile(new FileStream(handle, FileAccess.Read, 4096, isAsync: false), identity);
        }
        catch
        {
            handle.Dispose();
            throw;
        }
    }

    private static StagedStageFile OpenPortable(string path, bool allowWriters)
    {
        if ((File.GetAttributes(path) & (FileAttributes.Directory | FileAttributes.ReparsePoint)) != 0)
            throw StagedRequestRefusal.Create("Private stage must be a regular file without reparse points.");
        var stream = new FileStream(path, FileMode.Open, FileAccess.Read,
            FileShare.Read | FileShare.Delete | (allowWriters ? FileShare.Write : 0),
            4096, FileOptions.SequentialScan);
        try
        {
            // Developer-host fallback only. On Windows the exact object ID is
            // read from the opened handle through FILE_ID_INFO above.
            long created = File.GetCreationTimeUtc(path).Ticks;
            byte[] digest = SHA256.HashData(Encoding.UTF8.GetBytes(path + "\0" + created));
            return new StagedStageFile(stream, new StagedStageIdentity(0,
                BitConverter.ToUInt64(digest, 0), BitConverter.ToUInt64(digest, 8)));
        }
        catch
        {
            stream.Dispose();
            throw;
        }
    }

    public void Dispose() => Stream.Dispose();

    [StructLayout(LayoutKind.Sequential)]
    private struct ByHandleFileInformation
    {
        public uint Attributes;
        public System.Runtime.InteropServices.ComTypes.FILETIME CreationTime;
        public System.Runtime.InteropServices.ComTypes.FILETIME LastAccessTime;
        public System.Runtime.InteropServices.ComTypes.FILETIME LastWriteTime;
        public uint VolumeSerialNumber;
        public uint FileSizeHigh;
        public uint FileSizeLow;
        public uint LinkCount;
        public uint FileIndexHigh;
        public uint FileIndexLow;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct FileIdInfo
    {
        public ulong VolumeSerialNumber;
        public FileId128 FileId;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct FileId128
    {
        public ulong Low;
        public ulong High;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct FileDispositionInformation
    {
        [MarshalAs(UnmanagedType.U1)]
        public bool DeleteFile;
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
    private static extern bool GetFileSizeEx(SafeFileHandle file, out long fileSize);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool SetFileInformationByHandle(SafeFileHandle file,
        int informationClass, ref FileDispositionInformation information, int bufferSize);
}
