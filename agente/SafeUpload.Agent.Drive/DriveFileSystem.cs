using System.Runtime.InteropServices;
using System.Security.AccessControl;
using Fsp;
using FileInfo = Fsp.Interop.FileInfo;
using VolumeInfo = Fsp.Interop.VolumeInfo;

namespace SafeUpload.Agent.Drive;

/// <summary>The bytes behind one file name: a published backing file, or a private stage file.</summary>
internal sealed class Content
{
    public required string Path;          // where the bytes are now
    public bool IsStage;                  // false: the published backing file itself
    public long Size;
    public long Version;                  // +1 on every modification
    public long InspectedVersion;         // newest version whose inspection was started
    public long ApprovedVersion = -1;     // newest version approved for the destination
    public string? ApprovedSnapshot;      // exact bytes of ApprovedVersion
    public DriveDecision? ApprovedDecision;
    public bool PublicationFailed;       // report a failed publication once, then retry the same snapshot
    public long PublishedVersion = -1;
    public string? PublishedPath;
    public bool Deleted;
    public Node? Node;
    public DriveWriter? Writer;           // who last opened the file for writing
    public Guid? BlockedId;               // newest blocked version, kept for a justification
    public long BlockedVersion = -1;
    public string? BlockedSnapshot;
    public DriveDecision? BlockedDecision;
    public DateTime LastModified;
    public bool CleanupSeen;              // a handle was closed since the last modification
    public bool Inspecting;
}

internal sealed class Node
{
    public required string Name;
    public Node? Parent;
    public bool IsDirectory;
    public Dictionary<string, Node>? Children;   // directories only; null until loaded from the backing folder
    public Content? Content;                     // files only
    public uint Attributes;
    public ulong CreationTime, LastAccessTime, LastWriteTime, ChangeTime;
    public ulong Id;
    public bool Private;                         // Windows housekeeping (indexer, recycle bin): never published
}

internal sealed class Handle
{
    public required Node Node;
    public FileStream? Stream;
    public bool Modified;
    public List<KeyValuePair<string, Node?>>? Listing;
}

/// <summary>
/// A WinFsp file system in front of one protected destination folder (the "backing" folder).
///
/// The namespace users see is kept in memory. A file that is created or opened for writing gets a private stage copy;
/// the backing folder only ever receives bytes that the inspector approved. When a modified file is closed, a snapshot
/// of it is inspected; the reconciler then makes the backing folder match the namespace, using approved snapshots for
/// changed files. A blocked or still-pending version leaves whatever the backing folder already has under that name.
/// Directory operations carry no content and go to the backing folder directly.
/// </summary>
public sealed class DriveFileSystem : FileSystemBase
{
    private const int AllocationUnit = 4096;
    private const string TempPrefix = ".~su-";
    private const uint FILE_WRITE_DATA = 0x0002, FILE_APPEND_DATA = 0x0004;
    private static readonly TimeSpan IdleInspectDelay = TimeSpan.FromSeconds(5);
    private static readonly TimeSpan InspectDelay = TimeSpan.FromMilliseconds(300);
    private static readonly TimeSpan ReconcileDelay = TimeSpan.FromSeconds(1);

    private readonly object _gate = new();
    private readonly string _backing, _stage, _snapshots, _mountPoint;
    private readonly ContentInspector _inspector;
    private readonly IDriveObserver _observer;
    private readonly SafeUpload.Agent.Core.Domain.DestinationKind _kind;
    private readonly string _label;
    private static readonly HashSet<string> PrivateRootNames = new(StringComparer.OrdinalIgnoreCase)
        { "System Volume Information", "$RECYCLE.BIN" };
    private readonly Dictionary<Guid, Content> _blocked = [];
    private readonly Node _root;
    private readonly byte[] _fileSecurity, _dirSecurity;
    private ulong _nextId = 1;
    private DateTime _reconcileAfter = DateTime.MaxValue;
    private readonly HashSet<Content> _dirty = [];   // modified since their last inspection
    private readonly CancellationTokenSource _stop = new();

    internal DriveFileSystem(string backing, string privateRoot, string mountPoint, ContentInspector inspector,
        IDriveObserver observer, SafeUpload.Agent.Core.Domain.DestinationKind kind, string label)
    {
        _observer = observer;
        _kind = kind;
        _label = label.Length <= 32 ? label : label[..32];
        _backing = System.IO.Path.GetFullPath(backing);
        if (_backing.Length > 3) _backing = _backing.TrimEnd('\\');   // keep "E:\" for a drive root
        _stage = System.IO.Path.Combine(privateRoot, "stage");
        _snapshots = System.IO.Path.Combine(privateRoot, "snapshots");
        _mountPoint = mountPoint.TrimEnd('\\');
        _inspector = inspector;
        Directory.CreateDirectory(_backing);
        Directory.CreateDirectory(_stage);
        Directory.CreateDirectory(_snapshots);
        _root = new Node { Name = "", IsDirectory = true, Id = _nextId++, Attributes = (uint)FileAttributes.Directory };
        StampNow(_root);
        // Every user may work in the drive; access to the backing folder itself is restricted separately.
        _fileSecurity = Sddl("O:SYG:SYD:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FA;;;AU)");
        _dirSecurity = Sddl("O:SYG:SYD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;AU)");
    }

    public void StartBackgroundWork() => new Thread(BackgroundLoop) { IsBackground = true, Name = "drive-worker" }.Start();
    public void Stop() => _stop.Cancel();

    // ---------------------------------------------------------------- WinFsp entry points

    public override int ExceptionHandler(Exception ex)
    {
        DriveLog.Write($"error {ex.GetType().Name}: {ex.Message}");
        int hresult = ex.HResult;
        if ((hresult & 0xFFFF0000) == 0x80070000)
            return NtStatusFromWin32((uint)hresult & 0xFFFF);
        return STATUS_UNEXPECTED_IO_ERROR;
    }

    public override int Init(object host0)
    {
        var host = (FileSystemHost)host0;
        host.SectorSize = AllocationUnit;
        host.SectorsPerAllocationUnit = 1;
        host.MaxComponentLength = 255;
        host.FileInfoTimeout = 1000;
        host.CaseSensitiveSearch = false;
        host.CasePreservedNames = true;
        host.UnicodeOnDisk = true;
        host.PersistentAcls = true;
        host.PostCleanupWhenModifiedOnly = false;
        host.PassQueryDirectoryPattern = false;
        host.FlushAndPurgeOnCleanup = true;
        host.FileSystemName = "NTFS";
        host.VolumeCreationTime = (ulong)DateTime.UtcNow.ToFileTimeUtc();
        host.VolumeSerialNumber = (uint)Environment.TickCount;
        return STATUS_SUCCESS;
    }

    public override int GetVolumeInfo(out VolumeInfo volumeInfo)
    {
        volumeInfo = default;
        // GetDiskFreeSpaceEx also works for network shares (\\server\share).
        if (GetDiskFreeSpaceEx(_backing, out _, out ulong total, out ulong free))
        {
            volumeInfo.TotalSize = total;
            volumeInfo.FreeSize = free;
        }
        volumeInfo.SetVolumeLabel(_label);
        return STATUS_SUCCESS;
    }

    public override int GetSecurityByName(string fileName, out uint fileAttributes, ref byte[] securityDescriptor)
    {
        lock (_gate)
        {
            var node = Lookup(fileName, out var parentMissing);
            if (node is null)
            {
                fileAttributes = 0;
                return parentMissing ? STATUS_OBJECT_PATH_NOT_FOUND : STATUS_OBJECT_NAME_NOT_FOUND;
            }
            fileAttributes = node.IsDirectory ? node.Attributes | (uint)FileAttributes.Directory : node.Attributes;
            if (securityDescriptor is not null)
                securityDescriptor = node.IsDirectory ? _dirSecurity : _fileSecurity;
            return STATUS_SUCCESS;
        }
    }

    public override int Create(string fileName, uint createOptions, uint grantedAccess, uint fileAttributes,
        byte[] securityDescriptor, ulong allocationSize, out object fileNode, out object fileDesc,
        out FileInfo fileInfo, out string normalizedName)
    {
        fileNode = default!; fileDesc = default!; fileInfo = default; normalizedName = default!;
        lock (_gate)
        {
            var (parent, leaf) = SplitParent(fileName);
            if (parent is null) return STATUS_OBJECT_PATH_NOT_FOUND;
            if (!parent.IsDirectory) return STATUS_NOT_A_DIRECTORY;
            EnsureLoaded(parent);
            if (parent.Children!.ContainsKey(leaf)) return STATUS_OBJECT_NAME_COLLISION;

            var node = new Node { Name = leaf, Parent = parent, Id = _nextId++,
                Private = parent.Private || (parent == _root && PrivateRootNames.Contains(leaf)) };
            StampNow(node);
            Handle handle;
            if ((createOptions & FILE_DIRECTORY_FILE) != 0)
            {
                if (!node.Private) Directory.CreateDirectory(BackingPath(parent, leaf));
                node.IsDirectory = true;
                node.Children = new(StringComparer.OrdinalIgnoreCase);
                node.Attributes = fileAttributes | (uint)FileAttributes.Directory;
                handle = new Handle { Node = node };
            }
            else
            {
                var stagePath = NewStagePath();
                var stream = new FileStream(stagePath, FileMode.CreateNew, FileAccess.ReadWrite,
                    FileShare.ReadWrite | FileShare.Delete);
                node.Attributes = (fileAttributes & ~(uint)FileAttributes.Normal) | (uint)FileAttributes.Archive;
                node.Content = new Content { Path = stagePath, IsStage = true, Node = node };
                node.Content.Writer = _observer.IdentifyWriter((int)GetOperationProcessId());
                handle = new Handle { Node = node, Stream = stream };
                Modified(handle, 0);   // a new file, even an empty one, is a version to inspect
            }
            parent.Children[leaf] = node;
            DriveLog.Write($"create {VirtualPath(node)}{(node.IsDirectory ? "\\" : "")} pid={GetOperationProcessId()}");
            fileDesc = handle;
            fileInfo = Info(node);
            return STATUS_SUCCESS;
        }
    }

    public override int Open(string fileName, uint createOptions, uint grantedAccess, out object fileNode,
        out object fileDesc, out FileInfo fileInfo, out string normalizedName)
    {
        fileNode = default!; fileDesc = default!; fileInfo = default; normalizedName = default!;
        lock (_gate)
        {
            var node = Lookup(fileName, out var parentMissing);
            if (node is null) return parentMissing ? STATUS_OBJECT_PATH_NOT_FOUND : STATUS_OBJECT_NAME_NOT_FOUND;
            var handle = new Handle { Node = node };
            if (!node.IsDirectory)
            {
                // Word opens documents with write access and often never writes: the private stage copy is made on
                // the first real modification (WritableStream), not here.
                handle.Stream = OpenShared(node.Content!.Path, write: false);
                if ((grantedAccess & (FILE_WRITE_DATA | FILE_APPEND_DATA)) != 0)
                    node.Content.Writer = _observer.IdentifyWriter((int)GetOperationProcessId());
            }
            fileDesc = handle;
            fileInfo = Info(node);
            return STATUS_SUCCESS;
        }
    }

    public override int Overwrite(object fileNode, object fileDesc, uint fileAttributes, bool replaceFileAttributes,
        ulong allocationSize, out FileInfo fileInfo)
    {
        lock (_gate)
        {
            var handle = (Handle)fileDesc;
            var node = handle.Node;
            if (replaceFileAttributes)
                node.Attributes = (fileAttributes & ~(uint)FileAttributes.Normal) | (uint)FileAttributes.Archive;
            else if (fileAttributes != 0)
                node.Attributes = (node.Attributes | fileAttributes | (uint)FileAttributes.Archive) & ~(uint)FileAttributes.Normal;
            WritableStream(handle, emptyCopy: true).SetLength(0);
            Modified(handle, 0);
            fileInfo = Info(node);
            return STATUS_SUCCESS;
        }
    }

    public override void Cleanup(object fileNode, object fileDesc, string fileName, uint flags)
    {
        lock (_gate)
        {
            var handle = (Handle)fileDesc;
            var node = handle.Node;
            if ((flags & CleanupSetLastWriteTime) != 0) node.LastWriteTime = node.ChangeTime = Now();
            if ((flags & CleanupDelete) != 0)
            {
                Delete(node);
                return;
            }
            // Cached writes can reach us through another handle (the cache's), so track changes per file, not per handle.
            if (node.Content is { Deleted: false } content && content.Version != content.InspectedVersion)
                content.CleanupSeen = true;
        }
    }

    public override void Close(object fileNode, object fileDesc)
    {
        lock (_gate)
            ((Handle)fileDesc).Stream?.Dispose();
    }

    public override int Read(object fileNode, object fileDesc, IntPtr buffer, ulong offset, uint length,
        out uint bytesTransferred)
    {
        lock (_gate)
        {
            var stream = CurrentStream((Handle)fileDesc);
            if (offset >= (ulong)stream.Length)
            {
                bytesTransferred = 0;
                return STATUS_END_OF_FILE;
            }
            var bytes = new byte[length];
            stream.Seek((long)offset, SeekOrigin.Begin);
            int read = stream.Read(bytes, 0, bytes.Length);
            Marshal.Copy(bytes, 0, buffer, read);
            bytesTransferred = (uint)read;
            return STATUS_SUCCESS;
        }
    }

    public override int Write(object fileNode, object fileDesc, IntPtr buffer, ulong offset, uint length,
        bool writeToEndOfFile, bool constrainedIo, out uint bytesTransferred, out FileInfo fileInfo)
    {
        lock (_gate)
        {
            var handle = (Handle)fileDesc;
            var stream = WritableStream(handle, emptyCopy: false);
            if (constrainedIo)
            {
                if (offset >= (ulong)stream.Length)
                {
                    bytesTransferred = 0;
                    fileInfo = Info(handle.Node);
                    return STATUS_SUCCESS;
                }
                if (offset + length > (ulong)stream.Length)
                    length = (uint)((ulong)stream.Length - offset);
            }
            var bytes = new byte[length];
            Marshal.Copy(buffer, bytes, 0, bytes.Length);
            stream.Seek(writeToEndOfFile ? stream.Length : (long)offset, SeekOrigin.Begin);
            stream.Write(bytes, 0, bytes.Length);
            bytesTransferred = length;
            Modified(handle, stream.Length);
            fileInfo = Info(handle.Node);
            return STATUS_SUCCESS;
        }
    }

    public override int Flush(object fileNode, object fileDesc, out FileInfo fileInfo)
    {
        lock (_gate)
        {
            if (fileDesc is not Handle handle)
            {
                fileInfo = default;
                return STATUS_SUCCESS;
            }
            handle.Stream?.Flush(true);
            fileInfo = Info(handle.Node);
            return STATUS_SUCCESS;
        }
    }

    public override int GetFileInfo(object fileNode, object fileDesc, out FileInfo fileInfo)
    {
        lock (_gate)
        {
            fileInfo = Info(((Handle)fileDesc).Node);
            return STATUS_SUCCESS;
        }
    }

    public override int SetBasicInfo(object fileNode, object fileDesc, uint fileAttributes, ulong creationTime,
        ulong lastAccessTime, ulong lastWriteTime, ulong changeTime, out FileInfo fileInfo)
    {
        lock (_gate)
        {
            var node = ((Handle)fileDesc).Node;
            if (fileAttributes != unchecked((uint)-1))
                node.Attributes = node.IsDirectory ? fileAttributes | (uint)FileAttributes.Directory
                    : fileAttributes & ~(uint)FileAttributes.Normal;
            if (creationTime != 0) node.CreationTime = creationTime;
            if (lastAccessTime != 0) node.LastAccessTime = lastAccessTime;
            if (lastWriteTime != 0) node.LastWriteTime = lastWriteTime;
            if (changeTime != 0) node.ChangeTime = changeTime;
            if (node.Content is { IsStage: false })
                ScheduleReconcile();   // metadata of a published file: copied to the backing file on reconcile
            fileInfo = Info(node);
            return STATUS_SUCCESS;
        }
    }

    public override int SetFileSize(object fileNode, object fileDesc, ulong newSize, bool setAllocationSize,
        out FileInfo fileInfo)
    {
        lock (_gate)
        {
            var handle = (Handle)fileDesc;
            var stream = CurrentStream(handle);
            if (!setAllocationSize || (ulong)stream.Length > newSize)
            {
                if ((ulong)stream.Length != newSize)
                {
                    stream = WritableStream(handle, emptyCopy: newSize == 0);
                    stream.SetLength((long)newSize);
                    Modified(handle, (long)newSize);
                }
            }
            fileInfo = Info(handle.Node);
            return STATUS_SUCCESS;
        }
    }

    public override int CanDelete(object fileNode, object fileDesc, string fileName)
    {
        lock (_gate)
        {
            var node = ((Handle)fileDesc).Node;
            if (node == _root) return STATUS_ACCESS_DENIED;
            if (node.IsDirectory)
            {
                EnsureLoaded(node);
                if (node.Children!.Count > 0) return STATUS_DIRECTORY_NOT_EMPTY;
            }
            return STATUS_SUCCESS;
        }
    }

    public override int Rename(object fileNode, object fileDesc, string fileName, string newFileName, bool replaceIfExists)
    {
        lock (_gate)
        {
            var node = ((Handle)fileDesc).Node;
            var (newParent, newLeaf) = SplitParent(newFileName);
            if (newParent is null || !newParent.IsDirectory) return STATUS_OBJECT_PATH_NOT_FOUND;
            EnsureLoaded(newParent);
            if (newParent.Children!.TryGetValue(newLeaf, out var target) && target != node)
            {
                if (!replaceIfExists) return STATUS_OBJECT_NAME_COLLISION;
                if (target.IsDirectory) return STATUS_ACCESS_DENIED;
                Delete(target);
            }
            var oldPath = VirtualPath(node);
            if (node.IsDirectory && !node.Private)
            {
                // No content to inspect: move the backing directory now and re-point published files under it.
                var oldBacking = BackingPath(node.Parent!, node.Name);
                var newBacking = BackingPath(newParent, newLeaf);
                if (!string.Equals(oldBacking, newBacking, StringComparison.Ordinal))
                {
                    Directory.Move(oldBacking, newBacking);
                    RebaseBackingPaths(node, oldBacking, newBacking);
                }
            }
            node.Parent!.Children!.Remove(node.Name);
            node.Name = newLeaf;
            node.Parent = newParent;
            newParent.Children[newLeaf] = node;
            node.ChangeTime = Now();
            DriveLog.Write($"rename {oldPath} -> {VirtualPath(node)}");
            ScheduleReconcile();
            return STATUS_SUCCESS;
        }
    }

    public override int GetSecurity(object fileNode, object fileDesc, ref byte[] securityDescriptor)
    {
        securityDescriptor = ((Handle)fileDesc).Node.IsDirectory ? _dirSecurity : _fileSecurity;
        return STATUS_SUCCESS;
    }

    public override int SetSecurity(object fileNode, object fileDesc, AccessControlSections sections,
        byte[] securityDescriptor) => STATUS_SUCCESS;

    public override bool ReadDirectoryEntry(object fileNode, object fileDesc, string pattern, string marker,
        ref object context, out string fileName, out FileInfo fileInfo)
    {
        lock (_gate)
        {
            var handle = (Handle)fileDesc;
            var dir = handle.Node;
            if (handle.Listing is null || (context is null && marker is null))
            {
                EnsureLoaded(dir);
                var list = new List<KeyValuePair<string, Node?>>();
                if (dir != _root)
                {
                    list.Add(new(".", dir));
                    list.Add(new("..", dir.Parent));
                }
                list.AddRange(dir.Children!.Values.OrderBy(n => n.Name, StringComparer.OrdinalIgnoreCase)
                    .Select(n => new KeyValuePair<string, Node?>(n.Name, n)));
                handle.Listing = list;
            }
            int index;
            if (context is null)
            {
                index = 0;
                if (marker is not null)
                {
                    index = handle.Listing.FindIndex(e => string.Equals(e.Key, marker, StringComparison.OrdinalIgnoreCase));
                    index = index < 0 ? handle.Listing.Count : index + 1;
                }
            }
            else
                index = (int)context;
            if (index < handle.Listing.Count)
            {
                context = index + 1;
                fileName = handle.Listing[index].Key;
                fileInfo = Info(handle.Listing[index].Value ?? _root);
                return true;
            }
            fileName = default!;
            fileInfo = default;
            return false;
        }
    }

    // ---------------------------------------------------------------- namespace helpers

    private Node? Lookup(string fileName, out bool parentMissing)
    {
        parentMissing = false;
        var node = _root;
        var parts = fileName.Split('\\', StringSplitOptions.RemoveEmptyEntries);
        for (int i = 0; i < parts.Length; i++)
        {
            if (!node.IsDirectory) { parentMissing = true; return null; }
            EnsureLoaded(node);
            if (!node.Children!.TryGetValue(parts[i], out var next))
            {
                parentMissing = i < parts.Length - 1;
                return null;
            }
            node = next;
        }
        return node;
    }

    private (Node? Parent, string Leaf) SplitParent(string fileName)
    {
        var trimmed = fileName.TrimEnd('\\');
        int cut = trimmed.LastIndexOf('\\');
        var leaf = trimmed[(cut + 1)..];
        var parent = cut <= 0 ? _root : Lookup(trimmed[..cut], out _);
        return (parent, leaf);
    }

    private void EnsureLoaded(Node dir)
    {
        if (dir.Children is not null) return;
        dir.Children = new(StringComparer.OrdinalIgnoreCase);
        var path = BackingDirectory(dir);
        if (!Directory.Exists(path)) return;
        foreach (var info in new DirectoryInfo(path).EnumerateFileSystemInfos())
        {
            if (info.Name.StartsWith(TempPrefix, StringComparison.Ordinal)) continue;
            if (dir == _root && PrivateRootNames.Contains(info.Name)) continue;
            var node = new Node
            {
                Name = info.Name, Parent = dir, Id = _nextId++, Attributes = (uint)info.Attributes,
                CreationTime = (ulong)info.CreationTimeUtc.ToFileTimeUtc(),
                LastAccessTime = (ulong)info.LastAccessTimeUtc.ToFileTimeUtc(),
                LastWriteTime = (ulong)info.LastWriteTimeUtc.ToFileTimeUtc(),
                ChangeTime = (ulong)info.LastWriteTimeUtc.ToFileTimeUtc(),
            };
            if (info is DirectoryInfo)
                node.IsDirectory = true;
            else
                node.Content = new Content
                {
                    Path = info.FullName, Size = ((System.IO.FileInfo)info).Length, Node = node,
                    ApprovedVersion = 0, PublishedVersion = 0, PublishedPath = info.FullName,
                };
            dir.Children[info.Name] = node;
        }
    }

    /// <summary>The handle's stream on the file's current bytes (another handle may have made a stage copy).</summary>
    private static FileStream CurrentStream(Handle handle)
    {
        var path = handle.Node.Content!.Path;
        if (!string.Equals(handle.Stream!.Name, path, StringComparison.OrdinalIgnoreCase))
        {
            bool write = handle.Stream.CanWrite;
            handle.Stream.Dispose();
            handle.Stream = OpenShared(path, write);
        }
        return handle.Stream;
    }

    /// <summary>A writable stream on the file's private stage copy, making that copy on the first modification.</summary>
    private FileStream WritableStream(Handle handle, bool emptyCopy)
    {
        var content = handle.Node.Content!;
        if (!content.IsStage)
        {
            var stagePath = NewStagePath();
            if (emptyCopy) File.Create(stagePath).Dispose();
            else CopyShared(content.Path, stagePath);
            content.Path = stagePath;
            content.IsStage = true;
        }
        if (!handle.Stream!.CanWrite || !string.Equals(handle.Stream.Name, content.Path, StringComparison.OrdinalIgnoreCase))
        {
            handle.Stream.Dispose();
            handle.Stream = OpenShared(content.Path, write: true);
        }
        return handle.Stream;
    }

    private static FileStream OpenShared(string path, bool write) =>
        new(path, FileMode.Open, write ? FileAccess.ReadWrite : FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);

    /// <summary>File.Copy refuses a source that is open for writing; our own handles keep stage files open.</summary>
    private static void CopyShared(string source, string destination)
    {
        using var input = OpenShared(source, write: false);
        using var output = new FileStream(destination, FileMode.CreateNew, FileAccess.Write, FileShare.None);
        input.CopyTo(output);
    }

    private void Modified(Handle handle, long size)
    {
        var content = handle.Node.Content!;
        content.Size = size;
        content.Version++;
        content.LastModified = DateTime.UtcNow;
        _dirty.Add(content);
        handle.Modified = true;
        handle.Node.LastWriteTime = handle.Node.ChangeTime = Now();
    }

    private void Delete(Node node)
    {
        var path = VirtualPath(node);
        node.Parent?.Children?.Remove(node.Name);
        if (node.IsDirectory && !node.Private)
        {
            Reconcile();   // the backing folder may still hold files the namespace already removed
            var backing = BackingPath(node.Parent!, node.Name);
            if (Directory.Exists(backing)) Directory.Delete(backing, recursive: false);
        }
        else if (node.Content is { } content)
        {
            content.Deleted = true;
            _dirty.Remove(content);
            ForgetBlocked(content);
            if (content.IsStage) TryDelete(content.Path);
            ScheduleReconcile();
        }
        DriveLog.Write($"delete {path}");
    }

    private void RebaseBackingPaths(Node dir, string oldBacking, string newBacking)
    {
        if (dir.Children is null) return;
        foreach (var child in dir.Children.Values)
        {
            if (child.IsDirectory) RebaseBackingPaths(child, oldBacking, newBacking);
            else if (child.Content is { IsStage: false } c && c.Path.StartsWith(oldBacking + "\\", StringComparison.OrdinalIgnoreCase))
                c.Path = newBacking + c.Path[oldBacking.Length..];
            if (child.Content?.PublishedPath is { } p && p.StartsWith(oldBacking + "\\", StringComparison.OrdinalIgnoreCase))
                child.Content.PublishedPath = newBacking + p[oldBacking.Length..];
        }
    }

    private string Relative(Node node)
    {
        var parts = new Stack<string>();
        for (var n = node; n is not null && n != _root; n = n.Parent) parts.Push(n.Name);
        return string.Join("\\", parts);
    }

    private string BackingDirectory(Node dir) => dir == _root ? _backing : System.IO.Path.Combine(_backing, Relative(dir));
    private string BackingPath(Node parent, string leaf) => System.IO.Path.Combine(BackingDirectory(parent), leaf);
    private string VirtualPath(Node node) => _mountPoint + "\\" + Relative(node);
    private string NewStagePath() => System.IO.Path.Combine(_stage, Guid.NewGuid().ToString("N"));

    private FileInfo Info(Node node)
    {
        var info = default(FileInfo);
        info.FileAttributes = node.IsDirectory ? node.Attributes | (uint)FileAttributes.Directory
            : node.Attributes == 0 ? (uint)FileAttributes.Normal : node.Attributes;
        info.FileSize = node.IsDirectory ? 0 : (ulong)node.Content!.Size;
        info.AllocationSize = (info.FileSize + AllocationUnit - 1) / AllocationUnit * AllocationUnit;
        info.CreationTime = node.CreationTime;
        info.LastAccessTime = node.LastAccessTime;
        info.LastWriteTime = node.LastWriteTime;
        info.ChangeTime = node.ChangeTime;
        info.IndexNumber = node.Id;
        info.HardLinks = 0;
        return info;
    }

    private static ulong Now() => (ulong)DateTime.UtcNow.ToFileTimeUtc();
    private static void StampNow(Node node) => node.CreationTime = node.LastAccessTime = node.LastWriteTime = node.ChangeTime = Now();

    private static byte[] Sddl(string sddl)
    {
        var descriptor = new RawSecurityDescriptor(sddl);
        var bytes = new byte[descriptor.BinaryLength];
        descriptor.GetBinaryForm(bytes, 0);
        return bytes;
    }

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern bool GetDiskFreeSpaceEx(string directory, out ulong freeForCaller, out ulong total, out ulong free);

    private static void TryDelete(string path)
    {
        try { File.Delete(path); } catch (IOException) { } catch (UnauthorizedAccessException) { }
    }

    // ---------------------------------------------------------------- inspection and publication

    private void ScheduleReconcile()
    {
        var due = DateTime.UtcNow + ReconcileDelay;
        if (due < _reconcileAfter || _reconcileAfter == DateTime.MaxValue) _reconcileAfter = due;
    }

    private void BackgroundLoop()
    {
        while (!_stop.IsCancellationRequested)
        {
            try
            {
                Content? next = null;
                lock (_gate)
                {
                    var now = DateTime.UtcNow;
                    // Inspect soon after a close; inspect a file that stays open after it has been quiet for a while.
                    next = _dirty.FirstOrDefault(c => !c.Inspecting &&
                        c.LastModified + (c.CleanupSeen ? InspectDelay : IdleInspectDelay) <= now);
                    if (next is null && _reconcileAfter <= now)
                    {
                        _reconcileAfter = DateTime.MaxValue;
                        try { Reconcile(); }
                        catch (Exception error) when (error is IOException or UnauthorizedAccessException)
                        {
                            // For example the destination file is open elsewhere: nothing unapproved was written; retry.
                            DriveLog.Write($"publish retry: {error.Message}");
                            _reconcileAfter = DateTime.UtcNow + TimeSpan.FromSeconds(5);
                        }
                    }
                }
                if (next is not null) InspectOne(next);
                else Thread.Sleep(100);
            }
            catch (Exception error)
            {
                DriveLog.Write($"worker error {error.GetType().Name}: {error.Message}");
                Thread.Sleep(500);
            }
        }
    }

    private void InspectOne(Content content)
    {
        string snapshot, destination, target, name;
        long version;
        DriveWriter? writer;
        var versionId = Guid.NewGuid();
        lock (_gate)
        {
            _dirty.Remove(content);
            content.CleanupSeen = false;
            if (content.Deleted || content.Node is null || content.Node.Private || content.Version == content.InspectedVersion) return;
            // A snapshot taken under the lock is a consistent version: writes take the same lock.
            snapshot = System.IO.Path.Combine(_snapshots, Guid.NewGuid().ToString("N"));
            CopyShared(content.Path, snapshot);
            version = content.InspectedVersion = content.Version;
            destination = VirtualPath(content.Node);
            target = BackingPath(content.Node.Parent!, content.Node.Name);
            name = content.Node.Name;
            writer = content.Writer;
            content.Inspecting = true;
        }
        var started = DateTime.UtcNow;
        var outcome = _inspector.InspectAsync(snapshot, target, _kind, name, writer, _stop.Token).GetAwaiter().GetResult();
        var decision = new DriveDecision(versionId, destination, name, writer, outcome.Operation, outcome.Result,
            outcome.Publish, outcome.Summary, snapshot);
        bool report = false;
        lock (_gate)
        {
            content.Inspecting = false;
            var ms = (int)(DateTime.UtcNow - started).TotalMilliseconds;
            if (outcome.Publish && !content.Deleted && version > content.ApprovedVersion)
            {
                if (content.ApprovedSnapshot is not null) TryDelete(content.ApprovedSnapshot);
                content.ApprovedVersion = version;
                content.ApprovedSnapshot = snapshot;
                content.ApprovedDecision = decision;
                content.PublicationFailed = false;
                DriveLog.Write($"inspect APPROVED {destination} v{version} {outcome.Summary} ({ms} ms)");
                ScheduleReconcile();
                report = true;
            }
            else if (!outcome.Publish && !content.Deleted && version > content.BlockedVersion)
            {
                ForgetBlocked(content);
                content.BlockedId = versionId;
                content.BlockedVersion = version;
                content.BlockedSnapshot = snapshot;
                content.BlockedDecision = decision;
                _blocked[versionId] = content;
                DriveLog.Write($"inspect BLOCKED {destination} v{version} {outcome.Summary} ({ms} ms)");
                report = true;
            }
            else
            {
                TryDelete(snapshot);
                DriveLog.Write($"inspect SUPERSEDED {destination} v{version} {outcome.Summary} ({ms} ms)");
            }
            // A write that arrived during inspection is inspected after its own close.
        }
        if (report)
            _observer.OnDecision(decision);
    }

    /// <summary>
    /// Queues a blocked version for publication after authorization. Only that exact version, and only if no newer
    /// version has been approved since. A true result acknowledges queuing, not a completed destination write.
    /// </summary>
    public bool Approve(Guid versionId, DriveApprovalKind kind = DriveApprovalKind.Justification)
    {
        lock (_gate)
        {
            if (!_blocked.TryGetValue(versionId, out var content) || content.Deleted || content.BlockedSnapshot is null ||
                content.BlockedVersion <= content.ApprovedVersion || kind is not (DriveApprovalKind.Audit or DriveApprovalKind.Justification) ||
                content.BlockedDecision is not { } blocked || content.Node?.Parent is null || _stop.IsCancellationRequested)
                return false;
            var approved = blocked with { Approved = true, ApprovalKind = kind };
            try
            {
                if (!_inspector.IsPublicationAllowedAsync(approved, BackingPath(content.Node.Parent, content.Node.Name),
                        _stop.Token).GetAwaiter().GetResult()) return false;
            }
            catch (Exception error)
            {
                DriveLog.Write($"approval held: policy validation {error.GetType().Name}");
                return false;
            }
            if (content.ApprovedSnapshot is not null) TryDelete(content.ApprovedSnapshot);
            content.ApprovedVersion = content.BlockedVersion;
            content.ApprovedSnapshot = content.BlockedSnapshot;
            content.ApprovedDecision = approved;
            content.PublicationFailed = false;
            content.BlockedSnapshot = null;
            ForgetBlocked(content);
            DriveLog.Write($"justified {(content.Node is null ? "?" : VirtualPath(content.Node))} v{content.ApprovedVersion}");
            ScheduleReconcile();
            return true;
        }
    }

    private void ForgetBlocked(Content content)
    {
        if (content.BlockedId is { } id) _blocked.Remove(id);
        if (content.BlockedSnapshot is not null) TryDelete(content.BlockedSnapshot);
        content.BlockedId = null;
        content.BlockedSnapshot = null;
        content.BlockedDecision = null;
    }

    /// <summary>Makes the backing folder match the namespace, using only approved bytes. Caller holds the lock.</summary>
    private void Reconcile()
    {
        var referenced = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        CollectReferenced(_root, referenced);
        ReconcileDirectory(_root, referenced);
    }

    private static void CollectReferenced(Node dir, HashSet<string> referenced)
    {
        if (dir.Children is null) return;
        foreach (var child in dir.Children.Values)
        {
            if (child.IsDirectory) CollectReferenced(child, referenced);
            else if (child.Content is { IsStage: false } c) referenced.Add(c.Path);
        }
    }

    private void ReconcileDirectory(Node dir, HashSet<string> referenced)
    {
        if (dir.Children is null) return;   // never loaded: nothing changed below it
        var folder = BackingDirectory(dir);
        Directory.CreateDirectory(folder);
        var keep = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var child in dir.Children.Values)
        {
            if (child.Private) continue;
            keep.Add(child.Name);
            if (child.IsDirectory) { ReconcileDirectory(child, referenced); continue; }
            var content = child.Content!;
            var target = System.IO.Path.Combine(folder, child.Name);
            if (!content.IsStage)
            {
                if (!string.Equals(content.Path, target, StringComparison.OrdinalIgnoreCase) && File.Exists(content.Path))
                {
                    // A published file that was renamed. Copy instead of moving if its old name must stay as it is
                    // (for example the previous version of a document whose new version is still pending).
                    var oldName = System.IO.Path.GetFileName(content.Path);
                    bool oldNameKept = string.Equals(System.IO.Path.GetDirectoryName(content.Path), folder, StringComparison.OrdinalIgnoreCase)
                        && dir.Children.ContainsKey(oldName);
                    if (oldNameKept) File.Copy(content.Path, target, overwrite: true);
                    else File.Move(content.Path, target, overwrite: true);
                    DriveLog.Write($"publish rename {content.Path} -> {target}");
                    content.Path = content.PublishedPath = target;
                }
                ApplyMetadata(child, target);
            }
            else if (content.ApprovedSnapshot is not null &&
                     (content.PublishedVersion != content.ApprovedVersion ||
                      !string.Equals(content.PublishedPath, target, StringComparison.OrdinalIgnoreCase)))
            {
                if (!ValidatePublication(child, target)) continue;
                var temp = System.IO.Path.Combine(folder, TempPrefix + Guid.NewGuid().ToString("N"));
                try
                {
                    File.Copy(content.ApprovedSnapshot, temp);
                    if (!ValidatePublication(child, target)) continue;
                    File.Move(temp, target, overwrite: true);
                }
                catch (Exception error) when (error is IOException or UnauthorizedAccessException)
                {
                    if (!content.PublicationFailed)
                    {
                        content.PublicationFailed = true;
                        ReportPublication(child, target, succeeded: false);
                    }
                    throw;
                }
                finally { TryDelete(temp); }
                content.PublishedVersion = content.ApprovedVersion;
                content.PublishedPath = target;
                content.PublicationFailed = false;
                ReportPublication(child, target, succeeded: true);
                ApplyMetadata(child, target);
                DriveLog.Write($"publish {target} v{content.ApprovedVersion}");
            }
        }
        foreach (var file in Directory.EnumerateFiles(folder))
        {
            var name = System.IO.Path.GetFileName(file);
            if (keep.Contains(name) || referenced.Contains(file)) continue;
            File.Delete(file);
            DriveLog.Write($"publish delete {file}");
        }
    }

    private bool ValidatePublication(Node node, string target)
    {
        if (_stop.IsCancellationRequested) return false;
        var content = node.Content!;
        try
        {
            if (content.ApprovedDecision is { } decision &&
                _inspector.IsPublicationAllowedAsync(decision, target, _stop.Token).GetAwaiter().GetResult()) return true;
        }
        catch (Exception error)
        {
            // An unreadable policy does not revoke the retained snapshot; retry without silently granting authority.
            DriveLog.Write($"publish held: policy validation {error.GetType().Name}");
            _reconcileAfter = DateTime.UtcNow + TimeSpan.FromSeconds(5);
            return false;
        }
        // The bytes remain in the private stage. Invalidate old approvals/justifications and inspect the current
        // version again, even when neither the file version nor the human-assigned policy number changed.
        if (content.ApprovedSnapshot is { } snapshot) TryDelete(snapshot);
        content.ApprovedSnapshot = null;
        content.ApprovedDecision = null;
        content.ApprovedVersion = -1;
        content.PublicationFailed = false;
        ForgetBlocked(content);
        content.BlockedVersion = -1;
        content.InspectedVersion = -1;
        content.CleanupSeen = true;
        content.LastModified = DateTime.UtcNow;
        _dirty.Add(content);
        DriveLog.Write("publish held: policy changed; stage queued for inspection");
        return false;
    }

    private void ReportPublication(Node node, string target, bool succeeded)
    {
        if (node.Content?.ApprovedDecision is not { } decision) return;
        // A file may have acquired its final Office name since inspection. Report the destination actually attempted.
        decision = decision with { DrivePath = VirtualPath(node), FileName = node.Name };
        _observer.OnPublication(new DrivePublication(Guid.NewGuid(), decision, target, succeeded));
    }

    private static void ApplyMetadata(Node node, string path)
    {
        try
        {
            File.SetAttributes(path, (FileAttributes)(node.Attributes & ~(uint)FileAttributes.ReadOnly) & ~FileAttributes.Directory);
            File.SetCreationTimeUtc(path, DateTime.FromFileTimeUtc((long)node.CreationTime));
            File.SetLastWriteTimeUtc(path, DateTime.FromFileTimeUtc((long)node.LastWriteTime));
            if ((node.Attributes & (uint)FileAttributes.ReadOnly) != 0)
                File.SetAttributes(path, File.GetAttributes(path) | FileAttributes.ReadOnly);
        }
        catch (Exception error) when (error is IOException or UnauthorizedAccessException or ArgumentException)
        {
            DriveLog.Write($"metadata {path}: {error.Message}");
        }
    }
}
