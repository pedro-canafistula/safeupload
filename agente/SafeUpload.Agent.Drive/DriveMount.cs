using Fsp;

namespace SafeUpload.Agent.Drive;

/// <summary>One mounted SafeUpload drive: a drive letter in front of a destination folder.</summary>
public sealed class DriveMount : IDisposable
{
    private readonly FileSystemHost _host;

    public DriveFileSystem FileSystem { get; }
    public string MountPoint { get; }
    public string Destination { get; }

    private DriveMount(FileSystemHost host, DriveFileSystem fileSystem, string mountPoint, string destination)
    {
        _host = host;
        FileSystem = fileSystem;
        MountPoint = mountPoint;
        Destination = destination;
    }

    /// <summary>Mounts <paramref name="mountPoint"/> (for example "S:") in front of <paramref name="destination"/>.</summary>
    public static DriveMount Mount(string destination, string privateRoot, string mountPoint, ContentInspector inspector,
        IDriveObserver observer, SafeUpload.Agent.Core.Domain.DestinationKind kind, string label)
    {
        var fileSystem = new DriveFileSystem(destination, privateRoot, mountPoint, inspector, observer, kind, label);
        FileSystemHost? host = null;
        try
        {
            host = new FileSystemHost(fileSystem);
            int status = host.Mount(mountPoint, null, false, 0);
            if (status < 0)
                throw new IOException($"Cannot mount {mountPoint} (NTSTATUS 0x{status:X8}). Is WinFsp installed?");
            fileSystem.StartBackgroundWork();
            DriveLog.Write($"mounted {mountPoint} -> {destination}");
            return new DriveMount(host, fileSystem, mountPoint, destination);
        }
        catch
        {
            try { host?.Dispose(); }
            finally { fileSystem.Stop(); }
            throw;
        }
    }

    public void Dispose()
    {
        FileSystem.Stop();
        _host.Unmount();
        _host.Dispose();
        DriveLog.Write($"unmounted {MountPoint}");
    }
}
