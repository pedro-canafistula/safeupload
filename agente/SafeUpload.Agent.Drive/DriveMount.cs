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
        IDriveObserver observer)
    {
        var fileSystem = new DriveFileSystem(destination, privateRoot, mountPoint, inspector, observer);
        var host = new FileSystemHost(fileSystem);
        int status = host.Mount(mountPoint, null, false, 0);
        if (status < 0)
        {
            host.Dispose();
            throw new IOException($"Cannot mount {mountPoint} (NTSTATUS 0x{status:X8}). Is WinFsp installed?");
        }
        fileSystem.StartBackgroundWork();
        DriveLog.Write($"mounted {mountPoint} -> {destination}");
        return new DriveMount(host, fileSystem, mountPoint, destination);
    }

    public void Dispose()
    {
        FileSystem.Stop();
        _host.Unmount();
        _host.Dispose();
        DriveLog.Write($"unmounted {MountPoint}");
    }
}
