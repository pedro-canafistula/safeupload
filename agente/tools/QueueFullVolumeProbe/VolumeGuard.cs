using System.Runtime.InteropServices;
using System.Text;

namespace SafeUpload.Agent.QueueFullVolumeProbe;

public static class VolumeGuard
{
    public const long MinimumBytes = 32L * 1024 * 1024;
    public const long MaximumBytes = 80L * 1024 * 1024;

    public static void ValidateRequest(string root, string nonce, string volumeId, string output)
    {
        if (!OperatingSystem.IsWindows()) throw new PlatformNotSupportedException();
        if (root.Length != 3 || !char.IsAsciiLetter(root[0]) || root[1..] != @":\" ||
            root.Equals(Path.GetPathRoot(Environment.SystemDirectory), StringComparison.OrdinalIgnoreCase))
            throw new ArgumentException("A separate disposable drive root is required.");
        if (!Guid.TryParseExact(nonce, "N", out _) ||
            !volumeId.StartsWith(@"\\?\Volume{", StringComparison.OrdinalIgnoreCase) ||
            !volumeId.EndsWith(@"}\", StringComparison.Ordinal) ||
            !Guid.TryParse(volumeId[11..^2], out _))
            throw new ArgumentException("Invalid disposable volume identity.");
        if (!Path.IsPathFullyQualified(output) ||
            Path.GetPathRoot(output)!.Equals(root, StringComparison.OrdinalIgnoreCase) ||
            Directory.Exists(output) || File.Exists(output))
            throw new ArgumentException("Results must use a fresh directory outside the volume.");
        var data = Path.GetFullPath(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "SafeUpload"));
        var full = Path.GetFullPath(output);
        if (full.Equals(data, StringComparison.OrdinalIgnoreCase) || full.StartsWith(data + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase))
            throw new ArgumentException("Production data is not a probe destination.");
        for (var parent = new DirectoryInfo(full).Parent; parent is not null; parent = parent.Parent)
            if (parent.Exists && (parent.Attributes & FileAttributes.ReparsePoint) != 0)
                throw new ArgumentException("Result ancestors cannot redirect writes.");
    }

    public static void ValidateGeometry(string format, DriveType type, long bytes, string label, string nonce)
    {
        if (format != "NTFS" || type != DriveType.Fixed || bytes < MinimumBytes || bytes > MaximumBytes || label != "SUQ" + nonce[..12])
            throw new InvalidOperationException("Only the identified small NTFS test volume can be filled.");
    }

    public static void VerifyMounted(string root, string nonce, string expectedVolumeId)
    {
        var name = new StringBuilder(128);
        if (!GetVolumeNameForVolumeMountPoint(root, name, name.Capacity) ||
            !name.ToString().Equals(expectedVolumeId, StringComparison.OrdinalIgnoreCase))
            throw new InvalidOperationException("Mounted volume identity changed.");
        var drive = new DriveInfo(root);
        ValidateGeometry(drive.DriveFormat, drive.DriveType, drive.TotalSize, drive.VolumeLabel, nonce);
        var marker = Path.Combine(root, "safeupload-full-volume.marker");
        if ((File.GetAttributes(marker) & FileAttributes.ReparsePoint) != 0 ||
            File.ReadAllText(marker) != "SafeUpload disposable full-volume probe v1\n" + nonce)
            throw new InvalidOperationException("Missing owned-volume marker.");
    }

    [DllImport("kernel32.dll", EntryPoint = "GetVolumeNameForVolumeMountPointW", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetVolumeNameForVolumeMountPoint(string root, StringBuilder name, int length);
}
