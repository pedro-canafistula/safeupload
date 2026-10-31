using System.IO.Pipes;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

namespace SafeUpload.Agent.Core.Infrastructure;

/// <summary>Checks a locally connected pipe against the running SCM service and its protected registration.</summary>
public static class ServicePipePeer
{
    public static void RequireConnectedService(NamedPipeClientStream pipe, string expectedServiceImage)
    {
        ArgumentNullException.ThrowIfNull(pipe);
        if (!OperatingSystem.IsWindows() || !pipe.IsConnected || !Path.IsPathFullyQualified(expectedServiceImage)) throw Unverified();
        if (!GetNamedPipeServerProcessId(pipe.SafePipeHandle, out uint serverPid) || serverPid == 0) throw Unverified();
        using var manager = OpenSCManagerW(null, null, 1); // SC_MANAGER_CONNECT
        if (manager.IsInvalid) throw Unverified();
        using var service = OpenServiceW(manager, "SafeUploadAgent", 5); // QUERY_STATUS | QUERY_CONFIG only
        if (service.IsInvalid || !QueryServiceStatusEx(service, 0, out var status,
            (uint)Marshal.SizeOf<ServiceStatusProcess>(), out _)) throw Unverified();
        bool unexpectedSuccess = QueryServiceConfigW(service, IntPtr.Zero, 0, out uint required);
        if (unexpectedSuccess || Marshal.GetLastWin32Error() != 122 ||
            required < Marshal.SizeOf<ServiceConfig>() || required > 8192) throw Unverified();
        IntPtr buffer = Marshal.AllocHGlobal((int)required);
        try
        {
            if (!QueryServiceConfigW(service, buffer, required, out _)) throw Unverified();
            var config = Marshal.PtrToStructure<ServiceConfig>(buffer);
            string? image = ConfiguredExecutable(Marshal.PtrToStringUni(config.BinaryPath));
            if (image is null || (config.ServiceType & 0x30) != 0x10 ||
                !IsLocalSystemAccount(Marshal.PtrToStringUni(config.StartName)) ||
                !Matches(status.CurrentState, status.ServiceType, serverPid, status.ProcessId, image, expectedServiceImage)) throw Unverified();
            // A restart during the two read-only queries must not validate the old peer.
            if (!QueryServiceStatusEx(service, 0, out var after, (uint)Marshal.SizeOf<ServiceStatusProcess>(), out _) ||
                !Matches(after.CurrentState, after.ServiceType, serverPid, after.ProcessId, image, expectedServiceImage)) throw Unverified();
        }
        finally { Marshal.FreeHGlobal(buffer); }
    }

    internal static bool IsLocalSystemAccount(string? name) => string.Equals(name, "LocalSystem", StringComparison.OrdinalIgnoreCase) ||
        string.Equals(name, @"NT AUTHORITY\SYSTEM", StringComparison.OrdinalIgnoreCase);

    internal static string? ConfiguredExecutable(string? commandLine)
    {
        // Supported installation always quotes the absolute executable explicitly.
        // Do not guess an ambiguous unquoted service command or treat arguments as its image.
        if (string.IsNullOrWhiteSpace(commandLine)) return null;
        var text = commandLine.TrimStart();
        if (text[0] != '"') return null;
        int end = text.IndexOf('"', 1);
        if (end <= 1 || (end + 1 < text.Length && !char.IsWhiteSpace(text[end + 1]))) return null;
        string image = text[1..end];
        return image.Any(char.IsControl) || !Path.IsPathFullyQualified(image) ? null : image;
    }

    internal static bool Matches(uint state, uint serviceType, uint peerPid, uint servicePid, string actualImage, string expectedImage)
    {
        if (state != 4 || (serviceType & 0x30) != 0x10 || peerPid == 0 || peerPid != servicePid ||
            !Path.IsPathFullyQualified(actualImage) || !Path.IsPathFullyQualified(expectedImage)) return false;
        return string.Equals(Path.GetFullPath(actualImage), Path.GetFullPath(expectedImage), StringComparison.OrdinalIgnoreCase);
    }

    private static IOException Unverified() => new("The connected pipe is not a verified SafeUpload service.");

    [StructLayout(LayoutKind.Sequential)]
    private struct ServiceStatusProcess
    {
        public uint ServiceType, CurrentState, ControlsAccepted, Win32ExitCode, ServiceSpecificExitCode,
            CheckPoint, WaitHint, ProcessId, ServiceFlags;
    }
    [StructLayout(LayoutKind.Sequential)]
    private struct ServiceConfig
    {
        public uint ServiceType, StartType, ErrorControl;
        public IntPtr BinaryPath, LoadOrderGroup;
        public uint Tag;
        public IntPtr Dependencies, StartName, DisplayName;
    }
    private sealed class ServiceHandle : SafeHandleZeroOrMinusOneIsInvalid
    {
        public ServiceHandle() : base(true) { }
        protected override bool ReleaseHandle() => CloseServiceHandle(handle);
    }
    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetNamedPipeServerProcessId(SafePipeHandle pipe, out uint processId);
    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, ExactSpelling = true, SetLastError = true)]
    private static extern ServiceHandle OpenSCManagerW(string? machine, string? database, uint access);
    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, ExactSpelling = true, SetLastError = true)]
    private static extern ServiceHandle OpenServiceW(ServiceHandle manager, string name, uint access);
    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool QueryServiceStatusEx(ServiceHandle service, int level, out ServiceStatusProcess status, uint size, out uint required);
    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, ExactSpelling = true, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool QueryServiceConfigW(ServiceHandle service, IntPtr config, uint size, out uint required);
    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CloseServiceHandle(IntPtr handle);
}
