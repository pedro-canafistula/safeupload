using System.IO.Pipes;
using System.Runtime.InteropServices;
using System.Text;
using Microsoft.Win32.SafeHandles;

namespace SafeUpload.Agent.Core.Infrastructure;

/// <summary>Checks the connected local pipe against the running, own-process SCM service and its image.</summary>
public static class ServicePipePeer
{
    public static void RequireConnectedService(NamedPipeClientStream pipe, string expectedServiceImage)
    {
        ArgumentNullException.ThrowIfNull(pipe);
        if (!OperatingSystem.IsWindows() || !pipe.IsConnected || !Path.IsPathFullyQualified(expectedServiceImage)) throw Unverified();
        if (!GetNamedPipeServerProcessId(pipe.SafePipeHandle, out uint serverPid) || serverPid == 0) throw Unverified();
        using var process = OpenProcess(0x1000, false, serverPid); // QUERY_LIMITED_INFORMATION only
        if (process.IsInvalid) throw Unverified();
        using var manager = OpenSCManagerW(null, null, 1); // SC_MANAGER_CONNECT
        if (manager.IsInvalid) throw Unverified();
        using var service = OpenServiceW(manager, "SafeUploadAgent", 4); // SERVICE_QUERY_STATUS
        if (service.IsInvalid || !QueryServiceStatusEx(service, 0, out var status,
            (uint)Marshal.SizeOf<ServiceStatusProcess>(), out _)) throw Unverified();
        var image = new StringBuilder(32768);
        uint length = (uint)image.Capacity; // QueryFullProcessImageNameW takes characters.
        if (!QueryFullProcessImageNameW(process, 0, image, ref length) ||
            !Matches(status.CurrentState, status.ServiceType, serverPid, status.ProcessId, image.ToString(), expectedServiceImage)) throw Unverified();
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
    private sealed class ServiceHandle : SafeHandleZeroOrMinusOneIsInvalid
    {
        public ServiceHandle() : base(true) { }
        protected override bool ReleaseHandle() => CloseServiceHandle(handle);
    }
    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetNamedPipeServerProcessId(SafePipeHandle pipe, out uint processId);
    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern SafeProcessHandle OpenProcess(uint desiredAccess, [MarshalAs(UnmanagedType.Bool)] bool inherit, uint processId);
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, ExactSpelling = true, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool QueryFullProcessImageNameW(SafeProcessHandle process, uint flags, StringBuilder image, ref uint size);
    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, ExactSpelling = true, SetLastError = true)]
    private static extern ServiceHandle OpenSCManagerW(string? machine, string? database, uint access);
    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, ExactSpelling = true, SetLastError = true)]
    private static extern ServiceHandle OpenServiceW(ServiceHandle manager, string name, uint access);
    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool QueryServiceStatusEx(ServiceHandle service, int level, out ServiceStatusProcess status, uint size, out uint required);
    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CloseServiceHandle(IntPtr handle);
}
