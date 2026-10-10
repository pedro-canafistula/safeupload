using System.Runtime.InteropServices;

namespace SafeUpload.Agent.Tests;

/// <summary>Enables a privilege the test process's token already holds (no-op when it does not, or off Windows).</summary>
internal static class TestPrivileges
{
    private const uint TokenAdjustPrivileges = 0x0020;
    private const uint TokenQuery = 0x0008;
    private const int PrivilegeEnabled = 0x00000002;

    [StructLayout(LayoutKind.Sequential, Pack = 4)]
    private struct TokenPrivilegesOne
    {
        public int Count;
        public long Luid;
        public int Attributes;
    }

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool OpenProcessToken(IntPtr process, uint access, out IntPtr token);

    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern bool LookupPrivilegeValue(string? systemName, string name, out long luid);

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool AdjustTokenPrivileges(IntPtr token, bool disableAll, ref TokenPrivilegesOne newState,
        int bufferLength, IntPtr previousState, IntPtr returnLength);

    [DllImport("kernel32.dll")]
    private static extern IntPtr GetCurrentProcess();

    [DllImport("kernel32.dll")]
    private static extern bool CloseHandle(IntPtr handle);

    public static void TryEnable(string privilege)
    {
        if (!OperatingSystem.IsWindows()) return;
        if (!OpenProcessToken(GetCurrentProcess(), TokenAdjustPrivileges | TokenQuery, out IntPtr token)) return;
        try
        {
            if (!LookupPrivilegeValue(null, privilege, out long luid)) return;
            var state = new TokenPrivilegesOne { Count = 1, Luid = luid, Attributes = PrivilegeEnabled };
            _ = AdjustTokenPrivileges(token, false, ref state, Marshal.SizeOf<TokenPrivilegesOne>(), IntPtr.Zero, IntPtr.Zero);
        }
        finally
        {
            CloseHandle(token);
        }
    }
}
