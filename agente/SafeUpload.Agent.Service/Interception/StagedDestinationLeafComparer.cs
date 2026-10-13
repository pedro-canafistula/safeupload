using System.ComponentModel;
using System.Runtime.InteropServices;

namespace SafeUpload.Agent.Service.Interception;

// One filename comparator for durable heads, queue keys and observations.
// This is not linguistic casing and does not generate a second folded key.
internal static class StagedDestinationLeafComparer
{
    internal static bool Equals(string left, string right, bool caseSensitive) =>
        Compare(left, right, caseSensitive) == 0;

    internal static int Compare(string left, string right, bool caseSensitive)
    {
        if (caseSensitive) return string.CompareOrdinal(left, right);
        if (!OperatingSystem.IsWindows())
            throw new PlatformNotSupportedException("Destination authority requires the Windows filename comparator.");
        int result = CompareStringOrdinal(left, left.Length, right, right.Length, true);
        if (result == 0)
            throw new IOException("Windows filename comparison failed.", new Win32Exception(Marshal.GetLastWin32Error()));
        return result - 2; // CSTR_LESS_THAN/EQUAL/GREATER_THAN are 1/2/3.
    }

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, ExactSpelling = true, SetLastError = true)]
    private static extern int CompareStringOrdinal(string left, int leftChars, string right, int rightChars,
        [MarshalAs(UnmanagedType.Bool)] bool ignoreCase);
}
