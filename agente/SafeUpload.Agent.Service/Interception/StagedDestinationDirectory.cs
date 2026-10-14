#if SAFEUPLOAD_ADMISSION_EVIDENCE
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Text;
using Microsoft.Win32.SafeHandles;

namespace SafeUpload.Agent.Service.Interception;

// Reopens only the recorded volume and parent identities. The saved path is
// never passed to an open. Parent-relative source opens retain the same handle
// through seeding and compare the complete ID, not the NTFS selector alone.
internal sealed partial class StagedDestinationDirectory : IDisposable
{
    internal SafeFileHandle VolumeRoot { get; }
    internal SafeFileHandle Parent { get; }
    internal StagedDestinationIdentity Destination { get; }

    private StagedDestinationDirectory(SafeFileHandle root, SafeFileHandle parent,
        StagedDestinationIdentity destination) => (VolumeRoot, Parent, Destination) = (root, parent, destination);

    // Diagnostic locator only. Identity-bound opens/commits never reopen it.
    internal string ReadLocator()
    {
        var name = new StringBuilder(32768);
        uint length = GetFinalPathNameByHandleW(Parent, name, checked((uint)name.Capacity), 1);
        if (length == 0 || length >= name.Capacity)
            throw new IOException("Could not name the recorded parent.", new Win32Exception(Marshal.GetLastWin32Error()));
        RequireIdentity(Parent, Destination.Parent, directory: true);
        return Path.Combine(name.ToString(), Destination.CanonicalLeaf);
    }

    internal static StagedDestinationDirectory Open(StagedAllocationBindingV23 binding)
    {
        if (!OperatingSystem.IsWindows()) throw new PlatformNotSupportedException("Bound staging requires Windows NTFS.");
        binding.Validate();
        string volumePath = @"\\?\Volume{" + binding.MountManagerVolumeId.ToString("D") + @"}\";
        if (GetDriveTypeW(volumePath) != 3) throw new IOException("Bound staging requires a fixed volume.");
        var root = CreateFileW(volumePath, 0x1000A1, 7, IntPtr.Zero, 3, 0x02200000, IntPtr.Zero);
        if (root.IsInvalid)
        {
            int error = Marshal.GetLastWin32Error(); root.Dispose();
            throw new IOException("Could not open the recorded volume root.", new Win32Exception(error));
        }
        SafeFileHandle? parent = null;
        try
        {
            var format = new StringBuilder(32);
            if (!GetVolumeInformationByHandleW(root, null, 0, out _, out _, out _, format, format.Capacity) ||
                !string.Equals(format.ToString(), "NTFS", StringComparison.Ordinal))
                throw new IOException("The recorded volume is not qualified NTFS.");
            RequireIdentity(root, binding.VolumeRoot, directory: true);
            // FileIdType is the qualified NTFS selector. Never truncate a
            // nonzero high half, and never treat the selector as full proof.
            if (binding.Parent.FileIdHigh != 0)
                throw new IOException("The NTFS parent selector cannot represent this full file identity.");
            var descriptor = new FileIdDescriptor { Size = 24, Type = 0, Low = binding.Parent.FileIdLow };
            parent = OpenFileById(root, ref descriptor, 0x1000A1, 7, IntPtr.Zero, 0x02200000);
            if (parent.IsInvalid)
                throw new IOException("Could not reopen the recorded parent.", new Win32Exception(Marshal.GetLastWin32Error()));
            RequireIdentity(parent, binding.Parent, directory: true);
            var result = new StagedDestinationDirectory(root, parent, binding.Destination);
            result.RequireCaseMode();
            return result;
        }
        catch { parent?.Dispose(); root.Dispose(); throw; }
    }

    internal void RequirePublicTarget(StagedStageIdentity? expected, CancellationToken token)
    {
        var observation = StagedDestinationNameObserver.Observe(VolumeRoot, Parent, Destination, token);
        if (observation.PublicIdentity != expected)
            throw new IOException("The bound public target changed identity or absence.");
    }

    internal FileStream OpenPublicSource(StagedStageIdentity expected, CancellationToken token)
    {
        RequirePublicTarget(expected, token);
        RequireCaseMode();
        SafeFileHandle source = OpenRelative(Destination.CanonicalLeaf, 0x100081, 1, 1, 0x00200064);
        try
        {
            RequireIdentity(source, expected, directory: false);
            RequirePublicTarget(expected, token);
            return new FileStream(source, FileAccess.Read, 64 * 1024, isAsync: false);
        }
        catch { source.Dispose(); throw; }
    }

    private SafeFileHandle OpenRelative(string leaf, uint access, uint share, uint disposition, uint options,
        byte[]? security = null, uint fileAttributes = 0)
    {
        byte[] bytes = Encoding.Unicode.GetBytes(leaf);
        IntPtr name = Marshal.AllocHGlobal(bytes.Length + 2), unicode = IntPtr.Zero, descriptor = IntPtr.Zero;
        bool parentReference = false;
        try
        {
            Parent.DangerousAddRef(ref parentReference);
            Marshal.Copy(bytes, 0, name, bytes.Length);
            Marshal.WriteInt16(name, bytes.Length, 0);
            var value = new UnicodeString
            {
                Length = checked((ushort)bytes.Length), MaximumLength = checked((ushort)(bytes.Length + 2)),
                Buffer = name
            };
            unicode = Marshal.AllocHGlobal(Marshal.SizeOf<UnicodeString>());
            Marshal.StructureToPtr(value, unicode, false);
            if (security is not null)
            {
                descriptor = Marshal.AllocHGlobal(security.Length);
                Marshal.Copy(security, 0, descriptor, security.Length);
            }
            var attributes = new ObjectAttributes
            {
                Length = checked((uint)Marshal.SizeOf<ObjectAttributes>()),
                RootDirectory = Parent.DangerousGetHandle(), ObjectName = unicode,
                Attributes = Destination.CaseSensitive ? 0u : 0x40u,
                SecurityDescriptor = descriptor
            };
            int status = NtCreateFile(out SafeFileHandle handle, access, ref attributes, out var io,
                IntPtr.Zero, fileAttributes, share, disposition, options, IntPtr.Zero, 0);
            if (status == 0 && !handle.IsInvalid && (disposition != 2 || io.Information.ToUInt64() == 2)) return handle;
            handle.Dispose();
            throw new IOException("The checked parent-relative open failed.",
                new Win32Exception(checked((int)RtlNtStatusToDosError(status))));
        }
        finally
        {
            if (parentReference) Parent.DangerousRelease();
            if (unicode != IntPtr.Zero) Marshal.FreeHGlobal(unicode);
            if (descriptor != IntPtr.Zero) Marshal.FreeHGlobal(descriptor);
            Marshal.FreeHGlobal(name);
        }
    }

    private void RequireCaseMode()
    {
        uint flags = BitConverter.ToUInt32(Query(Parent, 23, 4));
        if ((flags & ~1u) != 0 || ((flags & 1) != 0) != Destination.CaseSensitive)
            throw new IOException("The recorded parent case mode changed.");
    }

    private static void RequireIdentity(SafeFileHandle handle, StagedStageIdentity expected, bool directory)
    {
        byte[] basic = Query(handle, 0, 40), id = Query(handle, 18, 24);
        uint attributes = BitConverter.ToUInt32(basic, 32);
        if ((attributes & 0x400) != 0 || ((attributes & 0x10) != 0) != directory ||
            new StagedStageIdentity(BitConverter.ToUInt64(id, 0),
                BitConverter.ToUInt64(id, 16), BitConverter.ToUInt64(id, 8)) != expected)
            throw new IOException("The reopened bound object changed full identity or type.");
    }

    private static byte[] Query(SafeFileHandle handle, int kind, int bytes)
    {
        byte[] data = new byte[bytes];
        if (!GetFileInformationByHandleEx(handle, kind, data, checked((uint)bytes)))
            throw new IOException("Could not query a bound object.", new Win32Exception(Marshal.GetLastWin32Error()));
        return data;
    }

    public void Dispose() { Parent.Dispose(); VolumeRoot.Dispose(); }

    [StructLayout(LayoutKind.Explicit, Size = 24)]
    private struct FileIdDescriptor
    {
        [FieldOffset(0)] internal uint Size;
        [FieldOffset(4)] internal uint Type;
        [FieldOffset(8)] internal ulong Low;
    }
    [StructLayout(LayoutKind.Sequential)]
    private struct UnicodeString { internal ushort Length; internal ushort MaximumLength; internal IntPtr Buffer; }
    [StructLayout(LayoutKind.Sequential)]
    private struct ObjectAttributes
    {
        internal uint Length; internal IntPtr RootDirectory; internal IntPtr ObjectName; internal uint Attributes;
        internal IntPtr SecurityDescriptor; internal IntPtr SecurityQualityOfService;
    }
    [StructLayout(LayoutKind.Sequential)]
    private struct IoStatusBlock { internal IntPtr Status; internal UIntPtr Information; }
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern uint GetFinalPathNameByHandleW(SafeFileHandle file, StringBuilder name, uint capacity, uint flags);
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern SafeFileHandle CreateFileW(string path, uint access, uint share,
        IntPtr security, uint disposition, uint flags, IntPtr template);
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode)]
    private static extern uint GetDriveTypeW(string root);
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetVolumeInformationByHandleW(SafeFileHandle root, StringBuilder? volumeName,
        int nameSize, out uint serial, out uint maximumComponent, out uint flags, StringBuilder format, int formatSize);
    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern SafeFileHandle OpenFileById(SafeFileHandle volumeHint, ref FileIdDescriptor id,
        uint access, uint share, IntPtr security, uint flags);
    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetFileInformationByHandleEx(SafeFileHandle file, int kind, [Out] byte[] data, uint bytes);
    [DllImport("ntdll.dll")]
    private static extern int NtCreateFile(out SafeFileHandle handle, uint access, ref ObjectAttributes attributes,
        out IoStatusBlock status, IntPtr allocationSize, uint attributesValue, uint share, uint disposition,
        uint options, IntPtr ea, uint eaLength);
    [DllImport("ntdll.dll")]
    private static extern uint RtlNtStatusToDosError(int status);
}
#endif
