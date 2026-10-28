#if SAFEUPLOAD_ADMISSION_EVIDENCE
using System.ComponentModel;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text;
using Microsoft.Win32.SafeHandles;
using SafeUpload.Agent.Minifilter;

namespace SafeUpload.Agent.Service.Interception;

internal enum MetadataReplacementMechanism { Classic, Extended, ExtendedPosix }
internal readonly record struct MetadataRenameOperation(int InformationClass, uint Flags);

// Synchronous, noncached, handle-relative transport. No path fallback, schema,
// policy or journal calls. Bootstrap supplies an already trusted held anchor.
internal sealed class StagedMetadataStoreNative : IStagedMetadataNative
{
    internal const uint AnchorAccess = 0x120081, AnchorShare = 3, ChildShare = 7;
    internal const uint OutputOptions = 0x0020006A; // NO_BUFFERING | WRITE_THROUGH | SYNC_NONALERT | OPEN_REPARSE_POINT
    // Builder mechanism evidence selects POSIX replacement; target qualification
    // remains separate. Discovery also preserves the refused legacy mechanisms.
    internal const MetadataReplacementMechanism SelectedReplacement = MetadataReplacementMechanism.ExtendedPosix;
    internal static int RenameInformationClass => RenameOperationFor(true).InformationClass;
    internal static MetadataRenameOperation ReplacementOperation(MetadataReplacementMechanism mechanism) => mechanism switch
    {
        MetadataReplacementMechanism.Classic => new(10, 1),
        MetadataReplacementMechanism.Extended => new(65, 1),
        MetadataReplacementMechanism.ExtendedPosix => new(65, 3),
        _ => throw new ArgumentOutOfRangeException(nameof(mechanism))
    };
    internal static MetadataRenameOperation RenameOperationFor(bool replace) =>
        replace ? ReplacementOperation(SelectedReplacement) : new(10, 0);
    private readonly SafeFileHandle _parent;
    private readonly byte[] _parentSecurity, _fileSecurity;
    private readonly SecurityIdentifier _owner;
    private readonly ConditionalWeakTable<SafeFileHandle, byte[]> _security = new();
    internal int NativeWriteCalls { get; private set; }
    internal int SuccessfulRenames { get; private set; }
    public uint HeldHandleShare => ChildShare;
    public long Alignment { get; }
    public long AllocationUnit { get; }
    public StagedStageIdentity ParentIdentity { get; }

    internal StagedMetadataStoreNative(SafeFileHandle parent, StagedStageIdentity expected)
    {
        if (!OperatingSystem.IsWindows()) throw new PlatformNotSupportedException();
        _parent = parent;
        using var identity = WindowsIdentity.GetCurrent();
        _owner = identity.User ?? throw new UnauthorizedAccessException("No native storage owner.");
        ParentIdentity = Identity(parent);
        if (ParentIdentity != expected) throw new IOException("Metadata anchor identity changed.");
        ValidateType(parent, directory: true);
        _parentSecurity = Security(parent);
        var descriptor = new FileSecurity();
        descriptor.SetOwner(_owner); descriptor.SetAccessRuleProtection(true, false);
        foreach (var sid in new[] { _owner, new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null),
                     new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null) }.Distinct())
            descriptor.AddAccessRule(new FileSystemAccessRule(sid, FileSystemRights.FullControl, AccessControlType.Allow));
        _fileSecurity = descriptor.GetSecurityDescriptorBinaryForm();
        var format = new StringBuilder(32);
        if (!GetVolumeInformationByHandleW(parent, null, 0, out _, out _, out _, format, format.Capacity) || format.ToString() != "NTFS")
            throw new IOException("Metadata anchor requires fixed NTFS.");
        byte[] device = Volume(parent, 4, 8);
        if (BitConverter.ToUInt32(device) != 7 || (BitConverter.ToUInt32(device, 4) & 1) != 0)
            throw new IOException("Metadata anchor requires a nonremovable disk.");
        byte[] size = Volume(parent, 3, 24), sectors = Volume(parent, 11, 28), alignment = Info(parent, 17, 4);
        long sectorBytes = BitConverter.ToUInt32(size, 20), units = BitConverter.ToUInt32(size, 16);
        AllocationUnit = checked(sectorBytes * units);
        long required = Math.Max(BitConverter.ToUInt32(sectors), Math.Max(BitConverter.ToUInt32(sectors, 4),
            Math.Max(BitConverter.ToUInt32(sectors, 8), BitConverter.ToUInt32(sectors, 12))));
        Alignment = Math.Max(4096, Math.Max(required, checked((long)BitConverter.ToUInt32(alignment) + 1)));
        if (!BoundedOutputPlan.PowerOfTwo(Alignment) || Alignment > 65536 || AllocationUnit < 512 ||
            !BoundedOutputPlan.PowerOfTwo(AllocationUnit) || sectorBytes != BitConverter.ToUInt32(sectors) || units == 0)
            throw new IOException("Invalid independent native alignment/allocation units.");
    }

    // Absolute lookup is bootstrap only. Every later child call is relative.
    internal static SafeFileHandle OpenAnchor(string path)
    {
        for (string? part = Path.GetFullPath(path); part is not null; part = Path.GetDirectoryName(part))
            if ((File.GetAttributes(part) & FileAttributes.ReparsePoint) != 0)
                throw new IOException("Reparse ancestor is not a metadata anchor.");
        var handle = CreateFileW(path, AnchorAccess, AnchorShare, IntPtr.Zero, 3, 0x02200000, IntPtr.Zero);
        if (!handle.IsInvalid) return handle;
        int error = Marshal.GetLastWin32Error(); handle.Dispose(); throw new IOException("Could not hold metadata anchor.", new Win32Exception(error));
    }
    private static void RequireOriginalToken()
    {
        using var impersonation = WindowsIdentity.GetCurrent(ifImpersonating: true);
        if (impersonation is not null) throw new UnauthorizedAccessException("Metadata mutation requires the original unimpersonated service token.");
    }
    public void ValidateParent()
    {
        RequireOriginalToken();
        if (Identity(_parent) != ParentIdentity || !Security(_parent).AsSpan().SequenceEqual(_parentSecurity))
            throw new IOException("Metadata anchor identity/security changed.");
        ValidateType(_parent, directory: true);
    }
    public SafeFileHandle Create(string leaf, MetadataRoleV32 role, out MetadataNativeResult result)
    {
        if (!MetadataStoreRoles.CanOutput(role)) throw new ArgumentException("Role has no output authority.");
        var handle = Relative(leaf, role, 2, _fileSecurity, out result);
        if (!result.Success) return handle;
        try
        {
            if (result.Information != 2) throw new IOException("Metadata FILE_CREATE did not create a new object.");
            ValidateType(handle, false);
            _security.Add(handle, Security(handle));
            return handle;
        }
        catch { handle.Dispose(); throw; } // Caller retains precharged unknown creation custody.
    }
    public SafeFileHandle Open(string leaf, MetadataRoleV32 role, StagedStageIdentity expected)
    {
        var handle = Relative(leaf, role, 1, null, out var result);
        try
        {
            result.Require(); ValidateType(handle, false);
            if (Identity(handle) != expected) throw new IOException("Held metadata object identity changed.");
            _security.Add(handle, Security(handle)); return handle;
        }
        catch { handle.Dispose(); throw; }
    }
    // Test-only opening seam. The production Open keeps its exact role mask,
    // share=7 and mandatory expected identity. No production caller uses this.
    internal SafeFileHandle OpenForReplacementDiscovery(string leaf, uint access, uint share, out MetadataNativeResult result)
    {
        if ((access != MetadataStoreRoles.Read && access != MetadataStoreRoles.ReadDelete) || share is not (3 or 7))
            throw new ArgumentException("Invalid replacement discovery handle grants/sharing.");
        var handle = Relative(leaf, MetadataRoleV32.ManifestCurrent, 1, null, out result, access, share);
        if (!result.Success) return handle;
        try { ValidateType(handle, false); _security.Add(handle, Security(handle)); return handle; }
        catch { handle.Dispose(); throw; }
    }
    internal uint AttributesForReplacementDiscovery(SafeFileHandle handle) => BitConverter.ToUInt32(Info(handle, 35, 8));
    private SafeFileHandle Relative(string leaf, MetadataRoleV32 role, uint disposition, byte[]? security, out MetadataNativeResult result,
        uint? discoveryAccess = null, uint? discoveryShare = null)
    {
        if (!ResourceControlWireV32.LeafValid(leaf)) throw new ArgumentException("Not one exact metadata component.");
        ValidateParent();
        IntPtr name = Marshal.StringToHGlobalUni(leaf), unicode = IntPtr.Zero, descriptor = IntPtr.Zero;
        bool parentReference = false;
        try
        {
            var text = new UnicodeString { Length = checked((ushort)(leaf.Length * 2)), MaximumLength = checked((ushort)((leaf.Length + 1) * 2)), Buffer = name };
            unicode = Marshal.AllocHGlobal(Marshal.SizeOf<UnicodeString>()); Marshal.StructureToPtr(text, unicode, false);
            if (security is not null) { descriptor = Marshal.AllocHGlobal(security.Length); Marshal.Copy(security, 0, descriptor, security.Length); }
            _parent.DangerousAddRef(ref parentReference);
            var attributes = new ObjectAttributes { Length = (uint)Marshal.SizeOf<ObjectAttributes>(), RootDirectory = _parent.DangerousGetHandle(),
                ObjectName = unicode, Attributes = 0x40, SecurityDescriptor = descriptor };
            int status = NtCreateFile(out var handle, discoveryAccess ?? MetadataStoreRoles.Access(role), ref attributes, out var io, IntPtr.Zero,
                0x80, discoveryShare ?? ChildShare, disposition, OutputOptions | 0x40, IntPtr.Zero, 0);
            result = new(status, io.Information.ToUInt64()); return handle;
        }
        finally
        {
            if (parentReference) _parent.DangerousRelease();
            if (unicode != IntPtr.Zero) Marshal.FreeHGlobal(unicode);
            if (descriptor != IntPtr.Zero) Marshal.FreeHGlobal(descriptor);
            Marshal.FreeHGlobal(name);
        }
    }
    public MetadataNativeObservation Query(SafeFileHandle handle)
    {
        ValidateType(handle, false, allowUnlinkedHeld: true);
        if (!_security.TryGetValue(handle, out var security) || !Security(handle).AsSpan().SequenceEqual(security))
            throw new IOException("Held metadata security changed.");
        byte[] standard = Info(handle, 5, 24);
        return new(Identity(handle), BitConverter.ToInt64(standard, 8), BitConverter.ToInt64(standard),
            BitConverter.ToUInt32(standard, 16), standard[20] != 0);
    }
    internal static StagedStageIdentity Identity(SafeFileHandle handle)
    {
        byte[] id = Info(handle, 59, 24);
        var identity = new StagedStageIdentity(BitConverter.ToUInt64(id), BitConverter.ToUInt64(id, 16), BitConverter.ToUInt64(id, 8));
        if (identity is { FileIdHigh: 0, FileIdLow: 0 }) throw new IOException("Metadata has no full identity.");
        return identity;
    }
    private static void ValidateType(SafeFileHandle handle, bool directory, bool allowUnlinkedHeld = false)
    {
        byte[] attributes = Info(handle, 35, 8), standard = Info(handle, 5, 24);
        if ((BitConverter.ToUInt32(attributes) & 0x400) != 0 || (standard[21] != 0) != directory ||
            (!directory && BitConverter.ToUInt32(standard, 16) != 1 &&
                !(allowUnlinkedHeld && BitConverter.ToUInt32(standard, 16) == 0)))
            throw new IOException("Metadata type/link count is unsafe.");
    }
    private byte[] Security(SafeFileHandle handle)
    {
        int status = GetSecurityInfo(handle, 1, 7, out _, out _, out _, out _, out var descriptor);
        try
        {
            if (status != 0 || descriptor == IntPtr.Zero) throw new IOException("Metadata security query failed.", new Win32Exception(status));
            uint length = GetSecurityDescriptorLength(descriptor);
            if (length is 0 or > 65536) throw new IOException("Unbounded metadata security descriptor.");
            byte[] bytes = new byte[length]; Marshal.Copy(descriptor, bytes, 0, bytes.Length);
            var raw = new RawSecurityDescriptor(bytes, 0);
            if ((raw.ControlFlags & ControlFlags.DiscretionaryAclProtected) == 0 || raw.DiscretionaryAcl is null || raw.Owner is null ||
                !(raw.Owner.Equals(_owner) || raw.Owner.IsWellKnown(WellKnownSidType.LocalSystemSid) || raw.Owner.IsWellKnown(WellKnownSidType.BuiltinAdministratorsSid)))
                throw new UnauthorizedAccessException("Untrusted metadata owner/DACL.");
            const int mutators = 0x500D0156; // data/EA/attributes/delete/WRITE_DAC/WRITE_OWNER
            foreach (GenericAce ace in raw.DiscretionaryAcl)
            {
                if (ace is not CommonAce common || common.IsCallback) throw new UnauthorizedAccessException("Unsupported metadata ACE.");
                if (common.AceQualifier != AceQualifier.AccessAllowed || (common.AceFlags & AceFlags.InheritOnly) != 0 || (common.AccessMask & mutators) == 0) continue;
                var sid = common.SecurityIdentifier;
                if (!sid.Equals(_owner) && !sid.IsWellKnown(WellKnownSidType.LocalSystemSid) && !sid.IsWellKnown(WellKnownSidType.BuiltinAdministratorsSid))
                    throw new UnauthorizedAccessException("Untrusted metadata mutator.");
            }
            return bytes;
        }
        finally { if (descriptor != IntPtr.Zero) LocalFree(descriptor); }
    }
    public MetadataNativeResult Write(SafeFileHandle handle, long offset, ReadOnlySpan<byte> bytes)
    {
        RequireOriginalToken();
        CheckAligned(offset, bytes.Length);
        return WriteAligned(handle, offset, bytes, Alignment);
    }
    internal MetadataNativeResult WriteAligned(SafeFileHandle handle, long offset, ReadOnlySpan<byte> bytes, long alignment)
    {
        RequireOriginalToken(); CheckAligned(offset, bytes.Length);
        if (alignment < Alignment || alignment > 65536 || !BoundedOutputPlan.PowerOfTwo(alignment) || offset % alignment != 0 || bytes.Length % alignment != 0)
            throw new ArgumentException("Invalid stricter verified I/O quantum.");
        using var aligned = new AlignedBuffer(bytes.Length, alignment); bytes.CopyTo(aligned.Span);
        NativeWriteCalls++;
        int status = NtWriteFile(handle, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, out var io, aligned.Pointer, (uint)bytes.Length, ref offset, IntPtr.Zero);
        return new(status, io.Information.ToUInt64());
    }
    public MetadataNativeResult Read(SafeFileHandle handle, long offset, Span<byte> bytes)
    {
        RequireOriginalToken();
        CheckAligned(offset, bytes.Length);
        using var aligned = new AlignedBuffer(bytes.Length, Alignment);
        int status = NtReadFile(handle, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, out var io, aligned.Pointer, (uint)bytes.Length, ref offset, IntPtr.Zero);
        if (status == 0)
        {
            if (io.Information.ToUInt64() > (ulong)bytes.Length) throw new IOException("Oversized native read.");
            aligned.Span[..(int)io.Information.ToUInt64()].CopyTo(bytes);
        }
        return new(status, io.Information.ToUInt64());
    }
    private void CheckAligned(long offset, int length)
    {
        if (offset < 0 || offset % Alignment != 0 || length == 0 || length % Alignment != 0 || length > 4 * 1024 * 1024)
            throw new ArgumentException("Adapter pre-issue alignment refusal (zero native calls).");
    }
    public MetadataNativeResult Flush(SafeFileHandle handle)
    { RequireOriginalToken(); int status = NtFlushBuffersFile(handle, out var io); return new(status, io.Information.ToUInt64()); }
    public MetadataNativeResult Allocation(SafeFileHandle handle, long length)
    {
        RequireOriginalToken();
        if (length < 0) throw new ArgumentOutOfRangeException(nameof(length));
        return Set(handle, BitConverter.GetBytes(length), 19); // FileAllocationInformation
    }
    public MetadataNativeResult EndOfFile(SafeFileHandle handle, long length)
    {
        RequireOriginalToken();
        if (length < 0) throw new ArgumentOutOfRangeException(nameof(length));
        return Set(handle, BitConverter.GetBytes(length), 20);
    }
    public MetadataNativeResult Rename(SafeFileHandle handle, string leaf, bool replace) =>
        RenameWithOperation(handle, leaf, RenameOperationFor(replace));
    internal MetadataNativeResult RenameForReplacementDiscovery(SafeFileHandle handle, string leaf, MetadataReplacementMechanism mechanism) =>
        RenameWithOperation(handle, leaf, ReplacementOperation(mechanism));

    internal static byte[] RenameBuffer(string leaf, IntPtr anchor, MetadataRenameOperation operation)
    {
        if (!ResourceControlWireV32.LeafValid(leaf) || anchor == IntPtr.Zero ||
            (operation.InformationClass == 10 ? operation.Flags > 1 : operation.InformationClass != 65 || (operation.Flags & ~3u) != 0))
            throw new ArgumentException("Invalid relative native rename shape.");
        int offset = IntPtr.Size == 8 ? 20 : 12;
        byte[] name = Encoding.Unicode.GetBytes(leaf), buffer = new byte[Math.Max(offset + name.Length, IntPtr.Size == 8 ? 24 : 16)];
        // Class 10 uses BOOLEAN ReplaceIfExists; Ex uses ULONG Flags. With
        // flags 0/1 this preserves the original class-10 bytes, including padding.
        BitConverter.GetBytes(operation.Flags).CopyTo(buffer, 0);
        if (IntPtr.Size == 8) BitConverter.GetBytes(anchor.ToInt64()).CopyTo(buffer, 8);
        else BitConverter.GetBytes(anchor.ToInt32()).CopyTo(buffer, 4);
        BitConverter.GetBytes(name.Length).CopyTo(buffer, offset - 4); name.CopyTo(buffer, offset);
        return buffer;
    }
    private MetadataNativeResult RenameWithOperation(SafeFileHandle handle, string leaf, MetadataRenameOperation operation)
    {
        if (!ResourceControlWireV32.LeafValid(leaf)) throw new ArgumentException("Invalid rename component.");
        ValidateParent();
        bool reference = false;
        try
        {
            _parent.DangerousAddRef(ref reference);
            byte[] buffer = RenameBuffer(leaf, _parent.DangerousGetHandle(), operation);
            var result = Set(handle, buffer, operation.InformationClass);
            if (result.Success) SuccessfulRenames++;
            return result;
        }
        finally { if (reference) _parent.DangerousRelease(); }
    }
    public MetadataNativeResult Delete(SafeFileHandle handle)
    { RequireOriginalToken(); return Set(handle, [1], 13); }
    private static MetadataNativeResult Set(SafeFileHandle handle, byte[] bytes, int kind)
    { int status = NtSetInformationFile(handle, out var io, bytes, bytes.Length, kind); return new(status, io.Information.ToUInt64()); }
    private static byte[] Info(SafeFileHandle handle, int kind, int length)
    {
        byte[] bytes = new byte[length]; int status = NtQueryInformationFile(handle, out var io, bytes, length, kind);
        new MetadataNativeResult(status, io.Information.ToUInt64()).Require();
        if (io.Information.ToUInt64() != (ulong)length) throw new IOException("Short native metadata query.");
        return bytes;
    }
    private static byte[] Volume(SafeFileHandle handle, int kind, int length)
    {
        byte[] bytes = new byte[length]; int status = NtQueryVolumeInformationFile(handle, out var io, bytes, length, kind);
        new MetadataNativeResult(status, io.Information.ToUInt64()).Require();
        if (io.Information.ToUInt64() != (ulong)length) throw new IOException("Short native volume query.");
        return bytes;
    }
    public void Dispose() { _security.Clear(); _parent.Dispose(); }
    private sealed class AlignedBuffer : IDisposable
    {
        private readonly IntPtr _allocation;
        internal IntPtr Pointer { get; }
        private readonly int _length;
        internal AlignedBuffer(int length, long alignment)
        {
            _allocation = Marshal.AllocHGlobal(checked(length + (int)alignment - 1));
            Pointer = (IntPtr)checked((_allocation.ToInt64() + alignment - 1) & -alignment); _length = length;
        }
        internal unsafe Span<byte> Span => new(Pointer.ToPointer(), _length);
        public void Dispose() => Marshal.FreeHGlobal(_allocation);
    }
    [StructLayout(LayoutKind.Sequential)] private struct UnicodeString { internal ushort Length, MaximumLength; internal IntPtr Buffer; }
    [StructLayout(LayoutKind.Sequential)] private struct ObjectAttributes
    { internal uint Length; internal IntPtr RootDirectory, ObjectName; internal uint Attributes; internal IntPtr SecurityDescriptor, SecurityQualityOfService; }
    [StructLayout(LayoutKind.Sequential)] private struct IoStatusBlock { internal IntPtr Status; internal UIntPtr Information; }
    [DllImport("ntdll.dll")] private static extern int NtCreateFile(out SafeFileHandle handle, uint access, ref ObjectAttributes attributes,
        out IoStatusBlock status, IntPtr allocation, uint flags, uint share, uint disposition, uint options, IntPtr ea, uint eaLength);
    [DllImport("ntdll.dll")] private static extern int NtWriteFile(SafeFileHandle handle, IntPtr evt, IntPtr apc, IntPtr context, out IoStatusBlock io, IntPtr buffer, uint length, ref long offset, IntPtr key);
    [DllImport("ntdll.dll")] private static extern int NtReadFile(SafeFileHandle handle, IntPtr evt, IntPtr apc, IntPtr context, out IoStatusBlock io, IntPtr buffer, uint length, ref long offset, IntPtr key);
    [DllImport("ntdll.dll")] private static extern int NtFlushBuffersFile(SafeFileHandle handle, out IoStatusBlock io);
    [DllImport("ntdll.dll")] private static extern int NtSetInformationFile(SafeFileHandle handle, out IoStatusBlock io, byte[] bytes, int length, int kind);
    [DllImport("ntdll.dll")] private static extern int NtQueryInformationFile(SafeFileHandle handle, out IoStatusBlock io, [Out] byte[] bytes, int length, int kind);
    [DllImport("ntdll.dll")] private static extern int NtQueryVolumeInformationFile(SafeFileHandle handle, out IoStatusBlock io, [Out] byte[] bytes, int length, int kind);
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)] private static extern SafeFileHandle CreateFileW(string path, uint access, uint share, IntPtr security, uint disposition, uint flags, IntPtr template);
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)] [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetVolumeInformationByHandleW(SafeFileHandle handle, StringBuilder? name, int size, out uint serial, out uint component, out uint flags, StringBuilder format, int formatSize);
    [DllImport("advapi32.dll")] private static extern int GetSecurityInfo(SafeFileHandle handle, int type, uint information, out IntPtr owner, out IntPtr group, out IntPtr dacl, out IntPtr sacl, out IntPtr descriptor);
    [DllImport("advapi32.dll")] private static extern uint GetSecurityDescriptorLength(IntPtr descriptor);
    [DllImport("kernel32.dll")] private static extern IntPtr LocalFree(IntPtr memory);
}
#endif
