using System.Buffers.Binary;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Text;
using Microsoft.Win32.SafeHandles;

namespace SafeUpload.Agent.Service.Interception;

/// <summary>Basic state of one sealed version. ChangeTime is deliberately absent.</summary>
public sealed record StagedFileMetadata(long CreationTime, long LastAccessTime, long LastWriteTime, uint Attributes)
{
    internal const uint SupportedAttributes = 0x000021A7; // R/H/S/Archive/Normal/Temporary/NoIndex
    internal const int MaximumStreamInventory = 64 * 1024;

    public void Validate()
    {
        if (CreationTime < 0 || LastAccessTime < 0 || LastWriteTime < 0)
            throw new StagedMetadataException("metadata_timestamp_control_unsupported");
        uint unsupported = Attributes & ~SupportedAttributes;
        if (unsupported == 0) return;
        throw new StagedMetadataException((unsupported & 0x4000) != 0 ? "metadata_efs_unsupported" :
            (unsupported & 0x1000) != 0 ? "metadata_offline_unsupported" :
            (unsupported & 0x800) != 0 ? "metadata_compression_unsupported" :
            (unsupported & 0x200) != 0 ? "metadata_sparse_unsupported" :
            (unsupported & 0x400) != 0 ? "metadata_reparse_unsupported" : "metadata_attributes_unsupported");
    }

    // Capture BEFORE data reads. Every query addresses the same no-follow
    // handle; no scanner path/name supplies object identity or metadata.
    internal static StagedFileMetadata Capture(SafeFileHandle file)
    {
        byte[] basic = Query(file, 0, 40);
        var result = new StagedFileMetadata(BitConverter.ToInt64(basic, 0), BitConverter.ToInt64(basic, 8),
            BitConverter.ToInt64(basic, 16), BitConverter.ToUInt32(basic, 32));
        result.Validate();
        byte[] standard = Query(file, 1, 24);
        if (BitConverter.ToUInt32(standard, 16) != 1 || standard[21] != 0 || standard[20] != 0)
            throw new StagedMetadataException("metadata_single_link_regular_file_required");
        uint eaSize = 0;
        int status = NtQueryInformationFile(file, out var io, ref eaSize, sizeof(uint), 7); // FileEaInformation
        if (status != 0 || io.Information.ToUInt64() != sizeof(uint))
            throw new StagedMetadataException("metadata_ea_query_failed");
        if (eaSize != 0) throw new StagedMetadataException("metadata_ea_unsupported");
        ValidateStreams(QueryStreams(file)); // FileStreamInfo, bounded; overflow fails closed
        return result;
    }

    internal static StagedFileMetadata CapturePath(string path)
    {
        using var handle = CreateFile(path, 0x88, 5, IntPtr.Zero, 3, 0x00200000, IntPtr.Zero);
        if (handle.IsInvalid)
            throw new StagedMetadataException("metadata_source_open_failed", new Win32Exception(Marshal.GetLastWin32Error()));
        return Capture(handle);
    }

    // FILE_STREAM_INFO is an offset chain; never trust a missing terminator,
    // odd name size, overlapping next entry or an unknown stream type/name.
    internal static void ValidateStreams(ReadOnlySpan<byte> bytes)
    {
        if (bytes.IsEmpty) return; // complete native ERROR_HANDLE_EOF enumeration
        int offset = 0, rows = 0;
        bool unnamed = false;
        while (true)
        {
            if (++rows > 256 || bytes.Length - offset < 24)
                throw new StagedMetadataException("metadata_stream_inventory_invalid");
            ReadOnlySpan<byte> entry = bytes[offset..];
            uint next = BinaryPrimitives.ReadUInt32LittleEndian(entry);
            uint nameBytes = BinaryPrimitives.ReadUInt32LittleEndian(entry[4..]);
            long size = BinaryPrimitives.ReadInt64LittleEndian(entry[8..]);
            if ((nameBytes & 1) != 0 || nameBytes == 0 || nameBytes > entry.Length - 24 || size < 0)
                throw new StagedMetadataException("metadata_stream_inventory_invalid");
            string name = Encoding.Unicode.GetString(entry.Slice(24, checked((int)nameBytes)));
            if (name.Equals(":Zone.Identifier:$DATA", StringComparison.OrdinalIgnoreCase))
                throw new StagedMetadataException("metadata_zone_transaction_unavailable");
            if (!name.Equals("::$DATA", StringComparison.Ordinal) || unnamed)
                throw new StagedMetadataException("metadata_ads_unsupported");
            unnamed = true;
            if (next == 0) return;
            if ((next & 7) != 0 || next < 24 + nameBytes || next > entry.Length - 24)
                throw new StagedMetadataException("metadata_stream_inventory_invalid");
            offset = checked(offset + (int)next);
        }
    }

    internal void Apply(SafeFileHandle output, bool includeAttributes = true)
    {
        Validate();
        byte[] basic = new byte[40];
        BitConverter.GetBytes(CreationTime).CopyTo(basic, 0);
        BitConverter.GetBytes(LastAccessTime).CopyTo(basic, 8);
        BitConverter.GetBytes(LastWriteTime).CopyTo(basic, 16);
        // ChangeTime=0: leave it to this mutation and the publication rename.
        BitConverter.GetBytes(includeAttributes ? (Attributes == 0 ? 0x80u : Attributes) : 0u).CopyTo(basic, 32);
        if (!SetFileInformationByHandle(output, 0, basic, basic.Length))
            throw new StagedMetadataException("metadata_apply_failed", new Win32Exception(Marshal.GetLastWin32Error()));
        // This lower FILE_OBJECT belongs only to our copy, unlike the shared
        // upper backing. Prevent its cleanup from replacing the final dates.
        Array.Clear(basic);
        BitConverter.GetBytes(-1L).CopyTo(basic, 8);
        BitConverter.GetBytes(-1L).CopyTo(basic, 16);
        if (!SetFileInformationByHandle(output, 0, basic, basic.Length))
            throw new StagedMetadataException("metadata_timestamp_freeze_failed", new Win32Exception(Marshal.GetLastWin32Error()));
    }

    private static byte[] Query(SafeFileHandle file, int infoClass, int size)
    {
        byte[] buffer = new byte[size];
        if (!GetFileInformationByHandleEx(file, infoClass, buffer, checked((uint)size)))
            throw new StagedMetadataException("metadata_query_failed", new Win32Exception(Marshal.GetLastWin32Error()));
        return buffer;
    }

    private static byte[] QueryStreams(SafeFileHandle file)
    {
        byte[] buffer = new byte[MaximumStreamInventory];
        if (GetFileInformationByHandleEx(file, 7, buffer, checked((uint)buffer.Length))) return buffer;
        int error = Marshal.GetLastWin32Error();
        if (error == 38) return []; // ERROR_HANDLE_EOF: no streams, not a partial/overflow result
        throw new StagedMetadataException("metadata_stream_query_failed", new Win32Exception(error));
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct IoStatus { public IntPtr Status; public UIntPtr Information; }
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern SafeFileHandle CreateFile(string path, uint access, uint share, IntPtr security,
        uint disposition, uint flags, IntPtr template);
    [DllImport("ntdll.dll")]
    private static extern int NtQueryInformationFile(SafeFileHandle file, out IoStatus io,
        ref uint info, uint length, int infoClass);
    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetFileInformationByHandleEx(SafeFileHandle file, int infoClass, byte[] info, uint length);
    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool SetFileInformationByHandle(SafeFileHandle file, int infoClass, byte[] info, int length);
}

internal sealed class StagedMetadataException(string reason, Exception? inner = null) : IOException(reason, inner)
{
    internal string Reason { get; } = reason;
    internal bool IsPermanent => Reason.EndsWith("_unsupported", StringComparison.Ordinal) ||
        Reason is "metadata_zone_transaction_unavailable" or "metadata_single_link_regular_file_required" or
            "metadata_stream_inventory_invalid" or "metadata_readonly_destination";
}
