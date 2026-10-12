using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Text;
using Microsoft.Win32.SafeHandles;

namespace SafeUpload.Agent.Service.Interception;

// Read-only recovery observation through driver-checked directory anchors.
// Never opens the child, follows a path, widens sharing, or proves unlink.
// The dispatcher must hold the anchors' operation rundown while borrowing
// them; the destination reconciliation turn keeps publication held.
internal static class StagedDestinationNameObserver
{
    private const int PageBytes = 64 * 1024;
    private const int MaximumPages = 64;
    private const int EntryHeaderBytes = 88;
    private static readonly Encoding StrictUtf16 = new UnicodeEncoding(false, false, true);

    internal static StagedDestinationNameObservation Observe(SafeFileHandle volumeRoot,
        SafeFileHandle parent, StagedDestinationIdentity destination, CancellationToken token)
    {
        if (!OperatingSystem.IsWindows()) throw new PlatformNotSupportedException("Native directory recovery requires Windows.");
        ArgumentNullException.ThrowIfNull(volumeRoot);
        ArgumentNullException.ThrowIfNull(parent);
        ArgumentNullException.ThrowIfNull(destination);
        // Enumeration has a cursor on the directory FILE_OBJECT. Serialize
        // users of this anchor and explicitly restart each complete pass.
        lock (parent)
        {
            bool rootReference = false, parentReference = false;
            try
            {
                volumeRoot.DangerousAddRef(ref rootReference);
                parent.DangerousAddRef(ref parentReference);
                RequireDirectory(volumeRoot, destination.VolumeRoot);
                StagedStageIdentity before = RequireDirectory(parent, destination.Parent);
                RequireCaseMode(parent, destination.CaseSensitive);
                StagedStageIdentity? first = Enumerate(parent, destination, token);
                StagedStageIdentity? second = Enumerate(parent, destination, token);
                RequireCaseMode(parent, destination.CaseSensitive);
                StagedStageIdentity after = RequireDirectory(parent, destination.Parent);
                RequireDirectory(volumeRoot, destination.VolumeRoot);
                if (first != second) throw new IOException("The public name changed during native recovery observation.");
                return new(destination, before, after, true, second);
            }
            finally
            {
                if (parentReference) parent.DangerousRelease();
                if (rootReference) volumeRoot.DangerousRelease();
            }
        }
    }

    private static StagedStageIdentity RequireDirectory(SafeFileHandle handle, StagedStageIdentity expected)
    {
        byte[] basic = Query(handle, 0, 40); // FILE_BASIC_INFO, FileAttributes at 32.
        uint attributes = BitConverter.ToUInt32(basic, 32);
        if ((attributes & 0x10) == 0 || (attributes & 0x400) != 0)
            throw new IOException("Native recovery requires a checked non-reparse directory anchor.");
        byte[] id = Query(handle, 18, 24); // volume serial + full FILE_ID_128.
        var actual = new StagedStageIdentity(BitConverter.ToUInt64(id, 0),
            BitConverter.ToUInt64(id, 16), BitConverter.ToUInt64(id, 8));
        if (actual != expected) throw new IOException("The native recovery directory anchor changed identity.");
        return actual;
    }

    private static void RequireCaseMode(SafeFileHandle parent, bool expected)
    {
        uint flags = BitConverter.ToUInt32(Query(parent, 23, 4), 0); // FILE_CASE_SENSITIVE_INFO.
        if ((flags & ~1u) != 0 || ((flags & 1) != 0) != expected)
            throw new IOException("The native recovery parent case mode is unknown or changed.");
    }

    private static byte[] Query(SafeFileHandle handle, int kind, int bytes)
    {
        byte[] data = new byte[bytes];
        if (!GetFileInformationByHandleEx(handle, kind, data, checked((uint)bytes)))
            throw new IOException("Could not query the checked native recovery anchor.",
                new Win32Exception(Marshal.GetLastWin32Error()));
        return data;
    }

    private static StagedStageIdentity? Enumerate(SafeFileHandle parent,
        StagedDestinationIdentity destination, CancellationToken token)
    {
        StagedStageIdentity? found = null;
        byte[] data = new byte[PageBytes];
        for (int page = 0; page < MaximumPages; page++)
        {
            token.ThrowIfCancellationRequested();
            Array.Clear(data);
            // https://learn.microsoft.com/windows/win32/api/winbase/ns-winbase-file_id_extd_dir_info
            if (!GetFileInformationByHandleEx(parent, page == 0 ? 20 : 19, data, PageBytes))
            {
                int error = Marshal.GetLastWin32Error();
                if (error == 18) return found; // ERROR_NO_MORE_FILES, never a child-open error.
                throw new IOException("The checked native parent enumeration did not complete.", new Win32Exception(error));
            }
            DecodePage(data, destination, ref found);
        }
        throw new IOException("Native parent enumeration exceeded its bound; no absence proof is available.");
    }

    internal static void DecodePage(byte[] data, StagedDestinationIdentity destination,
        ref StagedStageIdentity? found)
    {
        int offset = 0;
        while (true)
        {
            if (offset > data.Length - EntryHeaderBytes)
                throw new IOException("Short extended directory entry.");
            uint next = BitConverter.ToUInt32(data, offset);
            uint length = BitConverter.ToUInt32(data, offset + 60);
            if (length == 0 || (length & 1) != 0 || length > data.Length - offset - EntryHeaderBytes)
                throw new IOException("Invalid extended directory name length.");
            string name;
            try { name = StrictUtf16.GetString(data, offset + EntryHeaderBytes, checked((int)length)); }
            catch (DecoderFallbackException ex) { throw new IOException("Invalid native directory name encoding.", ex); }
            if (destination.LeafEquals(name))
            {
                if (found is not null) throw new IOException("Duplicate canonical name in native recovery enumeration.");
                uint attributes = BitConverter.ToUInt32(data, offset + 56);
                ulong low = BitConverter.ToUInt64(data, offset + 72), high = BitConverter.ToUInt64(data, offset + 80);
                if ((attributes & 0x410) != 0 || (high | low) == 0)
                    throw new IOException("The public recovery entry is a directory, reparse point or unknown identity.");
                found = new(destination.Parent.VolumeSerialNumber, high, low);
            }
            if (next == 0) return;
            if (next < EntryHeaderBytes + length || (next & 7) != 0 || next > data.Length - offset - EntryHeaderBytes)
                throw new IOException("Invalid extended directory entry offset.");
            offset = checked(offset + (int)next);
        }
    }

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetFileInformationByHandleEx(SafeFileHandle file, int kind,
        [Out] byte[] data, uint bytes);
}
