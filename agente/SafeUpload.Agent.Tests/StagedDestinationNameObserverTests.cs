using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Text;
using Microsoft.Win32.SafeHandles;
using SafeUpload.Agent.Service.Interception;

namespace SafeUpload.Agent.Tests;

// Actual unprotected Windows NTFS handle controls plus hostile buffer inputs.
// These do not qualify protected publication, Verifier or the driver exporter.
public sealed class StagedDestinationNameObserverTests : IDisposable
{
    private readonly TestWorkspace _workspace = new();
    public void Dispose() => _workspace.Dispose();

    private static SafeFileHandle Open(string path, uint access, uint share = 7, uint flags = 0x00200080)
    {
        var handle = CreateFileW(path, access, share, IntPtr.Zero, 3, flags, IntPtr.Zero);
        if (!handle.IsInvalid) return handle;
        int error = Marshal.GetLastWin32Error(); handle.Dispose();
        throw new IOException("Native observer control open failed.", new Win32Exception(error));
    }

    private static StagedStageIdentity Identity(SafeFileHandle handle)
    {
        byte[] data = new byte[24];
        if (!GetFileInformationByHandleEx(handle, 18, data, 24)) throw new Win32Exception(Marshal.GetLastWin32Error());
        return new(BitConverter.ToUInt64(data, 0), BitConverter.ToUInt64(data, 16), BitConverter.ToUInt64(data, 8));
    }

    private static StagedDestinationIdentity Destination(SafeFileHandle root, SafeFileHandle parent, string leaf) =>
        new(Identity(root), Identity(parent), false, leaf);

    [Fact]
    public void Real_pending_original_is_observed_without_child_reopen_then_absent_after_last_reader_close()
    {
        if (!OperatingSystem.IsWindows()) return;
        const string leaf = "pending.txt";
        string path = Path.Combine(_workspace.Root, leaf);
        File.WriteAllText(path, "original-pre-open");
        using var root = Open(Path.GetPathRoot(path)!, 0x80, flags: 0x02200080);
        using var parent = Open(_workspace.Root, 0x81, flags: 0x02200080);
        var destination = Destination(root, parent, leaf);
        using var reader = Open(path, 0x80000000);
        using var creator = Open(path, 0x10080, flags: 0x04200080); // Original native FILE_DELETE_ON_CLOSE.
        var original = Identity(creator);
        Assert.Equal(original, Identity(reader));
        creator.Dispose();
        using (var probe = CreateFileW(path, 0x80, 7, IntPtr.Zero, 3, 0x80, IntPtr.Zero))
        {
            Assert.True(probe.IsInvalid);
            Assert.Equal(5, Marshal.GetLastWin32Error()); // The child itself cannot be reopened.
        }
        var pending = StagedDestinationNameObserver.Observe(root, parent, destination, CancellationToken.None);
        Assert.True(pending.CompleteEnumeration);
        Assert.Equal(original, pending.PublicIdentity);
        Assert.Equal(destination.Parent, pending.ParentBefore);
        Assert.Equal(destination.Parent, pending.ParentAfter);
        reader.Dispose();
        var absent = StagedDestinationNameObserver.Observe(root, parent, destination, CancellationToken.None);
        Assert.True(absent.CompleteEnumeration);
        Assert.Null(absent.PublicIdentity);
    }

    [Fact]
    public void Real_share_none_child_is_observable_and_wrong_anchors_or_case_mode_fail_closed()
    {
        if (!OperatingSystem.IsWindows()) return;
        const string leaf = "Exclusive.txt";
        string path = Path.Combine(_workspace.Root, leaf);
        File.WriteAllText(path, "unchanged");
        using var root = Open(Path.GetPathRoot(path)!, 0x80, flags: 0x02200080);
        using var parent = Open(_workspace.Root, 0x81, flags: 0x02200080);
        using var exclusive = Open(path, 0x80000000, 0);
        var destination = Destination(root, parent, leaf);
        using (var probe = CreateFileW(path, 0x80000000, 7, IntPtr.Zero, 3, 0x80, IntPtr.Zero))
        {
            Assert.True(probe.IsInvalid);
            Assert.Equal(32, Marshal.GetLastWin32Error());
        }
        Assert.Equal(Identity(exclusive), StagedDestinationNameObserver.Observe(root, parent,
            destination, CancellationToken.None).PublicIdentity);
        Assert.Throws<IOException>(() => StagedDestinationNameObserver.Observe(root, root, destination, CancellationToken.None));
        var wrongRoot = new StagedDestinationIdentity(destination.VolumeRoot with { FileIdHigh = 999 },
            destination.Parent, false, leaf);
        Assert.Throws<IOException>(() => StagedDestinationNameObserver.Observe(root, parent, wrongRoot, CancellationToken.None));
        var wrongCase = new StagedDestinationIdentity(destination.VolumeRoot, destination.Parent, true, leaf);
        Assert.Throws<IOException>(() => StagedDestinationNameObserver.Observe(root, parent, wrongCase, CancellationToken.None));
        using var canceled = new CancellationTokenSource(); canceled.Cancel();
        Assert.Throws<OperationCanceledException>(() => StagedDestinationNameObserver.Observe(root, parent, destination, canceled.Token));
    }

    [Fact]
    public void Real_multi_page_directory_restarts_each_observation_and_never_infers_absence_from_one_page()
    {
        if (!OperatingSystem.IsWindows()) return;
        string padding = new('x', 150);
        for (int i = 0; i < 250; i++)
            File.WriteAllText(Path.Combine(_workspace.Root, $"{i:D4}-{padding}.txt"), "");
        string leaf = $"zz-{padding}-target.txt", path = Path.Combine(_workspace.Root, leaf);
        File.WriteAllText(path, "stable");
        using var root = Open(Path.GetPathRoot(path)!, 0x80, flags: 0x02200080);
        using var parent = Open(_workspace.Root, 0x81, flags: 0x02200080);
        using var target = Open(path, 0x80);
        var destination = Destination(root, parent, leaf);
        var expected = Identity(target);
        for (int pass = 0; pass < 3; pass++)
            Assert.Equal(expected, StagedDestinationNameObserver.Observe(root, parent, destination,
                CancellationToken.None).PublicIdentity);
        var missing = new StagedDestinationIdentity(destination.VolumeRoot, destination.Parent, false, "absent.txt");
        Assert.Null(StagedDestinationNameObserver.Observe(root, parent, missing, CancellationToken.None).PublicIdentity);
        Assert.Equal(expected, StagedDestinationNameObserver.Observe(root, parent, destination,
            CancellationToken.None).PublicIdentity);
    }

    private static byte[] Entry(string name = "document.txt")
    {
        byte[] encoded = Encoding.Unicode.GetBytes(name);
        byte[] data = new byte[88 + encoded.Length];
        BitConverter.GetBytes(0x80u).CopyTo(data, 56);
        BitConverter.GetBytes((uint)encoded.Length).CopyTo(data, 60);
        BitConverter.GetBytes(0x1234UL).CopyTo(data, 72);
        BitConverter.GetBytes(0x5678UL).CopyTo(data, 80);
        encoded.CopyTo(data, 88);
        return data;
    }

    private static StagedDestinationIdentity SyntheticDestination(bool sensitive = false) =>
        new(new(7, 11, 12), new(7, 21, 22), sensitive, "document.txt");

    [Fact]
    public void Directory_decoder_retains_all_128_identity_bits_and_rejects_duplicate_canonical_names()
    {
        StagedStageIdentity? found = null;
        var destination = SyntheticDestination();
        StagedDestinationNameObserver.DecodePage(Entry("Document.txt"), destination, ref found);
        Assert.Equal(new StagedStageIdentity(7, 0x5678, 0x1234), found);
        Assert.Throws<IOException>(() => StagedDestinationNameObserver.DecodePage(Entry("DOCUMENT.TXT"), destination, ref found));
        found = null;
        StagedDestinationNameObserver.DecodePage(Entry("Document.txt"), SyntheticDestination(true), ref found);
        Assert.Null(found);
    }

    [Theory]
    [InlineData("short")]
    [InlineData("zero-name")]
    [InlineData("odd-name")]
    [InlineData("long-name")]
    [InlineData("invalid-utf16")]
    [InlineData("overlap")]
    [InlineData("unaligned")]
    [InlineData("reparse")]
    [InlineData("directory")]
    [InlineData("zero-id")]
    public void Malformed_directory_page_never_becomes_complete_name_evidence(string mutation)
    {
        byte[] data = Entry();
        switch (mutation)
        {
            case "short": data = new byte[87]; break;
            case "zero-name": BitConverter.GetBytes(0u).CopyTo(data, 60); break;
            case "odd-name": BitConverter.GetBytes(1u).CopyTo(data, 60); break;
            case "long-name": BitConverter.GetBytes(uint.MaxValue).CopyTo(data, 60); break;
            case "invalid-utf16": data[88] = 0; data[89] = 0xD8; break;
            case "overlap": BitConverter.GetBytes(88u).CopyTo(data, 0); break;
            case "unaligned": BitConverter.GetBytes(113u).CopyTo(data, 0); break;
            case "reparse": BitConverter.GetBytes(0x400u).CopyTo(data, 56); break;
            case "directory": BitConverter.GetBytes(0x10u).CopyTo(data, 56); break;
            case "zero-id": Array.Clear(data, 72, 16); break;
        }
        StagedStageIdentity? found = null;
        Assert.Throws<IOException>(() => StagedDestinationNameObserver.DecodePage(data, SyntheticDestination(), ref found));
    }

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern SafeFileHandle CreateFileW(string path, uint access, uint share,
        IntPtr security, uint disposition, uint flags, IntPtr template);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetFileInformationByHandleEx(SafeFileHandle file, int kind, [Out] byte[] data, uint bytes);
}
