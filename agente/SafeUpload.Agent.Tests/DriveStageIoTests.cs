using System.Reflection;
using System.Runtime.InteropServices;
using System.Text;
using SafeUpload.Agent.Drive;

namespace SafeUpload.Agent.Tests;

public sealed class DriveStageIoTests
{
    [Theory]
    [InlineData(false, false)]
    [InlineData(false, true)]
    [InlineData(true, false)]
    [InlineData(true, true)]
    public void Open_writer_snapshot_contains_every_accepted_byte_without_an_explicit_flush(bool create, bool sensitive)
    {
        using var f = new DriveRecoveryTests.Fixture();
        var path = create ? @"\new.txt" : @"\report.txt";
        var target = Path.Combine(f.Backing, create ? "new.txt" : "report.txt");
        object node, handle;
        Assert.Equal(0, create
            ? f.Fs.Create(path, 0, 0, 0, [], 0, out node, out handle, out _, out _)
            : f.Fs.Open(path, 0, 0, out node, out handle, out _, out _));
        try
        {
            Assert.Equal(0, f.Fs.SetFileSize(node, handle, 0, false, out _));
            var bytes = sensitive ? "CPF: 529.982.247-25" : "Clean accepted bytes";
            Write(f, node, handle, bytes, 0);
            var content = ((Handle)handle).Node.Content!;
            // The idle worker can inspect while the writer remains open, without a Flush or Cleanup callback.
            Invoke(f.Fs, "InspectOne", content);
            var decision = Assert.Single(f.Observer.Decisions);
            Assert.Equal(bytes, File.ReadAllText(decision.Snapshot));
            Assert.Equal(!sensitive, decision.Approved);
            Invoke(f.Fs, "Reconcile");
            if (sensitive)
            {
                Assert.Empty(f.Observer.Publications);
                if (create) Assert.False(File.Exists(target));
                else Assert.Equal("Published old version", File.ReadAllText(target));
            }
            else
            {
                Assert.True(Assert.Single(f.Observer.Publications).Succeeded);
                Assert.Equal(bytes, File.ReadAllText(target));
            }
        }
        finally { f.Fs.Close(node, handle); }
    }

    [Fact]
    public void Other_handles_read_current_bytes_and_overlapping_writes_keep_callback_order()
    {
        using var f = new DriveRecoveryTests.Fixture();
        f.Create(@"\new.txt");
        f.Open(@"\new.txt", (node, first) =>
        {
            Write(f, node, first, "AAAA", 0);
            f.Open(@"\new.txt", (otherNode, second) =>
            {
                var pointer = Marshal.AllocHGlobal(4);
                try
                {
                    Assert.Equal(0, f.Fs.Read(otherNode, second, pointer, 0, 4, out var read));
                    Assert.Equal(4u, read);
                    var bytes = new byte[4];
                    Marshal.Copy(pointer, bytes, 0, 4);
                    Assert.Equal("AAAA", Encoding.UTF8.GetString(bytes));
                    Write(f, otherNode, second, "BB", 1);
                }
                finally { Marshal.FreeHGlobal(pointer); }
            });
            // Disposing the earlier writer must not overwrite the later writer's accepted bytes.
        });
        f.Read(@"\new.txt", "ABBA");
    }

    private static void Write(DriveRecoveryTests.Fixture f, object node, object handle, string text, ulong offset)
    {
        var bytes = Encoding.UTF8.GetBytes(text);
        var pointer = Marshal.AllocHGlobal(bytes.Length);
        try
        {
            Marshal.Copy(bytes, 0, pointer, bytes.Length);
            Assert.Equal(0, f.Fs.Write(node, handle, pointer, offset, (uint)bytes.Length, false, false, out var written, out _));
            Assert.Equal((uint)bytes.Length, written);
        }
        finally { Marshal.FreeHGlobal(pointer); }
    }

    private static void Invoke(object target, string method, params object[] args) =>
        target.GetType().GetMethod(method, BindingFlags.NonPublic | BindingFlags.Instance)!.Invoke(target, args);
}
