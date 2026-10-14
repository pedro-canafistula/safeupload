#if SAFEUPLOAD_ADMISSION_EVIDENCE
using Microsoft.Win32.SafeHandles;
using SafeUpload.Agent.Minifilter;

namespace SafeUpload.Agent.Tests;

public sealed class WriterMetadataClientTests
{
    [Theory]
    [InlineData(0, 0)]
    [InlineData(unchecked((int)0x80070005), 0)] // sender/connection authentication refusal
    [InlineData(0, -1)] // successful transport with incomplete receipt
    public void Client_requires_native_success_and_complete_receipts(int hresult, int adjustment)
    {
        var binding = SecuritySnapshotFixture.Binding(); byte[] envelope = WriterMetadataFixture.Envelope(binding);
        var sender = new Sender(input => WriterMetadataFixture.Page(envelope, input), hresult, adjustment);
        using var port = FilterPort.CreateForNativeReplayTesting(new SafeFileHandle(new IntPtr(123), false), sender);
        if (hresult != 0 || adjustment != 0)
            Assert.Throws<IOException>(() => port.ReadWriterMetadata(binding.DriverInstanceId, binding.ReservationId, 17));
        else
        {
            var metadata = port.ReadWriterMetadata(binding.DriverInstanceId, binding.ReservationId, 17);
            Assert.Equal(Convert.ToHexString(envelope), metadata.EnvelopeHex);
            Assert.Equal(3, sender.Calls); // discover + one page + confirm
        }
    }

    [Fact]
    public void Disposed_connection_cannot_resume_snapshot_or_send_a_page()
    {
        var binding = SecuritySnapshotFixture.Binding();
        var sender = new Sender(_ => [], 0, 0);
        var port = FilterPort.CreateForNativeReplayTesting(new SafeFileHandle(new IntPtr(123), false), sender);
        port.Dispose();
        Assert.Throws<ObjectDisposedException>(() => port.ReadWriterMetadata(binding.DriverInstanceId, binding.ReservationId, 17));
        Assert.Equal(0, sender.Calls);
    }

    private sealed class Sender(Func<byte[], byte[]> response, int hresult, int adjustment) : INativeRecordReplayNativeSender
    {
        internal int Calls;
        public int Send(SafeFileHandle handle, ReadOnlyMemory<byte> input, Memory<byte> output, out uint returned)
        {
            Assert.False(handle.IsClosed); ++Calls;
            byte[] bytes = response(input.ToArray()); bytes.AsSpan().CopyTo(output.Span);
            returned = checked((uint)(bytes.Length + adjustment)); return hresult;
        }
    }
}
#endif
