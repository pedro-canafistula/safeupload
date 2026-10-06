#if SAFEUPLOAD_ADMISSION_EVIDENCE
using System.Buffers.Binary;
using Microsoft.Win32.SafeHandles;
using SafeUpload.Agent.Minifilter;

namespace SafeUpload.Agent.Tests;

public sealed class AdmissionEvidenceWireTests
{
    [Fact]
    public void Managed_status_mirrors_match_driver_sizes_and_offsets()
    {
        AdmissionEvidenceWire.VerifyLayout();
        Assert.Equal(36136, AdmissionEvidenceWire.ExpectedReplySize(AdmissionEvidenceCommand.ActivatingStatus));
        Assert.Equal(32, AdmissionEvidenceWire.ExpectedReplySize(AdmissionEvidenceCommand.EpochStatus));
        Assert.Equal(6672, AdmissionEvidenceWire.ExpectedReplySize(AdmissionEvidenceCommand.VolumeObserve));
    }

    [Fact]
    public void Input_allows_only_readonly_status_commands_and_bounded_start_indices()
    {
        Assert.Equal(new uint[] { 19, 20, 23 },
            Enum.GetValues<AdmissionEvidenceCommand>().Select(command => (uint)command));

        byte[] lastAllowedPage = AdmissionEvidenceWire.CreateInput(
            AdmissionEvidenceCommand.ActivatingStatus, AdmissionEvidenceWire.MaximumActivatingStartIndex);
        Assert.Equal(Contract.Version, ReadUInt32(lastAllowedPage, 0));
        Assert.Equal(16u, ReadUInt32(lastAllowedPage, 4));
        Assert.Equal(19u, ReadUInt32(lastAllowedPage, 8));
        Assert.Equal(20480u, ReadUInt32(lastAllowedPage, 12));

        Assert.Throws<ArgumentOutOfRangeException>(() => AdmissionEvidenceWire.CreateInput(
            AdmissionEvidenceCommand.ActivatingStatus, AdmissionEvidenceWire.MaximumActivatingStartIndex + 1));
        Assert.Throws<ArgumentOutOfRangeException>(() => AdmissionEvidenceWire.CreateInput(
            (AdmissionEvidenceCommand)13, 0));
        Assert.Throws<ArgumentOutOfRangeException>(() => AdmissionEvidenceWire.CreateInput(
            (AdmissionEvidenceCommand)17, 0));
        Assert.Throws<ArgumentOutOfRangeException>(() => AdmissionEvidenceWire.CreateInput(
            AdmissionEvidenceCommand.EpochStatus, 1));
        Assert.Throws<ArgumentOutOfRangeException>(() => AdmissionEvidenceWire.CreateInput(
            AdmissionEvidenceCommand.VolumeObserve, 1));
    }

    [Theory]
    [InlineData(AdmissionEvidenceCommand.ActivatingStatus)]
    [InlineData(AdmissionEvidenceCommand.EpochStatus)]
    [InlineData(AdmissionEvidenceCommand.VolumeObserve)]
    public void Send_returns_exact_wire_receipt_for_each_fixed_status_control(
        AdmissionEvidenceCommand command)
    {
        byte[] expectedReply = ValidReply(command);
        var backend = new FakeSender((SafeFileHandle nativeHandle, byte[] nativeInput, Memory<byte> output, out uint bytesReturned) =>
        {
            _ = nativeHandle;
            _ = nativeInput;
            expectedReply.AsSpan().CopyTo(output.Span);
            bytesReturned = (uint)expectedReply.Length;
            return 0;
        });
        using var handle = FakeHandle();
        using var port = FilterPort.CreateForTesting(handle, backend);

        AdmissionEvidenceReply result = port.SendAdmissionEvidence(command);

        byte[] rawInput = result.RawInput;
        Assert.Equal(Contract.Version, ReadUInt32(rawInput, 0));
        Assert.Equal(16u, ReadUInt32(rawInput, 4));
        Assert.Equal((uint)command, ReadUInt32(rawInput, 8));
        Assert.Equal(0u, ReadUInt32(rawInput, 12));
        Assert.Equal(expectedReply, result.RawReply);
        Assert.Equal((uint)expectedReply.Length, result.BytesReturned);
        Assert.Equal(0, result.HResult);
        Assert.True(result.IsWirePayloadValid);
        Assert.Null(result.ResponseValidationError);
        Assert.True(result.FinishedUtc >= result.StartedUtc);
        Assert.True(result.FinishedTimestamp >= result.StartedTimestamp);

        rawInput[0] ^= 0xff;
        byte[] rawReply = result.RawReply;
        rawReply[0] ^= 0xff;
        Assert.Equal(Contract.Version, ReadUInt32(result.RawInput, 0));
        Assert.Equal(expectedReply, result.RawReply);
    }

    [Fact]
    public void Rejected_command_never_reaches_native_sender()
    {
        var backend = new FakeSender((SafeFileHandle nativeHandle, byte[] nativeInput, Memory<byte> nativeOutput, out uint bytesReturned) =>
        {
            _ = nativeHandle;
            _ = nativeInput;
            _ = nativeOutput;
            bytesReturned = 0;
            return 0;
        });
        using var handle = FakeHandle();
        using var port = FilterPort.CreateForTesting(handle, backend);

        Assert.Throws<ArgumentOutOfRangeException>(() => port.SendAdmissionEvidence((AdmissionEvidenceCommand)13));
        Assert.Throws<ArgumentOutOfRangeException>(() => port.SendAdmissionEvidence((AdmissionEvidenceCommand)17));
        Assert.Throws<ArgumentOutOfRangeException>(() => port.SendAdmissionEvidence((AdmissionEvidenceCommand)21));
        Assert.Throws<ArgumentOutOfRangeException>(() => port.SendAdmissionEvidence(
            AdmissionEvidenceCommand.ActivatingStatus, AdmissionEvidenceWire.MaximumActivatingStartIndex + 1));
        Assert.Equal(0, backend.CallCount);
    }

    [Fact]
    public void Native_failure_keeps_hresult_and_never_exposes_zeroed_reply_buffer()
    {
        const int nativeFailure = unchecked((int)0x80070005);
        var backend = new FakeSender((SafeFileHandle nativeHandle, byte[] nativeInput, Memory<byte> output, out uint bytesReturned) =>
        {
            _ = nativeHandle;
            _ = nativeInput;
            output.Span.Fill(0xA5);
            bytesReturned = 12;
            return nativeFailure;
        });
        using var handle = FakeHandle();
        using var port = FilterPort.CreateForTesting(handle, backend);

        AdmissionEvidenceReply result = port.SendAdmissionEvidence(AdmissionEvidenceCommand.EpochStatus);

        Assert.Equal(nativeFailure, result.HResult);
        Assert.Equal(12u, result.BytesReturned);
        Assert.Empty(result.RawReply);
        Assert.Null(result.ResponseValidationError);
        Assert.False(result.IsWirePayloadValid);
    }

    [Fact]
    public void Short_successful_reply_is_preserved_but_marked_invalid()
    {
        byte[] shortReply = new byte[4];
        BinaryPrimitives.WriteUInt32LittleEndian(shortReply, 32);
        var backend = new FakeSender((SafeFileHandle nativeHandle, byte[] nativeInput, Memory<byte> output, out uint bytesReturned) =>
        {
            _ = nativeHandle;
            _ = nativeInput;
            shortReply.AsSpan().CopyTo(output.Span);
            bytesReturned = (uint)shortReply.Length;
            return 0;
        });
        using var handle = FakeHandle();
        using var port = FilterPort.CreateForTesting(handle, backend);

        AdmissionEvidenceReply result = port.SendAdmissionEvidence(AdmissionEvidenceCommand.EpochStatus);

        Assert.Equal(shortReply, result.RawReply);
        Assert.False(result.IsWirePayloadValid);
        Assert.Contains("Reply length 4 differs from expected 32", result.ResponseValidationError);
    }

    [Fact]
    public void Overreported_success_keeps_available_bytes_and_marks_them_truncated()
    {
        byte[] availableOutput = ValidReply(AdmissionEvidenceCommand.EpochStatus);
        var backend = new FakeSender((SafeFileHandle nativeHandle, byte[] nativeInput, Memory<byte> output, out uint bytesReturned) =>
        {
            _ = nativeHandle;
            _ = nativeInput;
            availableOutput.AsSpan().CopyTo(output.Span);
            bytesReturned = (uint)output.Length + 1;
            return 0;
        });
        using var handle = FakeHandle();
        using var port = FilterPort.CreateForTesting(handle, backend);

        AdmissionEvidenceReply result = port.SendAdmissionEvidence(AdmissionEvidenceCommand.EpochStatus);

        Assert.Equal((uint)availableOutput.Length + 1, result.BytesReturned);
        Assert.Equal(availableOutput, result.RawReply);
        Assert.False(result.IsWirePayloadValid);
        Assert.Contains("truncated to buffer capacity", result.ResponseValidationError);
    }

    [Fact]
    public async Task Diagnostic_sends_on_one_port_are_serialized()
    {
        using var firstEnteredNative = new ManualResetEventSlim();
        using var releaseFirstNative = new ManualResetEventSlim();
        int sendOrdinal = 0;
        var backend = new FakeSender((SafeFileHandle nativeHandle, byte[] nativeInput, Memory<byte> output, out uint bytesReturned) =>
        {
            _ = nativeHandle;
            _ = nativeInput;
            if (Interlocked.Increment(ref sendOrdinal) == 1)
            {
                firstEnteredNative.Set();
                if (!releaseFirstNative.Wait(TimeSpan.FromSeconds(10)))
                {
                    throw new TimeoutException("Test did not release the first fake native send.");
                }
            }
            byte[] reply = ValidReply(AdmissionEvidenceCommand.EpochStatus);
            reply.AsSpan().CopyTo(output.Span);
            bytesReturned = (uint)reply.Length;
            return 0;
        });
        using var handle = FakeHandle();
        using var port = FilterPort.CreateForTesting(handle, backend);
        Task<AdmissionEvidenceReply> first = Task.Run(() =>
            port.SendAdmissionEvidence(AdmissionEvidenceCommand.EpochStatus));
        using var secondStarted = new ManualResetEventSlim();
        Task<AdmissionEvidenceReply>? second = null;

        try
        {
            Assert.True(firstEnteredNative.Wait(TimeSpan.FromSeconds(5)), "first native send was not entered");
            second = Task.Run(() =>
            {
                secondStarted.Set();
                return port.SendAdmissionEvidence(AdmissionEvidenceCommand.EpochStatus);
            });
            Assert.True(secondStarted.Wait(TimeSpan.FromSeconds(5)), "second sender did not start");
            await Task.Delay(TimeSpan.FromMilliseconds(100));
            Assert.Equal(1, backend.CallCount);
            Assert.Equal(1, backend.MaximumConcurrentCalls);
        }
        finally
        {
            releaseFirstNative.Set();
        }

        Assert.True((await first.WaitAsync(TimeSpan.FromSeconds(5))).IsWirePayloadValid);
        Assert.NotNull(second);
        Assert.True((await second!.WaitAsync(TimeSpan.FromSeconds(5))).IsWirePayloadValid);
        Assert.Equal(2, backend.CallCount);
        Assert.Equal(1, backend.MaximumConcurrentCalls);
    }

    [Fact]
    public async Task Dispose_drains_an_inflight_diagnostic_send_and_rejects_later_sends()
    {
        using var enteredNative = new ManualResetEventSlim();
        using var releaseNative = new ManualResetEventSlim();
        var backend = new FakeSender((SafeFileHandle nativeHandle, byte[] nativeInput, Memory<byte> output, out uint bytesReturned) =>
        {
            _ = nativeHandle;
            _ = nativeInput;
            enteredNative.Set();
            if (!releaseNative.Wait(TimeSpan.FromSeconds(10)))
            {
                throw new TimeoutException("Test did not release the fake native send.");
            }
            byte[] reply = ValidReply(AdmissionEvidenceCommand.EpochStatus);
            reply.AsSpan().CopyTo(output.Span);
            bytesReturned = (uint)reply.Length;
            return 0;
        });
        using var handle = FakeHandle();
        var port = FilterPort.CreateForTesting(handle, backend);
        Task<AdmissionEvidenceReply> sendTask = Task.Run(() =>
            port.SendAdmissionEvidence(AdmissionEvidenceCommand.EpochStatus));
        Task? disposeTask = null;

        try
        {
            Assert.True(enteredNative.Wait(TimeSpan.FromSeconds(5)), "native test sender was not entered");
            disposeTask = Task.Run(port.Dispose);
            await Task.Delay(TimeSpan.FromMilliseconds(100));
            Assert.False(disposeTask.IsCompleted);
            Assert.False(handle.IsClosed, "Dispose closed the port while its send was active");
        }
        finally
        {
            releaseNative.Set();
        }

        AdmissionEvidenceReply completed = await sendTask.WaitAsync(TimeSpan.FromSeconds(5));
        Assert.True(completed.IsWirePayloadValid);
        await (disposeTask ?? Task.Run(port.Dispose)).WaitAsync(TimeSpan.FromSeconds(5));
        Assert.True(handle.IsClosed);
        Assert.Throws<ObjectDisposedException>(() =>
            port.SendAdmissionEvidence(AdmissionEvidenceCommand.EpochStatus));
        Assert.Equal(1, backend.CallCount);
    }

    private static byte[] ValidReply(AdmissionEvidenceCommand command)
    {
        int size = AdmissionEvidenceWire.ExpectedReplySize(command);
        byte[] reply = new byte[size];
        BinaryPrimitives.WriteUInt32LittleEndian(reply.AsSpan(0, 4), (uint)size);
        switch (command)
        {
            case AdmissionEvidenceCommand.ActivatingStatus:
                BinaryPrimitives.WriteUInt32LittleEndian(reply.AsSpan(4, 4), 1);
                BinaryPrimitives.WriteUInt32LittleEndian(reply.AsSpan(8, 4), 1);
                BinaryPrimitives.WriteUInt32LittleEndian(reply.AsSpan(12, 4), 0);
                BinaryPrimitives.WriteUInt32LittleEndian(reply.AsSpan(16, 4), 1);
                break;
            case AdmissionEvidenceCommand.EpochStatus:
                break;
            case AdmissionEvidenceCommand.VolumeObserve:
                BinaryPrimitives.WriteUInt32LittleEndian(reply.AsSpan(4, 4), 0);
                break;
            default:
                throw new ArgumentOutOfRangeException(nameof(command));
        }
        return reply;
    }

    private static uint ReadUInt32(byte[] bytes, int offset) =>
        BinaryPrimitives.ReadUInt32LittleEndian(bytes.AsSpan(offset, sizeof(uint)));

    private static SafeFileHandle FakeHandle() => new(new IntPtr(1), ownsHandle: false);

    private delegate int SendCallback(SafeFileHandle handle, byte[] input,
        Memory<byte> output, out uint bytesReturned);

    private sealed class FakeSender(SendCallback callback) : IAdmissionEvidenceNativeSender
    {
        private int _callCount;
        private int _activeCalls;
        private int _maximumConcurrentCalls;
        public int CallCount => Volatile.Read(ref _callCount);
        public int MaximumConcurrentCalls => Volatile.Read(ref _maximumConcurrentCalls);

        public int Send(SafeFileHandle handle, ReadOnlyMemory<byte> input,
            Memory<byte> output, out uint bytesReturned)
        {
            Interlocked.Increment(ref _callCount);
            int activeCalls = Interlocked.Increment(ref _activeCalls);
            UpdateMaximum(activeCalls);
            try
            {
                return callback(handle, input.ToArray(), output, out bytesReturned);
            }
            finally
            {
                Interlocked.Decrement(ref _activeCalls);
            }
        }

        private void UpdateMaximum(int activeCalls)
        {
            int observed;
            while (activeCalls > (observed = Volatile.Read(ref _maximumConcurrentCalls)) &&
                   Interlocked.CompareExchange(ref _maximumConcurrentCalls, activeCalls, observed) != observed)
            {
            }
        }
    }
}
#endif
