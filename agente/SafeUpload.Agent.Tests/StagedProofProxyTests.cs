#if SAFEUPLOAD_ADMISSION_EVIDENCE
using System.Buffers.Binary;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Win32.SafeHandles;
using SafeUpload.Agent.Minifilter;
using SafeUpload.Agent.Service.Diagnostics;

namespace SafeUpload.Agent.Tests;

public sealed class StagedProofProxyTests
{
    private static byte[] Control(uint command, uint reserved = 0, int length = 16)
    {
        byte[] input = new byte[length];
        BinaryPrimitives.WriteUInt32LittleEndian(input, Contract.Version);
        BinaryPrimitives.WriteUInt32LittleEndian(input.AsSpan(4), (uint)length);
        BinaryPrimitives.WriteUInt32LittleEndian(input.AsSpan(8), command);
        BinaryPrimitives.WriteUInt32LittleEndian(input.AsSpan(12), reserved);
        return input;
    }

    [Theory]
    [InlineData(1)] [InlineData(3)] [InlineData(4)] [InlineData(9)]
    [InlineData(10)] [InlineData(11)] [InlineData(13)] [InlineData(14)]
    [InlineData(15)] [InlineData(16)] [InlineData(18)] [InlineData(21)] [InlineData(26)]
    public void MutatingOrUnspecifiedControlsNeverReachNative(uint command)
    {
        var backend = new Native();
        using var port = FilterPort.CreateForTesting(new SafeFileHandle(new IntPtr(1), false), backend);
        Assert.Throws<InvalidDataException>(() => port.SendStagedProof(Control(command), 0));
        Assert.Equal(0, backend.Calls);
    }

    [Fact]
    public void OptionsPagingAndExactBoundsFailClosed()
    {
        foreach (var (command, reserved, length, output) in new (uint, uint, int, int)[] {
            (20, 1, 16, 32), (20, 0, 17, 32), (20, 0, 16, 33),
            (5, 4, 16, 0), (6, 1, 16, 0), (8, 0, 16, 1960),
            (22, 1, 32, 672), (19, 1, 16, 36136), (25, 20481, 16, 36392) })
            Assert.Throws<InvalidDataException>(() => StagedProofProxyWire.Validate(Control(command, reserved, length), output));
        Assert.Equal(0, StagedProofProxyWire.Validate(Control(5, 3), 0));
        Assert.Equal(1960, StagedProofProxyWire.Validate(Control(8, 0, 32), 1960));
        Assert.Equal(36136, StagedProofProxyWire.Validate(Control(19, 20480), 36136));
        byte[] registry = Control(17, 0, 28);
        BinaryPrimitives.WriteUInt16LittleEndian(registry.AsSpan(16), 1);
        BinaryPrimitives.WriteUInt16LittleEndian(registry.AsSpan(18), 1);
        Assert.Equal(104, StagedProofProxyWire.Validate(registry, 104));
        BinaryPrimitives.WriteUInt16LittleEndian(registry.AsSpan(18), 2);
        Assert.Throws<InvalidDataException>(() => StagedProofProxyWire.Validate(registry, 104));
    }

    [Fact]
    public void FrameLengthReservedBytesAndReplyCapAreChecked()
    {
        byte[] body = new byte[80];
        BinaryPrimitives.WriteUInt32LittleEndian(body, StagedProofProxyWire.Magic);
        BinaryPrimitives.WriteUInt32LittleEndian(body.AsSpan(4), 32);
        BinaryPrimitives.WriteUInt32LittleEndian(body.AsSpan(8), 16);
        Control(20).CopyTo(body, 64);
        Assert.Equal(20u, BinaryPrimitives.ReadUInt32LittleEndian(StagedProofProxyWire.Parse(body).Input.AsSpan(8)));
        foreach (int offset in new[] { 12, 63, 8, 0 }) {
            byte[] invalid = (byte[])body.Clone(); invalid[offset] ^= 1;
            Assert.Throws<InvalidDataException>(() => StagedProofProxyWire.Parse(invalid));
        }
        BinaryPrimitives.WriteUInt32LittleEndian(body.AsSpan(4), uint.MaxValue);
        Assert.Throws<InvalidDataException>(() => StagedProofProxyWire.Parse(body));
    }

    [Fact]
    public void PrototypeRelayDefaultsOffAndRequiresSystem()
    {
        var logger = NullLogger<AdmissionEvidenceEndpoint>.Instance;
        Assert.False(new AdmissionEvidenceEndpoint(logger).StagedProofEnabled);
        var config = new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string, string?> {
            ["Diagnostics:StagedProofProxy"] = "true" }).Build();
        Assert.True(new AdmissionEvidenceEndpoint(logger, config).StagedProofEnabled);
        Assert.True(AdmissionEvidenceEndpoint.IsStagedProofAuthorized(true, "S-1-5-18"));
        Assert.False(AdmissionEvidenceEndpoint.IsStagedProofAuthorized(false, "S-1-5-18"));
        Assert.False(AdmissionEvidenceEndpoint.IsStagedProofAuthorized(true, "S-1-5-32-544"));
        Assert.False(AdmissionEvidenceEndpoint.IsStagedProofAuthorized(true, null));
    }

    [Fact]
    public void NativeReplyOverreportIsBoundedAndInvalid()
    {
        var backend = new Native { Overreport = true };
        using var port = FilterPort.CreateForTesting(new SafeFileHandle(new IntPtr(1), false), backend);
        var reply = port.SendStagedProof(Control(20), 32);
        Assert.False(reply.IsWirePayloadValid);
        Assert.Equal(32, reply.RawReply.Length);
        Assert.Equal(33u, reply.BytesReturned);
    }

    [Fact]
    public async Task BindingRejectsNewRequestsAndDrainsItsOwnedPortSend()
    {
        using var entered = new ManualResetEventSlim();
        using var release = new ManualResetEventSlim();
        var backend = new Native();
        using var port = FilterPort.CreateForTesting(new SafeFileHandle(new IntPtr(1), false), backend);
        var binding = AdmissionEvidenceBinding.TryCreate(port, 1, 1, new byte[32]);
        backend.Entered = entered; backend.Release = release;
        byte[] request = Control(20);
        Task<bool> sending = Task.Run(() => binding.TrySendStagedProof(request, 32, out _));
        Assert.True(entered.Wait(TimeSpan.FromSeconds(5)));
        request[8] = 1; // Caller mutation cannot change the validated request.
        Task drain = Task.Run(binding.StopAcceptingAndDrain);
        try {
            Assert.True(SpinWait.SpinUntil(() => !binding.IsAccepting, TimeSpan.FromSeconds(5)));
            Assert.False(binding.TrySendStagedProof(Control(20), 32, out _));
            Assert.False(drain.IsCompleted);
        } finally { release.Set(); }
        Assert.True(await sending.WaitAsync(TimeSpan.FromSeconds(5)));
        await drain.WaitAsync(TimeSpan.FromSeconds(5));
        Assert.Equal(20u, backend.LastCommand);
        Assert.Equal(2, backend.Calls); // Initial epoch receipt and one proof send.
    }

    private static byte[] Frame(byte[] input, int outputBytes)
    {
        byte[] body = new byte[64 + input.Length];
        BinaryPrimitives.WriteUInt32LittleEndian(body, StagedProofProxyWire.Magic);
        BinaryPrimitives.WriteUInt32LittleEndian(body.AsSpan(4), (uint)outputBytes);
        BinaryPrimitives.WriteUInt32LittleEndian(body.AsSpan(8), (uint)input.Length);
        input.CopyTo(body, 64);
        return body;
    }

    [Theory]
    [InlineData(2,184)] [InlineData(5,0)] [InlineData(6,0)] [InlineData(7,0)]
    [InlineData(8,1960)] [InlineData(12,288)] [InlineData(17,104)]
    [InlineData(19,36136)] [InlineData(20,32)] [InlineData(22,672)]
    [InlineData(23,6672)] [InlineData(24,54664)] [InlineData(25,36392)]
    public async Task EveryAllowedControlUsesExactBoundedServiceFrame(uint command, int outputBytes)
    {
        byte[] input = Control(command, 0, command is 8 or 22 ? 32 : command == 17 ? 28 : 16);
        if (command == 17) {
            BinaryPrimitives.WriteUInt16LittleEndian(input.AsSpan(16), 1);
            BinaryPrimitives.WriteUInt16LittleEndian(input.AsSpan(18), 1);
        }
        using var port = FilterPort.CreateForTesting(new SafeFileHandle(new IntPtr(1), false), new Native());
        var binding = AdmissionEvidenceBinding.TryCreate(port, 1, 1, new byte[32]);
        using var response = new MemoryStream();
        await AdmissionEvidenceEndpoint.ServeStagedProofAsync(response, binding, "S-1-5-18", true,
            _ => true, Frame(input, outputBytes), CancellationToken.None);
        byte[] result = response.ToArray();
        Assert.Equal(12 + outputBytes, result.Length);
        Assert.Equal(StagedProofProxyWire.Magic, BinaryPrimitives.ReadUInt32LittleEndian(result));
        Assert.Equal(0, BinaryPrimitives.ReadInt32LittleEndian(result.AsSpan(4)));
        Assert.Equal((uint)outputBytes, BinaryPrimitives.ReadUInt32LittleEndian(result.AsSpan(8)));
    }

    [Fact]
    public async Task DisconnectAndBackpressureCannotProduceACompletionClaim()
    {
        var backend = new Native();
        using var port = FilterPort.CreateForTesting(new SafeFileHandle(new IntPtr(1), false), backend);
        var binding = AdmissionEvidenceBinding.TryCreate(port, 1, 1, new byte[32]);
        using var disconnected = new FailedWriter(false);
        await Assert.ThrowsAsync<IOException>(() => AdmissionEvidenceEndpoint.ServeStagedProofAsync(
            disconnected, binding, "S-1-5-18", true, _ => true, Frame(Control(20),32), CancellationToken.None));
        using var blocked = new FailedWriter(true);
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => AdmissionEvidenceEndpoint.ServeStagedProofAsync(
            blocked, binding, "S-1-5-18", true, _ => true, Frame(Control(20),32), CancellationToken.None,
            TimeSpan.FromMilliseconds(20)));
        Assert.Equal(0, disconnected.Length);
        Assert.Equal(0, blocked.Length);
        Assert.True(binding.IsAccepting);
        using var next = new MemoryStream();
        await AdmissionEvidenceEndpoint.ServeStagedProofAsync(next, binding, "S-1-5-18", true,
            _ => true, Frame(Control(20),32), CancellationToken.None);
        Assert.Equal(44, next.Length);
    }

    [Fact]
    public async Task BindingDriftDuringSendReturnsOnlyAnErrorFrame()
    {
        using var port = FilterPort.CreateForTesting(new SafeFileHandle(new IntPtr(1), false), new Native());
        var binding = AdmissionEvidenceBinding.TryCreate(port, 1, 1, new byte[32]);
        int checks = 0;
        using var response = new MemoryStream();
        await AdmissionEvidenceEndpoint.ServeStagedProofAsync(response, binding, "S-1-5-18", true,
            _ => ++checks == 1, Frame(Control(20),32), CancellationToken.None);
        Assert.Equal(12, response.Length);
        Assert.Equal(unchecked((int)0x80004004), BinaryPrimitives.ReadInt32LittleEndian(response.ToArray().AsSpan(4)));
    }

    [Fact]
    public async Task CanceledResponseDoesNotAbandonTheNativeSendLease()
    {
        using var entered = new ManualResetEventSlim();
        using var release = new ManualResetEventSlim();
        var backend = new Native();
        using var port = FilterPort.CreateForTesting(new SafeFileHandle(new IntPtr(1), false), backend);
        var binding = AdmissionEvidenceBinding.TryCreate(port, 1, 1, new byte[32]);
        backend.Entered = entered; backend.Release = release;
        using var response = new MemoryStream();
        using var stop = new CancellationTokenSource();
        Task sending = Task.Run(() => AdmissionEvidenceEndpoint.ServeStagedProofAsync(response, binding,
            "S-1-5-18", true, _ => true, Frame(Control(20),32), stop.Token, TimeSpan.FromSeconds(30)));
        Assert.True(entered.Wait(TimeSpan.FromSeconds(5)));
        stop.Cancel(); // Deterministic cancellation while native send is held.
        Task drain = Task.Run(binding.StopAcceptingAndDrain);
        try {
            await Task.Delay(100);
            Assert.False(sending.IsCompleted);
            Assert.False(drain.IsCompleted);
        } finally { release.Set(); }
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => sending);
        await drain.WaitAsync(TimeSpan.FromSeconds(5));
        Assert.Equal(0, response.Length);
    }

    private sealed class FailedWriter(bool backpressure) : MemoryStream
    {
        public override async ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken token = default)
        {
            if (backpressure) await Task.Delay(Timeout.InfiniteTimeSpan, token);
            throw new IOException("Disconnected test reader");
        }
    }

    private sealed class Native : IAdmissionEvidenceNativeSender
    {
        public int Calls;
        public uint LastCommand;
        public bool Overreport;
        public ManualResetEventSlim? Entered, Release;
        public int Send(SafeFileHandle handle, ReadOnlyMemory<byte> input, Memory<byte> output, out uint bytesReturned)
        {
            Interlocked.Increment(ref Calls);
            Entered?.Set();
            if (Release is not null && !Release.Wait(TimeSpan.FromSeconds(5))) throw new TimeoutException();
            LastCommand = BinaryPrimitives.ReadUInt32LittleEndian(input.Span[8..]);
            if (output.Length >= 4) BinaryPrimitives.WriteUInt32LittleEndian(output.Span, (uint)output.Length);
            bytesReturned = (uint)output.Length + (Overreport ? 1u : 0u);
            return 0;
        }
    }
}
#endif
