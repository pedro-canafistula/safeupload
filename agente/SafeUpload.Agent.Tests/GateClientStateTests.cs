using Microsoft.Extensions.Logging.Abstractions;
using SafeUpload.Agent.Core.Domain;
using SafeUpload.Agent.Service.Gate;

namespace SafeUpload.Agent.Tests;

public sealed class GateClientStateTests
{
    [Fact]
    public void Connected_but_rejected_scope_is_not_applied_and_recovery_resends_it()
    {
        var wire = new Connection { PolicyResult = -1 };
        using var client = Client(wire);
        Assert.Equal(GateApplyResult.Rejected, client.Apply(["folder"], true, false));
        Assert.False(client.IsConnected);
        wire.PolicyResult = 0;
        Assert.Equal(GateApplyResult.Applied, client.Apply(["folder"], true, false));
        Assert.True(client.IsConnected);
        Assert.Equal(new uint[] { 1, 1 }, wire.Commands);
    }

    [Fact]
    public void Unavailable_gate_does_not_claim_application_or_send_a_message()
    {
        var wire = new Connection { Available = false };
        using var client = Client(wire);
        Assert.Equal(GateApplyResult.Unavailable, client.Apply(["folder"], false, false));
        Assert.False(client.IsConnected);
        Assert.Empty(wire.Commands);
        wire.Available = true;
        Assert.Equal(GateApplyResult.Applied, client.Apply(["folder"], false, false));
    }

    [Fact]
    public void Same_scope_polls_probe_the_existing_connection_instead_of_trusting_the_handle()
    {
        var wire = new Connection();
        using var client = Client(wire);
        Assert.Equal(GateApplyResult.Applied, client.Apply(["folder"], true, true));
        Assert.Equal(GateApplyResult.Applied, client.Apply(["folder"], true, true));
        Assert.Equal(new uint[] { 1, 2 }, wire.Commands);
        Assert.Equal(8, wire.Requests[1].Length);
        Assert.Equal(1u, BitConverter.ToUInt32(wire.Requests[1], 4));
        wire.ProbeResult = -1;
        Assert.True(client.IsConnected); // A locally valid handle alone cannot detect a lost peer.
        Assert.Equal(GateApplyResult.Unavailable, client.Apply(["folder"], true, true));
        Assert.False(client.IsConnected);
        wire.ProbeResult = 0;
        Assert.Equal(GateApplyResult.Applied, client.Apply(["folder"], true, true));
        Assert.Equal(new uint[] { 1, 2, 2, 1 }, wire.Commands);
    }

    [Theory]
    [InlineData(0u)]
    [InlineData(15u)]
    [InlineData(17u)]
    public void Malformed_probe_reply_revokes_the_cached_application(uint length)
    {
        var wire = new Connection();
        using var client = Client(wire);
        Assert.Equal(GateApplyResult.Applied, client.Apply([], true, false));
        wire.ReplyLength = length;
        Assert.Equal(GateApplyResult.Unavailable, client.Apply([], true, false));
        Assert.False(client.IsConnected);
        wire.ReplyLength = 16;
        Assert.Equal(GateApplyResult.Applied, client.Apply([], true, false));
        Assert.Equal(new uint[] { 1, 2, 1 }, wire.Commands);
    }

    [Fact]
    public void Diagnostics_connection_does_not_replace_the_scope_acknowledgement()
    {
        var wire = new Connection();
        using var client = Client(wire);
        Assert.Equal((3ul, 4ul), client.Counters());
        Assert.Equal(GateApplyResult.Applied, client.Apply(["folder"], false, false));
        wire.ProbeResult = -1;
        Assert.Null(client.Counters());
        wire.ProbeResult = 0;
        Assert.Equal((3ul, 4ul), client.Counters());
        Assert.Equal(GateApplyResult.Applied, client.Apply(["folder"], false, false));
        Assert.Equal(new uint[] { 2, 1, 2, 2, 1 }, wire.Commands);
    }

    [Fact]
    public void Scope_and_flag_changes_are_sent_and_invalid_scope_is_validated_before_connection()
    {
        var wire = new Connection();
        using var client = Client(wire);
        Assert.Throws<InvalidPolicyException>(() => client.Apply(new string[17], false, false));
        Assert.Equal(0, wire.ConnectCalls);
        Assert.Equal(GateApplyResult.Applied, client.Apply(["first"], false, false));
        Assert.Equal(GateApplyResult.Applied, client.Apply(["second"], false, false));
        Assert.Equal(GateApplyResult.Applied, client.Apply(["second"], true, false));
        Assert.Equal(new uint[] { 1, 1, 1 }, wire.Commands);
    }

    internal static GateClient Client(Connection wire) =>
        new(NullLogger<GateClient>.Instance, wire, path => @"\Device\Synthetic\" + path);

    // The boundary replaces only native port operations; validation, caching and liveness logic run in GateClient.
    internal sealed class Connection : IGateConnection
    {
        public bool Available = true;
        public int PolicyResult, ProbeResult, ConnectCalls;
        public uint ReplyLength = 16;
        public bool IsConnected { get; private set; }
        public List<byte[]> Requests { get; } = [];
        public uint[] Commands => Requests.Select(r => BitConverter.ToUInt32(r, 0)).ToArray();
        public bool Connect()
        {
            ConnectCalls++;
            if (IsConnected) return true;
            return IsConnected = Available;
        }
        public int Send(byte[] request, byte[]? reply, out uint returned)
        {
            Assert.True(IsConnected);
            Requests.Add(request.ToArray());
            returned = 0;
            if (BitConverter.ToUInt32(request, 0) == 1) return PolicyResult;
            Assert.Equal(2u, BitConverter.ToUInt32(request, 0));
            Assert.NotNull(reply);
            Assert.Equal(16, reply.Length);
            BitConverter.TryWriteBytes(reply.AsSpan(0), 3ul);
            BitConverter.TryWriteBytes(reply.AsSpan(8), 4ul);
            returned = ReplyLength;
            return ProbeResult;
        }
        public void Disconnect() => IsConnected = false;
    }
}
