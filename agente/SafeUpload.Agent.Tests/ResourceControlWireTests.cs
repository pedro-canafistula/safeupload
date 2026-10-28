#if SAFEUPLOAD_ADMISSION_EVIDENCE
using System.Runtime.InteropServices;
using System.Buffers.Binary;
using System.Text;
using SafeUpload.Agent.Minifilter;

namespace SafeUpload.Agent.Tests;

public sealed class ResourceControlWireTests
{
    [Fact]
    public void Passive_control_layouts_and_offsets_match_the_selected_contract()
    {
        ResourceControlWireV32.Verify();
        Assert.Equal(ResourceSendClass.MetadataProgress, FilterPort.ResourceClassForOpcode(ResourceControlOpcodeV32.RegisterRoot));
        Assert.Equal(ResourceSendClass.MetadataProgress, FilterPort.ResourceClassForOpcode(ResourceControlOpcodeV32.RegisterChildIntent));
        Assert.Equal(ResourceSendClass.Resolution, FilterPort.ResourceClassForOpcode(ResourceControlOpcodeV32.FenceAllocation));
        Assert.Equal(ResourceSendClass.Resolution, FilterPort.ResourceClassForOpcode(ResourceControlOpcodeV32.ResolveAllocationAck));
        Assert.Equal(ResourceSendClass.Resolution, FilterPort.ResourceClassForOpcode(ResourceControlOpcodeV32.ShellSnapshot));
        Assert.Equal(ResourceSendClass.Revoke, FilterPort.ResourceClassForOpcode(ResourceControlOpcodeV32.Revoke));
        Assert.Throws<ArgumentException>(() => FilterPort.ResourceClassForOpcode(ResourceControlOpcodeV32.Negotiate));
        Assert.Equal(24, Marshal.OffsetOf<ResourceControlHeaderV32>(nameof(ResourceControlHeaderV32.ControlRequestId)).ToInt32());
        Assert.Equal(40, Marshal.OffsetOf<ResourceControlHeaderV32>(nameof(ResourceControlHeaderV32.DriverInstance)).ToInt32());
        Assert.Equal(80, Marshal.OffsetOf<ResourceNegotiateV32>(nameof(ResourceNegotiateV32.Phase)).ToInt32());
        Assert.Equal(96, Marshal.OffsetOf<ResourceRegisterChildV32>(nameof(ResourceRegisterChildV32.Leaf)).ToInt32());
        Assert.Equal(608, Marshal.OffsetOf<ResourceRegisterChildV32>(nameof(ResourceRegisterChildV32.Reserved)).ToInt32());
        Assert.Equal(16, Marshal.OffsetOf<ResourcePairContextV32>(nameof(ResourcePairContextV32.ConnectionCookie)).ToInt32());
    }
    private static byte[] Probe(Guid agent)
    {
        var header = new ResourceControlHeaderV32 { Version = 18, StructSize = 176, Command = 36, ResourceVersion = 32,
            Opcode = ResourceControlOpcodeV32.Negotiate, ControlRequestId = 17, ConnectionCookie = 5,
            DriverInstance = Guid.NewGuid(), PayloadBytes = 112 };
        var body = new ResourceNegotiateReplyV32 { Result = 2, AgentInstance = agent };
        byte[] bytes = new byte[176]; MemoryMarshal.Write(bytes, in header); MemoryMarshal.Write(bytes.AsSpan(64), in body); return bytes;
    }
    [Fact]
    public void Probe_only_obtains_provisional_identity_and_every_reserved_or_authority_mutation_refuses()
    {
        Guid agent = Guid.NewGuid(); byte[] bytes = Probe(agent);
        Assert.True(ResourceControlWireV32.TryReadProbe(bytes, 17, agent, out var identity));
        Assert.Equal(5UL, identity.Cookie); Assert.NotEqual(Guid.Empty, identity.DriverInstance);
        foreach (int offset in new[] { 0, 4, 8, 12, 16, 20, 24, 56, 60, 64, 68, 72, 96, 128, 136, 140, 144, 148, 152, 156, 160, 175 })
        {
            byte[] mutant = (byte[])bytes.Clone(); mutant[offset] ^= 1;
            Assert.False(ResourceControlWireV32.TryReadProbe(mutant, 17, agent, out _));
        }
        Assert.False(ResourceControlWireV32.TryReadProbe(bytes[..^1], 17, agent, out _));
        Assert.False(ResourceControlWireV32.TryReadProbe(bytes.Concat(new byte[1]).ToArray(), 17, agent, out _));
        Assert.False(ResourceControlWireV32.TryReadProbe(bytes, 18, agent, out _));
        Assert.False(ResourceControlWireV32.TryReadProbe(bytes, 17, Guid.NewGuid(), out _));
    }
    [Fact]
    public void Root_child_pair_and_revoke_shapes_refuse_reserved_access_identity_and_tail_mutants()
    {
        byte[] root = new byte[64]; root[0] = 1; root[8] = 42; root[24] = 2; root[48] = 1;
        Assert.True(ResourceControlWireV32.TryReadRoot(root, out _));
        foreach (int offset in new[] { 0, 4, 8, 24, 40, 48, 52, 63 })
        {
            byte[] mutant = (byte[])root.Clone(); mutant[offset] ^= root[offset] == 0 ? (byte)1 : root[offset];
            Assert.False(ResourceControlWireV32.TryReadRoot(mutant, out _));
        }
        byte[] child = new byte[640]; child[0] = 1; Guid.NewGuid().TryWriteBytes(child.AsSpan(8)); child[24] = 2;
        BinaryPrimitives.WriteUInt32LittleEndian(child.AsSpan(28), 0x130083);
        BinaryPrimitives.WriteUInt64LittleEndian(child.AsSpan(32), 65536);
        byte[] name = Encoding.Unicode.GetBytes("ledger.new"); name.CopyTo(child, 96);
        child[88] = (byte)name.Length; child[92] = 2;
        Assert.True(ResourceControlWireV32.TryReadChild(child, out _));
        foreach (int offset in new[] { 0, 24, 29, 31, 39, 40, 88, 92, 116, 608, 639 })
        {
            byte[] mutant = (byte[])child.Clone(); mutant[offset] ^= offset == 24 ? (byte)0x80 : (byte)1;
            Assert.False(ResourceControlWireV32.TryReadChild(mutant, out _));
        }
        var pair = new ResourcePairContextV32 { DriverInstance = Guid.NewGuid(), ConnectionCookie = 1 };
        byte[] pairBytes = new byte[24]; MemoryMarshal.Write(pairBytes, in pair);
        Assert.True(ResourceControlWireV32.PairValid(pairBytes));
        Assert.False(ResourceControlWireV32.PairValid(pairBytes[..23]));
        pairBytes.AsSpan(16).Clear(); Assert.False(ResourceControlWireV32.PairValid(pairBytes));
        Assert.True(ResourceControlWireV32.RevokeValid([3, 0, 0, 0, 0, 0, 0, 0]));
        Assert.False(ResourceControlWireV32.RevokeValid([4, 0, 0, 0, 0, 0, 0, 0]));
        Assert.False(ResourceControlWireV32.RevokeValid([3, 0, 0, 0, 1, 0, 0, 0]));
    }

    [Fact]
    public void Commit_is_unconditionally_NotReady_with_no_accepted_capability_or_grant()
    {
        var reply = ResourceControlWireV32.Commit(Guid.NewGuid(), Guid.NewGuid());
        Assert.Equal(2u, reply.Result); Assert.Equal(0u, reply.Mode);
        Assert.Equal(0UL, reply.AcceptedCapabilities); Assert.Equal(0UL, reply.GrowthWaitTicks);
        Assert.Equal(0u, reply.AllocationLimit); Assert.Equal(0u, reply.GrowthWorkers);
    }
    [Theory]
    [InlineData("")]
    [InlineData("..")]
    [InlineData(".")]
    [InlineData("../outside")]
    [InlineData("a:stream")]
    [InlineData("a\\b")]
    [InlineData("a/b")]
    [InlineData("a\0b")]
    public void Invalid_relative_components_are_refused(string leaf) => Assert.False(ResourceControlWireV32.LeafValid(leaf));
}
#endif
