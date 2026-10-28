#if SAFEUPLOAD_ADMISSION_EVIDENCE
using System.Buffers.Binary;
using System.Runtime.InteropServices;
using System.Text;
using SafeUpload.Agent.Minifilter;

namespace SafeUpload.Agent.Tests;

public sealed class ResourceWireV32Tests
{
    private const ulong Window = 16 * 1024 * 1024, Alignment = 65536;
    private static readonly Guid Driver = new("00112233-4455-6677-8899-aabbccddeeff");
    private static readonly Guid Transfer = new("aabbccdd-eeff-0011-2233-445566778899");

    [Fact]
    public void Independent_byte_vectors_preserve_full_binding_and_all_fixed_layouts()
    {
        ResourceWireV32.Verify();
        Assert.Equal(112, Marshal.SizeOf<ResourceBindingV32>());
        Assert.Equal(104, Marshal.SizeOf<ResourceAllocationV32>());
        Assert.Equal(160, Marshal.SizeOf<ResourceGrowthV32>());
        Assert.Equal(160, Marshal.SizeOf<ResourceRetirementV32>());
        Assert.Equal(352, Marshal.SizeOf<ResourceResultV32>());
        Assert.Equal(376, Marshal.SizeOf<ResourceReplyV32>());
        Assert.True(ResourceWireV32.TryReadGrowth(Growth(), Alignment, out var request));
        Assert.Equal(Driver, request.Binding.DriverInstanceId);
        Assert.Equal(Transfer, request.Binding.TransferId);
        Assert.Equal(11UL, request.Binding.AllocationGeneration);
        Assert.Equal(13UL, request.Binding.DestinationGeneration);
        Assert.Equal(0x123456789abcdef0UL, request.Binding.StageIdentity.FileIdHigh);
        Assert.True(ResourceWireV32.TryReadGrowthReply(GrowthReply(), request, Alignment, 4 * Window, 23, 150, out var result));
        Assert.Equal(4 * Window, result.Capacity);
        Assert.Equal(ResourceResultCodeV32.CapacityCommitted, result.Result);
    }

    [Fact]
    public void Every_byte_of_a_correlated_growth_reply_is_checked_before_capacity_can_match()
    {
        Assert.True(ResourceWireV32.TryReadGrowth(Growth(), Alignment, out var request));
        byte[] original = GrowthReply();
        for (int index = 0; index < original.Length; index++)
        {
            var changed = (byte[])original.Clone(); changed[index] ^= 0x80;
            Assert.False(ResourceWireV32.TryReadGrowthReply(changed, request, Alignment, 4 * Window, 23, 150, out _),
                "Unchecked reply byte " + index);
        }
        Assert.False(ResourceWireV32.TryReadGrowthReply(original.AsSpan(0, 375), request, Alignment, 4 * Window, 23, 150, out _));
        Assert.False(ResourceWireV32.TryReadGrowthReply([.. original, 0], request, Alignment, 4 * Window, 23, 150, out _));
    }

    [Theory]
    [InlineData("version")]
    [InlineData("size")]
    [InlineData("kind")]
    [InlineData("reserved")]
    [InlineData("request")]
    [InlineData("cookie")]
    [InlineData("driver")]
    [InlineData("transfer")]
    [InlineData("allocation-generation")]
    [InlineData("full-file-id")]
    [InlineData("destination-generation")]
    [InlineData("sequence")]
    [InlineData("unaligned")]
    [InlineData("prefix-only")]
    [InlineData("overflow")]
    [InlineData("deadline")]
    [InlineData("tail")]
    public void Invalid_growth_shapes_refuse_without_returning_partial_payload(string mutation)
    {
        byte[] bytes = Growth();
        switch (mutation)
        {
            case "version": U32(bytes, 0, 31); break;
            case "size": U32(bytes, 4, 159); break;
            case "kind": U32(bytes, 8, 2); break;
            case "reserved": bytes[12] = 1; break;
            case "request": U64(bytes, 16, 0); break;
            case "cookie": U64(bytes, 24, 0); break;
            case "driver": bytes.AsSpan(32, 16).Clear(); break;
            case "transfer": bytes.AsSpan(48, 16).Clear(); break;
            case "allocation-generation": U64(bytes, 64, 0); break;
            case "full-file-id": bytes.AsSpan(80, 16).Clear(); break;
            case "destination-generation": U64(bytes, 96, 0); break;
            case "sequence": U64(bytes, 104, 0); break;
            case "unaligned": U64(bytes, 120, 2 * Window + 1); break;
            case "prefix-only": U64(bytes, 120, Window); break;
            case "overflow": U64(bytes, 120, 1UL << 63); break;
            case "deadline": U64(bytes, 136, 100); break;
            case "tail": bytes[159] = 1; break;
            default: throw new ArgumentOutOfRangeException(nameof(mutation));
        }
        Assert.False(ResourceWireV32.TryReadGrowth(bytes, Alignment, out var parsed));
        Assert.Equal(0UL, parsed.Binding.RequestId);
    }

    [Theory]
    [InlineData(4u, false)]
    [InlineData(5u, true)]
    [InlineData(6u, true)]
    [InlineData(7u, true)]
    [InlineData(8u, true)]
    [InlineData(9u, true)]
    [InlineData(10u, true)]
    public void Growth_failures_carry_no_capacity_or_noncommitment_authority(uint code, bool syntactic)
    {
        Assert.True(ResourceWireV32.TryReadGrowth(Growth(), Alignment, out var request));
        var bytes = GrowthReply(); U32(bytes, 36, code); U64(bytes, 168, 0); U64(bytes, 176, 0);
        Assert.Equal(syntactic, ResourceWireV32.TryReadGrowthReply(bytes, request, Alignment, 0, 0, 201, out var result));
        Assert.Equal(0UL, result.Capacity);
        Assert.Equal(0UL, result.LedgerRevision);
        U64(bytes, 168, Window);
        Assert.False(ResourceWireV32.TryReadGrowthReply(bytes, request, Alignment, Window, 0, 201, out _));
    }

    [Fact]
    public void Exact_deadline_and_companion_revision_prevent_late_or_unbacked_growth_adoption()
    {
        Assert.True(ResourceWireV32.TryReadGrowth(Growth(), Alignment, out var request));
        var bytes = GrowthReply();
        Assert.True(ResourceWireV32.TryReadReply(bytes, 7, out _)); // syntax alone is not adoption
        Assert.False(ResourceWireV32.TryReadGrowthReply(bytes, request, Alignment, 4 * Window, 23, 200, out _));
        Assert.False(ResourceWireV32.TryReadGrowthReply(bytes, request, Alignment, 4 * Window, 24, 150, out _));
        Assert.False(ResourceWireV32.TryReadGrowthReply(bytes, request, Alignment, 2 * Window, 23, 150, out _));
        request.Binding.RequestId++;
        Assert.False(ResourceWireV32.TryReadGrowthReply(bytes, request, Alignment, 4 * Window, 23, 150, out _));
    }

    [Fact]
    public void Tiny_retired_eof_keeps_the_measured_allocation_and_cannot_parse_as_growth()
    {
        byte[] requestBytes = Binding(2); U64(requestBytes, 112, 0); U64(requestBytes, 120, 4096); U64(requestBytes, 128, Window);
        Assert.True(ResourceWireV32.TryReadRetirement(requestBytes, Alignment, out var request));
        Assert.False(ResourceWireV32.TryReadGrowth(requestBytes, Alignment, out _));
        byte[] bytes = Reply(2, 3); requestBytes.AsSpan(16, 96).CopyTo(bytes.AsSpan(40));
        U64(bytes, 136, Window); U64(bytes, 176, 31); U64(bytes, 192, 4096);
        Assert.True(ResourceWireV32.TryReadRetirementReply(bytes, request, Alignment, out var result));
        Assert.Equal(4096UL, result.RetirementAllocationSize);
        Assert.Equal(0UL, result.Capacity);
        var wrongResult = (byte[])bytes.Clone(); U32(wrongResult, 36, 7); U64(wrongResult, 176, 0);
        Assert.False(ResourceWireV32.TryReadRetirementReply(wrongResult, request, Alignment, out _)); // no retirement deadline
        U64(bytes, 136, 2 * Window);
        Assert.False(ResourceWireV32.TryReadRetirementReply(bytes, request, Alignment, out _));
        U64(requestBytes, 120, Window + 1);
        Assert.False(ResourceWireV32.TryReadRetirement(requestBytes, Alignment, out _));
        U64(requestBytes, 120, 4096); requestBytes[159] = 1;
        Assert.False(ResourceWireV32.TryReadRetirement(requestBytes, Alignment, out _));
    }

    [Theory]
    [InlineData("")]
    [InlineData(".txt")]
    [InlineData(".a_b")]
    public void Allocation_requires_its_original_intent_and_exact_committed_capacity(string extension)
    {
        var intentBytes = new byte[104]; U32(intentBytes, 0, 32); U32(intentBytes, 4, 104);
        Transfer.TryWriteBytes(intentBytes.AsSpan(8)); U32(intentBytes, 40, 3); Driver.TryWriteBytes(intentBytes.AsSpan(48));
        U64(intentBytes, 64, 1234); U64(intentBytes, 72, 9); U64(intentBytes, 80, 100);
        U64(intentBytes, 88, 100 + ResourceWireV32.AllocationWaitTicks); U32(intentBytes, 96, 1);
        Assert.True(ResourceWireV32.TryReadAllocation(intentBytes, out var request));
        byte[] bytes = Reply(0, 1); Binding(1).AsSpan(24, 80).CopyTo(bytes.AsSpan(48));
        U64(bytes, 152, request.Issued); U64(bytes, 160, request.Deadline);
        U64(bytes, 168, Window); U64(bytes, 176, 23);
        byte[] name = Encoding.Unicode.GetBytes(Transfer.ToString("N") + extension);
        U32(bytes, 208, (uint)name.Length); name.CopyTo(bytes.AsSpan(216));
        Assert.True(ResourceWireV32.TryReadAllocationReply(bytes, request, 7, Alignment, Window, Window, 23, 150, out _));
        Assert.False(ResourceWireV32.TryReadAllocationReply(bytes, request, 7, Alignment, 2 * Window, Window, 23, 150, out _));
        Assert.False(ResourceWireV32.TryReadAllocationReply(bytes, request, 7, Alignment, Window, Window, 24, 150, out _));
        Assert.False(ResourceWireV32.TryReadAllocationReply(bytes, request, 7, Alignment, Window, Window, 23, request.Deadline, out _));
        bytes[216] = (byte)'f';
        Assert.False(ResourceWireV32.TryReadAllocationReply(bytes, request, 7, Alignment, Window, Window, 23, 150, out _));
        intentBytes[100] = 1;
        Assert.False(ResourceWireV32.TryReadAllocation(intentBytes, out _));
    }

    [Fact]
    public void Interrupt_time_deadlines_refuse_wraparound_and_do_not_follow_wall_clock()
    {
        Assert.True(ResourceWireV32.DeadlineValid(100, 200, 199, 100));
        Assert.False(ResourceWireV32.DeadlineValid(100, 200, 200, 100));
        Assert.False(ResourceWireV32.DeadlineValid(100, 200, 99, 100));
        Assert.False(ResourceWireV32.DeadlineValid(ulong.MaxValue - 10, 20, ulong.MaxValue - 1, 100));
        Assert.False(ResourceWireV32.DeadlineValid(100, 200, 150, 99));
        Assert.False(ResourceWireV32.DeadlineValid(100, 200, 150, 0));
        Assert.False(ResourceWireV32.CapacityValid(Window, 0));
        Assert.False(ResourceWireV32.CapacityValid(Window, 65537));
    }

    private static byte[] Growth()
    {
        byte[] bytes = Binding(1); U64(bytes, 112, Window); U64(bytes, 120, 2 * Window); U64(bytes, 128, 100); U64(bytes, 136, 200);
        return bytes;
    }
    private static byte[] GrowthReply()
    {
        byte[] bytes = Reply(1, 2); Growth().AsSpan(16, 128).CopyTo(bytes.AsSpan(40));
        U64(bytes, 168, 4 * Window); U64(bytes, 176, 23);
        return bytes;
    }
    private static byte[] Binding(uint kind)
    {
        var bytes = new byte[160]; U32(bytes, 0, 32); U32(bytes, 4, 160); U32(bytes, 8, kind);
        U64(bytes, 16, 7); U64(bytes, 24, 9); Driver.TryWriteBytes(bytes.AsSpan(32)); Transfer.TryWriteBytes(bytes.AsSpan(48));
        U64(bytes, 64, 11); U64(bytes, 72, 0x9988); U64(bytes, 80, 0xfedcba9876543210);
        U64(bytes, 88, 0x123456789abcdef0); U64(bytes, 96, 13); U64(bytes, 104, 17);
        return bytes;
    }
    private static byte[] Reply(uint kind, uint result)
    {
        var bytes = new byte[376]; U32(bytes, 0, 18); U32(bytes, 4, 376); U64(bytes, 8, 7); U32(bytes, 16, 1);
        U32(bytes, 24, 32); U32(bytes, 28, 352); U32(bytes, 32, kind); U32(bytes, 36, result);
        U64(bytes, 40, 7);
        return bytes;
    }
    private static void U32(byte[] bytes, int offset, uint value) => BinaryPrimitives.WriteUInt32LittleEndian(bytes.AsSpan(offset), value);
    private static void U64(byte[] bytes, int offset, ulong value) => BinaryPrimitives.WriteUInt64LittleEndian(bytes.AsSpan(offset), value);
}
#endif
