#if SAFEUPLOAD_ADMISSION_EVIDENCE
using System.Buffers.Binary;
using SafeUpload.Agent.Service.Interception;

namespace SafeUpload.Agent.Tests;

public sealed class PublicCustodyReceiptV3Tests
{
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void Every_fixed_field_round_trips_and_acceptance_is_source_only_zero(bool handback)
    {
        var source = ResourceSerializationLimitsV3Tests.Receipt(handback);
        byte[] completion = PublicCustodyReceiptCodecV3.Serialize(source, true);
        Assert.Equal(2048, completion.Length); Assert.Equal(2732, Convert.ToBase64String(completion).Length);
        Assert.Equal(source, PublicCustodyReceiptCodecV3.Deserialize(completion, true));
        Assert.Throws<InvalidDataException>(() => PublicCustodyReceiptCodecV3.Deserialize(completion, false));
        byte[] accepted = PublicCustodyReceiptCodecV3.Serialize(source with { AcceptedBudgetRevision = long.MaxValue }, false);
        Assert.Throws<InvalidDataException>(() => PublicCustodyReceiptCodecV3.Deserialize(accepted, true));
        Assert.Equal(completion[..160], accepted[..160]); Assert.Equal(completion[168..], accepted[168..]);
        Assert.Equal(ulong.MaxValue, BinaryPrimitives.ReadUInt64LittleEndian(completion.AsSpan(96)));
    }

    [Theory]
    [MemberData(nameof(ReservedOffsets))]
    public void Every_reserved_and_unused_carrier_byte_refuses(int offset)
    {
        byte[] bytes = PublicCustodyReceiptCodecV3.Serialize(ResourceSerializationLimitsV3Tests.Receipt(), true);
        bytes[offset] = 1;
        Assert.Throws<InvalidDataException>(() => PublicCustodyReceiptCodecV3.Deserialize(bytes, true));
    }
    public static IEnumerable<object[]> ReservedOffsets()
    {
        foreach (int index in Enumerable.Range(300, 4).Concat(Enumerable.Range(320, 24)).Concat(Enumerable.Range(348, 4))
            .Concat(Enumerable.Range(394, 502)).Concat(Enumerable.Range(940, 324))
            .Concat(Enumerable.Range(1346, 502)).Concat(Enumerable.Range(1864, 184))) yield return [index];
    }

    [Fact]
    public void Every_truncation_and_optional_tail_refuses()
    {
        byte[] bytes = PublicCustodyReceiptCodecV3.Serialize(ResourceSerializationLimitsV3Tests.Receipt(), true);
        for (int length = 0; length < bytes.Length; length++)
            Assert.Throws<InvalidDataException>(() => PublicCustodyReceiptCodecV3.Deserialize(bytes.AsSpan(0, length), true));
        Assert.Throws<InvalidDataException>(() => PublicCustodyReceiptCodecV3.Deserialize(bytes.Concat(new byte[1]).ToArray(), true));
    }

    [Theory]
    [InlineData(8, 2u)]
    [InlineData(12, 2049u)]
    [InlineData(120, 4u)]
    [InlineData(124, 1u)]
    [InlineData(124, 2u)]
    [InlineData(256, 2u)]
    [InlineData(260, 2u)]
    [InlineData(288, 3u)]
    [InlineData(292, 1u)]
    [InlineData(292, 512u)]
    [InlineData(296, 369u)]
    [InlineData(344, 2u)]
    [InlineData(1328, 2u)]
    [InlineData(1332, 1u)]
    [InlineData(1332, 512u)]
    public void Bad_version_length_role_kind_flags_and_carriers_refuse(int offset, uint value)
    {
        byte[] bytes = PublicCustodyReceiptCodecV3.Serialize(ResourceSerializationLimitsV3Tests.Receipt(), true);
        BinaryPrimitives.WriteUInt32LittleEndian(bytes.AsSpan(offset), value);
        Assert.Throws<InvalidDataException>(() => PublicCustodyReceiptCodecV3.Deserialize(bytes, true));
    }
}
#endif
