using System.Buffers.Binary;
using System.Runtime.InteropServices;
using System.Text;
using SafeUpload.Agent.Minifilter;

namespace SafeUpload.Agent.Tests;

public sealed class StagedRenameReceiptWireTests
{
    private static SafeUploadStageRenameV20 Source() => new()
    {
        Version = Contract.StageExtensionVersion, StructSize = Contract.StageRenameV20Size,
        Operation = Operation.StageRenameCommit, RequestId = 123, TransferId = Guid.NewGuid(),
        SourceGeneration = 99, StageIdentity = new() { VolumeSerialNumber = 4, FileIdLow = 5, FileIdHigh = 6 },
        DriverInstanceId = Guid.NewGuid(), ParentDirectoryIdentity = new() { VolumeSerialNumber = 4, FileIdLow = 7 },
        ViewGeneration = 42, OwnerProcessId = 1234
    };

    [Fact]
    public void Rename_layout_and_lower_destination_generation_are_exact()
    {
        Contract.Verify();
        Assert.Equal(128, Marshal.SizeOf<SafeUploadStageRenameV20>());
        Assert.Equal(1168, Marshal.SizeOf<SafeUploadStageRenameCommitV20>());
        Assert.Equal(1192, Marshal.SizeOf<SafeUploadStageRenameReplyV20>());
        const string destination = @"\Device\HarddiskVolume1\protected\replacement.txt";
        var source = Source();
        var reply = FilterPort.CreateStageRenameReplyV20(source, 1, destination, StageV20Result.RenameCommitted);
        FilterPort.ValidateStageRenameReplyV20(reply);
        byte[] bytes = Bytes(reply);
        Assert.Equal(Contract.Version, BinaryPrimitives.ReadUInt32LittleEndian(bytes));
        Assert.Equal(1192u, BinaryPrimitives.ReadUInt32LittleEndian(bytes.AsSpan(4)));
        Assert.Equal(1168u, BinaryPrimitives.ReadUInt32LittleEndian(bytes.AsSpan(20)));
        Assert.Equal(1UL, BinaryPrimitives.ReadUInt64LittleEndian(bytes.AsSpan(152)));
        Assert.Equal(Encoding.Unicode.GetBytes(destination), bytes.AsSpan(168, destination.Length * 2).ToArray());
        Assert.All(bytes.Skip(168 + destination.Length * 2), value => Assert.Equal((byte)0, value));
        var retry = FilterPort.CreateStageRenameReplyV20(source, 0, destination, StageV20Result.RetryableFailure);
        FilterPort.ValidateStageRenameReplyV20(retry);
        Assert.Equal(StageV20Result.RetryableFailure, retry.Receipt.Source.Result);
        Assert.Equal(0UL, retry.Receipt.DestinationGeneration);
    }

    [Theory]
    [InlineData(0, 99)] // outer version
    [InlineData(4, 0)] // outer size
    [InlineData(8, 0)] // outer request id
    [InlineData(16, 1)] // verdict
    [InlineData(20, 0)] // payload length
    [InlineData(24, 0)] // extension version
    [InlineData(28, 0)] // payload size
    [InlineData(32, 8)] // operation
    [InlineData(36, 0)] // result
    [InlineData(40, 0)] // transaction
    [InlineData(64, 0)] // source generation
    [InlineData(136, 0)] // view generation
    [InlineData(144, 0)] // owner
    [InlineData(148, 2)] // sealed flag
    [InlineData(152, 0)] // committed destination generation
    [InlineData(160, 3)] // odd destination byte length
    [InlineData(164, 1)] // reserved
    [InlineData(1191, 1)] // unused name bytes
    public void Rename_reply_refuses_malformed_envelope_tuple_and_padding(int offset, byte value)
    {
        var reply = FilterPort.CreateStageRenameReplyV20(Source(), 1, @"\Device\volume\file.txt",
            StageV20Result.RenameCommitted);
        byte[] changed = Bytes(reply);
        changed[offset] = value;
        var malformed = Read<SafeUploadStageRenameReplyV20>(changed);
        Assert.Throws<ArgumentException>(() => FilterPort.ValidateStageRenameReplyV20(malformed));
    }

    [Theory]
    [InlineData(Operation.StageRename)]
    [InlineData(Operation.StageRenameCommit)]
    [InlineData(Operation.StageRenameAbort)]
    public void Rename_request_requires_typed_version_size_and_zero_unused_bytes(uint operation)
    {
        byte[] bytes = new byte[Contract.RequestSize];
        void Put(int at, uint value) => BinaryPrimitives.WriteUInt32LittleEndian(bytes.AsSpan(at), value);
        Put(0, Contract.Version); Put(4, Contract.RequestSize); Put(8, 123); Put(16, operation);
        Put(20, 1234); Put(36, Contract.StageExtensionVersion);
        const string name = @"\Device\volume\file.txt";
        Put(28, checked((uint)name.Length * 2)); Put(32, Contract.StageRenameV20Size);
        Encoding.Unicode.GetBytes(name).CopyTo(bytes, 40);
        var source = Source(); source.Operation = operation;
        Bytes(source).CopyTo(bytes, 1064);
        Assert.True(Read<SafeUploadRequest>(bytes).TryReadStagePayload<SafeUploadStageRenameV20>(operation, out _));
        foreach (int offset in new[] { 28, 32, 36, 1064, 1068, 40 + name.Length * 2 })
        {
            var altered = (byte[])bytes.Clone(); altered[offset] ^= 1;
            Assert.False(Read<SafeUploadRequest>(altered).TryReadStagePayload<SafeUploadStageRenameV20>(operation, out _));
        }
    }

    private static byte[] Bytes<T>(T value) where T : struct
    {
        IntPtr pointer = Marshal.AllocHGlobal(Marshal.SizeOf<T>());
        try
        {
            Marshal.StructureToPtr(value, pointer, false);
            byte[] bytes = new byte[Marshal.SizeOf<T>()];
            Marshal.Copy(pointer, bytes, 0, bytes.Length);
            return bytes;
        }
        finally { Marshal.FreeHGlobal(pointer); }
    }

    private static T Read<T>(byte[] bytes) where T : struct
    {
        IntPtr pointer = Marshal.AllocHGlobal(bytes.Length);
        try { Marshal.Copy(bytes, 0, pointer, bytes.Length); return Marshal.PtrToStructure<T>(pointer); }
        finally { Marshal.FreeHGlobal(pointer); }
    }
}
