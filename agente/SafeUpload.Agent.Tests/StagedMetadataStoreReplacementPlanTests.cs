#if SAFEUPLOAD_ADMISSION_EVIDENCE
using System.Text;
using SafeUpload.Agent.Service.Interception;

namespace SafeUpload.Agent.Tests;

public sealed class StagedMetadataStoreReplacementPlanTests
{
    internal static readonly MetadataRenameOperation ExpectedProductionReplacement = new(65, 3);
    [Theory]
    [InlineData(0, 10, 1)]
    [InlineData(1, 65, 1)]
    [InlineData(2, 65, 3)]
    public void Native_rename_shape_keeps_exact_class_flags_relative_anchor_and_name(int mechanism, int informationClass, uint flags)
    {
        var operation = StagedMetadataStoreNative.ReplacementOperation((MetadataReplacementMechanism)mechanism);
        Assert.Equal(new MetadataRenameOperation(informationClass, flags), operation);
        var anchor = (IntPtr)1234; const string leaf = "target";
        byte[] buffer = StagedMetadataStoreNative.RenameBuffer(leaf, anchor, operation);
        int offset = IntPtr.Size == 8 ? 20 : 12;
        Assert.Equal(flags, BitConverter.ToUInt32(buffer));
        Assert.Equal(anchor.ToInt64(), IntPtr.Size == 8 ? BitConverter.ToInt64(buffer, 8) : BitConverter.ToInt32(buffer, 4));
        Assert.Equal(leaf.Length * 2, BitConverter.ToInt32(buffer, offset - 4));
        Assert.Equal(Encoding.Unicode.GetBytes(leaf), buffer[offset..]);
        if (IntPtr.Size == 8) Assert.Equal(new byte[4], buffer[4..8]);
    }
    [Fact]
    public void Production_selection_uses_class65_posix_replace_and_no_replace_is_unchanged()
    {
        Assert.Equal(ExpectedProductionReplacement, StagedMetadataStoreNative.RenameOperationFor(true));
        Assert.Equal(new MetadataRenameOperation(10, 0), StagedMetadataStoreNative.RenameOperationFor(false));
        Assert.Throws<ArgumentOutOfRangeException>(() => StagedMetadataStoreNative.ReplacementOperation((MetadataReplacementMechanism)99));
        Assert.Throws<ArgumentException>(() => StagedMetadataStoreNative.RenameBuffer("target", (IntPtr)1, new(10, 3)));
        Assert.Throws<ArgumentException>(() => StagedMetadataStoreNative.RenameBuffer("target", (IntPtr)1, new(65, 4)));
        Assert.Throws<ArgumentException>(() => StagedMetadataStoreNative.RenameBuffer("../target", (IntPtr)1, new(10, 1)));
        Assert.Throws<ArgumentException>(() => StagedMetadataStoreNative.RenameBuffer("target", IntPtr.Zero, new(10, 1)));
    }
    [Fact]
    public void Builder_regression_tables_preserve_positive_and_negative_control_counts()
    {
        var replacement = StagedMetadataStoreReplacementNativeTests.ReplacementVectors().ToArray();
        int[] statuses = replacement.Select(c => StagedMetadataStoreReplacementNativeTests.ExpectedStatus((string)c[0], (bool)c[1], (bool)c[2])).ToArray();
        Assert.Equal(22, statuses.Count(s => s == 0));
        Assert.Equal(8, statuses.Count(s => s == unchecked((int)0xC0000022)));
        Assert.Equal(2, statuses.Count(s => s == unchecked((int)0xC0000043)));
        var allocation = StagedMetadataStoreAllocationNativeTests.AllocationVectors().ToArray();
        Assert.Equal(48, allocation.Length);
        Assert.Equal(3, allocation.Count(c => StagedMetadataStoreAllocationNativeTests.ExpectedAllocation((string)c[0], (bool)c[1], (int)c[2]).Peak >
            BoundedOutputPlan.Round((int)c[2], (bool)c[1] ? 65536 : 4096)));
    }

    [Fact]
    public void Discovery_matrix_contains_all_thirty_two_handle_configurations()
    {
        var cases = StagedMetadataStoreReplacementNativeTests.ReplacementVectors().ToArray();
        Assert.Equal(32, cases.Length);
        Assert.Equal(32, cases.Select(c => string.Join("/", c)).Distinct().Count());
        foreach (string mechanism in new[] { "Classic", "Extended", "ExtendedPosix", "ReleasedClassic" })
            Assert.Equal(8, cases.Count(c => (string)c[0] == mechanism));
    }
}
#endif
