#if SAFEUPLOAD_ADMISSION_EVIDENCE
using Microsoft.Win32.SafeHandles;
using SafeUpload.Agent.Minifilter;
using SafeUpload.Agent.Service.Interception;
using Xunit.Abstractions;

namespace SafeUpload.Agent.Tests;

// Builder OS mechanism regression evidence, not target qualification. Assert
// per-run measured accounting, including potentially over-allocating paths.
// Held here never satisfies the strict N-U8-01 Committed baseline.
[Trait("Category", "NativeWindows")]
public sealed class StagedMetadataStoreAllocationNativeTests(ITestOutputHelper output)
{
    // m2t9fdiag1028a2 and m2t9fdiag1028a3 (t9-inc3-native-results-2.md,
    // Run 3) show identical Chunked inputs both within Q and over Q. Exact
    // overshoots/write counts were artifacts of one allocator state, not a
    // contract. Assert each run's own receipts; this preserves the accounting
    // invariant rather than weakening a deterministic bound. The other 36
    // rows stayed within Q in both runs and retain that positive requirement.
    public static IEnumerable<object[]> AllocationVectors()
    {
        foreach (string mechanism in new[] { "Chunked", "Single", "PreallocatedChunked", "PreallocatedSingle" })
        foreach (bool stricterQuantum in new[] { false, true })
        foreach (int length in new[] { 64, 192, 1192, 8192, 65537, 131072 })
            yield return [mechanism, stricterQuantum, length];
    }

    internal static bool RequiresBoundedPeak(string mechanism) => mechanism != "Chunked";
    internal sealed record AllocationReceipt(string Step, long EndOfFile, long AllocationSize,
        long RetainedCharge, MetadataStoreDisposition Disposition);

    internal static void AssertReceiptInvariant(IReadOnlyList<AllocationReceipt> receipts, long observedPeak,
        long q, long unit, long finalWriteSize)
    {
        Assert.True(observedPeak >= Math.Min(q, finalWriteSize));
        Assert.Equal(observedPeak, receipts.Max(r => r.AllocationSize));
        Assert.Contains(receipts, r => r.AllocationSize == observedPeak);
        long runningPeak = 0;
        foreach (var receipt in receipts)
        {
            runningPeak = Math.Max(runningPeak, receipt.AllocationSize);
            long retained = Math.Max(q, BoundedOutputPlan.Round(runningPeak, unit));
            Assert.Equal(retained, receipt.RetainedCharge);
            Assert.True(receipt.RetainedCharge >= receipt.AllocationSize);
            Assert.Equal(runningPeak > q ? MetadataStoreDisposition.Held : MetadataStoreDisposition.Committed, receipt.Disposition);
        }
    }

    private sealed class HeldFile(SafeFileHandle file, IDisposable pin) : IDisposable
    {
        public void Dispose() { file.Dispose(); pin.Dispose(); }
    }

    [Theory]
    [MemberData(nameof(AllocationVectors))]
    public void N_U8_01_Allocation_discovery_records_every_write_and_normalization(
        string mechanism, bool stricterQuantum, int logical)
    {
        if (!OperatingSystem.IsWindows()) return;
        using var fixture = new StagedMetadataStoreNativeTests.Fixture();
        var native = fixture.Native;
        // A=64KiB is an explicitly stricter, real buffer/offset/length quantum,
        // a verified multiple of actual native requirements. U is never faked.
        long alignment = stricterQuantum ? 65536 : native.Alignment;
        var plan = StagedMetadataStoreTests.Plan(logical, MetadataRoleV32.Segment, alignment, native.AllocationUnit);
        Assert.True(fixture.Accounting.TryReserve(plan, MetadataPhysicalClass.Shared));
        using var file = native.Create("allocation-probe", plan.Role, out var created);
        created.Require();
        var initial = native.Query(file); fixture.Accounting.Bind(plan.Object, initial.Identity);
        using var lifetime = new HeldFile(file, fixture.Accounting.Pin(initial.Identity));
        bool exceeded = false;
        var receipts = new List<AllocationReceipt>();
        bool boundedPeak = RequiresBoundedPeak(mechanism);
        long maximumObserved = 0;
        int writes = 0;
        output.WriteLine($"DiscoveryOnly=true MechanismEvidence=BuilderOSOnly OS={Environment.OSVersion} Mechanism={mechanism} " +
            $"Role={plan.Role} Access=0x{MetadataStoreRoles.Access(plan.Role):X} Share={StagedMetadataStoreNative.ChildShare} " +
            $"Options=0x{StagedMetadataStoreNative.OutputOptions:X} NativeRequiredA={native.Alignment} TestA={alignment} ActualU={native.AllocationUnit} " +
            $"L={logical} P={plan.PaddedExtent} NominalQ={plan.PeakAllocation} A>U={alignment > native.AllocationUnit}");
        // This regression table was measured with native A=U=4096 on the
        // builder. A different geometry must fail visibly, not borrow its proof.
        Assert.Equal(4096, native.Alignment); Assert.Equal(4096, native.AllocationUnit);
        if (alignment <= native.AllocationUnit)
            output.WriteLine("A>U=UnavailableForThisQuantumAndActualVolume; no simulated-native claim");

        MetadataNativeObservation Capture(string step, MetadataNativeResult result, long offset = 0, long length = 0)
        {
            var measured = native.Query(file);
            maximumObserved = Math.Max(maximumObserved, measured.AllocationSize);
            try { fixture.Accounting.Observe(plan.Object, measured.Identity, measured.AllocationSize, measured.Links); }
            catch (MetadataPhysicalOverrunException) { exceeded = true; }
            var receipt = new AllocationReceipt(step, measured.EndOfFile, measured.AllocationSize,
                fixture.Accounting.Charge(plan.Object), exceeded ? MetadataStoreDisposition.Held : MetadataStoreDisposition.Committed);
            receipts.Add(receipt);
            output.WriteLine($"Step={receipt.Step} Class={(step.Contains("Allocation", StringComparison.Ordinal) ? "FileAllocationInformation(19)" : step == "EOF" ? "FileEndOfFileInformation(20)" : "NativeIO")} " +
                $"NTSTATUS=0x{result.Status:X8} Information={result.Information} WriteIndex={writes} Offset={offset} Length={length} " +
                $"L={logical} P={plan.PaddedExtent} Q={plan.PeakAllocation} Identity={measured.Identity} EOF={receipt.EndOfFile} " +
                $"AllocationSize={receipt.AllocationSize} Links={measured.Links} DeletePending={measured.DeletePending} " +
                $"RetainedCharge={receipt.RetainedCharge} Disposition={receipt.Disposition} ExpectedProductHold={exceeded}");
            Assert.True(fixture.Accounting.Charge(plan.Object) >= measured.AllocationSize);
            Assert.Equal(initial.Identity, measured.Identity);
            Assert.Equal(1u, measured.Links); Assert.False(measured.DeletePending);
            if (step == "Create") Assert.Equal(0, measured.AllocationSize);
            else if (boundedPeak) Assert.Equal(plan.PeakAllocation, measured.AllocationSize);
            result.Require(); return measured;
        }

        Capture("Create", created);
        if (mechanism.StartsWith("Preallocated", StringComparison.Ordinal))
            Capture("AllocationBeforeWrite", native.Allocation(file, plan.PaddedExtent), length: plan.PaddedExtent);
        long written = 0, finalWriteSize = 0;
        if (!exceeded)
        {
            bool single = mechanism.EndsWith("Single", StringComparison.Ordinal);
            int stride = checked((int)(single ? plan.PaddedExtent : alignment));
            byte[] block = Enumerable.Repeat((byte)0x5A, stride).ToArray();
            while (written < plan.PaddedExtent)
            {
                var result = native.WriteAligned(file, written, block, alignment);
                writes++;
                finalWriteSize = Capture("Write", result, written, block.Length).EndOfFile;
                Assert.Equal((ulong)block.Length, result.Information);
                written += block.Length;
                if (exceeded) break; // No further data writes after the physical bound failed.
            }
        }
        Assert.InRange(writes, 1, checked((int)(mechanism.EndsWith("Single", StringComparison.Ordinal) ? 1 : plan.PaddedExtent / alignment)));
        Assert.Equal(written, finalWriteSize);
        if (!exceeded) Assert.Equal(plan.PaddedExtent, written);
        Capture("F1-BeforeEOFNormalization", native.Flush(file));
        // This remains an isolated, held diagnostic object if the write stopped.
        // Normalize only already-written bytes; never extend an incomplete probe.
        long normalizedEof = Math.Min(logical, written);
        Assert.Equal(normalizedEof, Capture("EOF", native.EndOfFile(file, normalizedEof), length: normalizedEof).EndOfFile);
        Assert.Equal(normalizedEof, Capture("F2", native.Flush(file)).EndOfFile);
        // Explicit post-EOF allocation normalization is observed separately.
        // Its success/lower allocation is never used to erase a witnessed peak.
        Capture("AllocationAfterEOF", native.Allocation(file, plan.PaddedExtent), length: plan.PaddedExtent);
        Capture("FlushAfterAllocation", native.Flush(file));
        if (boundedPeak) Assert.InRange(maximumObserved, 0, plan.PeakAllocation);
        AssertReceiptInvariant(receipts, maximumObserved, plan.PeakAllocation, native.AllocationUnit, finalWriteSize);
        Assert.Equal(maximumObserved > plan.PeakAllocation, exceeded);
        long retained = Math.Max(plan.PeakAllocation, BoundedOutputPlan.Round(maximumObserved, native.AllocationUnit));
        Assert.Equal(retained, fixture.Accounting.Charge(plan.Object));
        Assert.Equal(retained, fixture.Accounting.Totals.Shared);
        if (exceeded)
            Assert.Throws<IOException>(() => fixture.Accounting.TryReserve(fixture.Plan(128), MetadataPhysicalClass.HotJournal));
        output.WriteLine($"DiscoveryOnly=true EmpiricalPeak={maximumObserved} RetainedCharge={retained} Writes={writes} " +
            $"ExpectedProductDisposition={receipts[^1].Disposition} " +
            "NoUniversalUpperBoundInferred=true NoArchiveOrGrowthAuthority=true");
    }
}
#endif
