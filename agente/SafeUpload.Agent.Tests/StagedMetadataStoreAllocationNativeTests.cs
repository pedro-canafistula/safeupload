#if SAFEUPLOAD_ADMISSION_EVIDENCE
using Microsoft.Win32.SafeHandles;
using SafeUpload.Agent.Minifilter;
using SafeUpload.Agent.Service.Interception;
using Xunit.Abstractions;

namespace SafeUpload.Agent.Tests;

// Discovery, not a positive store/qualification verdict. These experiments
// deliberately compare potentially over-allocating paths. Existing N-U8-01
// still requires Committed; Held here never satisfies that positive baseline.
[Trait("Category", "NativeWindows")]
public sealed class StagedMetadataStoreAllocationNativeTests(ITestOutputHelper output)
{
    public static IEnumerable<object[]> AllocationVectors()
    {
        foreach (string mechanism in new[] { "Chunked", "Single", "PreallocatedChunked", "PreallocatedSingle" })
        foreach (bool stricterQuantum in new[] { false, true })
        foreach (int length in new[] { 64, 192, 1192, 8192, 65537, 131072 })
            yield return [mechanism, stricterQuantum, length];
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
        long maximumObserved = 0;
        int writes = 0;
        output.WriteLine($"DiscoveryOnly=true MechanismEvidence=BuilderOSOnly OS={Environment.OSVersion} Mechanism={mechanism} " +
            $"Role={plan.Role} Access=0x{MetadataStoreRoles.Access(plan.Role):X} Share={StagedMetadataStoreNative.ChildShare} " +
            $"Options=0x{StagedMetadataStoreNative.OutputOptions:X} NativeRequiredA={native.Alignment} TestA={alignment} ActualU={native.AllocationUnit} " +
            $"L={logical} P={plan.PaddedExtent} NominalQ={plan.PeakAllocation} A>U={alignment > native.AllocationUnit}");
        if (alignment <= native.AllocationUnit)
            output.WriteLine("A>U=UnavailableForThisQuantumAndActualVolume; no simulated-native claim");

        MetadataNativeObservation Capture(string step, MetadataNativeResult result, long offset = 0, long length = 0)
        {
            var measured = native.Query(file);
            maximumObserved = Math.Max(maximumObserved, measured.AllocationSize);
            try { fixture.Accounting.Observe(plan.Object, measured.Identity, measured.AllocationSize, measured.Links); }
            catch (MetadataPhysicalOverrunException) { exceeded = true; }
            output.WriteLine($"Step={step} Class={(step.Contains("Allocation", StringComparison.Ordinal) ? "FileAllocationInformation(19)" : step == "EOF" ? "FileEndOfFileInformation(20)" : "NativeIO")} " +
                $"NTSTATUS=0x{result.Status:X8} Information={result.Information} WriteIndex={writes} Offset={offset} Length={length} " +
                $"L={logical} P={plan.PaddedExtent} Q={plan.PeakAllocation} Identity={measured.Identity} EOF={measured.EndOfFile} " +
                $"AllocationSize={measured.AllocationSize} Links={measured.Links} DeletePending={measured.DeletePending} " +
                $"RetainedCharge={fixture.Accounting.Charge(plan.Object)} ExpectedProductHold={exceeded}");
            Assert.True(fixture.Accounting.Charge(plan.Object) >= measured.AllocationSize);
            Assert.Equal(initial.Identity, measured.Identity);
            result.Require(); return measured;
        }

        Capture("Create", created);
        if (mechanism.StartsWith("Preallocated", StringComparison.Ordinal))
            Capture("AllocationBeforeWrite", native.Allocation(file, plan.PaddedExtent), length: plan.PaddedExtent);
        long written = 0;
        if (!exceeded)
        {
            bool single = mechanism.EndsWith("Single", StringComparison.Ordinal);
            int stride = checked((int)(single ? plan.PaddedExtent : alignment));
            byte[] block = Enumerable.Repeat((byte)0x5A, stride).ToArray();
            while (written < plan.PaddedExtent)
            {
                var result = native.WriteAligned(file, written, block, alignment);
                writes++;
                Capture("Write", result, written, block.Length);
                Assert.Equal((ulong)block.Length, result.Information);
                written += block.Length;
                if (exceeded) break; // No further data writes after the physical bound failed.
            }
        }
        Capture("F1-BeforeEOFNormalization", native.Flush(file));
        // This remains an isolated, held diagnostic object if the write stopped.
        // Normalize only already-written bytes; never extend an incomplete probe.
        long normalizedEof = Math.Min(logical, written);
        Capture("EOF", native.EndOfFile(file, normalizedEof), length: normalizedEof);
        Capture("F2", native.Flush(file));
        // Explicit post-EOF allocation normalization is observed separately.
        // Its success/lower allocation is never used to erase a witnessed peak.
        Capture("AllocationAfterEOF", native.Allocation(file, plan.PaddedExtent), length: plan.PaddedExtent);
        Capture("FlushAfterAllocation", native.Flush(file));
        long retained = Math.Max(plan.PeakAllocation, BoundedOutputPlan.Round(maximumObserved, native.AllocationUnit));
        Assert.Equal(retained, fixture.Accounting.Charge(plan.Object));
        Assert.Equal(retained, fixture.Accounting.Totals.Shared);
        if (exceeded)
            Assert.Throws<IOException>(() => fixture.Accounting.TryReserve(fixture.Plan(128), MetadataPhysicalClass.HotJournal));
        output.WriteLine($"DiscoveryOnly=true EmpiricalPeak={maximumObserved} RetainedCharge={retained} Writes={writes} " +
            $"ExpectedProductDisposition={(exceeded ? "Held" : "NoPhysicalOverrunObserved")} " +
            "NoUniversalUpperBoundInferred=true NoArchiveOrGrowthAuthority=true");
    }
}
#endif
