#if SAFEUPLOAD_ADMISSION_EVIDENCE
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Security.Principal;
using Microsoft.Win32.SafeHandles;
using SafeUpload.Agent.Minifilter;
using SafeUpload.Agent.Service.Interception;
using Xunit.Abstractions;

namespace SafeUpload.Agent.Tests;

// Builder OS mechanism evidence only. No kernel metadata route, target OS,
// archive selector or physical power-loss qualification is exercised here.
[Trait("Category", "NativeWindows")]
public sealed class StagedMetadataStoreNativeTests(ITestOutputHelper output)
{
    internal sealed class Fixture : IDisposable
    {
        internal readonly TestWorkspace Workspace = new();
        internal readonly string Root;
        internal readonly StagedMetadataStoreNative Native;
        internal readonly FaultNative Adapter;
        internal readonly StagedMetadataStoreAccounting Accounting = new(64 << 20, 64 << 20, 128 << 20, 256);
        internal readonly StagedMetadataStore Store;
        internal Fixture()
        {
            Root = Path.Combine(Workspace.Root, "metadata"); StagedPrivateStorage.CreateDirectory(Root);
            var anchor = StagedMetadataStoreNative.OpenAnchor(Root);
            try { Native = new(anchor, StagedMetadataStoreNative.Identity(anchor)); }
            catch { anchor.Dispose(); throw; }
            Adapter = new(Native); Store = new(Adapter, Accounting);
        }
        internal BoundedOutputPlan Plan(long logical, MetadataRoleV32 role = MetadataRoleV32.ManifestNew, StagedStageIdentity? predecessor = null) =>
            StagedMetadataStoreTests.Plan(logical, role, Native.Alignment, Native.AllocationUnit, predecessor);
        public void Dispose() { Store.Dispose(); Workspace.Dispose(); }
    }
    internal sealed class FaultNative(IStagedMetadataNative inner) : IStagedMetadataNative
    {
        internal string? Fail;
        internal int FlushCount;
        private MetadataNativeResult Invoke(string name, Func<MetadataNativeResult> action) =>
            Fail == name ? new(unchecked((int)0xC0000022), 0) : action();
        public long Alignment => inner.Alignment;
        public long AllocationUnit => inner.AllocationUnit;
        public StagedStageIdentity ParentIdentity => inner.ParentIdentity;
        public void ValidateParent() => inner.ValidateParent();
        public SafeFileHandle Create(string leaf, MetadataRoleV32 role, out MetadataNativeResult result) => inner.Create(leaf, role, out result);
        public SafeFileHandle Open(string leaf, MetadataRoleV32 role, StagedStageIdentity expected) => inner.Open(leaf, role, expected);
        public MetadataNativeObservation Query(SafeFileHandle handle) => inner.Query(handle);
        public MetadataNativeResult Write(SafeFileHandle handle, long offset, ReadOnlySpan<byte> bytes) =>
            Fail == "Write" ? new(unchecked((int)0xC0000022), 0) : inner.Write(handle, offset, bytes);
        public MetadataNativeResult Read(SafeFileHandle handle, long offset, Span<byte> bytes) => inner.Read(handle, offset, bytes);
        public MetadataNativeResult Flush(SafeFileHandle handle) => Invoke("Flush" + ++FlushCount, () => inner.Flush(handle));
        public MetadataNativeResult Allocation(SafeFileHandle handle, long length) => Invoke("Allocation", () => inner.Allocation(handle, length));
        public MetadataNativeResult EndOfFile(SafeFileHandle handle, long length) => Invoke("EndOfFile", () => inner.EndOfFile(handle, length));
        public MetadataNativeResult Rename(SafeFileHandle handle, string leaf, bool replace) => Invoke("Rename", () => inner.Rename(handle, leaf, replace));
        public MetadataNativeResult Delete(SafeFileHandle handle) => Invoke("Delete", () => inner.Delete(handle));
        public void Dispose() => inner.Dispose();
    }
    private void Log(Fixture fixture, BoundedOutputPlan plan, StagedMetadataStore.Result result)
    {
        output.WriteLine($"MechanismEvidence=BuilderOSOnly OS={Environment.OSVersion} NativeRenameClass={StagedMetadataStoreNative.RenameOperationFor(plan.ExpectedPredecessor is not null).InformationClass} NativeRenameFlags=0x{StagedMetadataStoreNative.RenameOperationFor(plan.ExpectedPredecessor is not null).Flags:X} " +
            $"AnchorAccess=0x{StagedMetadataStoreNative.AnchorAccess:X} AnchorShare={StagedMetadataStoreNative.AnchorShare} " +
            $"ReplaceIfExists={plan.ExpectedPredecessor is not null} Role={plan.Role} Access=0x{MetadataStoreRoles.Access(plan.Role):X} ChildShare={StagedMetadataStoreNative.ChildShare} Options=0x{StagedMetadataStoreNative.OutputOptions:X} " +
            $"L={plan.LogicalLength} A={plan.Alignment} U={plan.AllocationUnit} P={plan.PaddedExtent} Q={plan.PeakAllocation} Result={result.Disposition} " +
            $"NativeWriteCalls={fixture.Native.NativeWriteCalls} SuccessfulNativeRenames={fixture.Native.SuccessfulRenames}");
        foreach (var receipt in result.Receipts)
            output.WriteLine($"Step={receipt.Step} NTSTATUS=0x{receipt.Native.Status:X8} Information={receipt.Native.Information} " +
                $"Identity={receipt.Observation?.Identity} EOF={receipt.Observation?.EndOfFile} AllocationSize={receipt.Observation?.AllocationSize} " +
                $"Links={receipt.Observation?.Links} UnlinkedHeld={receipt.Observation is { Links: 0 }} DeletePending={receipt.Observation?.DeletePending} RetainedChargeAtStep={receipt.RetainedCharge}");
    }

    [Fact]
    public void N_U4_01_Relative_create_no_follow_exact_role_and_substitution_refusals()
    {
        if (!OperatingSystem.IsWindows()) return;
        using var fixture = new Fixture(); var plan = fixture.Plan(1192);
        using var tx = fixture.Store.TryClaim(plan, "ledger.new", "ledger", new byte[1192], MetadataPhysicalClass.HotJournal)!;
        var result = fixture.Store.Execute(tx); Log(fixture, plan, result);
        Assert.Equal(MetadataStoreDisposition.Committed, result.Disposition);
        var actual = fixture.Native.Query(tx.Output!);
        Assert.Equal(1u, actual.Links); Assert.Equal(1192, actual.EndOfFile);
        foreach (string leaf in new[] { "../outside", "x:stream", @"x\y", ".", ".." })
            Assert.Throws<ArgumentException>(() => fixture.Native.Open(leaf, MetadataRoleV32.ManifestCurrent, actual.Identity));
        Assert.Throws<IOException>(() => fixture.Native.Open("ledger", MetadataRoleV32.ManifestCurrent, actual.Identity with { FileIdLow = actual.Identity.FileIdLow ^ 1 }));
        string other = Path.Combine(fixture.Workspace.Root, "other"); StagedPrivateStorage.CreateDirectory(other);
        using var otherAnchor = StagedMetadataStoreNative.OpenAnchor(other);
        Assert.Throws<IOException>(() => new StagedMetadataStoreNative(otherAnchor, fixture.Native.ParentIdentity));
        Assert.Equal(new byte[1192], ReadSharedBytes(Path.Combine(fixture.Root, "ledger")));
        tx.Dispose();
        using (var moved = fixture.Native.Open("ledger", MetadataRoleV32.ManifestCurrent, actual.Identity))
            fixture.Native.Rename(moved, "retained-predecessor", false).Require();
        var substitutePlan = fixture.Plan(1192);
        using (var substitute = fixture.Store.TryClaim(substitutePlan, "substitute.new", "ledger", Enumerable.Repeat((byte)3, 1192).ToArray(), MetadataPhysicalClass.HotJournal)!)
            Assert.Equal(MetadataStoreDisposition.Committed, fixture.Store.Execute(substitute).Disposition);
        var rejectedPlan = fixture.Plan(1192, predecessor: actual.Identity);
        using (var rejected = fixture.Store.TryClaim(rejectedPlan, "rejected.new", "ledger", new byte[1192], MetadataPhysicalClass.HotJournal)!)
        {
            var held = fixture.Store.Execute(rejected); Log(fixture, rejectedPlan, held);
            Assert.Equal(MetadataStoreDisposition.Held, held.Disposition);
            Assert.Null(rejected.Output); // Identity refusal precedes candidate create.
        }
        Assert.Equal(Enumerable.Repeat((byte)3, 1192), ReadSharedBytes(Path.Combine(fixture.Root, "ledger")));
        Assert.Equal(new byte[1192], ReadSharedBytes(Path.Combine(fixture.Root, "retained-predecessor")));
        // A directory reparse point must never be accepted as an anchor or child.
        string junction = Path.Combine(fixture.Root, "junction");
        CreateJunction(junction, fixture.Root);
        Assert.Throws<IOException>(() => StagedMetadataStoreNative.OpenAnchor(junction));
        Assert.Throws<IOException>(() => fixture.Native.Open("junction", MetadataRoleV32.ManifestCurrent, actual.Identity));
        Directory.Delete(junction);
    }

    [Theory]
    [InlineData(64)]
    [InlineData(128)]
    [InlineData(192)]
    [InlineData(1192)]
    [InlineData(65536)]
    [InlineData(131072)]
    public void N_U4_02_Actual_alignment_vectors_and_adapter_preissue_negatives(int logical)
    {
        if (!OperatingSystem.IsWindows()) return;
        using var fixture = new Fixture(); var plan = fixture.Plan(logical);
        using var tx = fixture.Store.TryClaim(plan, "aligned.new", "aligned", new byte[logical], MetadataPhysicalClass.HotJournal)!;
        var result = fixture.Store.Execute(tx); Log(fixture, plan, result);
        Assert.Equal(MetadataStoreDisposition.Committed, result.Disposition);
        int calls = fixture.Native.NativeWriteCalls;
        Assert.Throws<ArgumentException>(() => fixture.Native.Write(tx.Output!, 1, new byte[plan.Alignment]));
        Assert.Throws<ArgumentException>(() => fixture.Native.Write(tx.Output!, 0, new byte[1]));
        Assert.Equal(calls, fixture.Native.NativeWriteCalls);
        output.WriteLine("AlignmentNegative=AdapterPreIssue Expected=Refused NativeCalls=0; no claim of API-issued misalignment rejection.");
        output.WriteLine(plan.Alignment > plan.AllocationUnit ? "A>U=ObservedOnActualVolume" : "A>U=UnavailableOnActualVolume; pure cross-product remains diagnostic only");
    }

    [Theory]
    [InlineData("Allocation")]
    [InlineData("Write")]
    [InlineData("Flush1")]
    [InlineData("EndOfFile")]
    [InlineData("Flush2")]
    [InlineData("Rename")]
    [InlineData("Flush3")]
    public void N_U4_03_Predetermined_native_fault_is_Held_with_failed_output_peak(string fault)
    {
        if (!OperatingSystem.IsWindows()) return;
        using var fixture = new Fixture(); fixture.Adapter.Fail = fault;
        var plan = fixture.Plan(192);
        using var tx = fixture.Store.TryClaim(plan, "failed.new", "failed", new byte[192], MetadataPhysicalClass.HotJournal)!;
        var result = fixture.Store.Execute(tx); Log(fixture, plan, result);
        Assert.Equal(MetadataStoreDisposition.Held, result.Disposition);
        Assert.Equal(plan.PeakAllocation, fixture.Accounting.Charge(plan.Object));
        Assert.NotNull(tx.Output); Assert.False(tx.Output!.IsClosed);
        var retained = fixture.Native.Query(tx.Output);
        Assert.InRange(retained.AllocationSize, 0, plan.PeakAllocation);
        output.WriteLine($"RetainedFailedOutput Identity={retained.Identity} L=192 P={plan.PaddedExtent} Q={plan.PeakAllocation} EOF={retained.EndOfFile} AllocationSize={retained.AllocationSize}");
        Assert.Equal(MetadataStoreDisposition.Held, fixture.Store.RecoverBookkeeping(tx).Disposition);
        Assert.Throws<InvalidOperationException>(() => fixture.Store.Execute(tx));
    }

    [Fact]
    public void N_U4_04_Root_sharing_namespace_claim_and_untrusted_WRITE_DAC_exclusion()
    {
        if (!OperatingSystem.IsWindows()) return;
        using var fixture = new Fixture();
        using (var competing = CreateFileW(fixture.Root, 0x10000, 7, IntPtr.Zero, 3, 0x02200000, IntPtr.Zero))
        {
            int error = Marshal.GetLastWin32Error(); Assert.True(competing.IsInvalid); Assert.Equal(32, error);
            output.WriteLine($"CompetingRootDELETE NativeWin32={error} RootShare=3 NoSHARE_DELETE=true");
        }
        var plan = fixture.Plan(128);
        using var tx = fixture.Store.TryClaim(plan, "claim.new", "claim", new byte[128], MetadataPhysicalClass.HotJournal)!;
        Assert.Null(fixture.Store.TryClaim(fixture.Plan(128), "competing.new", "claim", new byte[128], MetadataPhysicalClass.HotJournal));
        Assert.Equal(MetadataStoreDisposition.Committed, fixture.Store.Execute(tx).Disposition);
        using var identity = WindowsIdentity.GetCurrent(TokenAccessLevels.Duplicate | TokenAccessLevels.Query);
        var world = new SecurityIdentifier(WellKnownSidType.WorldSid, null); byte[] sidBytes = new byte[world.BinaryLength]; world.GetBinaryForm(sidBytes, 0);
        IntPtr sid = Marshal.AllocHGlobal(sidBytes.Length);
        try
        {
            Marshal.Copy(sidBytes, 0, sid, sidBytes.Length);
            var restricted = new SidAndAttributes { Sid = sid };
            Assert.True(CreateRestrictedToken(identity.AccessToken, 1, 0, IntPtr.Zero, 0, IntPtr.Zero, 1, ref restricted, out var token), new Win32Exception(Marshal.GetLastWin32Error()).Message);
            using (token)
                WindowsIdentity.RunImpersonated(token, () =>
                {
                    using var denied = CreateFileW(Path.Combine(fixture.Root, "claim"), 0x40000, 7, IntPtr.Zero, 3, 0x00200000, IntPtr.Zero);
                    int error = Marshal.GetLastWin32Error(); Assert.True(denied.IsInvalid); Assert.Equal(5, error);
                    output.WriteLine($"UntrustedRestrictedToken WRITE_DAC=0x40000 Share=7 NativeWin32={error}; ACL exclusion, not sharing");
                });
        }
        finally { Marshal.FreeHGlobal(sid); }
    }

    [Fact]
    public void N_U4_05_Held_target_class10_replace_lost_bookkeeping_repeat_interrupted_recovery()
    {
        if (!OperatingSystem.IsWindows()) return;
        using var fixture = new Fixture(); var old = fixture.Plan(128); StagedStageIdentity oldId;
        using (var first = fixture.Store.TryClaim(old, "old.new", "current", Enumerable.Repeat((byte)1, 128).ToArray(), MetadataPhysicalClass.HotJournal)!)
        {
            var baseline = fixture.Store.Execute(first); Log(fixture, old, baseline);
            Assert.Equal(MetadataStoreDisposition.Committed, baseline.Disposition); oldId = fixture.Native.Query(first.Output!).Identity;
        }
        int before = fixture.Native.SuccessfulRenames;
        var next = fixture.Plan(192, predecessor: oldId);
        using var tx = fixture.Store.TryClaim(next, "replacement.new", "current", Enumerable.Repeat((byte)2, 192).ToArray(), MetadataPhysicalClass.HotJournal)!;
        var lost = fixture.Store.Execute(tx, step => { if (step == MetadataStoreStep.Replace) throw new IOException("injected lost bookkeeping after native success"); });
        Log(fixture, next, lost); Assert.Equal(MetadataStoreDisposition.Held, lost.Disposition);
        Assert.True(tx.MutationSucceeded, "The selected class-10 rename must succeed before bookkeeping recovery; a native refusal is not an unlinked predecessor.");
        Assert.Contains(lost.Receipts, r => r.Step == MetadataStoreStep.Replace && r.Native.Success);
        Assert.Equal(before + 1, fixture.Native.SuccessfulRenames);
        Assert.NotNull(tx.Predecessor); Assert.False(tx.Predecessor!.IsClosed);
        var oldHeld = fixture.Native.Query(tx.Predecessor); Assert.Equal(oldId, oldHeld.Identity); Assert.Equal(0u, oldHeld.Links);
        Assert.False(oldHeld.DeletePending);
        Assert.Equal(MetadataObjectLinkState.UnlinkedHeld, fixture.Accounting.LinkState(oldId));
        Assert.Equal(Enumerable.Repeat((byte)1, 128), ReadHeldBytes(fixture.Native, tx.Predecessor, 128));
        var newId = fixture.Native.Query(tx.Output!).Identity;
        using (var independent = fixture.Native.Open("current", MetadataRoleV32.ManifestCurrent, newId))
            Assert.Equal(newId, fixture.Native.Query(independent).Identity);
        Assert.NotEqual(oldId, newId); Assert.Equal(before + 1, fixture.Native.SuccessfulRenames);
        output.WriteLine($"IndependentOld Identity={oldId} EOF={oldHeld.EndOfFile} AllocationSize={oldHeld.AllocationSize} Links={oldHeld.Links} UnlinkedHeld={oldHeld.Links == 0} DeletePending={oldHeld.DeletePending} RetainedCharge={fixture.Accounting.Charge(old.Object)}");
        Assert.Equal(MetadataStoreDisposition.Held, fixture.Store.RecoverBookkeeping(tx, _ => throw new IOException("second interruption")).Disposition);
        var recovered = fixture.Store.RecoverBookkeeping(tx); Log(fixture, next, recovered);
        Assert.Equal(MetadataStoreDisposition.RecoverableBookkeeping, recovered.Disposition);
        Assert.Equal(before + 1, fixture.Native.SuccessfulRenames);
        Assert.Equal(old.PeakAllocation + next.PeakAllocation, fixture.Accounting.Totals.HotJournal);
        Assert.Equal(StagedMetadataStoreReplacementPlanTests.ExpectedProductionReplacement, StagedMetadataStoreNative.RenameOperationFor(true));
        Assert.Equal(Enumerable.Repeat((byte)2, 192), ReadSharedBytes(Path.Combine(fixture.Root, "current")));
    }

    [Fact]
    public void N_U8_01_Raw_append_dual_slot_fault_recovery_and_additive_native_allocation()
    {
        if (!OperatingSystem.IsWindows()) return;
        using var fixture = new Fixture(); long a = fixture.Native.Alignment;
        var plan = fixture.Plan(2 * a, MetadataRoleV32.Segment);
        using var tx = fixture.Store.TryClaim(plan, "segment", "segment", new byte[2 * a], MetadataPhysicalClass.Shared)!;
        var initial = fixture.Store.Execute(tx); Log(fixture, plan, initial);
        Assert.Equal(MetadataStoreDisposition.Committed, initial.Disposition);
        var extension = BoundedOutputPlan.Create(MetadataRoleV32.Segment, plan.Object, 3 * a, a, fixture.Native.AllocationUnit);
        byte[] frame = Enumerable.Repeat((byte)7, (int)a).ToArray(), slot = Enumerable.Repeat((byte)9, (int)a).ToArray();
        int writes = fixture.Native.NativeWriteCalls;
        var lost = fixture.Store.Append(tx, extension, 2 * a, frame, 1, slot,
            step => { if (step == MetadataStoreStep.Append) throw new IOException("lost raw append bookkeeping"); });
        Log(fixture, extension, lost); Assert.Equal(MetadataStoreDisposition.Held, lost.Disposition);
        Assert.Equal(writes + 1, fixture.Native.NativeWriteCalls);
        Assert.Equal(MetadataStoreDisposition.Held, fixture.Store.RecoverBookkeeping(tx,
            step => { if (step == MetadataStoreStep.Slot) throw new IOException("second recovery interruption"); }).Disposition);
        var recovered = fixture.Store.RecoverBookkeeping(tx); Log(fixture, extension, recovered);
        Assert.Equal(MetadataStoreDisposition.RecoverableBookkeeping, recovered.Disposition);
        Assert.Equal(writes + 2, fixture.Native.NativeWriteCalls); // One frame + one inactive slot.
        byte[] actual = ReadSharedBytes(Path.Combine(fixture.Root, "segment"));
        Assert.Equal(new byte[a], actual[..(int)a]);
        Assert.Equal(slot, actual[(int)a..(int)(2 * a)]); Assert.Equal(frame, actual[(int)(2 * a)..]);
        Assert.Equal(extension.PeakAllocation, fixture.Accounting.Totals.Shared);
        // A separate failed output coexists; neither final EOF nor retry releases it.
        fixture.Adapter.Fail = "Write"; var residue = fixture.Plan(128, MetadataRoleV32.InventoryNew);
        using var failed = fixture.Store.TryClaim(residue, "inventory.new", "inventory", new byte[128], MetadataPhysicalClass.Shared)!;
        var held = fixture.Store.Execute(failed); Log(fixture, residue, held);
        Assert.Equal(MetadataStoreDisposition.Held, held.Disposition);
        Assert.Equal(extension.PeakAllocation + residue.PeakAllocation, fixture.Accounting.Totals.Shared);
        failed.Dispose(); fixture.Adapter.Fail = null;
        var old = fixture.Plan(128, MetadataRoleV32.InventoryNew); StagedStageIdentity oldId;
        using (var current = fixture.Store.TryClaim(old, "old-inventory.new", "replaceable", new byte[128], MetadataPhysicalClass.Shared)!)
        {
            var committed = fixture.Store.Execute(current); Log(fixture, old, committed);
            Assert.Equal(MetadataStoreDisposition.Committed, committed.Disposition);
            oldId = fixture.Native.Query(current.Output!).Identity;
        }
        fixture.Adapter.Fail = "Rename";
        var refusedPlan = fixture.Plan(128, MetadataRoleV32.InventoryNew, oldId);
        using (var refused = fixture.Store.TryClaim(refusedPlan, "refused-inventory.new", "replaceable", new byte[128], MetadataPhysicalClass.Shared)!)
        {
            var refusal = fixture.Store.Execute(refused); Log(fixture, refusedPlan, refusal);
            Assert.Equal(MetadataStoreDisposition.Held, refusal.Disposition);
            Assert.False(fixture.Native.Query(refused.Predecessor!).DeletePending);
            Assert.Equal(oldId, fixture.Native.Query(refused.Predecessor!).Identity);
            Assert.Equal(extension.PeakAllocation + residue.PeakAllocation + old.PeakAllocation + refusedPlan.PeakAllocation,
                fixture.Accounting.Totals.Shared);
        }
        fixture.Adapter.Fail = null;
        var successor = fixture.Plan(128, MetadataRoleV32.InventoryNew, oldId);
        using var replacement = fixture.Store.TryClaim(successor, "successor-inventory.new", "replaceable", new byte[128], MetadataPhysicalClass.Shared)!;
        var success = fixture.Store.Execute(replacement); Log(fixture, successor, success);
        Assert.Equal(MetadataStoreDisposition.Committed, success.Disposition);
        var predecessor = fixture.Native.Query(replacement.Predecessor!);
        Assert.Equal(0u, predecessor.Links); Assert.False(predecessor.DeletePending); Assert.Equal(oldId, predecessor.Identity);
        Assert.Equal(new byte[128], ReadHeldBytes(fixture.Native, replacement.Predecessor!, 128));
        Assert.Equal(MetadataObjectLinkState.UnlinkedHeld, fixture.Accounting.LinkState(oldId));
        Assert.Equal(extension.PeakAllocation + residue.PeakAllocation + old.PeakAllocation + refusedPlan.PeakAllocation + successor.PeakAllocation,
            fixture.Accounting.Totals.Shared);
        output.WriteLine($"RetainedPredecessor Identity={predecessor.Identity} L=128 P={old.PaddedExtent} Q={old.PeakAllocation} EOF={predecessor.EndOfFile} AllocationSize={predecessor.AllocationSize} Links={predecessor.Links} DeletePending={predecessor.DeletePending}; no release inferred from selection or unlink");
    }

    private static byte[] ReadSharedBytes(string path)
    {
        using var reader = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read | FileShare.Write | FileShare.Delete);
        byte[] bytes = new byte[checked((int)reader.Length)]; reader.ReadExactly(bytes); return bytes;
    }
    private static byte[] ReadHeldBytes(StagedMetadataStoreNative native, SafeFileHandle held, int length)
    {
        byte[] result = new byte[length], block = new byte[native.Alignment];
        var before = native.Query(held);
        for (int offset = 0; offset < length; offset += block.Length)
        {
            var read = native.Read(held, offset, block); read.Require();
            int count = Math.Min(block.Length, length - offset); Assert.True(read.Information >= (ulong)count);
            block.AsSpan(0, count).CopyTo(result.AsSpan(offset));
        }
        Assert.Equal(before.Identity, native.Query(held).Identity); return result;
    }

    private static void CreateJunction(string link, string target)
    {
        Directory.CreateDirectory(link);
        string substitute = @"\??\" + target;
        byte[] sub = System.Text.Encoding.Unicode.GetBytes(substitute), print = System.Text.Encoding.Unicode.GetBytes(target);
        byte[] buffer = new byte[16 + sub.Length + 2 + print.Length + 2];
        BitConverter.GetBytes(0xA0000003u).CopyTo(buffer, 0); BitConverter.GetBytes((ushort)(buffer.Length - 8)).CopyTo(buffer, 4);
        BitConverter.GetBytes((ushort)sub.Length).CopyTo(buffer, 10); BitConverter.GetBytes((ushort)(sub.Length + 2)).CopyTo(buffer, 12);
        BitConverter.GetBytes((ushort)print.Length).CopyTo(buffer, 14); sub.CopyTo(buffer, 16); print.CopyTo(buffer, 16 + sub.Length + 2);
        using var handle = CreateFileW(link, 0x100002, 7, IntPtr.Zero, 3, 0x02200000, IntPtr.Zero);
        Assert.False(handle.IsInvalid);
        Assert.True(DeviceIoControl(handle, 0x900A4, buffer, buffer.Length, IntPtr.Zero, 0, out _, IntPtr.Zero), new Win32Exception(Marshal.GetLastWin32Error()).Message);
    }
    [StructLayout(LayoutKind.Sequential)] private struct SidAndAttributes { internal IntPtr Sid; internal uint Attributes; }
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)] private static extern SafeFileHandle CreateFileW(string path, uint access, uint share, IntPtr security, uint disposition, uint flags, IntPtr template);
    [DllImport("kernel32.dll", SetLastError = true)] [return: MarshalAs(UnmanagedType.Bool)] private static extern bool DeviceIoControl(SafeFileHandle handle, uint code, byte[] input, int length, IntPtr output, int outputLength, out uint returned, IntPtr overlapped);
    [DllImport("advapi32.dll", SetLastError = true)] [return: MarshalAs(UnmanagedType.Bool)] private static extern bool CreateRestrictedToken(SafeAccessTokenHandle existing, uint flags, uint disableCount, IntPtr disable, uint privilegeCount, IntPtr privileges, uint restrictCount, ref SidAndAttributes restrict, out SafeAccessTokenHandle token);
}
#endif
