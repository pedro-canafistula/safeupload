#if SAFEUPLOAD_ADMISSION_EVIDENCE
using System.Reflection;
using Microsoft.Win32.SafeHandles;
using SafeUpload.Agent.Minifilter;
using SafeUpload.Agent.Service.Interception;

namespace SafeUpload.Agent.Tests;

public sealed class StagedMetadataStoreTests
{
    internal static BoundedOutputPlan Plan(long logical = 192, MetadataRoleV32 role = MetadataRoleV32.CompanionNew,
        long alignment = 65536, long unit = 4096, StagedStageIdentity? predecessor = null) =>
        BoundedOutputPlan.Create(role, new(Guid.NewGuid(), 1), logical, alignment, unit, predecessor);
    internal static StagedMetadataStoreAccounting Accounting(long journal = 1024 * 1024, long other = 1024 * 1024) =>
        new(journal, other, 64 * 1024 * 1024, 128);

    [Fact]
    public void Production_L_P_Q_matches_independent_archive_model_for_all_sixty_A_U_pairs_and_boundaries()
    {
        MethodInfo oracle = typeof(GrowthArchiveFitModelTests).GetMethod("PlanOutput", BindingFlags.Static | BindingFlags.NonPublic)!;
        int pairs = 0;
        for (long a = 4096; a <= 65536; a *= 2)
        for (long u = 512; u <= 1048576; u *= 2)
        {
            pairs++;
            foreach (long logical in new long[] { 0, 1, 64, 128, 192, 1192, 4095, 4096, 4097, 65536, 65537, 131072 })
            {
                object expected = oracle.Invoke(null, [logical, a, u])!;
                long Value(string name) => (long)expected.GetType().GetProperty(name)!.GetValue(expected)!;
                var production = Plan(logical, MetadataRoleV32.ManifestNew, a, u);
                Assert.Equal(Value("Logical"), production.LogicalLength);
                Assert.Equal(Value("Padded"), production.PaddedExtent);
                Assert.Equal(Value("Peak"), production.PeakAllocation);
            }
        }
        Assert.Equal(60, pairs);
    }

    [Theory]
    [InlineData(8192, 4096, 4096, 16384)]
    [InlineData(192, 65536, 4096, 69632)]
    [InlineData(128, 4096, 65536, 131072)]
    public void Model_Q_is_a_minimum_precharge_and_measured_native_peak_is_retained(long logical, long a, long u, long observed)
    {
        MethodInfo oracle = typeof(GrowthArchiveFitModelTests).GetMethod("PlanOutput", BindingFlags.Static | BindingFlags.NonPublic)!;
        object expected = oracle.Invoke(null, [logical, a, u])!;
        long nominal = (long)expected.GetType().GetProperty("Peak")!.GetValue(expected)!;
        var plan = Plan(logical, MetadataRoleV32.ManifestNew, a, u); var account = Accounting();
        var identity = new StagedStageIdentity(1, 0, 42);
        Assert.True(account.TryReserve(plan, MetadataPhysicalClass.HotJournal)); account.Bind(plan.Object, identity);
        Assert.Throws<MetadataPhysicalOverrunException>(() => account.Observe(plan.Object, identity, observed));
        long measured = checked((observed + u - 1) / u * u);
        Assert.Equal(Math.Max(nominal, measured), account.Charge(plan.Object));
        Assert.Equal(account.Charge(plan.Object), account.Totals.HotJournal);
        account.Observe(plan.Object, identity, 0); // Later normalization cannot erase the peak.
        Assert.Equal(Math.Max(nominal, measured), account.Charge(plan.Object));
        Assert.Throws<IOException>(() => account.TryReserve(Plan(), MetadataPhysicalClass.HotOther));
    }

    [Fact]
    public void Persisted_larger_measurement_and_extreme_native_size_retain_the_measured_debit_before_holding()
    {
        var plan = Plan(8192, MetadataRoleV32.Segment, 4096, 4096); var identity = new StagedStageIdentity(1, 0, 42);
        var account = Accounting(); Assert.True(account.TryReserve(plan, MetadataPhysicalClass.Shared)); account.Bind(plan.Object, identity);
        Assert.Throws<MetadataPhysicalOverrunException>(() => account.Apply(new(plan.Object, identity, 1, 16384, true, true, true, false)));
        Assert.Equal(16384, account.Charge(plan.Object)); Assert.Equal(16384, account.Totals.Shared);
        Assert.Throws<MetadataPhysicalOverrunException>(() => account.Observe(plan.Object, identity, long.MaxValue));
        Assert.Equal(long.MaxValue, account.Charge(plan.Object)); Assert.Equal(long.MaxValue, account.Totals.Shared);
        Assert.Throws<IOException>(() => account.TryReserve(Plan(), MetadataPhysicalClass.HotOther));
    }

    [Fact]
    public void Logical_EOF_mutant_cannot_reserve_a_padded_write_even_if_its_apparent_budget_fits()
    {
        var plan = Plan();
        var account = Accounting(other: 4096);
        Assert.False(account.TryReserve(plan, MetadataPhysicalClass.HotOther));
        Assert.Throws<ArgumentException>(() => new BoundedOutputPlan(plan.Role, plan.Object, 192, 65536, 4096,
            65536, 4096, null, 192));
        Assert.Equal((0L, 0L, 0L), account.Totals);
    }

    [Theory]
    [InlineData(-1, 4096, 4096)]
    [InlineData(193, 4096, 4096)]
    [InlineData(192, 512, 4096)]
    [InlineData(192, 131072, 4096)]
    [InlineData(192, 6144, 4096)]
    [InlineData(192, 4096, 6000)]
    public void Invalid_plans_fail_before_native_issue(long logical, long a, long u) =>
        Assert.Throws<ArgumentOutOfRangeException>(() => Plan(logical, alignment: a, unit: u));

    [Fact]
    public void Checked_rounding_and_shared_debit_do_not_wrap()
    {
        Assert.Throws<OverflowException>(() => BoundedOutputPlan.Round(long.MaxValue, 65536));
        Assert.Throws<OverflowException>(() => StagedMetadataStoreAccounting.SharedDebit(long.MaxValue));
        Assert.Throws<ArgumentOutOfRangeException>(() => StagedMetadataStoreAccounting.SharedDebit(-1));
    }

    [Fact]
    public void Additive_predecessor_new_and_residue_need_exact_persisted_measurement_or_release()
    {
        var account = Accounting();
        var predecessor = Plan(); var next = Plan(); var residue = Plan(128);
        var id = new StagedStageIdentity(1, 0, 5);
        foreach (var p in new[] { predecessor, next, residue }) Assert.True(account.TryReserve(p, MetadataPhysicalClass.HotOther));
        account.Bind(predecessor.Object, id);
        Assert.Equal(196608, account.Totals.HotOther);
        var measured = new MetadataStorageTransition(predecessor.Object, id, 1, 4096, true, true, true, false);
        Assert.Throws<IOException>(() => account.Apply(measured with { Persisted = false }));
        Assert.Throws<IOException>(() => account.Apply(measured with { OperationsDrained = false }));
        Assert.Throws<IOException>(() => account.Apply(measured with { F2MeasuredClosed = false }));
        Assert.Throws<IOException>(() => account.Apply(measured with { Identity = id with { FileIdLow = 6 } }));
        account.Apply(measured);
        Assert.Equal(135168, account.Totals.HotOther);
        account.Apply(measured); Assert.Equal(135168, account.Totals.HotOther);
        Assert.Throws<IOException>(() => account.Apply(measured with { Allocation = 8192 }));
        account.Apply(measured with { Revision = 2, Allocation = 0, StorageReleased = true, F2MeasuredClosed = false });
        Assert.Equal(131072, account.Totals.HotOther);
    }

    [Fact]
    public void Journal_half_and_shared_physical_deltas_remain_independent_with_failed_residue()
    {
        var account = Accounting(journal: 512 * 1024);
        for (int i = 0; i < 4; i++) Assert.True(account.TryReserve(Plan(131072, MetadataRoleV32.ManifestNew), MetadataPhysicalClass.HotJournal));
        Assert.False(account.TryReserve(Plan(131072, MetadataRoleV32.ManifestNew), MetadataPhysicalClass.HotJournal));
        Assert.True(account.TryReserve(Plan(), MetadataPhysicalClass.HotOther));
        for (int i = 0; i < 4; i++) Assert.True(account.TryReserve(Plan(65536, MetadataRoleV32.AppendIntentNew), MetadataPhysicalClass.Shared));
        for (int i = 0; i < 4; i++) Assert.True(account.TryReserve(Plan(128, MetadataRoleV32.InventoryNew), MetadataPhysicalClass.Shared));
        Assert.True(account.TryReserve(Plan(131072, MetadataRoleV32.HistoryCandidate), MetadataPhysicalClass.Shared));
        Assert.Equal((524288L, 65536L, 655360L), account.Totals);
        Assert.Equal(655360L * 2 + 16 * 1024 * 1024, StagedMetadataStoreAccounting.SharedDebit(account.Totals.Shared));
    }

    [Theory]
    [InlineData("Create")]
    [InlineData("Allocation")]
    [InlineData("Write")]
    [InlineData("Flush1")]
    [InlineData("EndOfFile")]
    [InlineData("Flush2")]
    [InlineData("Rename")]
    [InlineData("Flush3")]
    public void Native_refusals_are_Held_keep_peak_and_never_retry(string fault)
    {
        var native = new MetadataMemoryNative { Fail = fault }; var account = Accounting();
        using var store = new StagedMetadataStore(native, account);
        var plan = Plan(); using var tx = store.TryClaim(plan, "a.new", "a", new byte[192], MetadataPhysicalClass.HotOther)!;
        var result = store.Execute(tx);
        Assert.Equal(MetadataStoreDisposition.Held, result.Disposition);
        Assert.Equal(65536, account.Charge(plan.Object));
        Assert.Contains(result.Receipts, r => r.Native.Status == MetadataMemoryNative.Failure);
        int renames = native.Renames;
        Assert.Equal(MetadataStoreDisposition.Held, store.RecoverBookkeeping(tx).Disposition);
        Assert.Throws<InvalidOperationException>(() => store.Execute(tx));
        Assert.Equal(renames, native.Renames);
    }

    [Fact]
    public void Predecessor_without_SHARE_DELETE_is_refused_before_reservation_or_native_issue()
    {
        var native = new MetadataMemoryNative(); var account = Accounting(); using var store = new StagedMetadataStore(native, account);
        var old = Plan(); StagedStageIdentity identity;
        using (var first = store.TryClaim(old, "old.new", "current", new byte[192], MetadataPhysicalClass.HotOther)!)
        { Assert.Equal(MetadataStoreDisposition.Committed, store.Execute(first).Disposition); identity = native.Query(first.Output!).Identity; }
        var next = Plan(predecessor: identity); int calls = native.Mutations.Count;
        native.HeldHandleShare = 3;
        Assert.Throws<ArgumentException>(() => store.TryClaim(next, "next.new", "current", new byte[192], MetadataPhysicalClass.HotOther));
        Assert.Equal(calls, native.Mutations.Count); Assert.Equal(old.PeakAllocation, account.Totals.HotOther);
        native.HeldHandleShare = 7;
        using var tx = store.TryClaim(next, "next.new", "current", new byte[192], MetadataPhysicalClass.HotOther)!;
        native.HeldHandleShare = 3; // A changed adapter contract also refuses before opening/creating anything.
        Assert.Equal(MetadataStoreDisposition.Held, store.Execute(tx).Disposition);
        Assert.Equal(calls, native.Mutations.Count); Assert.False(tx.MutationSucceeded); Assert.Null(tx.Predecessor);
    }

    [Fact]
    public void Production_initial_and_append_extent_sequences_preallocate_before_chunked_writes()
    {
        var native = new MetadataMemoryNative(4096); var account = Accounting(); using var store = new StagedMetadataStore(native, account);
        var plan = Plan(8192, MetadataRoleV32.Segment, 4096);
        using var tx = store.TryClaim(plan, "segment", "segment", new byte[8192], MetadataPhysicalClass.Shared)!;
        Assert.Equal(MetadataStoreDisposition.Committed, store.Execute(tx).Disposition);
        Assert.Equal(new[] { ("Allocation", 0L, 8192L), ("Write", 0L, 4096L), ("Write", 4096L, 4096L) }, native.ExtentCalls);
        AssertSafeExtentSequence(native.ExtentCalls, 8192);
        Assert.Throws<Xunit.Sdk.TrueException>(() => AssertSafeExtentSequence(native.ExtentCalls.Where(c => c.Operation != "Allocation"), 8192));
        native.ExtentCalls.Clear();
        var extension = BoundedOutputPlan.Create(MetadataRoleV32.Segment, plan.Object, 12288, 4096, 4096);
        Assert.Equal(MetadataStoreDisposition.Committed, store.Append(tx, extension, 8192, new byte[4096], 1, new byte[4096]).Disposition);
        Assert.Equal(new[] { ("Allocation", 0L, 12288L), ("Write", 8192L, 4096L), ("Write", 4096L, 4096L) }, native.ExtentCalls);
        AssertSafeExtentSequence(native.ExtentCalls, 12288);
        Assert.Throws<Xunit.Sdk.TrueException>(() => AssertSafeExtentSequence(native.ExtentCalls.Where(c => c.Operation != "Allocation"), 12288));
        // A single full-extent write is a measured alternative. Successive
        // unpreallocated extension is the conservation-negative control.
        AssertSafeExtentSequence([("Write", 0, 8192)], 8192);
        Assert.Throws<Xunit.Sdk.TrueException>(() => AssertSafeExtentSequence([("Write", 0, 4096), ("Write", 4096, 4096)], 8192));
    }
    private static void AssertSafeExtentSequence(IEnumerable<(string Operation, long Offset, long Length)> calls, long padded)
    {
        bool allocated = false;
        foreach (var call in calls)
        {
            if (call.Operation == "Allocation") allocated = call.Length >= padded;
            else if (call.Operation == "Write")
                Assert.True(allocated || call.Offset == 0 && call.Length == padded, "Chunked extension requires preallocation of P before the first write.");
        }
    }

    [Fact]
    public void Success_has_ordered_F1_EOF_F2_replace_F3_and_pre_normalization_observations()
    {
        var native = new MetadataMemoryNative(); var account = Accounting(); using var store = new StagedMetadataStore(native, account);
        var plan = Plan(); byte[] bytes = Enumerable.Range(0, 192).Select(i => (byte)i).ToArray();
        using var tx = store.TryClaim(plan, "a.new", "a", bytes, MetadataPhysicalClass.HotOther)!;
        bytes[0] = 255; // The admitted immutable copy owns its bytes through completion.
        var result = store.Execute(tx);
        Assert.Equal(MetadataStoreDisposition.Committed, result.Disposition);
        Assert.Equal(new[] { "Create", "Allocation", "Write", "Flush1", "EndOfFile", "Flush2", "Rename", "Flush3" }, native.Mutations);
        Assert.Contains(result.Receipts, r => r.Step == MetadataStoreStep.F1 && r.Observation is { EndOfFile: 65536, AllocationSize: 65536 });
        Assert.Contains(result.Receipts, r => r.Step == MetadataStoreStep.F2 && r.Observation is { EndOfFile: 192, AllocationSize: 65536 });
        Assert.Equal(65536, account.Charge(plan.Object));
    }

    [Fact]
    public void Known_rename_success_lost_bookkeeping_and_repeat_interrupted_recovery_never_rename_twice()
    {
        var native = new MetadataMemoryNative(); var account = Accounting(); using var store = new StagedMetadataStore(native, account);
        var plan = Plan(); using var tx = store.TryClaim(plan, "a.new", "a", new byte[192], MetadataPhysicalClass.HotOther)!;
        Assert.Equal(MetadataStoreDisposition.Held, store.Execute(tx, step => { if (step == MetadataStoreStep.Replace) throw new IOException("lost return"); }).Disposition);
        var independent = native.Named("a");
        Assert.Equal(native.Query(tx.Output!).Identity, independent.Identity);
        Assert.Equal(MetadataStoreDisposition.Held, store.RecoverBookkeeping(tx, _ => throw new IOException("interrupted again")).Disposition);
        Assert.Equal(MetadataStoreDisposition.RecoverableBookkeeping, store.RecoverBookkeeping(tx).Disposition);
        Assert.Equal(1, native.Renames);
        Assert.Equal(65536, account.Charge(plan.Object));
    }

    [Fact]
    public void Claims_exclude_registered_writers_and_replacement_holds_old_target_and_charge_until_drain()
    {
        var native = new MetadataMemoryNative(); var account = Accounting(); using var store = new StagedMetadataStore(native, account);
        var old = Plan();
        StagedStageIdentity oldId;
        using (var first = store.TryClaim(old, "a.old", "a", new byte[192], MetadataPhysicalClass.HotOther)!)
        { Assert.Equal(MetadataStoreDisposition.Committed, store.Execute(first).Disposition); oldId = native.Query(first.Output!).Identity; }
        var next = Plan(predecessor: oldId); using var tx = store.TryClaim(next, "a.new", "a", new byte[192], MetadataPhysicalClass.HotOther)!;
        Assert.Null(store.TryClaim(Plan(), "competing", "a", new byte[192], MetadataPhysicalClass.HotOther));
        Assert.Equal(MetadataStoreDisposition.Committed, store.Execute(tx).Disposition);
        Assert.NotNull(tx.Predecessor); Assert.False(tx.Predecessor!.IsClosed);
        Assert.Equal(0u, native.Query(tx.Predecessor).Links);
        Assert.True(native.Query(tx.Predecessor).DeletePending);
        Assert.Equal(MetadataObjectLinkState.UnlinkedHeld, account.LinkState(oldId));
        Assert.Equal(new byte[192], ReadFakeHeld(native, tx.Predecessor, 192));
        var release = new MetadataStorageTransition(old.Object, oldId, 1, 0, true, true, false, true);
        Assert.Throws<IOException>(() => account.Apply(release));
        Assert.Equal(131072, account.Totals.HotOther);
        Assert.Equal(MetadataStoreDisposition.Committed, store.Delete(tx).Disposition);
        Assert.Equal(131072, account.Totals.HotOther); // No refund from delete-pending or wrapper success.
        Assert.Throws<InvalidOperationException>(() => store.Delete(tx));
        tx.Dispose();
        Assert.Equal(MetadataObjectLinkState.UnlinkedDrained, account.LinkState(oldId));
        Assert.Equal(131072, account.Totals.HotOther);
        account.Apply(release);
        Assert.Equal(65536, account.Totals.HotOther);
    }
    private static byte[] ReadFakeHeld(MetadataMemoryNative native, SafeFileHandle held, int length)
    { byte[] bytes = new byte[length]; native.Read(held, 0, bytes).Require(); return bytes; }

    [Fact]
    public void Native_rename_refusal_does_not_imply_unlink_or_lost_success()
    {
        var native = new MetadataMemoryNative(); var account = Accounting(); using var store = new StagedMetadataStore(native, account);
        var old = Plan(); StagedStageIdentity oldId;
        using (var first = store.TryClaim(old, "old.new", "current", new byte[192], MetadataPhysicalClass.HotOther)!)
        { Assert.Equal(MetadataStoreDisposition.Committed, store.Execute(first).Disposition); oldId = native.Query(first.Output!).Identity; }
        native.Fail = "Rename"; var next = Plan(predecessor: oldId);
        using var tx = store.TryClaim(next, "next.new", "current", new byte[192], MetadataPhysicalClass.HotOther)!;
        var result = store.Execute(tx);
        Assert.Equal(MetadataStoreDisposition.Held, result.Disposition); Assert.False(tx.MutationSucceeded);
        Assert.Contains(result.Receipts, r => r.Step == MetadataStoreStep.Replace && r.Native.Status == MetadataMemoryNative.Failure);
        Assert.Contains(result.Receipts, r => r.Step == MetadataStoreStep.Predecessor && r.Observation is { Links: 1, DeletePending: false });
        Assert.Equal(oldId, native.Named("current").Identity);
        Assert.Equal(MetadataObjectLinkState.Linked, account.LinkState(oldId));
        Assert.Equal(MetadataStoreDisposition.Held, store.RecoverBookkeeping(tx).Disposition);
        Assert.Equal(1, native.Renames); Assert.Equal(131072, account.Totals.HotOther);
    }

    [Fact]
    public void Raw_append_recovery_keeps_disjoint_frame_and_slot_and_never_repeats_append()
    {
        var native = new MetadataMemoryNative(4096, 512); var account = Accounting(); using var store = new StagedMetadataStore(native, account);
        var initial = Plan(8192, MetadataRoleV32.Segment, 4096, 512);
        using var tx = store.TryClaim(initial, "segment", "segment", new byte[8192], MetadataPhysicalClass.Shared)!;
        Assert.Equal(MetadataStoreDisposition.Committed, store.Execute(tx).Disposition);
        var extended = BoundedOutputPlan.Create(MetadataRoleV32.Segment, initial.Object, 12288, 4096, 512);
        byte[] frame = Enumerable.Repeat((byte)7, 4096).ToArray(), slot = Enumerable.Repeat((byte)9, 4096).ToArray();
        Assert.Equal(MetadataStoreDisposition.Held, store.Append(tx, extended, 8192, frame, 1, slot,
            step => { if (step == MetadataStoreStep.Append) throw new IOException("lost append completion"); }).Disposition);
        Assert.Equal(12288, account.Totals.Shared);
        Assert.Equal(MetadataStoreDisposition.Held, store.RecoverBookkeeping(tx, step =>
            { if (step == MetadataStoreStep.Slot) throw new IOException("lost slot bookkeeping"); }).Disposition);
        Assert.Equal(MetadataStoreDisposition.RecoverableBookkeeping, store.RecoverBookkeeping(tx).Disposition);
        Assert.Equal(2, native.Mutations.Count(name => name == "EndOfFile")); // Initial and append, never repeated recovery.
        Assert.Equal(1, native.Writes.Count(w => w.Offset == 8192));
        Assert.Equal(1, native.Writes.Count(w => w.Offset == 4096 && w.First == 9));
        Assert.Equal(new byte[4096], native.Bytes("segment")[..4096]);
        Assert.Equal(slot, native.Bytes("segment")[4096..8192]);
        Assert.Equal(frame, native.Bytes("segment")[8192..12288]);
    }

    [Fact]
    public void Eight_growth_claims_cannot_consume_the_eight_reserved_other_transaction_slots()
    {
        var native = new MetadataMemoryNative(); var account = Accounting(); using var store = new StagedMetadataStore(native, account);
        var claims = new List<StagedMetadataStore.Transaction>();
        try
        {
            for (int i = 0; i < 8; i++) claims.Add(store.TryClaim(Plan(), "growth" + i, "g" + i, new byte[192], MetadataPhysicalClass.HotOther, true)!);
            Assert.Null(store.TryClaim(Plan(), "overflow", "overflow", new byte[192], MetadataPhysicalClass.HotOther, true));
            for (int i = 0; i < 8; i++) claims.Add(store.TryClaim(Plan(), "other" + i, "o" + i, new byte[192], MetadataPhysicalClass.HotJournal)!);
            Assert.Equal(16, claims.Count); Assert.All(claims, Assert.NotNull);
            Assert.Null(store.TryClaim(Plan(), "overflow", "overflow", new byte[192], MetadataPhysicalClass.HotOther));
        }
        finally { foreach (var claim in claims) claim.Dispose(); }
    }

    [Fact]
    public async Task Reentry_is_locally_busy_and_close_joins_the_exact_native_operation()
    {
        using var entered = new ManualResetEventSlim(); using var release = new ManualResetEventSlim();
        var native = new MetadataMemoryNative { BeforeCreate = () => { entered.Set(); Assert.True(release.Wait(TimeSpan.FromSeconds(10))); } };
        var account = Accounting(); using var store = new StagedMetadataStore(native, account);
        var plan = Plan(); var tx = store.TryClaim(plan, "a.new", "a", new byte[192], MetadataPhysicalClass.HotOther)!;
        var execution = Task.Run(() => store.Execute(tx));
        Task? closing = null;
        try
        {
            Assert.True(entered.Wait(TimeSpan.FromSeconds(10)));
            Assert.Equal(65536, account.Charge(plan.Object));
            Assert.Throws<IOException>(() => store.Execute(tx));
            closing = Task.Run(tx.Dispose);
            Assert.False(execution.IsCompleted);
            release.Set(); Assert.Equal(MetadataStoreDisposition.Committed, (await execution).Disposition);
            await closing.WaitAsync(TimeSpan.FromSeconds(10));
            Assert.True(tx.Output!.IsClosed);
            Assert.Throws<InvalidOperationException>(() => store.Execute(tx));
        }
        finally { release.Set(); await execution; if (closing is not null) await closing; tx.Dispose(); }
    }

    [Fact]
    public void Preallocation_overrun_is_measured_and_charged_before_any_data_write()
    {
        var native = new MetadataMemoryNative(4096, 4096) { OverallocateOnAllocation = true };
        var account = Accounting(); using var store = new StagedMetadataStore(native, account);
        var plan = Plan(8192, MetadataRoleV32.Segment, 4096, 4096);
        using var tx = store.TryClaim(plan, "segment", "segment", new byte[8192], MetadataPhysicalClass.Shared)!;
        var result = store.Execute(tx);
        Assert.Equal(MetadataStoreDisposition.Held, result.Disposition);
        Assert.Empty(native.Writes); Assert.Equal(12288, account.Charge(plan.Object)); Assert.Equal(12288, account.Totals.Shared);
        Assert.Contains(result.Receipts, r => r.Step == MetadataStoreStep.Allocation && r.Observation is { AllocationSize: 12288 } && r.RetainedCharge == 12288);
        Assert.Equal(MetadataStoreDisposition.Held, store.RecoverBookkeeping(tx).Disposition);
    }

    [Fact]
    public void Native_overallocation_faults_future_admission_without_erasing_the_receipt()
    {
        var native = new MetadataMemoryNative { Overallocate = true }; var account = Accounting(); using var store = new StagedMetadataStore(native, account);
        var plan = Plan(); using var tx = store.TryClaim(plan, "a.new", "a", new byte[192], MetadataPhysicalClass.HotOther)!;
        var result = store.Execute(tx);
        Assert.Equal(MetadataStoreDisposition.Held, result.Disposition);
        Assert.Contains(result.Receipts, r => r.Observation is { AllocationSize: 69632 });
        Assert.Throws<IOException>(() => account.TryReserve(Plan(), MetadataPhysicalClass.HotOther));
        Assert.Equal(69632, account.Charge(plan.Object));
        Assert.Equal(69632, account.Totals.HotOther);
        Assert.Contains(result.Receipts, r => r.RetainedCharge == 69632);
        Assert.Equal(MetadataStoreDisposition.Held, store.RecoverBookkeeping(tx).Disposition);
    }
}

internal sealed class MetadataMemoryNative(long alignment = 65536, long unit = 4096) : IStagedMetadataNative
{
    internal const int Failure = unchecked((int)0xC0000022);
    private sealed class FileState(ulong id)
    { internal readonly StagedStageIdentity Identity = new(1, 0, id); internal byte[] Data = []; internal long Eof, Allocation; internal bool Deleted, Unlinked; }
    private readonly Dictionary<string, FileState> _names = new();
    private readonly Dictionary<SafeFileHandle, FileState> _handles = new();
    private ulong _id;
    private int _flush;
    internal string? Fail;
    internal bool Overallocate, OverallocateOnAllocation;
    internal Action? BeforeCreate;
    internal int Renames;
    internal List<string> Mutations { get; } = new();
    internal List<(string Operation, long Offset, long Length)> ExtentCalls { get; } = new();
    internal List<(long Offset, byte First)> Writes { get; } = new();
    public uint HeldHandleShare { get; set; } = 7;
    public long Alignment => alignment;
    public long AllocationUnit => unit;
    public StagedStageIdentity ParentIdentity => new(1, 0, 1);
    public void ValidateParent() { }
    private MetadataNativeResult Result(string operation, ulong info = 0)
    { Mutations.Add(operation); return new(Fail == operation ? Failure : 0, info); }
    public SafeFileHandle Create(string leaf, MetadataRoleV32 role, out MetadataNativeResult result)
    {
        BeforeCreate?.Invoke();
        result = Result("Create", 2); var handle = new SafeFileHandle((IntPtr)checked((int)++_id + 100), false);
        if (result.Success) { var file = new FileState(_id + 100); _names.Add(leaf, file); _handles.Add(handle, file); }
        return handle;
    }
    public SafeFileHandle Open(string leaf, MetadataRoleV32 role, StagedStageIdentity expected)
    {
        var file = _names[leaf]; if (file.Identity != expected) throw new IOException("Wrong identity.");
        var handle = new SafeFileHandle((IntPtr)checked((int)++_id + 100), false); _handles.Add(handle, file); return handle;
    }
    public MetadataNativeObservation Query(SafeFileHandle handle)
    { var file = _handles[handle]; return new(file.Identity, file.Eof, file.Allocation, file.Unlinked ? 0u : 1u, file.Deleted); }
    internal MetadataNativeObservation Named(string leaf) { var file = _names[leaf]; return new(file.Identity, file.Eof, file.Allocation, file.Unlinked ? 0u : 1u, file.Deleted); }
    internal byte[] Bytes(string leaf) => _names[leaf].Data[..(int)_names[leaf].Eof];
    public MetadataNativeResult Write(SafeFileHandle handle, long offset, ReadOnlySpan<byte> bytes)
    {
        ExtentCalls.Add(("Write", offset, bytes.Length));
        var result = Result("Write", (ulong)bytes.Length); if (!result.Success) return result;
        var file = _handles[handle]; long end = checked(offset + bytes.Length);
        if (end > file.Data.Length) Array.Resize(ref file.Data, (int)end);
        bytes.CopyTo(file.Data.AsSpan((int)offset)); file.Eof = Math.Max(file.Eof, end);
        file.Allocation = Math.Max(file.Allocation, BoundedOutputPlan.Round(end, unit) + (Overallocate ? unit : 0));
        Writes.Add((offset, bytes[0])); return result;
    }
    public MetadataNativeResult Read(SafeFileHandle handle, long offset, Span<byte> bytes)
    {
        var file = _handles[handle]; int length = (int)Math.Min(bytes.Length, file.Eof - offset);
        file.Data.AsSpan((int)offset, length).CopyTo(bytes); return new(0, (ulong)length);
    }
    public MetadataNativeResult Flush(SafeFileHandle handle) => Result("Flush" + ++_flush);
    public MetadataNativeResult Allocation(SafeFileHandle handle, long length)
    {
        ExtentCalls.Add(("Allocation", 0, length));
        var result = Result("Allocation");
        if (result.Success) _handles[handle].Allocation = BoundedOutputPlan.Round(length, unit) + (OverallocateOnAllocation ? unit : 0);
        return result;
    }
    public MetadataNativeResult EndOfFile(SafeFileHandle handle, long length)
    { var result = Result("EndOfFile"); if (result.Success) _handles[handle].Eof = length; return result; }
    public MetadataNativeResult Rename(SafeFileHandle handle, string leaf, bool replace)
    {
        var result = Result("Rename"); if (!result.Success) return result;
        var file = _handles[handle]; string old = _names.Single(p => ReferenceEquals(p.Value, file)).Key;
        if (_names.TryGetValue(leaf, out var predecessor)) { if (!replace) return new(Failure, 0); predecessor.Unlinked = true; predecessor.Deleted = true; }
        _names.Remove(old); _names[leaf] = file; Renames++; return result;
    }
    public MetadataNativeResult Delete(SafeFileHandle handle) { _handles[handle].Deleted = true; return Result("Delete"); }
    public void Dispose() { foreach (var handle in _handles.Keys) handle.Dispose(); }
}
#endif
