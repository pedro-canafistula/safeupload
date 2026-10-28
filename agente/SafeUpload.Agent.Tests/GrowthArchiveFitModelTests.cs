#if SAFEUPLOAD_ADMISSION_EVIDENCE
namespace SafeUpload.Agent.Tests;

// Pure proposal model, DiagnosticOnly on Linux. No I/O or unfinished production
// dependencies. These are acceptance arithmetic/state vectors, not a native
// durability, serialization, kernel-resource or protected-pair proof.
public sealed class GrowthArchiveFitModelTests
{
    private const long KiB = 1024, MiB = 1024 * KiB;
    private const long MaximumEnvelope = 128 * KiB, MaximumState = 64 * KiB;
    private const long WrapperAllowance = 8 * KiB, MaximumSegment = 4 * MiB;
    private const int FrameHeader = 60, FrontierSlots = 2, FrontierHeader = 128;

    [Theory]
    [InlineData(1, 4096, 4096)]
    [InlineData(192, 4096, 4096)]
    [InlineData(4036, 4096, 4096)]
    [InlineData(4037, 4096, 8192)]
    [InlineData(131072, 4096, 135168)]
    [InlineData(1, 65536, 65536)]
    [InlineData(131072, 65536, 196608)]
    public void Frame_stride_matches_independent_boundary_vectors(long payload, long alignment, long expected) =>
        Assert.Equal(expected, Stride(payload, alignment));

    [Theory]
    [InlineData(4096)]
    [InlineData(8192)]
    [InlineData(16384)]
    [InlineData(32768)]
    [InlineData(65536)]
    public void Frames_never_share_committed_sectors_and_fit_only_complete_strides(long alignment)
    {
        long cursor = FrontierSlots * alignment;
        foreach (long payload in new long[] { 1, 192, 4036, 4037, 65536, 131072 })
        {
            long next = checked(cursor + Stride(payload, alignment));
            Assert.Equal(0, cursor % alignment);
            Assert.Equal(0, next % alignment);
            Assert.True(next >= cursor + FrameHeader + payload);
            Assert.InRange(next - cursor - FrameHeader - payload, 0, alignment - 1);
            Assert.True(next <= MaximumSegment);
            cursor = next;
        }
        long maximumStride = Stride(MaximumEnvelope, alignment);
        long frames = (MaximumSegment - FrontierSlots * alignment) / maximumStride;
        long end = checked(FrontierSlots * alignment + frames * maximumStride);
        Assert.True(end <= MaximumSegment);
        Assert.True(end + maximumStride > MaximumSegment);
    }

    [Fact]
    public void Maximum_alignment_has_two_64KiB_frontiers_and_192KiB_maximum_frame()
    {
        Assert.Equal(131072, FrontierSlots * 65536);
        Assert.Equal(196608, Stride(MaximumEnvelope, 65536));
        Assert.Equal(327680, FrontierSlots * 65536 + Stride(MaximumEnvelope, 65536));
        Assert.Equal(128, FrontierHeader);
    }

    [Theory]
    [InlineData(0)]
    [InlineData(512)]
    [InlineData(6144)]
    [InlineData(131072)]
    public void Unsupported_archive_alignment_is_rejected_not_rounded_into_support(long alignment) =>
        Assert.Throws<ArgumentOutOfRangeException>(() => Stride(192, alignment));

    [Theory]
    [InlineData(0)]
    [InlineData(-1)]
    [InlineData(131073)]
    public void Invalid_payload_is_not_admitted(long payload) =>
        Assert.Throws<ArgumentOutOfRangeException>(() => Stride(payload, 4096));

    [Theory]
    [InlineData(64, 512, 512)]
    [InlineData(128, 4096, 4096)]
    [InlineData(192, 4096, 4096)]
    [InlineData(1192, 4096, 4096)]
    [InlineData(65536, 65536, 65536)]
    [InlineData(131072, 1048576, 1048576)]
    public void Output_allocation_rounds_complete_logical_extent(long logical, long unit, long expected) =>
        Assert.Equal(expected, Round(logical, unit));

    [Fact]
    public void Rounding_and_overlap_arithmetic_never_wrap()
    {
        Assert.Throws<OverflowException>(() => Round(long.MaxValue, 65536));
        Assert.Throws<OverflowException>(() => SharedCharge(long.MaxValue));
        Assert.Throws<ArgumentOutOfRangeException>(() => Round(-1, 4096));
        Assert.Throws<ArgumentOutOfRangeException>(() => Round(128, 6000));
    }

    [Theory]
    [InlineData(512)]
    [InlineData(4096)]
    [InlineData(65536)]
    [InlineData(1048576)]
    public void Full_transfer_metadata_overlap_fits_each_reserved_half(long allocationUnit)
    {
        long envelope = Math.Max(MiB, checked(16 * allocationUnit));
        // Existing journal current/new plus immutable handoff candidate.
        long journal = checked(3 * Round(MaximumEnvelope, allocationUnit));
        // Ledger current/new and companion current/new, all coexist for charge.
        long other = checked(2 * Round(MaximumState, allocationUnit) + 2 * Round(192, allocationUnit));
        Assert.True(journal <= envelope / 2);
        Assert.True(other <= envelope / 2);
        Assert.True(journal + other <= envelope);
        long unexpectedResidue = checked(envelope + allocationUnit);
        Assert.False(journal + other + unexpectedResidue <= envelope);
    }

    [Fact]
    public void Complete_envelope_uses_combined_budget_not_two_independent_maxima()
    {
        Assert.Equal(131072, 56 * KiB + MaximumState + WrapperAllowance);
        Assert.True(EnvelopeFits(56 * KiB, MaximumState, WrapperAllowance));
        Assert.False(EnvelopeFits(56 * KiB + 1, MaximumState, WrapperAllowance));
        Assert.Equal(204800, MaximumEnvelope + MaximumState + WrapperAllowance);
        Assert.False(EnvelopeFits(MaximumEnvelope, MaximumState, WrapperAllowance));
        Assert.True(EnvelopeFits(MaximumEnvelope - WrapperAllowance, 0, WrapperAllowance));
        Assert.False(EnvelopeFits(1, MaximumState + 1, 0));
        Assert.False(EnvelopeFits(1, 0, WrapperAllowance + 1));
    }

    [Fact]
    public void Full_entry_and_closure_refusal_keeps_ledger_instead_of_truncating_a_witness()
    {
        bool immutable = true, initialResolved = true;
        bool allowed = immutable && initialResolved && EnvelopeFits(MaximumEnvelope, MaximumState, WrapperAllowance);
        Assert.False(allowed);
        bool ledgerRetained = !allowed;
        Assert.True(ledgerRetained);
        // Deliberately wrong admission checks each component alone.
        bool mutant = MaximumEnvelope <= 128 * KiB && MaximumState <= 64 * KiB;
        Assert.NotEqual(allowed, mutant);
    }

    [Theory]
    [InlineData(4096)]
    [InlineData(65536)]
    public void Global_shared_controls_and_compaction_overlap_are_precharged(long unit)
    {
        // Each current/new pair: append intent, compaction intent, inventory,
        // marker; one candidate remains until exact append/frontier completion.
        long controls = checked(4 * Round(MaximumState, unit) + 4 * Round(128, unit) + Round(MaximumEnvelope, unit));
        long oldSegments = 32 * MaximumSegment, targets = 32 * MaximumSegment;
        long allPhysical = checked(oldSegments + targets + controls);
        Assert.Equal(checked(allPhysical * 2 + 16 * MiB), SharedCharge(allPhysical));
        Assert.True(SharedCharge(allPhysical) > SharedCharge(oldSegments + controls));
        // Selection alone is not final storage release.
        Assert.Equal(allPhysical, RetainedPhysical(oldSegments, targets + controls, true, false));
        Assert.Equal(allPhysical, RetainedPhysical(oldSegments, targets + controls, false, true));
        Assert.Equal(targets + controls, RetainedPhysical(oldSegments, targets + controls, true, true));
    }

    [Theory]
    [InlineData(1, 8, 3, 2, 4, 10)]
    [InlineData(1, 3, 3, 2, 4, 5)]
    [InlineData(9, 40, 32, 32, 41, 72)]
    public void Prefix_compaction_selects_consecutive_suffix_plus_new_targets(
        int first, int end, int sources, int targets, int expectedFirst, int expectedEnd)
    {
        var selected = Select(first, end, sources, targets);
        Assert.Equal((expectedFirst, expectedEnd), selected);
        int[] physical = Enumerable.Range(first + sources, end - first - sources + 1)
            .Concat(Enumerable.Range(end + 1, targets)).ToArray();
        Assert.Equal(Enumerable.Range(selected.First, selected.End - selected.First + 1), physical);
        Assert.DoesNotContain(first, physical);
    }

    [Theory]
    [InlineData(0, 1)]
    [InlineData(33, 1)]
    [InlineData(1, 0)]
    [InlineData(1, 33)]
    [InlineData(9, 1)]
    public void Compaction_rejects_unbounded_or_unselected_source_prefix(int sources, int targets) =>
        Assert.Throws<ArgumentOutOfRangeException>(() => Select(1, 8, sources, targets));

    [Fact]
    public void Migration_never_relabels_contiguous_legacy_frames_as_modern()
    {
        const long payload = 4037;
        Assert.Equal(4097, FrameHeader + payload);
        Assert.Equal(8192, Stride(payload, 4096));
        Assert.False(IsModernSegment(1, 1, 4096));
        Assert.False(IsModernSegment(3, 1, 4096));
        Assert.True(IsModernSegment(3, 3, 4096));
        Assert.False(IsModernSegment(3, 3, 512));
    }

    [Theory]
    [InlineData(59, 2, 128, 131072)]
    [InlineData(60, 1, 128, 131072)]
    [InlineData(60, 2, 48, 131072)]
    [InlineData(60, 2, 128, 204800)]
    public void Deliberately_wrong_format_parameters_fail_the_contract(
        int frameHeader, int slots, int frontierHeader, int envelope)
    {
        Assert.False(ApprovedParameters(frameHeader, slots, frontierHeader, envelope));
        Assert.True(ApprovedParameters(FrameHeader, FrontierSlots, FrontierHeader, (int)MaximumEnvelope));
    }

    [Fact]
    public void Mutation_ignoring_padding_or_one_frontier_undercharges_physical_storage()
    {
        long correct = 2 * 65536 + Stride(MaximumEnvelope, 65536);
        long noPadding = 2 * 65536 + FrameHeader + MaximumEnvelope;
        long oneFrontier = 65536 + Stride(MaximumEnvelope, 65536);
        Assert.True(noPadding < correct);
        Assert.True(oneFrontier < correct);
        Assert.NotEqual(correct, noPadding);
        Assert.NotEqual(correct, oneFrontier);
    }

    [Theory]
    [InlineData(1)]
    [InlineData(2)]
    [InlineData(3)]
    [InlineData(4)]
    [InlineData(5)]
    [InlineData(6)]
    [InlineData(7)]
    public void Every_closure_base_has_an_explicit_initial_resolution_state(int state)
    {
        var initial = (InitialState)state;
        Assert.Equal(state == 7, ClosureEligible(true, true, initial));
        Assert.Equal(state is 5 or 6, ClosureEligible(true, false, initial));
        Assert.Equal(state is 5 or 6, ClosureEligible(false, false, initial));
        Assert.False(ClosureEligible(false, true, initial));
    }

    [Fact]
    public void Delayed_query_immediate_close_cannot_delete_the_only_success_resolution_ledger()
    {
        InitialState state = InitialState.Attached;
        bool metadataOnly = true;
        Assert.False(metadataOnly && ClosureEligible(true, true, state));
        // Restart before the query sees exactly the unresolved Attached state.
        Assert.False(ClosureEligible(true, true, state));
        state = InitialState.InitialResolved;
        Assert.True(metadataOnly && ClosureEligible(true, true, state));
    }

    [Fact]
    public void Durable_success_releases_debt_once_but_not_kernel_shell_capacity()
    {
        var model = new InitialModel();
        for (int id = 1; id <= 8; id++)
        {
            Assert.True(model.TryCapture(id, id));
            model.ResolveSuccess(id, true);
            model.ResolveSuccess(id, true);
        }
        Assert.Equal(0, model.Debt);
        Assert.Equal(8, model.Occupied);
        Assert.False(model.TryCapture(9, 9));
        var restarted = model.Reconnect();
        Assert.Equal(0, restarted.Debt);
        Assert.Equal(8, restarted.Occupied);
        Assert.False(restarted.TryCapture(9, 9));
        Assert.True(restarted.AckEvicted(1, true));
        Assert.False(restarted.AckEvicted(1, true));
        Assert.True(restarted.TryCapture(9, 9));
        Assert.Equal(8, restarted.Occupied);
        Assert.Equal(1, restarted.Debt);
    }

    [Fact]
    public void Sid_debt_bound_is_independent_of_the_global_eight_shell_limit()
    {
        var model = new InitialModel();
        for (int id = 1; id <= 4; id++) Assert.True(model.TryCapture(id, 10));
        Assert.False(model.TryCapture(5, 10));
        Assert.True(model.TryCapture(5, 20));
        model.ResolveSuccess(1, true);
        Assert.True(model.TryCapture(6, 10));
        Assert.Equal(6, model.Occupied);
        Assert.Equal(5, model.Debt);
    }

    [Fact]
    public void Neither_unauthenticated_receipt_nor_ack_enqueue_evicts_a_shell()
    {
        var model = new InitialModel();
        Assert.True(model.TryCapture(1, 1));
        Assert.Throws<InvalidOperationException>(() => model.ResolveSuccess(1, false));
        Assert.Throws<InvalidOperationException>(() => model.AckEvicted(1, false));
        Assert.Equal(1, model.Debt);
        Assert.Equal(1, model.Occupied);
        model.ResolveSuccess(1, true);
        Assert.Equal(0, model.Debt);
        Assert.Equal(1, model.Reconnect().Occupied); // ACK queued/lost, no native eviction.
        Assert.NotEqual(model.Debt, model.Occupied); // Mutant debt-as-capacity fails.
    }

    [Fact]
    public void Ack_queue_is_unique_bounded_and_does_not_return_occupied_credit()
    {
        var model = new InitialModel();
        var queued = new HashSet<int>();
        for (int id = 1; id <= 8; id++)
        {
            Assert.True(model.TryCapture(id, id));
            model.ResolveSuccess(id, true);
            Assert.True(queued.Add(id));
            Assert.False(queued.Add(id));
        }
        Assert.Equal(8, queued.Count);
        Assert.Equal(8, model.Occupied);
        Assert.Equal(2, Math.Min(2, queued.Count)); // Native send class, not eight parallel sends.
        Assert.False(model.TryCapture(9, 9));
    }

    [Fact]
    public void Authenticated_but_premature_ack_is_not_eviction_authority()
    {
        var model = new InitialModel();
        Assert.True(model.TryCapture(1, 1));
        Assert.Throws<InvalidOperationException>(() => model.AckEvicted(1, true));
        Assert.Equal(1, model.Occupied);
        Assert.Equal(1, model.Debt);
    }

    private static long Round(long value, long unit)
    {
        if (value < 0 || unit < 512 || (unit & (unit - 1)) != 0)
            throw new ArgumentOutOfRangeException(nameof(value));
        return checked(checked(value + unit - 1) / unit * unit);
    }

    private static long Stride(long payload, long alignment)
    {
        if (payload is < 1 or > MaximumEnvelope || !ValidAlignment(alignment))
            throw new ArgumentOutOfRangeException(nameof(payload));
        return Round(checked(FrameHeader + payload), alignment);
    }

    private static bool ValidAlignment(long alignment) =>
        alignment is >= 4096 and <= 65536 && (alignment & (alignment - 1)) == 0;
    private static bool ApprovedParameters(int header, int slots, int frontier, int envelope) =>
        header == FrameHeader && slots == FrontierSlots && frontier == FrontierHeader && envelope == MaximumEnvelope;
    private static bool IsModernSegment(int frameVersion, int frontierVersion, long alignment) =>
        frameVersion == 3 && frontierVersion == 3 && ValidAlignment(alignment);
    private static bool EnvelopeFits(long entry, long closure, long wrapper) =>
        entry is >= 0 and <= MaximumEnvelope && closure is >= 0 and <= MaximumState &&
        wrapper is >= 0 and <= WrapperAllowance && checked(entry + closure + wrapper) <= MaximumEnvelope;
    private static long SharedCharge(long physical) => checked(physical * 2 + 16 * MiB);
    private static long RetainedPhysical(long oldBytes, long newBytes, bool selectionDurable, bool releaseProved) =>
        checked(newBytes + (selectionDurable && releaseProved ? 0 : oldBytes));
    private static (int First, int End) Select(int first, int end, int sources, int targets)
    {
        if (first < 1 || end < first || sources is < 1 or > 32 || targets is < 1 or > 32 || sources > end - first + 1)
            throw new ArgumentOutOfRangeException(nameof(sources));
        return (checked(first + sources), checked(end + targets));
    }

    private enum InitialState { Open = 1, Closing, Fenced, Attached, CleanupComplete, ResolutionAcknowledged, InitialResolved }
    private static bool ClosureEligible(bool hasEntry, bool successful, InitialState state) =>
        successful ? hasEntry && state == InitialState.InitialResolved :
        state is InitialState.CleanupComplete or InitialState.ResolutionAcknowledged;

    private sealed class InitialModel
    {
        private readonly Dictionary<int, (int Sid, InitialState State)> _durable = new();
        private readonly HashSet<int> _kernelShells = new();
        public int Debt => _durable.Values.Count(v => Unresolved(v.State));
        public int Occupied => _kernelShells.Count;
        private static bool Unresolved(InitialState state) =>
            state is not (InitialState.InitialResolved or InitialState.ResolutionAcknowledged);
        public bool TryCapture(int id, int sid)
        {
            if (_durable.ContainsKey(id) || Occupied >= 8 || Debt >= 8 ||
                _durable.Values.Count(v => v.Sid == sid && Unresolved(v.State)) >= 4) return false;
            _kernelShells.Add(id); // Reserve before modeled CREATE capture/admission.
            _durable.Add(id, (sid, InitialState.Open));
            return true;
        }
        public void ResolveSuccess(int id, bool authenticated)
        {
            if (!authenticated || !_kernelShells.Contains(id)) throw new InvalidOperationException("No authenticated kernel receipt");
            var original = _durable[id];
            _durable[id] = (original.Sid, InitialState.InitialResolved);
        }
        public bool AckEvicted(int id, bool authenticated)
        {
            if (!authenticated || (_kernelShells.Contains(id) &&
                _durable[id].State is not (InitialState.InitialResolved or InitialState.CleanupComplete or InitialState.ResolutionAcknowledged)))
                throw new InvalidOperationException("No authenticated terminal ACK eviction");
            return _kernelShells.Remove(id);
        }
        public InitialModel Reconnect()
        {
            var restored = new InitialModel();
            foreach (var item in _durable) restored._durable.Add(item.Key, item.Value);
            foreach (int occupied in _kernelShells) restored._kernelShells.Add(occupied);
            return restored;
        }
    }
}
#endif
