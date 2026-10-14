using SafeUpload.Agent.Service.Interception;
#if SAFEUPLOAD_ADMISSION_EVIDENCE
using SafeUpload.Agent.Minifilter;
#endif

namespace SafeUpload.Agent.Tests;

public sealed class StagedBoundReadinessTests
{
#if SAFEUPLOAD_ADMISSION_EVIDENCE
    private readonly Guid _driver = Guid.NewGuid();
    private StagedBoundRecoveryReceipt Receipt(bool held = false) => new(_driver, 11, 42, 17, held);
    private static AdmissionCoverageDecision Coverage(uint generation = 7) =>
        new(AdmissionCoverageReadiness.Ready, "CoverageReady", generation);
    private (StagedBoundReadiness State, long Ticket) Prepared(bool held = false)
    {
        var state = new StagedBoundReadiness();
        long ticket = state.BeginConnection();
        state.CompleteRecovery(ticket, Receipt(held));
        state.CompleteNegotiation(ticket, _driver, Contract.StageExtensionVersion,
            (uint)StageV20Capability.Required | StagedBoundReadiness.BoundCapability, true);
        state.ObserveCoverage(Coverage());
        return (state, ticket);
    }

    [Fact]
    public void Composition_requires_every_completed_prerequisite_independently()
    {
        for (int mask = 0; mask < 16; ++mask)
        {
            var decision = StagedBoundReadiness.Compose((mask & 1) != 0, (mask & 2) != 0,
                (mask & 4) != 0, (mask & 8) != 0, StagedBoundBlocker.None, StagedBoundBlocker.None);
            Assert.Equal(mask == 15, decision.IsReady);
        }
        foreach (var blocker in Enum.GetValues<StagedBoundBlocker>().Where(b => b != StagedBoundBlocker.None))
            Assert.False(StagedBoundReadiness.Compose(true, true, true, true, blocker, StagedBoundBlocker.None).IsReady);
    }

    [Fact]
    public void Production_has_named_native_holds_even_after_complete_negotiation_recovery_and_coverage()
    {
        var (state, _) = Prepared();
        Assert.False(state.Snapshot.IsReady);
        Assert.Equal(StagedBoundReadiness.NativeHolds, state.Snapshot.Blockers);
        foreach (string reason in new[] { "native_create_security_unproved", "seed_coherence_unproved",
                     "seed_export_authority_unproved", "version_publication_authority_unproved" })
            Assert.Contains(reason, state.Snapshot.Reason);
        Assert.False(MinifilterInterceptor.BoundAllocationImplemented);
        // There is no setter or configuration input for these production holds.
        Assert.Null(typeof(StagedBoundReadiness).GetProperty("Snapshot",
            System.Reflection.BindingFlags.Instance | System.Reflection.BindingFlags.NonPublic)?.SetMethod);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void V20_alone_or_lost_negotiation_reply_never_advertises_bound_capability(bool delivered)
    {
        var state = new StagedBoundReadiness(); long ticket = state.BeginConnection();
        state.CompleteRecovery(ticket, Receipt());
        state.CompleteNegotiation(ticket, _driver, Contract.StageExtensionVersion,
            (uint)StageV20Capability.Required, delivered);
        Assert.True(state.Snapshot.Blockers.HasFlag(StagedBoundBlocker.NegotiatedPathIncomplete));
        Assert.False(state.Snapshot.IsReady);
    }

    [Theory]
    [InlineData((int)StagedBoundBlocker.Disconnected)]
    [InlineData((int)StagedBoundBlocker.ReplayInvalidated)]
    [InlineData((int)StagedBoundBlocker.PolicyChanged)]
    [InlineData((int)StagedBoundBlocker.ProtocolChanged)]
    [InlineData((int)StagedBoundBlocker.UnresolvedPrerequisite)]
    public void Invalidation_bars_late_negotiation_and_recovery_from_the_old_ticket(int reasonValue)
    {
        var reason = (StagedBoundBlocker)reasonValue;
        var (state, ticket) = Prepared();
        state.Invalidate(reason);
        state.CompleteRecovery(ticket, Receipt());
        state.CompleteNegotiation(ticket, _driver, Contract.StageExtensionVersion,
            (uint)StageV20Capability.Required | StagedBoundReadiness.BoundCapability, true);
        Assert.True(state.Snapshot.Blockers.HasFlag(reason));
        Assert.True(state.Snapshot.Blockers.HasFlag(StagedBoundBlocker.StartupRecoveryIncomplete));
        Assert.True(state.Snapshot.Blockers.HasFlag(StagedBoundBlocker.NegotiatedPathIncomplete));
        long next = state.BeginConnection(); Assert.NotEqual(ticket, next);
        state.CompleteRecovery(ticket, Receipt());
        Assert.True(state.Snapshot.Blockers.HasFlag(StagedBoundBlocker.StartupRecoveryIncomplete));
    }

    [Theory]
    [InlineData("driver")]
    [InlineData("epoch")]
    [InlineData("boot")]
    [InlineData("revision")]
    [InlineData("publication")]
    public void Changed_authenticated_replay_invalidates_the_complete_startup_pass(string change)
    {
        var (state, _) = Prepared();
        state.ObserveReplay("publication", _driver, 11, 42, 20);
        state.ObserveReplay(change == "publication" ? "publication" : "native",
            change == "driver" ? Guid.NewGuid() : _driver, change == "epoch" ? 12ul : 11ul,
            change == "boot" ? 43u : 42u, change is "revision" or "publication" ? 21ul : 17ul);
        Assert.True(state.Snapshot.Blockers.HasFlag(StagedBoundBlocker.ReplayInvalidated));
        Assert.True(state.Snapshot.Blockers.HasFlag(StagedBoundBlocker.StartupRecoveryIncomplete));
    }

    [Fact]
    public void Authority_policy_and_protocol_changes_cannot_reuse_recovery()
    {
        var (state, _) = Prepared();
        state.ObserveAuthority(_driver, 11, 5); state.ObserveAuthority(_driver, 11, 6);
        Assert.True(state.Snapshot.Blockers.HasFlag(StagedBoundBlocker.ProtocolChanged));
        (state, _) = Prepared(); state.ObserveCoverage(Coverage(8));
        Assert.True(state.Snapshot.Blockers.HasFlag(StagedBoundBlocker.PolicyChanged));
        var (other, ticket) = Prepared();
        other.CompleteNegotiation(ticket, _driver, Contract.StageExtensionVersion + 1,
            (uint)StageV20Capability.Required | StagedBoundReadiness.BoundCapability, true);
        Assert.True(other.Snapshot.Blockers.HasFlag(StagedBoundBlocker.ProtocolChanged));
    }

    [Fact]
    public void Replay_change_between_startup_completion_and_receipt_consumption_cannot_restore_readiness()
    {
        var state = new StagedBoundReadiness(); long ticket = state.BeginConnection();
        state.ObserveReplay("native", _driver, 11, 42, 18);
        state.CompleteRecovery(ticket, Receipt()); // completed pass was revision 17
        Assert.True(state.Snapshot.Blockers.HasFlag(StagedBoundBlocker.ReplayInvalidated));
        Assert.True(state.Snapshot.Blockers.HasFlag(StagedBoundBlocker.StartupRecoveryIncomplete));
    }

    [Theory]
    [InlineData("native")]
    [InlineData("publication")]
    public void Replay_change_before_receipt_consumption_invalidates_the_connection_ticket(string map)
    {
        var state = new StagedBoundReadiness(); long ticket = state.BeginConnection();
        state.ObserveReplay(map, _driver, 11, 42, 17);
        state.ObserveReplay(map, _driver, 11, 42, 18);
        state.CompleteRecovery(ticket, Receipt());
        state.CompleteNegotiation(ticket, _driver, Contract.StageExtensionVersion,
            (uint)StageV20Capability.Required | StagedBoundReadiness.BoundCapability, true);
        Assert.True(state.Snapshot.Blockers.HasFlag(StagedBoundBlocker.ReplayInvalidated));
        Assert.True(state.Snapshot.Blockers.HasFlag(StagedBoundBlocker.StartupRecoveryIncomplete));
        Assert.True(state.Snapshot.Blockers.HasFlag(StagedBoundBlocker.NegotiatedPathIncomplete));
    }

    [Fact]
    public void Successful_pass_with_held_names_and_unstable_SOP_coverage_are_separate_refusals()
    {
        var (state, _) = Prepared(held: true);
        Assert.True(state.Snapshot.Blockers.HasFlag(StagedBoundBlocker.UnresolvedPrerequisite));
        state.ObserveCoverage(new(AdmissionCoverageReadiness.Pending, "WriterPromotionPending", 7));
        Assert.True(state.Snapshot.Blockers.HasFlag(StagedBoundBlocker.CoverageNotReady));
    }
#else
    [Fact]
    public void Normal_service_has_no_bound_readiness_or_native_proof_switch()
    {
        Assert.Null(typeof(MinifilterInterceptor).Assembly.GetType(
            "SafeUpload.Agent.Service.Interception.StagedBoundReadiness"));
    }
#endif
}
