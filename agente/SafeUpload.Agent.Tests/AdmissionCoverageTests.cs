using SafeUpload.Agent.Minifilter;

namespace SafeUpload.Agent.Tests;

public sealed class AdmissionCoverageTests
{
    private const uint CompleteStableFutureRegistry =
        AdmissionCoverageContract.CompleteFlag |
        AdmissionCoverageContract.StableFlag |
        AdmissionCoverageContract.FutureGateFlag |
        AdmissionCoverageContract.RegistryCompleteFlag;

    [Fact]
    public void Managed_coverage_wire_layout_matches_the_shared_protocol_contract()
    {
        Contract.Verify();
    }

    [Fact]
    public void Ready_requires_a_stable_current_generation_and_every_accepted_scope()
    {
        AdmissionCoverageDecision result = AdmissionCoverageEvaluator.Evaluate(
            ReadyReceipt(PrefixScope()), [@"\Device\HarddiskVolume3\Users\victor\Cloud"],
            expectedPolicyFlags: 0, boundNativePolicyGeneration: 7);

        Assert.Equal(AdmissionCoverageReadiness.Ready, result.Readiness);
        Assert.Equal("Ready", result.Reason);
        Assert.Equal(7u, result.NativePolicyGeneration);
    }

    [Fact]
    public void An_absent_accepted_prefix_is_degraded_even_when_all_global_gates_are_ready()
    {
        var absent = PrefixScope(state: AdmissionCoverageContract.Degraded,
            resolution: AdmissionCoverageContract.AbsentResolution,
            reason: 4, matching: 0, unique: 0, ready: 0);

        AdmissionCoverageDecision result = AdmissionCoverageEvaluator.Evaluate(
            ReadyReceipt(absent, topReason: 4), [absent.Prefix], expectedPolicyFlags: 0,
            boundNativePolicyGeneration: 7);

        Assert.Equal(AdmissionCoverageReadiness.Degraded, result.Readiness);
        Assert.Equal("DestinationAbsent", result.Reason);
    }

    [Fact]
    public void Accepted_future_removable_scope_can_reach_ready_when_its_mount_gate_is_active()
    {
        AdmissionCoverageScopeReceipt[] scopes =
        [
            PrefixScope(),
            new(AdmissionCoverageContract.RemovableScope, 0,
                AdmissionCoverageContract.NotApplicableResolution,
                AdmissionCoverageContract.Ready, 0, 0, 0, 0, string.Empty)
        ];

        AdmissionCoverageDecision result = AdmissionCoverageEvaluator.Evaluate(
            ReadyReceipt(scopes, policyFlags: 1), [scopes[0].Prefix],
            expectedPolicyFlags: 1, boundNativePolicyGeneration: 7);

        Assert.Equal(AdmissionCoverageReadiness.Ready, result.Readiness);
        Assert.Equal(7u, result.NativePolicyGeneration);
    }

    [Fact]
    public void Unsupported_current_instance_is_degraded_instead_of_dropped_from_scope()
    {
        var unsupported = PrefixScope(state: AdmissionCoverageContract.Degraded,
            reason: 7);

        AdmissionCoverageDecision result = AdmissionCoverageEvaluator.Evaluate(
            ReadyReceipt(unsupported, topReason: 7), [unsupported.Prefix],
            expectedPolicyFlags: 0, boundNativePolicyGeneration: 7);

        Assert.Equal(AdmissionCoverageReadiness.Degraded, result.Readiness);
        Assert.Equal("UnsupportedDestination", result.Reason);
    }

    [Fact]
    public void A_missing_future_mount_gate_cannot_publish_ready_for_an_empty_flag_scope()
    {
        AdmissionCoverageScopeReceipt[] scopes =
        [
            PrefixScope(),
            new(AdmissionCoverageContract.RemovableScope, 0,
                AdmissionCoverageContract.NotApplicableResolution,
                AdmissionCoverageContract.Ready, 0, 0, 0, 0, string.Empty)
        ];
        AdmissionCoverageReceipt receipt = ReadyReceipt(scopes,
            flags: CompleteStableFutureRegistry & ~AdmissionCoverageContract.FutureGateFlag,
            futureMountGateReady: 0, policyFlags: 1);

        AdmissionCoverageDecision result = AdmissionCoverageEvaluator.Evaluate(
            receipt, [scopes[0].Prefix], expectedPolicyFlags: 1,
            boundNativePolicyGeneration: 7);

        Assert.Equal(AdmissionCoverageReadiness.Pending, result.Readiness);
        Assert.Equal("CoverageIncomplete", result.Reason);
    }

    [Fact]
    public void Current_topology_receipt_from_a_different_accepted_generation_is_degraded()
    {
        AdmissionCoverageDecision result = AdmissionCoverageEvaluator.Evaluate(
            ReadyReceipt(PrefixScope(), generation: 8), [PrefixScope().Prefix],
            expectedPolicyFlags: 0, boundNativePolicyGeneration: 7);

        Assert.Equal(AdmissionCoverageReadiness.Degraded, result.Readiness);
        Assert.Equal("NativePolicyGenerationChanged", result.Reason);
        Assert.Equal(8u, result.NativePolicyGeneration);
    }

    [Fact]
    public void A_topology_change_during_the_receipt_is_pending_not_ready()
    {
        AdmissionCoverageReceipt receipt = ReadyReceipt(PrefixScope()) with
        {
            TopologySequenceEnd = 12
        };

        AdmissionCoverageDecision result = AdmissionCoverageEvaluator.Evaluate(
            receipt, [PrefixScope().Prefix], expectedPolicyFlags: 0,
            boundNativePolicyGeneration: 7);

        Assert.Equal(AdmissionCoverageReadiness.Pending, result.Readiness);
        Assert.Equal("PolicyOrTopologyChanging", result.Reason);
    }

    [Fact]
    public void A_registry_change_after_the_writer_census_is_pending_not_ready()
    {
        AdmissionCoverageReceipt receipt = ReadyReceipt(PrefixScope()) with
        {
            RegistrySequenceEnd = 45
        };

        AdmissionCoverageDecision result = AdmissionCoverageEvaluator.Evaluate(
            receipt, [PrefixScope().Prefix], expectedPolicyFlags: 0,
            boundNativePolicyGeneration: 7);

        Assert.Equal(AdmissionCoverageReadiness.Pending, result.Readiness);
        Assert.Equal("PolicyOrTopologyChanging", result.Reason);
    }

    [Fact]
    public void An_instance_or_global_tracking_loss_cannot_publish_ready()
    {
        AdmissionCoverageReceipt instanceLoss = ReadyReceipt(PrefixScope()) with
        {
            CoverageChangesInFlight = 1
        };
        AdmissionCoverageReceipt globalLoss = ReadyReceipt(PrefixScope()) with
        {
            WriterGlobalUnknown = 1
        };

        AdmissionCoverageDecision instanceResult = AdmissionCoverageEvaluator.Evaluate(
            instanceLoss, [PrefixScope().Prefix], expectedPolicyFlags: 0,
            boundNativePolicyGeneration: 7);
        AdmissionCoverageDecision globalResult = AdmissionCoverageEvaluator.Evaluate(
            globalLoss, [PrefixScope().Prefix], expectedPolicyFlags: 0,
            boundNativePolicyGeneration: 7);

        Assert.Equal(AdmissionCoverageReadiness.Pending, instanceResult.Readiness);
        Assert.Equal(AdmissionCoverageReadiness.Degraded, globalResult.Readiness);
        Assert.Equal("WriterStateUnknown", globalResult.Reason);
    }

    [Fact]
    public void Unknown_epoch_flag_bits_are_degraded_instead_of_accepted_as_ready()
    {
        AdmissionCoverageReceipt receipt = ReadyReceipt(PrefixScope()) with
        {
            EpochFlags = 0x8,
            EpochFlagsEnd = 0x8
        };

        AdmissionCoverageDecision result = AdmissionCoverageEvaluator.Evaluate(
            receipt, [PrefixScope().Prefix], expectedPolicyFlags: 0,
            boundNativePolicyGeneration: 7);

        Assert.Equal(AdmissionCoverageReadiness.Degraded, result.Readiness);
        Assert.Equal("UnknownEpochFlags", result.Reason);
    }

    [Fact]
    public void Candidate_scope_union_without_final_ack_remains_pending()
    {
        AdmissionCoverageReceipt receipt = ReadyReceipt(Array.Empty<AdmissionCoverageScopeReceipt>(),
            generation: 0, flags: AdmissionCoverageContract.PolicyPendingFlag,
            futureMountGateReady: 0) with
        {
            State = AdmissionCoverageContract.Pending,
            ExpectedScopeCount = 3,
            PolicyGenerationEnd = 0,
            FutureMountGateReady = 0
        };

        AdmissionCoverageDecision result = AdmissionCoverageEvaluator.Evaluate(
            receipt, [@"\Device\HarddiskVolume3\Users\victor\Cloud"],
            expectedPolicyFlags: 0, boundNativePolicyGeneration: 0);

        Assert.Equal(AdmissionCoverageReadiness.Pending, result.Readiness);
        Assert.Equal("PolicyOrTopologyChanging", result.Reason);
    }

    private static AdmissionCoverageScopeReceipt PrefixScope(
        uint state = AdmissionCoverageContract.Ready,
        uint resolution = AdmissionCoverageContract.UniqueResolution,
        uint reason = 0, uint matching = 1, uint unique = 1, uint ready = 1) =>
        new(AdmissionCoverageContract.PrefixScope, 0, resolution, state, reason,
            matching, unique, ready, @"\Device\HarddiskVolume3\Users\victor\Cloud");

    private static AdmissionCoverageReceipt ReadyReceipt(
        AdmissionCoverageScopeReceipt scope, uint topReason = 0,
        uint generation = 7, uint flags = CompleteStableFutureRegistry,
        uint futureMountGateReady = 1, uint policyFlags = 0) =>
        ReadyReceipt([scope], topReason, generation, flags, futureMountGateReady, policyFlags);

    private static AdmissionCoverageReceipt ReadyReceipt(
        IReadOnlyList<AdmissionCoverageScopeReceipt> scopes,
        uint topReason = 0, uint generation = 7,
        uint flags = CompleteStableFutureRegistry, uint futureMountGateReady = 1,
        uint policyFlags = 0) =>
        new(Contract.Version, AdmissionCoverageContract.Ready, flags,
            generation, policyFlags, BootPolicyState: 1,
            ScopeCount: (uint)scopes.Count, ExpectedScopeCount: (uint)scopes.Count,
            PolicyGenerationEnd: generation, PolicyFlagsEnd: policyFlags,
            BootPolicyStateEnd: 1, EpochGeneration: 3, EpochFlags: 0,
            EpochActiveCallbacks: 0, EpochGenerationEnd: 3, EpochFlagsEnd: 0,
            EpochActiveCallbacksEnd: 0, EnumeratedInstances: 1,
            SetupInFlight: 0, TeardownInFlight: 0, CoverageChangesInFlight: 0,
            WriterGlobalUnknown: 0, WriterEntries: 0, WriterEntriesNotReady: 0,
            WriterEntriesUnknown: 0, FutureMountGateReady: futureMountGateReady,
            Reason: topReason, PolicyScopeSequenceStart: 14,
            PolicyScopeSequenceEnd: 14, TopologySequenceStart: 22,
            TopologySequenceEnd: 22, CoverageSequenceStart: 30,
            CoverageSequenceEnd: 30, RegistrySequenceStart: 44,
            RegistrySequenceEnd: 44, Scopes: scopes);
}
