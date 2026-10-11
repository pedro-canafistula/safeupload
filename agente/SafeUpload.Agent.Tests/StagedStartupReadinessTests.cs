using SafeUpload.Agent.Minifilter;
using SafeUpload.Agent.Service.Interception;

namespace SafeUpload.Agent.Tests;

public sealed class StagedStartupReadinessTests
{
    [Theory]
    [InlineData(false, false)]
    [InlineData(true, false)]
    [InlineData(false, true)]
    public void Coverage_alone_never_announces_ready_before_epoch_and_recovery(bool handshake, bool recovery)
    {
        var coverage = new AdmissionCoverageDecision(AdmissionCoverageReadiness.Ready, "CoverageReady", 7);
        var decision = MinifilterInterceptor.ApplyStageStartupReadiness(coverage, handshake, recovery, false);
        Assert.Equal(AdmissionCoverageReadiness.Pending, decision.Readiness);
        Assert.Equal("StageStartupPending", decision.Reason); Assert.Equal(7u, decision.NativePolicyGeneration);
    }

    [Fact]
    public void Failed_startup_advertises_degraded_even_with_good_coverage_and_old_ready_bits()
    {
        var coverage = new AdmissionCoverageDecision(AdmissionCoverageReadiness.Ready, "CoverageReady", 7);
        var decision = MinifilterInterceptor.ApplyStageStartupReadiness(coverage, true, true, true);
        Assert.Equal(AdmissionCoverageReadiness.Degraded, decision.Readiness);
        Assert.Equal("StageStartupFailed", decision.Reason); Assert.Equal(7u, decision.NativePolicyGeneration);
    }

    [Fact]
    public void Completed_startup_preserves_the_actual_coverage_receipt()
    {
        var coverage = new AdmissionCoverageDecision(AdmissionCoverageReadiness.Ready, "CoverageReady", 7);
        Assert.Equal(coverage, MinifilterInterceptor.ApplyStageStartupReadiness(coverage, true, true, false));
    }

    [Theory]
    [InlineData(AdmissionCoverageReadiness.Pending)]
    [InlineData(AdmissionCoverageReadiness.Degraded)]
    public void Startup_never_upgrades_or_hides_a_pending_or_degraded_coverage_receipt(AdmissionCoverageReadiness state)
    {
        var coverage = new AdmissionCoverageDecision(state, "OriginalCoverageReason", 7);
        Assert.Equal(coverage, MinifilterInterceptor.ApplyStageStartupReadiness(coverage, true, true, true));
    }
}
