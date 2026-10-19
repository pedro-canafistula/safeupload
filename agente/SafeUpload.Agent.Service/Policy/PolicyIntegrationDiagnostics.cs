using SafeUpload.Agent.Core.Domain;

namespace SafeUpload.Agent.Service.Policies;

/// <summary>Local observations only. Never used to authorize, refresh or apply a policy.</summary>
public sealed class PolicyIntegrationDiagnostics
{
    private readonly object _gate = new();
    private readonly ILogger<PolicyIntegrationDiagnostics> _logger;
    private PolicyIntegrationSnapshot _state = new();

    public PolicyIntegrationDiagnostics(ILogger<PolicyIntegrationDiagnostics> logger) => _logger = logger;

    internal PolicyIntegrationSnapshot Read()
    {
        lock (_gate) return _state;
    }

    internal void RecordSnapshot(Policy policy, string source) => Update(state => state with
    { SnapshotVersion = policy.Version, SnapshotSource = source });

    internal void RecordStrictRead(Policy policy)
    {
        string? fingerprint = TryFingerprint(policy);
        Update(state => state with { StrictVersion = policy.Version, StrictFingerprint = fingerprint, StrictReadError = null });
    }

    internal void RecordStrictFailure(Exception error) => Update(state => state with
    { StrictReadError = error.GetType().Name });

    // Call only after the live port and durable boot-policy operations return successfully.
    // Acceptance of that scope is not staging readiness or proof of protection.
    internal void RecordDriverScopeAccepted(Policy policy)
    {
        string? fingerprint = TryFingerprint(policy);
        Update(state => state with { LastAcceptedVersion = policy.Version, LastAcceptedFingerprint = fingerprint,
            DriverScopeRecorded = true, ApplyError = null });
    }

    internal void RecordApplyFailure(Exception error) => Update(state => state with
    { DriverScopeRecorded = false, ApplyError = error.GetType().Name });

    internal void RecordDriverDisconnected() => Update(state => state with { DriverScopeRecorded = false });

    private static string? TryFingerprint(Policy policy)
    {
        try { return PolicyContentFingerprint.Compute(policy); }
        catch (Exception) { return null; } // Diagnostics must not change the policy consumer's outcome.
    }

    private void Update(Func<PolicyIntegrationSnapshot, PolicyIntegrationSnapshot> change)
    {
        lock (_gate)
        {
            var next = change(_state);
            if (next == _state) return;
            _state = next;
            try
            {
            _logger.LogInformation("PolicyIntegration: SnapshotVersion={SnapshotVersion} SnapshotSource={SnapshotSource} " +
                "StrictVersion={StrictVersion} StrictFingerprint={StrictFingerprint} StrictReadError={StrictReadError} " +
                "LastAcceptedVersion={LastAcceptedVersion} LastAcceptedFingerprint={LastAcceptedFingerprint} " +
                "DriverScopeRecorded={DriverScopeRecorded} ApplyError={ApplyError}. Acceptance is not protection readiness.",
                next.SnapshotVersion, next.SnapshotSource, next.StrictVersion, next.StrictFingerprint, next.StrictReadError,
                next.LastAcceptedVersion, next.LastAcceptedFingerprint, next.DriverScopeRecorded, next.ApplyError);
            }
            catch (Exception) { /* A broken log provider cannot grant or prevent policy application. */ }
        }
    }
}

internal sealed record PolicyIntegrationSnapshot
{
    public int? SnapshotVersion { get; init; }
    public string? SnapshotSource { get; init; }
    public int? StrictVersion { get; init; }
    public string? StrictFingerprint { get; init; }
    public string? StrictReadError { get; init; }
    public int? LastAcceptedVersion { get; init; }
    public string? LastAcceptedFingerprint { get; init; }
    public bool DriverScopeRecorded { get; init; }
    public string? ApplyError { get; init; }
}
