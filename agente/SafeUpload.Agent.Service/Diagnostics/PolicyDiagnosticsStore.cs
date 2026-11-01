using SafeUpload.Agent.Core.Application;
using SafeUpload.Agent.Core.Domain;
using SafeUpload.Agent.Core.Infrastructure;
using SafeUpload.Agent.Service.Gate;

namespace SafeUpload.Agent.Service.Diagnostics;

public sealed record PolicySummary(int Version, string ContentFingerprint, int CategoryCount,
    bool AuditOnly, bool FailOpen, bool OverrideAllowed);
public sealed record PolicyReadStatus(string State, DateTimeOffset? LastSuccessUtc,
    PolicySummary? LastSuccess, string? LastFailureKind);
public sealed record PolicyDiagnosticsSnapshot(string Mode, PolicyReadStatus SnapshotRead,
    PolicyReadStatus CurrentOriginRead, RemotePolicyStatus? Remote, GatePolicyStatus Gate);

/// <summary>Observes existing reads. Diagnostics never load a policy, touch disk, connect or refresh authority.</summary>
public sealed class PolicyDiagnosticsStore(IPolicyStore inner, string mode,
    DurableHttpPolicyStore? remote = null) : IPolicyStore
{
    private readonly object _gate = new();
    private long _sequence, _snapshotCompleted, _currentCompleted;
    private PolicyReadStatus _snapshot = new("not_attempted", null, null, null);
    private PolicyReadStatus _current = new("not_attempted", null, null, null);

    public Task<Policy> LoadAsync(CancellationToken token) => LoadAsync(false, token);
    public Task<Policy> LoadCurrentAsync(CancellationToken token) => LoadAsync(true, token);

    private async Task<Policy> LoadAsync(bool current, CancellationToken token)
    {
        long attempt = Interlocked.Increment(ref _sequence);
        Policy policy;
        try
        {
            policy = current ? await inner.LoadCurrentAsync(token).ConfigureAwait(false)
                : await inner.LoadAsync(token).ConfigureAwait(false);
        }
        catch (Exception error)
        {
            Complete(current, attempt, null, error is OperationCanceledException && token.IsCancellationRequested
                ? "cancelled" : CommunicationObservation.Classify(error).ToString());
            throw;
        }
        // Observation must not change the result, including for third-party IPolicyStore implementations.
        try
        {
            Complete(current, attempt, new(policy.Version, PolicyContentFingerprint.Compute(policy),
                policy.ActiveCategories.Count, policy.AuditOnly, policy.FailOpen, policy.OverrideAllowed), null);
        }
        catch { /* Diagnostics are best effort. */ }
        return policy;
    }

    private void Complete(bool current, long attempt, PolicySummary? policy, string? failure)
    {
        lock (_gate)
        {
            if (attempt < (current ? _currentCompleted : _snapshotCompleted)) return;
            var previous = current ? _current : _snapshot;
            var next = policy is not null ? new PolicyReadStatus("success", DateTimeOffset.UtcNow, policy, null)
                : previous with { State = failure == "cancelled" ? "cancelled" : "failure", LastFailureKind = failure };
            if (current) { _currentCompleted = attempt; _current = next; }
            else { _snapshotCompleted = attempt; _snapshot = next; }
        }
    }

    public PolicyDiagnosticsSnapshot Read(GatePolicyStatus gate)
    {
        lock (_gate) return new(mode, _snapshot, _current, remote?.ReadStatus(), gate);
    }
}
