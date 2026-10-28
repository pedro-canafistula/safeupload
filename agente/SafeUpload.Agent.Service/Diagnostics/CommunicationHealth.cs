using SafeUpload.Agent.Core.Application;

namespace SafeUpload.Agent.Service.Diagnostics;

public sealed record CommunicationOperationHealth(string Operation, string State, long Attempts,
    long Successes, long Failures, long Cancellations, long InFlight,
    DateTimeOffset? LastAttemptUtc, DateTimeOffset? LastSuccessUtc, DateTimeOffset? LastFailureUtc,
    DateTimeOffset? LastCancellationUtc, string? LastOutcome, string? LastFailureKind,
    int? LastHttpStatus, string? LastPolicySource, bool? LastRemoteCachePersisted);
public sealed record CommunicationHealthSnapshot(DateTimeOffset SinceUtc, bool Configured,
    IReadOnlyList<CommunicationOperationHealth> Operations)
{
    public bool ProtectionQualified => false;
    public bool ApiPersistenceQualified => false;
    public bool PolicyAppliedToDriverQualified => false;
}

/// <summary>Three fixed process-local slots; Read performs no network, file or driver access.</summary>
public sealed class CommunicationHealth(bool configured, TimeProvider? timeProvider = null) : ICommunicationObserver
{
    private readonly object _gate = new();
    private readonly TimeProvider _time = timeProvider ?? TimeProvider.System;
    private readonly DateTimeOffset _since = (timeProvider ?? TimeProvider.System).GetUtcNow();
    private long _sequence;
    private readonly Dictionary<CommunicationOperation, Slot> _slots =
        Enum.GetValues<CommunicationOperation>().ToDictionary(operation => operation, _ => new Slot());

    public long Started(CommunicationOperation operation)
    {
        lock (_gate)
        {
            var slot = _slots[operation];
            slot.Attempts++; slot.InFlight++; slot.LastAttempt = _time.GetUtcNow();
            return ++_sequence;
        }
    }

    public void Completed(CommunicationOperation operation, long attempt, CommunicationOutcome outcome,
        CommunicationFailure? failure, int? httpStatus, PolicyLoadSource? policySource, bool? cachePersisted)
    {
        lock (_gate)
        {
            var slot = _slots[operation]; var now = _time.GetUtcNow();
            slot.InFlight--;
            switch (outcome)
            {
                case CommunicationOutcome.Success: slot.Successes++; slot.LastSuccess = now; break;
                case CommunicationOutcome.Failure:
                    slot.Failures++; slot.LastFailure = now; slot.FailureKind = failure?.ToString(); break;
                case CommunicationOutcome.Cancelled: slot.Cancellations++; slot.LastCancellation = now; break;
            }
            // Older attempts completing later cannot overwrite the newest completed result.
            if (attempt < slot.LastCompleted) return;
            slot.LastCompleted = attempt; slot.Outcome = outcome.ToString();
            slot.HttpStatus = httpStatus;
            slot.PolicySource = policySource?.ToString(); slot.CachePersisted = cachePersisted;
        }
    }

    public CommunicationHealthSnapshot Read()
    {
        lock (_gate)
        {
            return new(_since, configured, _slots.Select(pair =>
            {
                var s = pair.Value;
                string state = !configured ? "not_configured" : s.InFlight > 0 ? "in_progress" :
                    s.Attempts == 0 ? "not_attempted" : s.Outcome ?? "not_attempted";
                return new CommunicationOperationHealth(pair.Key.ToString(), state, s.Attempts,
                    s.Successes, s.Failures, s.Cancellations, s.InFlight, s.LastAttempt, s.LastSuccess,
                    s.LastFailure, s.LastCancellation, s.Outcome, s.FailureKind, s.HttpStatus,
                    s.PolicySource, s.CachePersisted);
            }).ToArray());
        }
    }

    private sealed class Slot
    {
        public long Attempts, Successes, Failures, Cancellations, InFlight, LastCompleted;
        public DateTimeOffset? LastAttempt, LastSuccess, LastFailure, LastCancellation;
        public string? Outcome, FailureKind, PolicySource;
        public int? HttpStatus;
        public bool? CachePersisted;
    }
}
