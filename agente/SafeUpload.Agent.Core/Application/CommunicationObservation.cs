using System.Text.Json;
using SafeUpload.Agent.Core.Domain;

namespace SafeUpload.Agent.Core.Application;

public enum CommunicationOperation { Policy, Heartbeat, Audit }
public enum CommunicationOutcome { Success, Failure, Cancelled }
public enum CommunicationFailure { HttpRejected, TransportError, Timeout, InvalidResponse, UnexpectedError }
public enum PolicyLoadSource { Remote, Memory, Disk, Default }

/// <summary>Closed metadata only. No URL, identity, body or exception text crosses this boundary.</summary>
public interface ICommunicationObserver
{
    long Started(CommunicationOperation operation);
    void Completed(CommunicationOperation operation, long attempt, CommunicationOutcome outcome,
        CommunicationFailure? failure, int? httpStatus, PolicyLoadSource? policySource, bool? cachePersisted);
}

/// <summary>Optional, best-effort observation must never change delivery or policy semantics.</summary>
public sealed class CommunicationObservation : IDisposable
{
    private readonly ICommunicationObserver? _observer;
    private readonly CommunicationOperation _operation;
    private readonly long _attempt;
    private int _finished;

    public CommunicationObservation(ICommunicationObserver? observer, CommunicationOperation operation)
    {
        _operation = operation;
        try { _attempt = observer?.Started(operation) ?? 0; _observer = observer; }
        catch { /* Monitoring cannot prevent the real operation. */ }
    }

    public void Success(int? status = null, PolicyLoadSource? source = null, bool? cachePersisted = null) =>
        Complete(CommunicationOutcome.Success, null, status, source, cachePersisted);
    public void Failure(CommunicationFailure failure, int? status = null, PolicyLoadSource? source = null) =>
        Complete(CommunicationOutcome.Failure, failure, status, source, null);
    public void Exception(Exception exception, CancellationToken token, int? receivedStatus = null) =>
        Complete(exception is OperationCanceledException && token.IsCancellationRequested
                ? CommunicationOutcome.Cancelled : CommunicationOutcome.Failure,
            exception is OperationCanceledException && token.IsCancellationRequested ? null : Classify(exception),
            exception is HttpRequestException request && request.StatusCode is { } status ? (int)status : receivedStatus, null, null);

    private void Complete(CommunicationOutcome outcome, CommunicationFailure? failure,
        int? status, PolicyLoadSource? source, bool? cachePersisted)
    {
        if (Interlocked.Exchange(ref _finished, 1) != 0) return;
        try { _observer?.Completed(_operation, _attempt, outcome, failure, status, source, cachePersisted); }
        catch { /* A completed remote action must not become a failed action due to diagnostics. */ }
    }

    public void Dispose() => Failure(CommunicationFailure.UnexpectedError);

    public static CommunicationFailure Classify(Exception exception) => exception switch
    {
        HttpRequestException { StatusCode: not null } => CommunicationFailure.HttpRejected,
        HttpRequestException or IOException => CommunicationFailure.TransportError,
        OperationCanceledException => CommunicationFailure.Timeout,
        JsonException or InvalidPolicyException => CommunicationFailure.InvalidResponse,
        _ => CommunicationFailure.UnexpectedError
    };
}
