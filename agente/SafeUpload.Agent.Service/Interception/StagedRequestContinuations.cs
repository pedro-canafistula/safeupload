#if SAFEUPLOAD_ADMISSION_EVIDENCE
namespace SafeUpload.Agent.Service.Interception;

// One instance per authenticated port. The receive loop enqueues without
// waiting for destination turns; connection shutdown cancels and joins every
// accepted continuation before it disposes the port.
internal sealed class StagedRequestContinuations : IDisposable
{
    private readonly StagedRequestLane _lane = new(StagedRequestDispatcher.ContinuationWorkers,
        StagedRequestDispatcher.QueuedContinuationRequests);
    private readonly object _gate = new();
    private readonly CancellationTokenRegistration _cancellation;
    private bool _draining;

    internal StagedRequestContinuations(CancellationToken connectionToken) =>
        _cancellation = connectionToken.Register(_lane.Stop);

    internal void Dispatch(Func<CancellationToken, Task> operation)
    {
        ArgumentNullException.ThrowIfNull(operation);
        lock (_gate)
        {
            if (_draining) throw new InvalidOperationException("The port continuations are draining.");
            if (!_lane.TryDispatch(operation))
                throw new InvalidOperationException("The bounded port continuations are full.");
        }
    }

    internal async Task DrainAsync()
    {
        lock (_gate) _draining = true;
        await _lane.DrainAsync().ConfigureAwait(false);
    }

    public void Dispose()
    {
        _cancellation.Dispose();
        _lane.Dispose();
    }
}
#endif
