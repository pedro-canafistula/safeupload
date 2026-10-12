#if SAFEUPLOAD_ADMISSION_EVIDENCE
namespace SafeUpload.Agent.Service.Interception;

// One instance per authenticated port. The receive loop enqueues without
// waiting for destination turns; connection shutdown cancels and joins every
// accepted continuation before it disposes the port.
internal sealed class StagedRequestContinuations(CancellationToken connectionToken) : IDisposable
{
    private readonly CancellationTokenSource _stop = CancellationTokenSource.CreateLinkedTokenSource(connectionToken);
    private readonly HashSet<Task> _tasks = new();
    private bool _draining;

    internal void Dispatch(Func<CancellationToken, Task> operation)
    {
        ArgumentNullException.ThrowIfNull(operation);
        lock (_tasks)
        {
            if (_draining) throw new InvalidOperationException("The port continuations are draining.");
            Task task = Task.Run(() => operation(_stop.Token), CancellationToken.None);
            _tasks.Add(task);
            _ = task.ContinueWith(completed =>
            {
                lock (_tasks) _tasks.Remove(completed);
            }, CancellationToken.None, TaskContinuationOptions.ExecuteSynchronously, TaskScheduler.Default);
        }
    }

    internal async Task DrainAsync()
    {
        Task[] accepted;
        lock (_tasks) { _draining = true; accepted = _tasks.ToArray(); }
        _stop.Cancel();
        try { await Task.WhenAll(accepted).ConfigureAwait(false); }
        catch (OperationCanceledException) when (_stop.IsCancellationRequested) { }
    }

    public void Dispose() => _stop.Dispose();
}
#endif
