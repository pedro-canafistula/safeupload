using System.Diagnostics;

namespace SafeUpload.Agent.Service.Interception;

// A failed private archive write must not kill the publication/discard worker.
// Backoff is monotonic and never delays under the journal gate. Integrity faults
// escape to the caller's readiness hold; only unfinished metadata is retried.
internal sealed class StagedJournalMaintenanceRetry(Func<long>? timestamp = null, long frequency = 0)
{
    private readonly Func<long> _timestamp = timestamp ?? Stopwatch.GetTimestamp;
    private readonly long _frequency = frequency == 0 ? Stopwatch.Frequency : frequency;
    private int _failures;
    private long _retryAt;

    internal async Task<bool> RunAsync(Func<CancellationToken, Task> work, Action<Exception> report, CancellationToken token)
    {
        token.ThrowIfCancellationRequested();
        if (_timestamp() < _retryAt) return false;
        try
        {
            await work(token).ConfigureAwait(false);
            _failures = 0; _retryAt = 0;
            return true;
        }
        catch (Exception error) when (error is IOException or UnauthorizedAccessException or System.ComponentModel.Win32Exception)
        {
            _failures = Math.Min(_failures + 1, 6);
            _retryAt = _timestamp() + _frequency * (1 << (_failures - 1)) / 4;
            report(error); // 250 ms, 500 ms, 1 s, 2 s, 4 s, then 8 s
            return false;
        }
    }
}
