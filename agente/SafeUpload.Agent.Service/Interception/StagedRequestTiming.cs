using System.Diagnostics;
using System.Globalization;

namespace SafeUpload.Agent.Service.Interception;

// Monotonic diagnostics, never timeout, readiness or cleanup authority.
// Overlapping scopes of the same phase count their time once, including parallel
// journal scans; live phase is the most recently entered unfinished scope. The
// ambient reference flows into asynchronous request continuations, not workers
// started before the receive loop. Phase scopes include nested work; @ is the
// last phase completion's offset from dequeue, not a wall-clock timestamp.
internal sealed class StagedRequestTiming
{
    private static readonly AsyncLocal<StagedRequestTiming?> Ambient = new();
    private readonly Func<long> _clock;
    private readonly long _frequency;
    private readonly long _started;
    private readonly object _gate = new();
    private readonly Dictionary<string, (double Duration, double End)> _phases = new();
    private readonly List<(object Id, string Name)> _active = [];
    private readonly Dictionary<string, (int Count, long Start)> _open = new();
    internal StagedRequestTiming(Func<long>? clock = null, long frequency = 0)
    {
        _clock = clock ?? Stopwatch.GetTimestamp;
        _frequency = frequency == 0 ? Stopwatch.Frequency : frequency;
        _started = _clock();
    }
    internal static StagedRequestTiming? Current => Ambient.Value;
    internal double ElapsedMs => Milliseconds(_clock() - _started);
    internal bool ShouldWarn(bool failedReply) => failedReply || ElapsedMs >= 1000;
    private double Milliseconds(long ticks) => ticks * 1000d / _frequency;
    internal (string Phase, double AgeMs) Snapshot()
    {
        lock (_gate) return (_active.Count == 0 ? "dequeued" : _active[^1].Name, ElapsedMs);
    }
    internal IDisposable Activate()
    {
        var previous = Ambient.Value;
        Ambient.Value = this;
        return new ActionScope(() => Ambient.Value = previous);
    }
    internal static IDisposable? Measure(string phase) => Current?.StartPhase(phase);
    internal IDisposable StartPhase(string phase)
    {
        lock (_gate)
        {
            object id = new();
            _active.Add((id, phase));
            _open.TryGetValue(phase, out var open);
            _open[phase] = (open.Count + 1, open.Count == 0 ? _clock() : open.Start);
            return new ActionScope(() =>
            {
                lock (_gate)
                {
                    _active.Remove((id, phase));
                    var current = _open[phase];
                    _open[phase] = (current.Count - 1, current.Start);
                    if (current.Count != 1) return;
                    long end = _clock();
                    _phases.TryGetValue(phase, out var prior);
                    _phases[phase] = (prior.Duration + Milliseconds(end - current.Start), Milliseconds(end - _started));
                }
            });
        }
    }
    public override string ToString()
    {
        lock (_gate) return string.Join(",", _phases.Select(p =>
            p.Key + "=" + p.Value.Duration.ToString("F1", CultureInfo.InvariantCulture) +
            "@" + p.Value.End.ToString("F1", CultureInfo.InvariantCulture)));
    }
    private sealed class ActionScope(Action action) : IDisposable
    {
        private Action? _action = action;
        public void Dispose() => Interlocked.Exchange(ref _action, null)?.Invoke();
    }
}

// Same semaphore semantics, with wait diagnostics shared by all journal partials.
internal sealed class StagedJournalGate
{
    private readonly SemaphoreSlim _gate = new(1, 1);
    private Exception? _failure;
    internal bool IntegrityHeld => Volatile.Read(ref _failure) is not null;
    internal void FailClosed(Exception error) => Interlocked.CompareExchange(ref _failure, error, null);
    internal async Task WaitAsync(CancellationToken token = default)
    {
        using var timing = StagedRequestTiming.Measure("journal-wait");
        await _gate.WaitAsync(token).ConfigureAwait(false);
        if (Volatile.Read(ref _failure) is { } failure)
        {
            _gate.Release();
            throw new IOException("Terminal journal integrity is held until validated restart.", failure);
        }
    }
    internal int Release() => _gate.Release();
}
