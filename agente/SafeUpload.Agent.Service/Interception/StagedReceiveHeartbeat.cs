using System.Diagnostics;
using System.Globalization;

namespace SafeUpload.Agent.Service.Interception;

// One heartbeat per connection/60 monotonic seconds. A separate service task
// can report a blocked receive/handler thread; a process-wide stall stops both.
internal sealed class StagedReceiveHeartbeat
{
    private readonly Func<long> _clock;
    private readonly long _frequency;
    private readonly object _gate = new();
    private readonly Dictionary<StagedRequestTiming, (ulong Request, string Operation)> _active = new();
    private StagedRequestTiming? _handling;
    private long _last;
    private bool _running;
    internal StagedReceiveHeartbeat(Func<long>? clock = null, long frequency = 0)
    {
        _clock = clock ?? Stopwatch.GetTimestamp;
        _frequency = frequency == 0 ? Stopwatch.Frequency : frequency;
    }
    internal void Start()
    {
        lock (_gate) { _running = true; _last = _clock(); }
    }
    internal void Waiting() { lock (_gate) _handling = null; }
    internal void Handling(ulong request, string operation, StagedRequestTiming timing)
    {
        lock (_gate) { _active.Add(timing, (request, operation)); _handling = timing; }
    }
    internal void Complete(StagedRequestTiming timing)
    {
        lock (_gate)
        {
            _active.Remove(timing);
            if (ReferenceEquals(_handling, timing)) _handling = null;
        }
    }
    internal void Stop() { lock (_gate) { _running = false; _active.Clear(); _handling = null; } }
    internal string? Poll()
    {
        lock (_gate)
        {
            long now = _clock();
            if (!_running || (now - _last) / (double)_frequency < 60) return null;
            _last = now; // Do not burst/replay missed heartbeats after a stall.
            if (_handling is { } handling) return Describe("handling", handling);
            string waiting = "waiting for a message";
            // Continuations can still be slow while the receive thread is free.
            var oldest = _active.Keys.OrderByDescending(t => t.ElapsedMs).FirstOrDefault();
            return oldest is null ? waiting : waiting + "; " + Describe("asynchronous", oldest);
        }
    }
    private string Describe(string position, StagedRequestTiming timing)
    {
        var request = _active[timing];
        var state = timing.Snapshot();
        return $"{position} request {request.Request}, operation {request.Operation}, phase {state.Phase}, " +
            "age " + state.AgeMs.ToString("F1", CultureInfo.InvariantCulture) + " ms";
    }
}
