#if SAFEUPLOAD_ADMISSION_EVIDENCE

namespace SafeUpload.Agent.Service.Diagnostics;

// Local controls test this machinery only; they are never native execution.
internal sealed class Nu501Latch : IDisposable
{
    private readonly TaskCompletionSource _release = new(TaskCreationOptions.RunContinuationsAsynchronously);
    private readonly object _gate = new();
    private readonly ManualResetEvent _stop = new(false);
    private readonly Thread _watchdog;
    private bool _disposed;
    private readonly CancellationTokenRegistration _cancellation;
    private int _expired;
    internal bool Released => _release.Task.IsCompleted;
    internal bool Expired => Volatile.Read(ref _expired) != 0;
    internal Nu501Latch(TimeSpan timeout, CancellationToken token)
    {
        // A dedicated thread is essential: all pool workers may be blocked in
        // the synchronous native sends whose progress this latch measures.
        _watchdog = new Thread(() =>
        {
            if (!_stop.WaitOne(timeout)) { Interlocked.Exchange(ref _expired, 1); Release(); }
        }) { IsBackground = true, Name = "SafeUpload.Nu501Watchdog" };
        _watchdog.Start();
        _cancellation = token.Register(Release);
    }
    internal void Wait() => _release.Task.GetAwaiter().GetResult();
    internal void Release()
    {
        _release.TrySetResult();
        lock (_gate) { if (!_disposed) _stop.Set(); }
    }
    public void Dispose()
    {
        Release(); _cancellation.Dispose(); _watchdog.Join();
        lock (_gate) { if (!_disposed) { _disposed = true; _stop.Dispose(); } }
    }
}

internal sealed record Nu501Step(string Name, ulong RequestId, string Status, int HResult,
    double ElapsedMs, bool LegacyHeld, bool Passed, string Detail);
internal sealed record Nu501Receipt(string Schema, string RunId, string Verdict, string Scope,
    IReadOnlyList<Nu501Step> Steps, string? Failure)
{
    internal static readonly string[] Required = new[] { "Idle", "Probe", "Pair", "CommitWire", "CommitNotReady", "LeaseHeld",
        "LegacyBlocked", "ChildCreditsBusy", "OtherPoolBusy", "GrowthPoolBusy", "Malformed", "RefusedWire", "Refused",
        "LocalStoreBusy", "LocalSendBusy", "LocalSendsReturned", "HeldProgressComplete", "LegacyReleased", "ChildrenClosed",
        "DisconnectRetains", "RevokeLatchReleased", "DisconnectDrain" }
        .Concat(new[] { "Timeout", "Failure", "Cancellation" }.SelectMany(c => new[] { $"Release{c}Held", $"Release{c}Returned" }))
        .Concat(Enumerable.Range(1, 4).SelectMany(i => new[] { $"Root{i}Wire", $"Root{i}" }))
        .Concat(Enumerable.Range(0, 4).SelectMany(i => new[] { $"Child{i}Wire", $"Child{i}", $"Store{i}" }
            .Concat(new[] { "Create", "Allocation", "Write", "F1", "EndOfFile", "F2", "F3" }.Select(n => $"Store{i}.{n}"))))
        .Concat(Enumerable.Range(0, 7).SelectMany(i => new[] { $"OtherPool{i}Wire", $"OtherPool{i}" }))
        .Concat(Enumerable.Range(0, 8).SelectMany(i => new[] { $"GrowthPool{i}Wire", $"GrowthPool{i}" })).ToArray();

    internal bool ValidPass
    {
        get
        {
            if (Schema != "SafeUpload.N-U5-01.v1" || !Guid.TryParseExact(RunId, "N", out _) || Verdict != "PASS" ||
                Failure is not null || Steps.Count > 512 ||
                !Steps.All(s => s.Passed && double.IsFinite(s.ElapsedMs) && s.ElapsedMs >= 0) ||
                !Required.All(n => Steps.Count(s => s.Name == n) == 1)) return false;
            var names = Steps.Select(s => s.Name).ToList();
            Nu501Step One(string name) => Steps.Single(s => s.Name == name);
            int held = names.IndexOf("LeaseHeld"), released = names.IndexOf("LegacyReleased");
            if (!(names.IndexOf("Idle") < names.IndexOf("Probe") && names.IndexOf("Probe") < names.IndexOf("Pair") &&
                names.IndexOf("Pair") < names.IndexOf("CommitNotReady") && names.IndexOf("CommitNotReady") < held &&
                held < names.IndexOf("LegacyBlocked") && names.IndexOf("HeldProgressComplete") < released &&
                released < names.IndexOf("DisconnectRetains") && names.IndexOf("DisconnectRetains") < names.IndexOf("DisconnectDrain"))) return false;
            if (!new[] { "Timeout", "Failure", "Cancellation" }.All(c =>
                One($"Release{c}Held").LegacyHeld && !One($"Release{c}Returned").LegacyHeld &&
                One($"Release{c}Returned").HResult == 0 && names.IndexOf($"Release{c}Held") < names.IndexOf($"Release{c}Returned") &&
                names.IndexOf($"Release{c}Returned") < held) || !One("DisconnectRetains").LegacyHeld ||
                One("RevokeLatchReleased").LegacyHeld || names.IndexOf("DisconnectRetains") >= names.IndexOf("RevokeLatchReleased") ||
                names.IndexOf("RevokeLatchReleased") >= names.IndexOf("DisconnectDrain")) return false;
            if (Steps.Zip(Steps.Skip(1)).Any(p => p.First.ElapsedMs > p.Second.ElapsedMs)) return false;
            if (!Steps.Skip(held).Take(released - held).All(s => s.LegacyHeld) || One("LegacyReleased").LegacyHeld) return false;
            return Enumerable.Range(1, 4).All(i => One($"Root{i}") is { RequestId: > 0, HResult: 0 }) &&
                Enumerable.Range(0, 4).All(i => One($"Child{i}").RequestId > 0 && One($"Store{i}").RequestId > 0 &&
                    new[] { "Create", "Allocation", "Write", "F1", "EndOfFile", "F2", "F3" }.All(n =>
                        One($"Store{i}.{n}") is { HResult: 0, Status: "Native" })) &&
                new[] { "ChildCreditsBusy", "OtherPoolBusy", "GrowthPoolBusy" }.All(n =>
                    One(n) is { Status: "Completed", HResult: < 0, RequestId: > 0 }) &&
                One("LocalSendBusy").HResult == 0 && One("Malformed").HResult < 0 && One("Refused").HResult == 0;
        }
    }
}
#endif
