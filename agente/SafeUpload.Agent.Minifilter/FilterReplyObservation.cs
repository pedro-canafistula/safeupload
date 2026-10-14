namespace SafeUpload.Agent.Minifilter;

// Diagnostics only. Observe every native reply without translating its result
// or changing the typed/bound APIs' existing exception/recovery behavior.
public sealed class FilterReplyObservation : IDisposable
{
    private static readonly AsyncLocal<Action<bool, int?>?> Observer = new();
    private readonly Action<bool, int?> _observer;
    private int? _result;
    private FilterReplyObservation(Action<bool, int?> observer)
    {
        _observer = observer;
        observer(true, null);
    }
    public static IDisposable Listen(Action<bool, int?> observer)
    {
        var previous = Observer.Value;
        Observer.Value = observer;
        return new Listener(previous);
    }
    internal static FilterReplyObservation? Begin() => Observer.Value is { } observer ? new(observer) : null;
    internal void Complete(int result) => _result = result;
    public void Dispose() => _observer(false, _result);
    private sealed class Listener(Action<bool, int?>? previous) : IDisposable
    {
        public void Dispose() => Observer.Value = previous;
    }
}
