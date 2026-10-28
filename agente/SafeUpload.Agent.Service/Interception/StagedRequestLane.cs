using System.Runtime.ExceptionServices;
using System.Threading.Channels;

namespace SafeUpload.Agent.Service.Interception;

internal sealed class StagedRequestLane : IDisposable
{
    private sealed record Work(Func<CancellationToken, Task> Run, ExecutionContext? Context);
    private readonly Channel<Work> _queue;
    private readonly CancellationTokenSource _stop = new();
    private readonly Task[] _workers;
    private ExceptionDispatchInfo? _failure;

    internal StagedRequestLane(int workers, int queued)
    {
        ArgumentOutOfRangeException.ThrowIfLessThan(workers, 1);
        ArgumentOutOfRangeException.ThrowIfLessThan(queued, 1);
        _queue = Channel.CreateBounded<Work>(new BoundedChannelOptions(queued)
        {
            SingleReader = workers == 1, FullMode = BoundedChannelFullMode.Wait,
            AllowSynchronousContinuations = false
        });
        using (ExecutionContext.SuppressFlow())
            _workers = Enumerable.Range(0, workers).Select(_ => Task.Run(RunAsync)).ToArray();
    }

    internal bool TryDispatch(Func<CancellationToken, Task> operation) =>
        _queue.Writer.TryWrite(new(operation, ExecutionContext.Capture()));

    private async Task RunAsync()
    {
        await foreach (var work in _queue.Reader.ReadAllAsync().ConfigureAwait(false))
        {
            try
            {
                Task? pending = null;
                if (work.Context is null) pending = work.Run(_stop.Token);
                else ExecutionContext.Run(work.Context, _ => pending = work.Run(_stop.Token), null);
                await pending!.ConfigureAwait(false);
            }
            catch (OperationCanceledException) when (_stop.IsCancellationRequested) { }
            catch (Exception error)
            {
                Interlocked.CompareExchange(ref _failure, ExceptionDispatchInfo.Capture(error), null);
            }
        }
    }

    internal void Stop()
    {
        _queue.Writer.TryComplete();
        _stop.Cancel();
    }

    internal async Task DrainAsync()
    {
        Stop();
        await Task.WhenAll(_workers).ConfigureAwait(false);
        _failure?.Throw();
    }

    public void Dispose()
    {
        Stop();
        try { Task.WhenAll(_workers).GetAwaiter().GetResult(); }
        finally { _stop.Dispose(); }
    }
}
