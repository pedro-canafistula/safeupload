namespace SafeUpload.Agent.Service.Interception;

internal enum StagedDispatchLane { Ordered, Allocation, Continuation, Growth }

// Ordering contract (v1/v20 and the existing feature continuations):
// * Allocate/Discard/Lifecycle/Rename/Reconcile/EpochDrain/legacy Judge were
//   inline, including replies. They stay FIFO on Ordered (one worker). In
//   particular active-driver, v20/recovery-ready and drain-replay state from
//   a reconcile/drain reply is visible to the next ordered handler.
// * Seal/public-open/native-lifecycle/private-cancellation/bound-allocation
//   already overlapped those handlers and each other. Their captured driver
//   comes from the preceding ordered completion, never receiver scheduling.
//   Existing journal/destination-generation barriers remain their authority;
//   no new lifecycle lock spans I/O and journal -> budget order is unchanged.
// * Bound allocation uses Allocation; the other existing asynchronous work
//   uses Continuation. Legacy allocation stays Ordered: splitting it would
//   change the observable v1/v20 ordering. Growth has no registered handler;
//   its queue, workers, cancellation and failure replies are independent.
// * A reply credit is reserved BEFORE dequeue. Saturation never waits on an
//   operation lane: its reserved credit guarantees a bounded failure slot.
//   If reply delivery itself stalls, intake backpressures before dequeue;
//   accepting unlimited messages with bounded storage is impossible. Growth
//   has separate credits/replies; it never waits on ordinary reply workers.
//   The physical receive transport still shares the pre-dequeue backpressure.
internal sealed class StagedRequestDispatcher : IDisposable
{
    internal const int GrowthWorkers = 8;
    internal const int QueuedGrowthRequests = 32;
    // Conservative shell bounds, not durable unresolved-allocation/SID caps.
    // Bound allocation has at most eight running + queued operations.
    internal const int AllocationWorkers = 2;
    internal const int QueuedAllocationRequests = 6;
    internal const int OrderedWorkers = 1;
    internal const int QueuedOrderedRequests = 32;
    internal const int ContinuationWorkers = 8;
    internal const int QueuedContinuationRequests = 32;
    internal const int FailureReplyWorkers = 1;
    internal const int PendingFailureReplies = 64;
    internal const int PendingGrowthFailureReplies = GrowthWorkers + QueuedGrowthRequests;

    private readonly object _gate = new();
    private readonly Func<bool> _isCurrent;
    private readonly Action<Exception> _replyFailed;
    private readonly StagedRequestLane _ordered = new(OrderedWorkers, QueuedOrderedRequests);
    private readonly StagedRequestLane _allocation = new(AllocationWorkers, QueuedAllocationRequests);
    private readonly StagedRequestLane _continuation = new(ContinuationWorkers, QueuedContinuationRequests);
    private readonly StagedRequestLane _growth = new(GrowthWorkers, QueuedGrowthRequests);
    private readonly StagedRequestLane _failures = new(FailureReplyWorkers, PendingFailureReplies);
    private readonly StagedRequestLane _growthFailures = new(FailureReplyWorkers, PendingGrowthFailureReplies);
    private readonly SemaphoreSlim _replyCredits = new(PendingFailureReplies, PendingFailureReplies);
    private readonly SemaphoreSlim _growthReplyCredits = new(PendingGrowthFailureReplies, PendingGrowthFailureReplies);
    private readonly CancellationTokenSource _stop = new();
    private readonly CancellationTokenSource _receiveStop = new();
    private readonly CancellationTokenRegistration _cancellation;
    private Task? _drain;
    private int _revoked;
    private bool _disposed;
    internal Guid Cookie { get; } = Guid.NewGuid();
    internal bool IsCurrent(Guid cookie) => cookie == Cookie && Volatile.Read(ref _revoked) == 0 && _isCurrent();

    internal StagedRequestDispatcher(CancellationToken connectionToken, Func<bool> isCurrent,
        Action<Exception> replyFailed)
    {
        _isCurrent = isCurrent;
        _replyFailed = replyFailed;
        _cancellation = connectionToken.Register(Revoke);
    }

    internal sealed class ReplyCredit(SemaphoreSlim credits, bool growth) : IDisposable
    {
        private SemaphoreSlim? _credits = credits;
        internal bool Growth { get; } = growth;
        internal bool BelongsTo(SemaphoreSlim pool) => ReferenceEquals(_credits, pool);
        internal ReplyCredit Transfer() => new(Interlocked.Exchange(ref _credits, null) ??
            throw new InvalidOperationException("The reply credit was already consumed."), Growth);
        public void Dispose() => Interlocked.Exchange(ref _credits, null)?.Release();
    }

    internal async ValueTask<ReplyCredit> ReserveReplyAsync(CancellationToken token, bool growth = false)
    {
        var credits = growth ? _growthReplyCredits : _replyCredits;
        using var linked = CancellationTokenSource.CreateLinkedTokenSource(token, _receiveStop.Token);
        await credits.WaitAsync(linked.Token).ConfigureAwait(false);
        return new(credits, growth);
    }

    internal bool Dispatch(ReplyCredit credit, Guid cookie, StagedDispatchLane lane,
        Func<CancellationToken, Task> operation, Func<Exception?, Task> failure,
        Func<Func<CancellationToken, Task>, Func<CancellationToken, Task>>? decorate = null,
        Action? completed = null)
    {
        lock (_gate)
        {
            if (_drain is not null || _disposed) throw new InvalidOperationException("The port dispatcher is draining.");
            if (credit.Growth != (lane == StagedDispatchLane.Growth) ||
                !credit.BelongsTo(credit.Growth ? _growthReplyCredits : _replyCredits))
                throw new ArgumentException("The reply credit must belong to the request lane.", nameof(credit));

            Func<CancellationToken, Task> Run(bool rejected) => async laneToken =>
            {
                using var linked = CancellationTokenSource.CreateLinkedTokenSource(laneToken, _stop.Token);
                try
                {
                    Exception? error = null;
                    bool execute = !rejected && !linked.IsCancellationRequested && IsCurrent(cookie);
                    if (execute)
                    {
                        try { await operation(linked.Token).ConfigureAwait(false); }
                        catch (Exception caught) { error = caught; }
                    }
                    if (!execute || error is not null)
                    {
                        try { await failure(error).ConfigureAwait(false); }
                        catch (Exception replyError) { _replyFailed(replyError); }
                    }
                }
                finally { completed?.Invoke(); }
            };
            var target = lane switch
            {
                StagedDispatchLane.Ordered => _ordered,
                StagedDispatchLane.Allocation => _allocation,
                StagedDispatchLane.Continuation => _continuation,
                StagedDispatchLane.Growth => _growth,
                _ => throw new ArgumentOutOfRangeException(nameof(lane))
            };
            Func<CancellationToken, Task> Wrap(Func<CancellationToken, Task> run) => decorate?.Invoke(run) ?? run;
            if (IsCurrent(cookie) && target.TryDispatch(Wrap(Run(false))))
            {
                credit.Dispose();
                return true;
            }
            var rejected = Wrap(Run(true));
            var replies = credit.Growth ? _growthFailures : _failures;
            var ownedCredit = credit.Transfer();
            // Every queued rejection owns a pre-dequeue credit. There cannot
            // be more queued rejections than this lane's fixed queue bound.
            if (!replies.TryDispatch(async token =>
            {
                try { await rejected(token).ConfigureAwait(false); }
                finally { ownedCredit.Dispose(); }
            })) throw new InvalidOperationException("A reserved failure reply slot was lost.");
            return false;
        }
    }

    internal void Revoke()
    {
        // Synchronously release growth waiters before cancelling any work
        // that could drain an object on which a growth waiter depends.
        if (Interlocked.Exchange(ref _revoked, 1) != 0) return;
        RevokeGrowth();
        _receiveStop.Cancel();
        _stop.Cancel();
    }

    internal void RevokeGrowth() => _growth.Stop();

    internal Task DrainAsync()
    {
        lock (_gate) return _drain ??= DrainCoreAsync();
    }

    private async Task DrainCoreAsync()
    {
        Revoke();
        try
        {
            await Task.WhenAll(_growth.DrainAsync(), _growthFailures.DrainAsync()).ConfigureAwait(false);
        }
        finally
        {
            try
            {
                await Task.WhenAll(_ordered.DrainAsync(), _allocation.DrainAsync(), _continuation.DrainAsync()).ConfigureAwait(false);
            }
            finally { await _failures.DrainAsync().ConfigureAwait(false); }
        }
    }

    public void Dispose()
    {
        if (_disposed) return;
        try { DrainAsync().GetAwaiter().GetResult(); }
        finally
        {
            _disposed = true;
            _cancellation.Dispose();
            _ordered.Dispose(); _allocation.Dispose(); _continuation.Dispose();
            _growth.Dispose(); _failures.Dispose(); _growthFailures.Dispose();
            _stop.Dispose(); _receiveStop.Dispose(); _replyCredits.Dispose(); _growthReplyCredits.Dispose();
        }
    }
}
