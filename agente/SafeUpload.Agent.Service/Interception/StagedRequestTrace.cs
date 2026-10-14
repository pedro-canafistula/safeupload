using SafeUpload.Agent.Minifilter;

namespace SafeUpload.Agent.Service.Interception;

internal sealed class StagedRequestTrace : IDisposable
{
    private readonly ILogger _logger;
    private readonly SafeUploadRequest _request;
    private readonly ulong _messageId;
    private readonly StagedReceiveHeartbeat _heartbeat;
    private readonly IDisposable _ambient;
    private readonly IDisposable _observer;
    private readonly IDisposable _handler;
    private readonly IDisposable _preparation;
    private IDisposable? _replyPhase;
    private readonly List<string> _replies = [];
    private bool _failedReply;
    private bool _deferred;
    internal StagedRequestTiming Timing { get; }
    internal StagedAllocation? Allocation { get; set; }

    internal StagedRequestTrace(SafeUploadRequest request, ulong messageId, ILogger logger,
        StagedReceiveHeartbeat heartbeat, StagedRequestTiming? timing = null)
    {
        Timing = timing ?? new();
        _request = request;
        _messageId = messageId;
        _logger = logger;
        _heartbeat = heartbeat;
        _ambient = Timing.Activate();
        _handler = Timing.StartPhase("handler");
        _preparation = Timing.StartPhase("prepare");
        _observer = FilterReplyObservation.Listen((starting, status) =>
        {
            if (starting)
            {
                _preparation.Dispose();
                _handler.Dispose();
                _replyPhase = Timing.StartPhase("reply");
            }
            else
            {
                _replyPhase?.Dispose();
                _replies.Add(status switch
                {
                    0 => "Delivered (0x00000000)",
                    unchecked((int)0x801F0020) => "ERROR_FLT_NO_WAITER_FOR_REPLY (0x801F0020)",
                    { } hr => $"0x{hr:X8}",
                    _ => "exception"
                });
                _failedReply |= status != 0;
            }
        });
        heartbeat.Handling(request.RequestId, OperationName(request.Operation), Timing);
    }

    internal static string OperationName(uint operation) => operation switch
    {
        Operation.Create => nameof(Operation.Create),
        Operation.Read => nameof(Operation.Read),
        Operation.StageAllocate => nameof(Operation.StageAllocate),
        Operation.StageSeal => nameof(Operation.StageSeal),
        Operation.StageRename => nameof(Operation.StageRename),
        Operation.StageDiagnostic => nameof(Operation.StageDiagnostic),
        Operation.StageRenameCommit => nameof(Operation.StageRenameCommit),
        Operation.StageRenameAbort => nameof(Operation.StageRenameAbort),
        Operation.StageDiscard => nameof(Operation.StageDiscard),
        Operation.StageCreateAfterDiscard => nameof(Operation.StageCreateAfterDiscard),
        Operation.StageReconcile => nameof(Operation.StageReconcile),
        Operation.StageAttachPrepare => nameof(Operation.StageAttachPrepare),
        Operation.StageAttachCommit => nameof(Operation.StageAttachCommit),
        Operation.StageAttachAbort => nameof(Operation.StageAttachAbort),
        Operation.StageCompletionPermit => nameof(Operation.StageCompletionPermit),
        Operation.StageRetireUnexposed => nameof(Operation.StageRetireUnexposed),
        Operation.StageEpochDrain => nameof(Operation.StageEpochDrain),
        Operation.StageRetireAttachedPrivate => nameof(Operation.StageRetireAttachedPrivate),
        Operation.StageHandleObserved => nameof(Operation.StageHandleObserved),
#if SAFEUPLOAD_ADMISSION_EVIDENCE
        NativeLifecycleV24.Operation => nameof(NativeLifecycleV24),
        PublicDispositionV25.Operation => nameof(PublicDispositionV25),
        PrivateCancellationV28.Operation => nameof(PrivateCancellationV28),
#endif
        _ => "Unknown"
    };

    internal Func<CancellationToken, Task> Defer(Func<CancellationToken, Task> operation)
    {
        _deferred = true;
        return async token =>
        {
            try { await operation(token).ConfigureAwait(false); }
            finally { Complete(); }
        };
    }

    private void Complete()
    {
        _preparation.Dispose();
        _handler.Dispose();
        _heartbeat.Complete(Timing);
        if (Timing.ShouldWarn(_failedReply || _replies.Count == 0))
            _logger.LogWarning("Request {RequestId}, message {MessageId}, operation {Operation} ({OperationId}), " +
                "reply {Reply}, transfer {TransferId}, generation {Generation}, file {FileIdentity}, " +
                "elapsed {ElapsedMs:F1} ms, phases {Phases} (inclusive duration@dequeue-offset ms).",
                _request.RequestId, _messageId, OperationName(_request.Operation), _request.Operation, string.Join(",", _replies),
                Allocation?.Entry.Transfer.TransferId, Allocation?.Entry.DestinationGeneration,
                Allocation?.Identity, Timing.ElapsedMs, Timing.ToString());
    }
    public void Dispose()
    {
        if (!_deferred) Complete();
        _observer.Dispose();
        _ambient.Dispose();
    }
}

public sealed partial class MinifilterInterceptor
{
    private async Task ReceiveHeartbeatAsync(StagedReceiveHeartbeat heartbeat, CancellationToken token)
    {
        using var timer = new PeriodicTimer(TimeSpan.FromSeconds(1));
        while (await timer.WaitForNextTickAsync(token).ConfigureAwait(false))
            if (heartbeat.Poll() is { } state)
                _logger.LogInformation("Minifilter receive heartbeat: {LoopState}.", state);
    }
}
