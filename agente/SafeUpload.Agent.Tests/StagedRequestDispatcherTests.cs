using System.Collections.Concurrent;
using System.Runtime.InteropServices;
using System.Text;
using Microsoft.Extensions.Logging.Abstractions;
using SafeUpload.Agent.Minifilter;
using SafeUpload.Agent.Service.Interception;

namespace SafeUpload.Agent.Tests;

public sealed class StagedRequestDispatcherTests
{
    private static TaskCompletionSource Signal() => new(TaskCreationOptions.RunContinuationsAsynchronously);
    private static Task Wait(Task task) => task.WaitAsync(TimeSpan.FromSeconds(10));
    private static StagedRequestDispatcher Dispatcher(ConcurrentQueue<Exception> errors,
        CancellationToken token = default, Func<bool>? current = null) => new(token, current ?? (() => true), errors.Enqueue);

    private static async Task<bool> Send(StagedRequestDispatcher dispatcher, StagedDispatchLane lane,
        Func<CancellationToken, Task> execute, Func<Exception?, Task>? failure = null, Guid? cookie = null,
        Action? completed = null)
    {
        using var credit = await dispatcher.ReserveReplyAsync(default, lane == StagedDispatchLane.Growth);
        return dispatcher.Dispatch(credit, cookie ?? dispatcher.Cookie, lane, execute,
            failure ?? (_ => Task.CompletedTask), completed: completed);
    }

    [Fact]
    public async Task Ordered_lane_is_FIFO_at_the_dispatch_linearization_point_under_concurrent_producers()
    {
        var errors = new ConcurrentQueue<Exception>();
        using var dispatcher = Dispatcher(errors);
        var entered = Signal(); var release = Signal(); var complete = Signal();
        Assert.True(await Send(dispatcher, StagedDispatchLane.Ordered, async token =>
        { entered.SetResult(); await release.Task.WaitAsync(token); }));
        await Wait(entered.Task);
        var expected = new List<int>(); var observed = new List<int>();
        object gate = new();
        await Task.WhenAll(Enumerable.Range(0, 4).Select(producer => Task.Run(async () =>
        {
            for (int n = 0; n < 8; n++)
            {
                int id = producer * 8 + n;
                using var credit = await dispatcher.ReserveReplyAsync(default);
                lock (gate)
                {
                    expected.Add(id);
                    Assert.True(dispatcher.Dispatch(credit, dispatcher.Cookie, StagedDispatchLane.Ordered, _ =>
                    {
                        observed.Add(id);
                        if (observed.Count == 32) complete.SetResult();
                        return Task.CompletedTask;
                    }, error => throw new InvalidOperationException("Unexpected FIFO refusal", error)));
                }
            }
        })));
        release.SetResult();
        await Wait(complete.Task);
        Assert.Equal(expected, observed);
        Assert.Empty(errors);
    }

    [Theory]
    [InlineData(0, 1, 32)]
    [InlineData(1, 2, 6)]
    [InlineData(2, 8, 32)]
    [InlineData(3, 8, 32)]
    public async Task Full_lane_refuses_with_correlated_reply_without_waiting_or_starving_another_lane(
        int laneId, int workers, int queued)
    {
        var lane = (StagedDispatchLane)laneId;
        var errors = new ConcurrentQueue<Exception>();
        using var dispatcher = Dispatcher(errors);
        var allEntered = Signal(); var release = Signal();
        int running = 0, mutations = 0;
        for (int n = 0; n < workers; n++)
            Assert.True(await Send(dispatcher, lane, async token =>
            {
                if (Interlocked.Increment(ref running) == workers) allEntered.SetResult();
                await release.Task.WaitAsync(token);
            }));
        await Wait(allEntered.Task);
        for (int n = 0; n < queued; n++)
            Assert.True(await Send(dispatcher, lane, _ => Task.CompletedTask));
        ulong messageId = 734, requestId = 913;
        var reply = new TaskCompletionSource<(ulong, ulong, uint)>(TaskCreationOptions.RunContinuationsAsynchronously);
        Assert.False(await Send(dispatcher, lane, _ =>
        { Interlocked.Increment(ref mutations); return Task.CompletedTask; }, error =>
        { reply.SetResult((messageId, requestId, Verdict.Deny)); return Task.CompletedTask; }));
        Assert.Equal((messageId, requestId, Verdict.Deny), await reply.Task.WaitAsync(TimeSpan.FromSeconds(10)));
        Assert.False(release.Task.IsCompleted);
        var independent = Signal();
        var other = lane == StagedDispatchLane.Growth ? StagedDispatchLane.Ordered : StagedDispatchLane.Growth;
        Assert.True(await Send(dispatcher, other, _ => { independent.SetResult(); return Task.CompletedTask; }));
        await Wait(independent.Task);
        Assert.Equal(0, mutations);
        release.SetResult();
        Assert.Empty(errors);
    }

    [Fact]
    public async Task Blocked_ordered_handler_leaves_dequeue_and_growth_reply_free()
    {
        var errors = new ConcurrentQueue<Exception>();
        using var dispatcher = Dispatcher(errors);
        var entered = Signal(); var release = Signal(); var growthReply = Signal();
        var messages = new Queue<(ulong Message, ulong Request, StagedDispatchLane Lane)>([
            (51, 151, StagedDispatchLane.Ordered), (52, 152, StagedDispatchLane.Growth),
            (53, 153, StagedDispatchLane.Ordered)]);
        var replied = new ConcurrentQueue<(ulong, ulong)>();
        int received = 0;
        while (messages.TryDequeue(out var message))
        {
            received++;
            Assert.True(await Send(dispatcher, message.Lane, async token =>
            {
                if (message.Message == 51) { entered.SetResult(); await release.Task.WaitAsync(token); }
                replied.Enqueue((message.Message, message.Request));
                if (message.Lane == StagedDispatchLane.Growth) growthReply.SetResult();
            }));
        }
        await Wait(entered.Task); await Wait(growthReply.Task);
        Assert.Equal(3, received);
        Assert.Equal((52UL, 152UL), Assert.Single(replied));
        release.SetResult();
        Assert.Empty(errors);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task Revoke_and_connection_cancellation_release_growth_before_cancelling_dependent_work(bool externalCancel)
    {
        var errors = new ConcurrentQueue<Exception>();
        using var connection = new CancellationTokenSource();
        using var dispatcher = Dispatcher(errors, connection.Token);
        var growthEntered = Signal(); var growthReleased = Signal(); var growthExited = Signal();
        var restEntered = Signal(); var restExited = Signal();
        Assert.True(await Send(dispatcher, StagedDispatchLane.Growth, async token =>
        {
            using var release = token.Register(() => growthReleased.SetResult());
            growthEntered.SetResult();
            try { await Task.Delay(Timeout.Infinite, token); }
            finally { growthExited.SetResult(); }
        }));
        Assert.True(await Send(dispatcher, StagedDispatchLane.Ordered, async token =>
        {
            restEntered.SetResult();
            try { await Task.Delay(Timeout.Infinite, token); }
            finally
            {
                Assert.True(growthReleased.Task.IsCompleted);
                restExited.SetResult();
            }
        }));
        await Wait(Task.WhenAll(growthEntered.Task, restEntered.Task));
        if (externalCancel) connection.Cancel(); else dispatcher.Revoke();
        Assert.False(dispatcher.IsCurrent(dispatcher.Cookie));
        await Wait(dispatcher.DrainAsync());
        Assert.True(growthExited.Task.IsCompleted); Assert.True(restExited.Task.IsCompleted);
        Assert.Empty(errors);
    }

    [Fact]
    public async Task Stale_cookie_and_revoked_queued_work_reply_without_mutation_and_dispose_joins_every_item()
    {
        var errors = new ConcurrentQueue<Exception>();
        var dispatcher = Dispatcher(errors);
        var staleReply = Signal();
        int mutations = 0, failures = 0;
        Assert.False(await Send(dispatcher, StagedDispatchLane.Ordered,
            _ => { Interlocked.Increment(ref mutations); return Task.CompletedTask; },
            _ => { staleReply.SetResult(); return Task.CompletedTask; }, Guid.NewGuid()));
        await Wait(staleReply.Task);
        var entered = Signal();
        Assert.True(await Send(dispatcher, StagedDispatchLane.Ordered, async token =>
        { entered.SetResult(); await Task.Delay(Timeout.Infinite, token); }));
        await Wait(entered.Task);
        for (int n = 0; n < 32; n++)
            Assert.True(await Send(dispatcher, StagedDispatchLane.Ordered,
                _ => { Interlocked.Increment(ref mutations); return Task.CompletedTask; },
                _ => { Interlocked.Increment(ref failures); return Task.CompletedTask; }));
        // The extra credit represents a dequeued item racing with shutdown.
        using var credit = await dispatcher.ReserveReplyAsync(default);
        await Wait(dispatcher.DrainAsync());
        Assert.Throws<InvalidOperationException>(() => dispatcher.Dispatch(credit, dispatcher.Cookie,
            StagedDispatchLane.Ordered, _ => Task.CompletedTask, _ => Task.CompletedTask));
        credit.Dispose();
        dispatcher.Dispose();
        Assert.Throws<InvalidOperationException>(() => dispatcher.Dispatch(credit, dispatcher.Cookie,
            StagedDispatchLane.Ordered, _ => { mutations++; return Task.CompletedTask; }, _ => Task.CompletedTask));
        Assert.Equal(0, mutations); Assert.Equal(32, failures); Assert.Empty(errors);
    }

    [Fact]
    public async Task Replacement_connection_identity_fences_already_queued_work_before_any_side_effect()
    {
        var errors = new ConcurrentQueue<Exception>(); int current = 1, mutations = 0;
        using var dispatcher = Dispatcher(errors, current: () => Volatile.Read(ref current) == 1);
        var entered = Signal(); var release = Signal(); var refused = Signal();
        Assert.True(await Send(dispatcher, StagedDispatchLane.Ordered, async token =>
        { entered.SetResult(); await release.Task.WaitAsync(token); }));
        await Wait(entered.Task);
        Assert.True(await Send(dispatcher, StagedDispatchLane.Ordered,
            _ => { Interlocked.Increment(ref mutations); return Task.CompletedTask; },
            _ => { refused.SetResult(); return Task.CompletedTask; }));
        Volatile.Write(ref current, 0); release.SetResult();
        await Wait(refused.Task);
        Assert.Equal(0, mutations); Assert.Empty(errors);
    }

    [Fact]
    public async Task Exception_yields_one_failure_and_reply_failure_does_not_kill_lane_or_retry_public_mutation()
    {
        var errors = new ConcurrentQueue<Exception>();
        using var dispatcher = Dispatcher(errors);
        var complete = Signal(); int mutations = 0, attempts = 0;
        var handlerError = new IOException("handler failed before reply");
        var replyError = new IOException("reply port failed");
        Assert.True(await Send(dispatcher, StagedDispatchLane.Ordered, _ =>
        { mutations++; throw handlerError; }, error =>
        { Assert.Same(handlerError, error); attempts++; throw replyError; }));
        Assert.True(await Send(dispatcher, StagedDispatchLane.Ordered,
            _ => { complete.SetResult(); return Task.CompletedTask; }));
        await Wait(complete.Task);
        Assert.Equal(1, mutations); Assert.Equal(1, attempts);
        Assert.Same(replyError, Assert.Single(errors));
    }

    [Fact]
    public async Task Unexpected_completion_fault_still_joins_other_lanes_before_disposal()
    {
        var errors = new ConcurrentQueue<Exception>();
        var dispatcher = Dispatcher(errors);
        var entered = Signal(); var exited = Signal(); var faulted = Signal();
        Assert.True(await Send(dispatcher, StagedDispatchLane.Ordered, async token =>
        {
            entered.SetResult();
            try { await Task.Delay(Timeout.Infinite, token); }
            finally { exited.SetResult(); }
        }));
        await Wait(entered.Task);
        var fault = new IOException("Completion observer failed");
        Assert.True(await Send(dispatcher, StagedDispatchLane.Growth, _ => Task.CompletedTask,
            completed: () => { faulted.SetResult(); throw fault; }));
        await Wait(faulted.Task);
        Assert.Same(fault, await Assert.ThrowsAsync<IOException>(() => dispatcher.DrainAsync()));
        Assert.True(exited.Task.IsCompleted);
        Assert.Same(fault, Assert.Throws<IOException>(() => dispatcher.Dispose()));
        Assert.Empty(errors);
    }

    [Fact]
    public async Task Stalled_failure_delivery_is_bounded_before_dequeue_and_growth_has_its_own_reply_capacity()
    {
        var errors = new ConcurrentQueue<Exception>();
        using var dispatcher = Dispatcher(errors);
        var entered = Signal(); var release = Signal(); int refused = 0;
        for (int n = 0; n < StagedRequestDispatcher.PendingFailureReplies; n++)
        {
            using var credit = await dispatcher.ReserveReplyAsync(default);
            Assert.False(dispatcher.Dispatch(credit, Guid.NewGuid(), StagedDispatchLane.Ordered,
                _ => throw new InvalidOperationException("Stale work executed"), async _ =>
                {
                    entered.TrySetResult();
                    await release.Task;
                    Interlocked.Increment(ref refused);
                }));
        }
        await Wait(entered.Task);
        var waitingCredit = dispatcher.ReserveReplyAsync(default).AsTask();
        Assert.False(waitingCredit.IsCompleted);
        var growthReply = Signal();
        Assert.False(await Send(dispatcher, StagedDispatchLane.Growth, _ => Task.CompletedTask,
            _ => { growthReply.SetResult(); return Task.CompletedTask; }, Guid.NewGuid()));
        await Wait(growthReply.Task);
        release.SetResult();
        using var acquired = await waitingCredit.WaitAsync(TimeSpan.FromSeconds(10));
        await Wait(dispatcher.DrainAsync());
        Assert.Equal(StagedRequestDispatcher.PendingFailureReplies, refused);
        acquired.Dispose();
        Assert.Empty(errors);
    }

    [Fact]
    public async Task Fixed_workers_preserve_dequeue_trace_context_and_native_reply_observation()
    {
        var errors = new ConcurrentQueue<Exception>();
        using var dispatcher = Dispatcher(errors);
        var completed = Signal();
        var heartbeat = new StagedReceiveHeartbeat(); heartbeat.Start();
        var timing = new StagedRequestTiming();
        using (var trace = new StagedRequestTrace(new() { RequestId = 901, Operation = Operation.StageSeal },
            801, NullLogger.Instance, heartbeat, timing))
        {
            using var credit = await dispatcher.ReserveReplyAsync(default);
            Assert.True(dispatcher.Dispatch(credit, dispatcher.Cookie, StagedDispatchLane.Ordered, async _ =>
            {
                await Task.Yield();
                Assert.Same(timing, StagedRequestTiming.Current);
#if SAFEUPLOAD_ADMISSION_EVIDENCE
                using var observation = FilterReplyObservation.Begin();
                Assert.NotNull(observation); observation.Complete(0);
#endif
            }, _ => throw new InvalidOperationException("Unexpected trace refusal"), trace.Defer,
                () => completed.SetResult()));
        }
        await Wait(completed.Task);
        Assert.Null(StagedRequestTiming.Current);
#if SAFEUPLOAD_ADMISSION_EVIDENCE
        Assert.Null(FilterReplyObservation.Begin());
#endif
        Assert.Empty(errors);
    }

    [Fact]
    public async Task Continuation_captures_preceding_ordered_reply_state_and_rechecks_connection_after_wait()
    {
        var errors = new ConcurrentQueue<Exception>();
        using var dispatcher = Dispatcher(errors);
        var preceding = new TaskCompletionSource<Guid?>(TaskCreationOptions.RunContinuationsAsynchronously);
        var oldDriver = Guid.NewGuid(); var newDriver = Guid.NewGuid();
        var pending = MinifilterInterceptor.AwaitDispatchDriverAsync(preceding.Task, dispatcher, dispatcher.Cookie, default);
        Assert.False(pending.IsCompleted);
        preceding.SetResult(oldDriver);
        Assert.Equal(oldDriver, await pending);
        // A later reconcile cannot rewrite the immutable preceding snapshot.
        Assert.NotEqual(newDriver, await MinifilterInterceptor.AwaitDispatchDriverAsync(preceding.Task,
            dispatcher, dispatcher.Cookie, default));
        var waiting = new TaskCompletionSource<Guid?>(TaskCreationOptions.RunContinuationsAsynchronously);
        var stale = MinifilterInterceptor.AwaitDispatchDriverAsync(waiting.Task, dispatcher, dispatcher.Cookie, default);
        dispatcher.Revoke(); waiting.SetResult(oldDriver);
        await Assert.ThrowsAsync<OperationCanceledException>(() => stale);
        Assert.Empty(errors);
    }

    [Fact]
    public async Task Thousand_messages_with_randomized_completion_have_one_correlated_outcome_each()
    {
        var errors = new ConcurrentQueue<Exception>();
        using var dispatcher = Dispatcher(errors);
        var replies = new ConcurrentDictionary<(ulong Message, ulong Request), bool>();
        var completionOrder = new ConcurrentQueue<ulong>();
        var complete = Signal(); var release = Signal(); int finished = 0;
        var random = new Random(9571);
        for (ulong n = 0; n < 1000; n++)
        {
            ulong message = n + 1000, request = n + 2000;
            int delay = random.Next(1, 8);
            var lane = (StagedDispatchLane)(n % 4);
            void Reply(bool accepted)
            {
                Assert.True(replies.TryAdd((message, request), accepted));
                completionOrder.Enqueue(message);
            }
            await Send(dispatcher, lane, async token =>
                { await release.Task.WaitAsync(token); await Task.Delay(delay, token); Reply(true); },
                _ => { Reply(false); return Task.CompletedTask; }, completed: () =>
                { if (Interlocked.Increment(ref finished) == 1000) complete.SetResult(); });
        }
        release.SetResult();
        await Wait(complete.Task);
        await Wait(dispatcher.DrainAsync());
        Assert.Equal(1000, replies.Count);
        Assert.Equal(Enumerable.Range(0, 1000).Select(n => ((ulong)n + 1000, (ulong)n + 2000)).Order(), replies.Keys.Order());
        Assert.Contains(true, replies.Values); Assert.Contains(false, replies.Values);
        Assert.False(completionOrder.SequenceEqual(completionOrder.Order()));
        Assert.Empty(errors);
    }

    [Theory]
    [InlineData(Operation.StageAllocate)] [InlineData(Operation.StageDiscard)]
    [InlineData(Operation.StageReconcile)] [InlineData(Operation.StageEpochDrain)]
    [InlineData(Operation.StageRename)] [InlineData(Operation.StageAttachCommit)]
    [InlineData(Operation.Create)] [InlineData(Operation.Read)]
    public void Former_inline_operations_keep_one_ordered_lane_and_no_growth_handler_is_registered(uint operation)
    {
        var request = new SafeUploadRequest { Version = Contract.Version, StructSize = Contract.RequestSize, Operation = operation };
        Assert.Equal(StagedDispatchLane.Ordered, MinifilterInterceptor.DispatchLane(request));
        foreach (var field in typeof(Operation).GetFields())
        {
            request.Operation = (uint)field.GetRawConstantValue()!;
            Assert.NotEqual(StagedDispatchLane.Growth, MinifilterInterceptor.DispatchLane(request));
        }
        request.Version++;
        Assert.False(MinifilterInterceptor.HasDispatchHeader(request));
    }

    [Fact]
    public void Saturation_rename_reply_is_the_existing_exact_retry_receipt_and_malformed_tuples_still_get_generic_denial()
    {
        var source = new SafeUploadStageRenameV20
        {
            Version = Contract.StageExtensionVersion, StructSize = Contract.StageRenameV20Size,
            Operation = Operation.StageRenameCommit, RequestId = 731, TransferId = Guid.NewGuid(),
            SourceGeneration = 17, StageIdentity = new() { FileIdLow = 1 }, DriverInstanceId = Guid.NewGuid(),
            ParentDirectoryIdentity = new() { FileIdLow = 2 }, ViewGeneration = 31, OwnerProcessId = 123
        };
        const string destination = @"C:\protected\document.txt";
        var request = Typed(source.Operation, source);
        var failure = MinifilterInterceptor.CreateDispatchFailure(request);
        var expected = FilterPort.CreateStageRenameReplyV20(source, 0, destination, StageV20Result.RetryableFailure);
        var actual = failure.Rename!.Value;
        Assert.Equal(Bytes(expected), Bytes(actual));
        FilterPort.ValidateStageRenameReplyV20(actual);
        source.TransferId = Guid.Empty;
        Assert.Null(MinifilterInterceptor.CreateDispatchFailure(Typed(source.Operation, source)).Rename);
        source.Operation = Operation.StageRename;
        Assert.Null(MinifilterInterceptor.CreateDispatchFailure(Typed(source.Operation, source)).Rename);

        static byte[] Bytes<T>(T value) where T : unmanaged =>
            MemoryMarshal.AsBytes(MemoryMarshal.CreateReadOnlySpan(ref value, 1)).ToArray();
        static SafeUploadRequest Typed<T>(uint operation, T payload) where T : unmanaged
        {
            var request = new SafeUploadRequest
            {
                Version = Contract.Version, StructSize = Contract.RequestSize, Operation = operation,
                RequestId = 731, RequestorProcessId = 123, Reserved = Contract.StageExtensionVersion,
                PathLength = (uint)destination.Length * 2, ImageNameLength = (uint)Marshal.SizeOf<T>()
            };
            var bytes = Bytes(request);
            Encoding.Unicode.GetBytes(destination).CopyTo(bytes, 40);
            Bytes(payload).CopyTo(bytes, 1064);
            return MemoryMarshal.Read<SafeUploadRequest>(bytes);
        }
    }
}
