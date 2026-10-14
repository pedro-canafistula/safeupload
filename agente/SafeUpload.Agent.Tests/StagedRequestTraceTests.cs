using Microsoft.Extensions.Logging;
using SafeUpload.Agent.Minifilter;
using SafeUpload.Agent.Service.Interception;

namespace SafeUpload.Agent.Tests;

public sealed class StagedRequestTraceTests
{
    private sealed class CaptureLogger : ILogger
    {
        internal readonly List<string> Messages = [];
        public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;
        public bool IsEnabled(LogLevel level) => true;
        public void Log<TState>(LogLevel level, EventId eventId, TState state, Exception? exception,
            Func<TState, Exception?, string> formatter) => Messages.Add(formatter(state, exception));
    }

    [Theory]
    [InlineData(Operation.Create, "Create")]
    [InlineData(Operation.StageSeal, "StageSeal")]
    [InlineData(Operation.StageAllocate, "StageAllocate")]
    [InlineData(uint.MaxValue, "Unknown")]
#if SAFEUPLOAD_ADMISSION_EVIDENCE
    [InlineData(NativeLifecycleV24.Operation, "NativeLifecycleV24")]
    [InlineData(PublicDispositionV25.Operation, "PublicDispositionV25")]
    [InlineData(PrivateCancellationV28.Operation, "PrivateCancellationV28")]
#endif
    public void Operation_names_identify_requests_without_guessing_from_the_reply(uint operation, string expected)
        => Assert.Equal(expected, StagedRequestTrace.OperationName(operation));

    [Fact]
    public void Every_base_protocol_operation_has_a_diagnostic_name()
    {
        foreach (var field in typeof(Operation).GetFields())
            Assert.Equal(field.Name, StagedRequestTrace.OperationName((uint)field.GetRawConstantValue()!));
    }

    [Fact]
    public async Task Deferred_request_logs_only_when_handler_finishes_with_original_dequeue_age()
    {
        long now = 0;
        var timing = new StagedRequestTiming(() => now, 1000);
        var logger = new CaptureLogger();
        var heartbeat = new StagedReceiveHeartbeat(() => now, 1000);
        heartbeat.Start();
        var release = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        Task work;
        using (var trace = new StagedRequestTrace(new() { RequestId = 1833, Operation = Operation.StageSeal },
            44, logger, heartbeat, timing))
        {
            var operation = trace.Defer(async _ =>
            {
                await release.Task;
                Assert.Same(timing, StagedRequestTiming.Current);
                using var seal = StagedRequestTiming.Measure("inspection-seal");
            });
            work = Task.Run(() => operation(CancellationToken.None));
        }
        Assert.Empty(logger.Messages);
        Assert.Null(StagedRequestTiming.Current);
        now = 2000;
        release.SetResult();
        await work;
        string message = Assert.Single(logger.Messages);
        Assert.Contains("request", message, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("1833", message);
        Assert.Contains("StageSeal (4)", message);
        Assert.Contains("inspection-seal=0.0@2000.0", message);
        Assert.Contains("handler=2000.0@2000.0", message);
    }

#if SAFEUPLOAD_ADMISSION_EVIDENCE
    [Theory]
    [InlineData(0, 999, false)]
    [InlineData(0, 1000, true)]
    [InlineData(unchecked((int)0x801F0020), 0, true)]
    [InlineData(unchecked((int)0x80070005), 0, true)]
    public void Native_reply_observation_preserves_warning_rule_and_formats_operation(int status, long elapsed, bool warning)
    {
        long now = 0;
        var timing = new StagedRequestTiming(() => now, 1000);
        var logger = new CaptureLogger();
        using (var trace = new StagedRequestTrace(new() { RequestId = 1836, Operation = Operation.Create },
            45, logger, new StagedReceiveHeartbeat(), timing))
        {
            now = elapsed;
            using var reply = FilterReplyObservation.Begin();
            Assert.NotNull(reply);
            reply.Complete(status);
        }
        Assert.Equal(warning ? 1 : 0, logger.Messages.Count);
        if (warning)
        {
            Assert.Contains("Create (1)", logger.Messages[0]);
            Assert.Contains($"0x{status:X8}", logger.Messages[0]);
            Assert.Contains("reply=0.0@", logger.Messages[0]);
        }
        Assert.Null(FilterReplyObservation.Begin());
    }
#endif
}
