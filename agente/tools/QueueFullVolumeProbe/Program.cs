using System.Reflection;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text.Json;
using Microsoft.Extensions.Logging;
using SafeUpload.Agent.Core.Domain;
using SafeUpload.Agent.Core.Infrastructure;
using SafeUpload.Agent.QueueFullVolumeProbe;
using SafeUpload.Agent.Service.Diagnostics;

// Run only through Test-QueueFullVolume.ps1 in the clone or a disposable runner.
// No production paths, installed service, driver, network or automatic queue repair.
if (args.Length != 4) throw new ArgumentException("Usage: QueueFullVolumeProbe <drive-root> <nonce-N> <volume-guid-path> <fresh-results-directory>");
var (root, nonce, volumeId, output) = (args[0], args[1], args[2], args[3]);
VolumeGuard.ValidateRequest(root, nonce, volumeId, output);
VolumeGuard.VerifyMounted(root, nonce, volumeId);
Directory.CreateDirectory(output);
var options = new JsonSerializerOptions { WriteIndented = true };
var phases = new List<object>();
var started = DateTimeOffset.UtcNow;
using var deadline = new CancellationTokenSource(TimeSpan.FromMinutes(3));
try
{
    foreach (var operation in new[] { AuditQueueOperation.WriteEvent, AuditQueueOperation.WriteOverride,
        AuditQueueOperation.ConfirmEvents, AuditQueueOperation.ConfirmOverrides })
    {
        deadline.Token.ThrowIfCancellationRequested();
        VolumeGuard.VerifyMounted(root, nonce, volumeId);
        var trial = Path.Combine(root, "trial-" + operation);
        if (Directory.Exists(trial)) throw new IOException("Trial already exists.");
        Directory.CreateDirectory(trial);
        var path = Path.Combine(trial, "queue.jsonl");
        var queue = new LocalQueueAuditSink(path);
        var events = Enumerable.Range(0, 3).Select(i => Event(i, "SYNTHETIC_ONLY")).ToArray();
        foreach (var item in events) await queue.WriteAsync(item, deadline.Token);
        var reason = new AuditOverride(events[0].EventId, "Justificativa sintetica", DateTimeOffset.UtcNow, "usuario-sintetico", "PC-SINTETICO");
        await queue.RecordOverrideAsync(reason, deadline.Token);
        var before = await File.ReadAllBytesAsync(path, deadline.Token);
        var health = new AuditQueueHealth();
        var logger = new ProbeLogger();
        var sink = new MonitoredAuditSink(queue, health, logger);
        var attempted = Event(99, "SYNTHETIC_CONTENT_DO_NOT_LOG_" + new string('X', 65536));
        var attemptedReason = reason with { EventId = Guid.NewGuid(), Justification = attempted.MaskedSnippets[0] };
        var filler = Path.Combine(root, "filler-" + Guid.NewGuid().ToString("N") + ".bin");
        long fillerBytes = 0;
        try
        {
            fillerBytes = Fill(filler, deadline.Token);
            var availableAtFailure = new DriveInfo(root).AvailableFreeSpace;
            Exception? failure = null;
            try { await Invoke(sink, operation, attempted, attemptedReason, events[0].EventId, reason, deadline.Token); }
            catch (IOException error) when (IsFull(error)) { failure = error; }
            Check(failure is not null, "Queue operation did not report a real disk-full error.");
            var failedHealth = health.Read();
            var state = failedHealth.Operations.Single(o => o.Operation == operation.ToString());
            Check(failedHealth.Degraded && state.Degraded && state.Failures == 1 && state.FailureKind == "disk_full", "Disk-full observability mismatch.");
            var afterFailure = await File.ReadAllBytesAsync(path, deadline.Token);
            Check(afterFailure.AsSpan().StartsWith(before), "An existing queue prefix was changed.");
            if (operation is AuditQueueOperation.ConfirmEvents or AuditQueueOperation.ConfirmOverrides)
                Check(before.AsSpan().SequenceEqual(afterFailure), "Failed confirmation changed published bytes.");
            var failedIntegrity = await queue.InspectIntegrityAsync(deadline.Token);
            // Release only this probe's filler. Never delete a queue, candidate or report.
            VolumeGuard.VerifyMounted(root, nonce, volumeId);
            File.Delete(filler);
            var recoveredEvent = Event(100, "RECOVERY_SYNTHETIC_ONLY");
            var recoveredReason = reason with { EventId = Guid.NewGuid(), Justification = "Retomada sintetica" };
            await Invoke(sink, operation, recoveredEvent, recoveredReason, events[0].EventId, reason, deadline.Token);
            var recoveredHealth = health.Read();
            Check(!recoveredHealth.Degraded && recoveredHealth.Operations.Single(o => o.Operation == operation.ToString()).Failures == 1, "Recovery cleared failure history or stayed degraded.");
            var reopened = new LocalQueueAuditSink(path);
            var history = await reopened.ReadRecentAsync(0, deadline.Token);
            foreach (var original in events)
            {
                var item = history.Single(e => e.EventId == original.EventId);
                Check(JsonSerializer.Serialize(item with { Dispatched = false }) == JsonSerializer.Serialize(original), "Seed metadata changed.");
            }
            var reasons = await reopened.ReadPendingOverridesAsync(0, deadline.Token);
            if (operation == AuditQueueOperation.WriteEvent) Check(history.Count(e => e.EventId == recoveredEvent.EventId) == 1, "Recovery event missing.");
            if (operation == AuditQueueOperation.WriteOverride) Check(reasons.Count(r => r.EventId == recoveredReason.EventId) == 1, "Recovery override missing.");
            if (operation == AuditQueueOperation.ConfirmEvents) Check(history.Single(e => e.EventId == events[0].EventId).Dispatched, "Retry did not confirm event.");
            if (operation == AuditQueueOperation.ConfirmOverrides) Check(!reasons.Contains(reason), "Retry did not confirm override.");
            Check(logger.Entries.Select(e => e.Id).SequenceEqual(new[] { 3101, 3102 }) && logger.Entries.All(e => !e.AttachedException), "Failure/recovery logs missing or attach an exception.");
            Check(logger.Entries.All(e => !e.Text.Contains("SYNTHETIC_CONTENT") && !e.Text.Contains(path)), "Sensitive queue details reached logs.");
            var integrity = await reopened.InspectIntegrityAsync(deadline.Token);
            phases.Add(new { operation = operation.ToString(), result = "passed", fillerBytes, availableAtFailure,
                failureType = failure!.GetType().Name, failureHResult = failure.HResult, failedHealth, recoveredHealth,
                beforeSha256 = Convert.ToHexString(SHA256.HashData(before)), afterFailureSha256 = Convert.ToHexString(SHA256.HashData(afterFailure)),
                originalPrefixPreserved = true, originalEventIds = events.Select(e => e.EventId), failedIntegrity, recoveredIntegrity = integrity,
                failedEventPresent = history.Any(e => e.EventId == attempted.EventId), failedOverridePresent = reasons.Any(r => r.EventId == attemptedReason.EventId),
                failedAppendNote = "A refused append may leave a tail or even an observable record; no failed attempt is automatically recovered. Recovery uses a NEW event/override; confirmations retry original identities.",
                logs = logger.Entries, temporaries = await reopened.InspectTemporaryFilesAsync(deadline.Token) });
            await Save("progress.json", new { result = "running", phases });
        }
        finally
        {
            VolumeGuard.VerifyMounted(root, nonce, volumeId);
            if (File.Exists(filler)) File.Delete(filler);
        }
    }
    using var identity = WindowsIdentity.GetCurrent();
    await Save("result.json", new { result = "passed", startedAtUtc = started, finishedAtUtc = DateTimeOffset.UtcNow,
        framework = RuntimeInformation.FrameworkDescription, os = RuntimeInformation.OSDescription,
        administrator = new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator), isSystem = identity.IsSystem,
        coreVersion = typeof(LocalQueueAuditSink).Assembly.GetCustomAttribute<AssemblyInformationalVersionAttribute>()?.InformationalVersion,
        serviceVersion = typeof(MonitoredAuditSink).Assembly.GetCustomAttribute<AssemblyInformationalVersionAttribute>()?.InformationalVersion,
        volumeBytes = new DriveInfo(root).TotalSize, phases,
        note = "Real NTFS disk-full on an owned small virtual volume. Real Core queue and service monitor, not installed SCM service/pipe, not the production queue. No power-loss, physical durability, network, driver, lost-event repair or long-run claim." });
    Console.WriteLine("PASS: four real disk-full/refill recovery phases.");
}
catch (Exception error)
{
    await Save("failure.json", new { result = "failed", startedAtUtc = started, errorType = error.GetType().Name, error = error.Message, phases });
    throw;
}

Task Save(string name, object value) => File.WriteAllTextAsync(Path.Combine(output, name), JsonSerializer.Serialize(value, options));
static bool IsFull(IOException error) => error.HResult is unchecked((int)0x80070070) or unchecked((int)0x80070027);
static void Check(bool condition, string message) { if (!condition) throw new InvalidDataException(message); }
static AuditEvent Event(int index, string masked) => new(Guid.NewGuid(), DateTimeOffset.UtcNow, "PC-SINTETICO", "usuario-sintetico",
    $"sintetico-{index}.txt", ".txt", 42, Verdict.Blocked, [Category.Cpf], [masked], "processo-sintetico", 123, @"P:\Sintetico", null, 1, 10, false);
static Task Invoke(MonitoredAuditSink sink, AuditQueueOperation operation, AuditEvent item, AuditOverride reason,
    Guid seedId, AuditOverride seedReason, CancellationToken token) => operation switch
    {
        AuditQueueOperation.WriteEvent => sink.WriteAsync(item, token),
        AuditQueueOperation.WriteOverride => sink.RecordOverrideAsync(reason, token),
        AuditQueueOperation.ConfirmEvents => sink.MarkDispatchedAsync([seedId], token),
        AuditQueueOperation.ConfirmOverrides => sink.MarkOverridesDispatchedAsync([seedReason], token),
        _ => throw new ArgumentOutOfRangeException(nameof(operation))
    };
static long Fill(string path, CancellationToken token)
{
    var buffer = new byte[1024 * 1024]; RandomNumberGenerator.Fill(buffer);
    using var stream = new FileStream(path, FileMode.CreateNew, FileAccess.Write, FileShare.None, 4096, FileOptions.WriteThrough);
    long written = 0;
    foreach (var block in new[] { buffer.Length, 4096 })
    {
        while (true)
        {
            token.ThrowIfCancellationRequested();
            if (written > VolumeGuard.MaximumBytes + buffer.Length) throw new IOException("Filler exceeded bounded volume budget.");
            try { stream.Write(buffer, 0, block); written += block; }
            catch (IOException error) when (IsFull(error)) { break; }
        }
    }
    return stream.Length;
}

sealed class ProbeLogger : ILogger<MonitoredAuditSink>
{
    public List<LogEntry> Entries { get; } = [];
    public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;
    public bool IsEnabled(LogLevel logLevel) => true;
    public void Log<TState>(LogLevel level, EventId id, TState state, Exception? error, Func<TState, Exception?, string> formatter)
        => Entries.Add(new(id.Id, formatter(state, error), error is not null));
}
sealed record LogEntry(int Id, string Text, bool AttachedException);
