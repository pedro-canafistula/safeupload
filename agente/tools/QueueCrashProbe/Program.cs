using System.Diagnostics;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text.Json;
using SafeUpload.Agent.Core.Domain;
using SafeUpload.Agent.Core.Infrastructure;

// Diagnostic only. Fresh synthetic files; never install/stop a service, use a
// network, delete data, load a driver or terminate a process not created here.
const int SeedCount = 4096;
var scenarios = new[] { "append-event", "append-override", "confirm-events", "confirm-overrides" };
var jsonOptions = new JsonSerializerOptions { WriteIndented = true };
if (args.Length == 3 && args[0] == "--worker")
{
    var trial = GuardWorker(args[1], args[2]);
    await Worker(trial, args[2]);
    return;
}
if (args.Length is < 1 or > 2 || (args.Length == 2 && !int.TryParse(args[1], out _)))
    throw new ArgumentException("Usage: QueueCrashProbe <output-parent> [repeats: 1..5]");
var repeats = args.Length == 2 ? int.Parse(args[1]) : 3;
if (repeats is < 1 or > 5) throw new ArgumentOutOfRangeException(nameof(repeats));
var parent = GuardPath(args[0]);
Directory.CreateDirectory(parent);
GuardPath(parent);
var drive = new DriveInfo(Path.GetPathRoot(parent)!);
if (drive.AvailableFreeSpace < 2L * 1024 * 1024 * 1024)
    throw new IOException("At least 2 GiB free space required for this bounded probe.");
var root = Path.Combine(parent, "queue-crash-" + Guid.NewGuid().ToString("N"));
Directory.CreateDirectory(root);
await File.WriteAllTextAsync(Path.Combine(root, "probe.marker"), "SafeUpload synthetic crash probe v1");
var started = DateTimeOffset.UtcNow;
var trials = new List<TrialResult>();
Console.WriteLine("Diagnostic directory: " + root);
try
{
    var seedPath = Path.Combine(root, "seed.jsonl");
    var seed = new LocalQueueAuditSink(seedPath);
    var ids = new List<Guid>();
    var fingerprints = new Dictionary<Guid, string>();
    var reasons = new List<AuditOverride>();
    for (var i = 0; i < SeedCount; i++)
    {
        var item = Event(i, 4096);
        await seed.WriteAsync(item, CancellationToken.None);
        ids.Add(item.EventId); fingerprints.Add(item.EventId, Fingerprint(item));
        if (i % 256 == 0)
        {
            var reason = new AuditOverride(item.EventId, "Justificativa sintetica " + i,
                item.OccurredAtUtc, item.UserName, item.EndpointId);
            await seed.RecordOverrideAsync(reason, CancellationToken.None);
            reasons.Add(reason);
        }
    }
    foreach (var scenario in scenarios)
    for (var repeat = 1; repeat <= repeats; repeat++)
    {
        var trial = Path.Combine(root, scenario + "-" + repeat);
        Directory.CreateDirectory(trial);
        var queuePath = Path.Combine(trial, "queue.jsonl");
        File.Copy(seedPath, queuePath);
        var operationId = Guid.NewGuid();
        await File.WriteAllTextAsync(Path.Combine(trial, "operation.json"),
            JsonSerializer.Serialize(new Operation(operationId, scenario)));
        var result = await RunTrial(trial, scenario, operationId, ids, fingerprints, reasons);
        trials.Add(result);
        Console.WriteLine($"{scenario} #{repeat}: {result.Observation}; returned={result.WorkerReportedCompletion}; invalid={result.InvalidLines}; temp={result.OrphanTemporaryFiles}");
    }
    var process = Process.GetCurrentProcess(); process.Refresh();
    await File.WriteAllTextAsync(Path.Combine(root, "result.json"), JsonSerializer.Serialize(new
    {
        result = "passed", startedAtUtc = started, finishedAtUtc = DateTimeOffset.UtcNow,
        framework = RuntimeInformation.FrameworkDescription, os = RuntimeInformation.OSDescription,
        coreAssemblySha256 = Hash(await File.ReadAllBytesAsync(typeof(LocalQueueAuditSink).Assembly.Location)),
        probeAssemblySha256 = Hash(await File.ReadAllBytesAsync(Assembly.GetExecutingAssembly().Location)),
        seedEvents = SeedCount, seedOverrides = reasons.Count, repeats, trials,
        peakWorkingSetBytes = process.PeakWorkingSet64,
        note = "Owned worker processes were killed after the Core task-state boundary, a temporary-file notification or completion receipt. OperationPendingAtWorkerBoundary describes the Task at the worker's earlier report, not necessarily the instruction executing at Kill. WorkerReportedCompletion proves the call returned. A complete append or old/new acknowledgement state are both legitimate. OS remained running; no power-loss, full-disk, physical-flush or API deduplication guarantee. Raw synthetic queues and orphan files retained; no automatic cleanup."
    }, jsonOptions));
    Console.WriteLine("PASS: " + Path.Combine(root, "result.json"));
}
catch (Exception ex)
{
    await File.WriteAllTextAsync(Path.Combine(root, "failure.json"), JsonSerializer.Serialize(new
        { result = "failed", startedAtUtc = started, error = ex.ToString(), trials }, jsonOptions));
    throw;
}

async Task<TrialResult> RunTrial(string trial, string scenario, Guid operationId,
    List<Guid> ids, Dictionary<Guid, string> fingerprints, List<AuditOverride> reasons)
{
    var queuePath = Path.Combine(trial, "queue.jsonl");
    var beforeHash = Hash(await File.ReadAllBytesAsync(queuePath));
    var activity = new TaskCompletionSource<string>(TaskCreationOptions.RunContinuationsAsynchronously);
    using var watcher = new FileSystemWatcher(trial, "queue.jsonl*")
        { NotifyFilter = NotifyFilters.FileName | NotifyFilters.Size | NotifyFilters.LastWrite };
    watcher.Created += (_, _) => { if (scenario.StartsWith("confirm-", StringComparison.Ordinal)) activity.TrySetResult("temporary-file-notification"); };
    watcher.Changed += (_, _) => { if (scenario.StartsWith("confirm-", StringComparison.Ordinal)) activity.TrySetResult("temporary-file-notification"); };
    watcher.EnableRaisingEvents = true;
    var start = new ProcessStartInfo(Environment.ProcessPath!)
    {
        UseShellExecute = false, CreateNoWindow = true, RedirectStandardInput = true,
        RedirectStandardOutput = true, RedirectStandardError = true
    };
    if (Path.GetFileNameWithoutExtension(Environment.ProcessPath!).Equals("dotnet", StringComparison.OrdinalIgnoreCase))
        start.ArgumentList.Add(Assembly.GetExecutingAssembly().Location);
    start.ArgumentList.Add("--worker"); start.ArgumentList.Add(trial); start.ArgumentList.Add(scenario);
    using var worker = Process.Start(start) ?? throw new InvalidOperationException("Worker did not start.");
    var stderr = worker.StandardError.ReadToEndAsync();
    using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(60));
    var boundary = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
    bool requestedKill = false;
    try
    {
        var ready = await worker.StandardOutput.ReadLineAsync(timeout.Token);
        Check(ready == "ready", "Owned worker did not reach operation boundary.");
        var completed = ReadCompletion();
        await worker.StandardInput.WriteLineAsync("go");
        await worker.StandardInput.FlushAsync(timeout.Token);
        Task boundarySignal = scenario.StartsWith("append-", StringComparison.Ordinal)
            ? boundary.Task : Task.Delay(TimeSpan.FromSeconds(20), timeout.Token);
        var first = await Task.WhenAny(activity.Task, completed, boundarySignal, Task.Delay(TimeSpan.FromSeconds(20), timeout.Token));
        Check(first == activity.Task || first == completed || first == boundary.Task, "No queue activity or completion observed.");
        var observedActivity = activity.Task.IsCompletedSuccessfully;
        var completedBeforeKill = completed.IsCompletedSuccessfully;
        Check(!worker.HasExited, "Worker exited before controlled interruption.");
        worker.Kill(entireProcessTree: true);
        requestedKill = true;
        await worker.WaitForExitAsync(timeout.Token);
        var queueBytesAfterKill = new FileInfo(queuePath).Length;
        var temporaryBytes = Directory.GetFiles(trial, "queue.jsonl.*.tmp")
            .Select(p => new FileInfo(p).Length).ToArray();
        var receipt = await completed;
        var error = await stderr;
        Check(string.IsNullOrWhiteSpace(error), "Worker encountered an error before interruption: " + error);
        Check(receipt is null or "completed", "Unexpected worker receipt.");

        var reopened = new LocalQueueAuditSink(queuePath);
        var history = await reopened.ReadRecentAsync(0, timeout.Token);
        var pendingReasons = await reopened.ReadPendingOverridesAsync(0, timeout.Token);
        var integrity = await reopened.InspectIntegrityAsync(timeout.Token);
        var original = history.Where(e => fingerprints.ContainsKey(e.EventId)).ToArray();
        Check(original.Length == SeedCount && original.Select(e => e.EventId).Distinct().Count() == SeedCount,
            "Baseline event lost or duplicated.");
        Check(original.All(e => Fingerprint(e) == fingerprints[e.EventId]), "Baseline event metadata changed.");
        Check(integrity.UnknownRecords == 0 && integrity.InvalidLines <= 1, "Unexpected corruption scope.");
        var newEvents = history.Where(e => !fingerprints.ContainsKey(e.EventId)).ToArray();
        Check(newEvents.All(e => e.EventId == operationId) && newEvents.Length <= 1, "Unexpected/duplicate appended event.");
        var selectedEvents = ids.Take(100).ToHashSet();
        var confirmed = original.Where(e => e.Dispatched).Select(e => e.EventId).ToHashSet();
        Check(scenario == "confirm-events"
            ? confirmed.Count is 0 or 100 && confirmed.IsSubsetOf(selectedEvents)
            : confirmed.Count == 0, "Acknowledgement changed only part of the selected batch or unrelated events.");
        var missingReasons = reasons.Where(r => !pendingReasons.Contains(r)).ToArray();
        Check(scenario == "confirm-overrides" ? missingReasons.Length == 0 || missingReasons.Length == reasons.Count
            : missingReasons.Length == 0, "Override acknowledgement partially applied or lost unrelated records.");
        Check(pendingReasons.All(r => reasons.Contains(r) ||
            (scenario == "append-override" && r.EventId == operationId)), "Unexpected override record.");
        var appendedReasons = pendingReasons.Count(r => r.EventId == operationId);
        Check(appendedReasons <= 1, "Duplicate appended override.");
        Check(integrity.ValidOverrides == reasons.Count + appendedReasons,
            "An override disappeared from the physical queue instead of being marked delivered.");
        Check(newEvents.All(e => !e.Dispatched && e.MaskedSnippets.Count == 2 &&
            e.MaskedSnippets[1].Length == 8 * 1024 * 1024 && e.MaskedSnippets[1].All(c => c == 'x')),
            "Surviving appended event payload changed.");
        Check(pendingReasons.Where(r => r.EventId == operationId).All(r =>
            r.Justification.Length == 8 * 1024 * 1024 && r.Justification.All(c => c == 'x')),
            "Surviving appended override payload changed.");
        if (receipt == "completed" || (boundary.Task.IsCompletedSuccessfully && !boundary.Task.Result))
            Check(scenario switch
            {
                "append-event" => newEvents.Length == 1,
                "append-override" => appendedReasons == 1,
                "confirm-events" => confirmed.Count == 100,
                "confirm-overrides" => missingReasons.Length == reasons.Count,
                _ => false
            }, "Operation returned successfully but did not survive process termination.");
        if (scenario.StartsWith("confirm-", StringComparison.Ordinal))
            Check(integrity.InvalidLines == 0, "Interrupted confirmation damaged published queue.");
        if (scenario.StartsWith("append-", StringComparison.Ordinal))
            Check(confirmed.Count == 0 && missingReasons.Length == 0, "Append changed pending state.");

        var beforeRecoveryHash = Hash(await File.ReadAllBytesAsync(queuePath));
        var orphanCount = Directory.GetFiles(trial, "queue.jsonl.*.tmp").Length;
        var recovery = Event(SeedCount + 1, 0);
        await reopened.WriteAsync(recovery, timeout.Token);
        await reopened.RecordOverrideAsync(new AuditOverride(recovery.EventId, "Recuperacao sintetica",
            recovery.OccurredAtUtc, recovery.UserName, recovery.EndpointId), timeout.Token);
        var afterRecovery = new LocalQueueAuditSink(queuePath);
        Check((await afterRecovery.ReadPendingAsync(0, timeout.Token)).Count(e => e.EventId == recovery.EventId) == 1,
            "New event could not be persisted after interruption.");
        var afterHistory = await afterRecovery.ReadRecentAsync(0, timeout.Token);
        Check(afterHistory.Count == history.Count + 1 && afterHistory.Select(e => e.EventId).Distinct().Count() == afterHistory.Count,
            "Recovery append lost/duplicated history.");
        var afterIntegrity = await afterRecovery.InspectIntegrityAsync(timeout.Token);
        Check(afterIntegrity.InvalidLines == integrity.InvalidLines, "Recovery append hid existing corruption or created new corruption.");
        // Acknowledge again after recovery; also validates the old-or-new state is safely retryable.
        await afterRecovery.MarkDispatchedAsync(selectedEvents, timeout.Token);
        await afterRecovery.MarkOverridesDispatchedAsync(reasons, timeout.Token);
        var finalHistory = await new LocalQueueAuditSink(queuePath).ReadRecentAsync(0, timeout.Token);
        Check(finalHistory.Count == afterHistory.Count && finalHistory.Count(e => e.Dispatched) == 100,
            "Retry of acknowledgement changed event count or selected set.");
        Check((await afterRecovery.ReadPendingOverridesAsync(0, timeout.Token)).All(r => !reasons.Contains(r)),
            "Retry failed to acknowledge original overrides.");
        Check((await afterRecovery.InspectIntegrityAsync(timeout.Token)).InvalidLines == integrity.InvalidLines,
            "Acknowledgement retry hid or added a malformed line.");
        Check(Directory.GetFiles(trial, "queue.jsonl.*.tmp").Length == orphanCount,
            "Normal recovery unexpectedly removed an orphan or left another temporary file.");
        return new(scenario, worker.Id, worker.ExitCode,
            observedActivity ? activity.Task.Result : "worker-operation-boundary",
            boundary.Task.IsCompletedSuccessfully ? boundary.Task.Result : null,
            completedBeforeKill, receipt == "completed", queueBytesAfterKill, temporaryBytes,
            history.Count, confirmed.Count, pendingReasons.Count, integrity.InvalidLines, orphanCount,
            beforeHash, beforeRecoveryHash, Hash(await File.ReadAllBytesAsync(queuePath)));
    }
    finally
    {
        // This object owns exactly the child created above; never look up a process by executable name.
        if (!worker.HasExited) { worker.Kill(entireProcessTree: true); await worker.WaitForExitAsync(); }
        if (!requestedKill) Console.Error.WriteLine("Trial failed before a controlled worker kill.");
    }

    async Task<string?> ReadCompletion()
    {
        var state = await worker.StandardOutput.ReadLineAsync(timeout.Token);
        if (state is null) return null; // Process died before its first task-state report.
        Check(state is "operation-pending" or "operation-already-complete", "Unexpected operation state.");
        boundary.TrySetResult(state == "operation-pending");
        return await worker.StandardOutput.ReadLineAsync(timeout.Token);
    }
}

async Task Worker(string trial, string scenario)
{
    var operation = JsonSerializer.Deserialize<Operation>(await File.ReadAllTextAsync(Path.Combine(trial, "operation.json")))!;
    Check(operation.Scenario == scenario && operation.Id != Guid.Empty, "Invalid operation manifest.");
    var sink = new LocalQueueAuditSink(Path.Combine(trial, "queue.jsonl"));
    var events = scenario == "confirm-events" ? await sink.ReadPendingAsync(100, CancellationToken.None) : [];
    var overrides = scenario == "confirm-overrides" ? await sink.ReadPendingOverridesAsync(0, CancellationToken.None) : [];
    var appended = Event(SeedCount, 8 * 1024 * 1024) with { EventId = operation.Id };
    Console.WriteLine("ready");
    Check(await Console.In.ReadLineAsync() == "go", "Missing parent handshake.");
    var operationTask = scenario switch
    {
        "append-event" => sink.WriteAsync(appended, CancellationToken.None),
        "append-override" => sink.RecordOverrideAsync(new AuditOverride(operation.Id,
            new string('x', 8 * 1024 * 1024), appended.OccurredAtUtc, appended.UserName, appended.EndpointId), CancellationToken.None),
        "confirm-events" => sink.MarkDispatchedAsync(events.Select(e => e.EventId).ToArray(), CancellationToken.None),
        "confirm-overrides" => sink.MarkOverridesDispatchedAsync(overrides, CancellationToken.None),
        _ => throw new ArgumentException("Unknown scenario.")
    };
    Console.WriteLine(operationTask.IsCompleted ? "operation-already-complete" : "operation-pending");
    await operationTask;
    Console.WriteLine("completed");
    await Task.Delay(Timeout.InfiniteTimeSpan); // Parent always owns and terminates this worker.
}

string GuardWorker(string path, string scenario)
{
    Check(scenarios.Contains(scenario), "Unknown worker scenario.");
    var trial = GuardPath(path);
    var root = Directory.GetParent(trial) ?? throw new ArgumentException("Missing probe root.");
    Check(root.Name.StartsWith("queue-crash-", StringComparison.Ordinal) &&
        File.ReadAllText(Path.Combine(root.FullName, "probe.marker")) == "SafeUpload synthetic crash probe v1" &&
        Path.GetFileName(trial).StartsWith(scenario + "-", StringComparison.Ordinal), "Worker is restricted to a synthetic probe directory.");
    Check(File.Exists(Path.Combine(trial, "queue.jsonl")), "Synthetic queue is absent.");
    return trial;
}

static string GuardPath(string path)
{
    var full = Path.GetFullPath(path);
    var protectedRoot = Path.GetFullPath(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "SafeUpload"));
    Check(!full.Equals(protectedRoot, StringComparison.OrdinalIgnoreCase) &&
        !full.StartsWith(protectedRoot + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase), "Never use installed agent data.");
    for (var item = new DirectoryInfo(full); item is not null; item = item.Parent)
        if (item.Exists) Check((item.Attributes & FileAttributes.ReparsePoint) == 0, "Reparse-point paths are not allowed.");
    return full;
}
static void Check(bool value, string message) { if (!value) throw new InvalidDataException(message); }
static string Hash(byte[] bytes) => Convert.ToHexString(SHA256.HashData(bytes));
static string Fingerprint(AuditEvent item) => Hash(JsonSerializer.SerializeToUtf8Bytes(item with { Dispatched = false }));
static AuditEvent Event(int index, int padding) => new(Guid.NewGuid(),
    new DateTimeOffset(2026, 10, 23, 12, 0, 0, TimeSpan.Zero).AddSeconds(index),
    "PC-SINTETICO", "usuario-sintetico", $"sintetico-{index}.txt", ".txt", 42,
    Verdict.Blocked, [Category.Cpf], ["mascarado-sintetico", new string('x', padding)],
    "processo-sintetico", 123, "destino-sintetico", null, 1, 10, false);
internal sealed record Operation(Guid Id, string Scenario);
internal sealed record TrialResult(string Scenario, int OwnedWorkerPid, int ExitCode, string Observation,
    bool? OperationPendingAtWorkerBoundary, bool CompletionTaskReadyBeforeKill, bool WorkerReportedCompletion, long QueueBytesAfterKill,
    long[] TemporaryBytesAfterKill, int ReopenedEvents, int ConfirmedEvents, int PendingOverrides,
    long InvalidLines, int OrphanTemporaryFiles, string SeedSha256, string ReopenedSha256, string FinalSha256);
