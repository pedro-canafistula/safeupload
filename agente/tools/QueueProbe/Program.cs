using System.Collections.Concurrent;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text.Json;
using SafeUpload.Agent.Core.Domain;
using SafeUpload.Agent.Core.Infrastructure;

// Diagnostic only: synthetic queues in a fresh child directory. No service,
// production paths, networking, retention changes or automatic deletion.
if (args.Length is < 1 or > 2 || (args.Length == 2 && !int.TryParse(args[1], out _)))
    throw new ArgumentException("Usage: QueueProbe <output-parent> [soak-seconds: 10..600]");
var seconds = args.Length == 2 ? int.Parse(args[1]) : 120;
if (seconds is < 10 or > 600) throw new ArgumentOutOfRangeException(nameof(seconds));
var parent = Path.GetFullPath(args[0]);
// Refuse direct use of the installed agent's data directory, including its children.
var protectedRoot = Path.GetFullPath(Path.Combine(
    Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "SafeUpload"));
if (parent.Equals(protectedRoot, StringComparison.OrdinalIgnoreCase) ||
    parent.StartsWith(protectedRoot + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase))
    throw new ArgumentException("Use a diagnostic output directory, never the agent data directory.");
var root = Path.Combine(parent, "queue-probe-" + Guid.NewGuid().ToString("N"));
Directory.CreateDirectory(root);
var drive = new DriveInfo(Path.GetPathRoot(root)!);
if (drive.AvailableFreeSpace < 2L * 1024 * 1024 * 1024)
    throw new IOException("At least 2 GiB of free disk space required for this bounded probe.");
var started = DateTimeOffset.UtcNow;
var samples = new List<Sample>();
var stages = new List<object>();
Console.WriteLine($"Diagnostic directory: {root}");
try
{
    // Warm the serializer and disk path before collecting the scale measurements.
    var warm = new LocalQueueAuditSink(Path.Combine(root, "warmup.jsonl"));
    await warm.WriteAsync(Event(0), CancellationToken.None);
    await warm.ReadPendingAsync(100, CancellationToken.None);
    await warm.MarkDispatchedAsync((await warm.ReadPendingAsync(100, CancellationToken.None)).Select(e => e.EventId).ToArray(), CancellationToken.None);
    foreach (var count in new[] { 1000, 10000, 50000 })
    {
        var file = Path.Combine(root, $"scale-{count}.jsonl");
        var sink = new LocalQueueAuditSink(file);
        var seed = Stopwatch.StartNew();
        for (var i = 0; i < count; i++) await sink.WriteAsync(Event(i), CancellationToken.None);
        var seedMs = seed.Elapsed.TotalMilliseconds;
        var bytes = new FileInfo(file).Length;
        for (var repeat = 0; repeat < 5; repeat++)
        {
            await Measure("pending-100", count, async () =>
                Check((await sink.ReadPendingAsync(100, CancellationToken.None)).Count == 100, "Incomplete pending batch"));
            await Measure("recent-500", count, async () =>
                Check((await sink.ReadRecentAsync(500, CancellationToken.None)).Count == 500, "Incomplete history"));
        }
        for (var repeat = 0; repeat < 3; repeat++)
        {
            var batch = await sink.ReadPendingAsync(100, CancellationToken.None);
            var ids = batch.Select(e => e.EventId).ToHashSet();
            await Measure("ack-100", count, () => sink.MarkDispatchedAsync(ids, CancellationToken.None));
            Check(!(await sink.ReadPendingAsync(100, CancellationToken.None)).Any(e => ids.Contains(e.EventId)), "Acknowledged event still pending");
        }
        // Reopen from disk, preserving the complete local trail.
        var reopened = new LocalQueueAuditSink(file);
        var all = await reopened.ReadRecentAsync(0, CancellationToken.None);
        Check(all.Count == count && all.Select(e => e.EventId).Distinct().Count() == count, "Scale queue lost or duplicated events");
        Check(all.Count(e => e.Dispatched) == 300, "Unexpected acknowledgement count");
        // Direct Core calls deliberately measure full scans without the pipe deadline.
        // Never report a timeout/partial scan as a successful inventory.
        var diagnosticHashBefore = await Hash(file);
        var diagnosticBytes = new FileInfo(file).Length;
        var cutoff = new DateTimeOffset(2030, 1, 1, 0, 0, 0, TimeSpan.Zero);
        var expectedOldestPending = all.Where(e => !e.Dispatched).Min(e => e.OccurredAtUtc);
        for (var repeat = 0; repeat < 5; repeat++)
        {
            await Measure("integrity-mixed", count, async () =>
                CheckInventory(await reopened.InspectIntegrityAsync(CancellationToken.None), count, diagnosticBytes, expectedOldestPending));
            await Measure("retention-preview-mixed", count, async () =>
            {
                var preview = await reopened.PreviewRetentionAsync(cutoff, CancellationToken.None);
                CheckInventory(preview.Integrity, count, diagnosticBytes, expectedOldestPending);
                Check(preview.OccurredBeforeUtc == cutoff && preview.ConfirmedEventsBeforeCutoff == 300 &&
                    preview.ConfirmedOverridesBeforeCutoff == 0 && preview.ConfirmedWithoutTimestamp == 0 &&
                    preview.PreviewOnly && !preview.DeletionSupported &&
                    preview.TimestampBasis == "record-occurrence-time", "Unexpected retention preview");
            });
        }
        var diagnosticHashAfter = await Hash(file);
        Check(diagnosticHashBefore == diagnosticHashAfter, "Diagnostics modified queue bytes");
        stages.Add(new { events = count, bytesBeforeAcknowledgement = bytes, seedMs,
            acknowledged = 300, sha256 = diagnosticHashAfter,
            diagnostics = new { repeatsPerQuery = 5, queueBytes = diagnosticBytes,
                pending = count - 300, confirmed = 300, occurredBeforeUtc = cutoff,
                sha256Before = diagnosticHashBefore, sha256After = diagnosticHashAfter,
                previewOnly = true, deletionSupported = false } });
        Console.WriteLine($"Scale {count}: {bytes} bytes; integrity passed.");
    }

    var soakFile = Path.Combine(root, "soak.jsonl");
    var soak = new LocalQueueAuditSink(soakFile);
    var expected = new ConcurrentDictionary<Guid, byte>();
    for (var i = 0; i < 10000; i++)
    {
        var e = Event(i); await soak.WriteAsync(e, CancellationToken.None); expected.TryAdd(e.EventId, 0);
    }
    var confirmed = new HashSet<Guid>();
    var clock = Stopwatch.StartNew();
    var producer = Produce();
    var cycles = 0;
    long rewriteDestinationBytes = 0;
    while (clock.Elapsed < TimeSpan.FromSeconds(seconds))
    {
        var batch = await soak.ReadPendingAsync(100, CancellationToken.None);
        if (batch.Count > 0)
        {
            rewriteDestinationBytes += new FileInfo(soakFile).Length;
            await soak.MarkDispatchedAsync(batch.Select(e => e.EventId).ToArray(), CancellationToken.None);
            foreach (var e in batch) confirmed.Add(e.EventId);
        }
        await soak.ReadRecentAsync(500, CancellationToken.None);
        cycles++;
        await Task.Delay(100);
    }
    await producer;
    var recovered = new LocalQueueAuditSink(soakFile);
    var history = await recovered.ReadRecentAsync(0, CancellationToken.None);
    var pending = await recovered.ReadPendingAsync(0, CancellationToken.None);
    Check(history.Count == expected.Count && history.Select(e => e.EventId).ToHashSet().SetEquals(expected.Keys), "Soak lost or duplicated events");
    Check(history.Where(e => e.Dispatched).Select(e => e.EventId).ToHashSet().SetEquals(confirmed), "Soak confirmation mismatch");
    Check(pending.Select(e => e.EventId).ToHashSet().SetEquals(expected.Keys.Except(confirmed)), "Soak pending mismatch");
    var soakResult = new { requestedSeconds = seconds, elapsedSeconds = clock.Elapsed.TotalSeconds, cycles,
        events = history.Count, confirmed = confirmed.Count, pending = pending.Count,
        fileBytes = new FileInfo(soakFile).Length, rewriteDestinationBytes,
        sha256 = Convert.ToHexString(SHA256.HashData(await File.ReadAllBytesAsync(soakFile))),
        integrity = "passed-after-reopening" };
    var process = Process.GetCurrentProcess(); process.Refresh();
    var report = new { result = "passed", startedAtUtc = started, finishedAtUtc = DateTimeOffset.UtcNow,
        framework = RuntimeInformation.FrameworkDescription, os = RuntimeInformation.OSDescription,
        architecture = RuntimeInformation.ProcessArchitecture.ToString(), logicalProcessors = Environment.ProcessorCount,
        coreAssemblySha256 = Convert.ToHexString(SHA256.HashData(await File.ReadAllBytesAsync(typeof(LocalQueueAuditSink).Assembly.Location))),
        peakWorkingSetBytes = process.PeakWorkingSet64, freeDiskBytesAtEnd = drive.AvailableFreeSpace,
        measurementNote = "Warm OS cache; five reads, five integrity scans, five retention previews and three acknowledgements per size. Direct Core calls, no pipe deadline, network or service; five-second service budget is not enforced. Process-wide allocation deltas include assertions, not live heap or latency guarantees. Rewrite bytes are destination-length estimates, not physical disk writes. No crash, power-loss or full-disk simulation.",
        stages, samples, soak = soakResult };
    await File.WriteAllTextAsync(Path.Combine(root, "result.json"), JsonSerializer.Serialize(report, new JsonSerializerOptions { WriteIndented = true }));
    Console.WriteLine(JsonSerializer.Serialize(soakResult));
    Console.WriteLine("PASS: " + Path.Combine(root, "result.json"));

    async Task Produce()
    {
        var i = 10000;
        while (clock.Elapsed < TimeSpan.FromSeconds(seconds))
        {
            var e = Event(i++);
            // Never cancel midway through an append just because the sample interval elapsed.
            await soak.WriteAsync(e, CancellationToken.None);
            expected.TryAdd(e.EventId, 0);
            await Task.Delay(250);
        }
    }
}
catch (Exception exception)
{
    await File.WriteAllTextAsync(Path.Combine(root, "failure.json"), JsonSerializer.Serialize(new
        { result = "failed", startedAtUtc = started, error = exception.ToString(), stages, samples },
        new JsonSerializerOptions { WriteIndented = true }));
    throw;
}

async Task Measure(string operation, int count, Func<Task> action)
{
    var allocated = GC.GetTotalAllocatedBytes(precise: true);
    var watch = Stopwatch.StartNew();
    await action();
    var elapsed = watch.Elapsed.TotalMilliseconds;
    samples.Add(new Sample(operation, count, elapsed, GC.GetTotalAllocatedBytes(precise: true) - allocated));
}
static void Check(bool condition, string message) { if (!condition) throw new InvalidDataException(message); }
static async Task<string> Hash(string path)
{
    await using var stream = File.OpenRead(path);
    return Convert.ToHexString(await SHA256.HashDataAsync(stream));
}
static void CheckInventory(AuditQueueIntegritySnapshot snapshot, int count, long bytes, DateTimeOffset oldest)
{
    Check(snapshot.FileExists && snapshot.QueueBytes == bytes && snapshot.LinesScanned == count &&
        snapshot.ValidEvents == count && snapshot.PendingEvents == count - 300 &&
        snapshot.DispatchedEvents == 300 && snapshot.ValidOverrides == 0 &&
        snapshot.PendingOverrides == 0 && snapshot.DispatchedOverrides == 0 &&
        snapshot.PendingWithoutTimestamp == 0 && snapshot.InvalidLines == 0 &&
        snapshot.UnknownRecords == 0 && snapshot.BlankLines == 0 && snapshot.OldestPendingUtc == oldest &&
        !snapshot.RequiresAttention && snapshot.Issues.Count == 0 && !snapshot.IssuesTruncated,
        "Unexpected diagnostic inventory");
}
static AuditEvent Event(int index) => new(Guid.NewGuid(),
    new DateTimeOffset(2026, 10, 22, 12, 0, 0, TimeSpan.Zero).AddSeconds(index),
    "PC-SINTETICO", "usuario-sintetico", $"sintetico-{index}.txt", ".txt", 42,
    Verdict.Blocked, [Category.Cpf], ["mascarado-sintetico"], "processo-sintetico", 123,
    @"C:\DestinoSintetico", null, 1, 10, false);
internal sealed record Sample(string Operation, int Events, double Milliseconds, long AllocatedBytes);
