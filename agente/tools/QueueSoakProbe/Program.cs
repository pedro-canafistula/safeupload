using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.Json.Serialization;
using SafeUpload.Agent.Core.Domain;
using SafeUpload.Agent.Core.Infrastructure;

// Own synthetic queue only; no service, network, retention, cleanup or fault injection.
if (args.Length != 2) throw new ArgumentException("Usage: QueueSoakProbe <output-parent> <profile.json>");
var json = new JsonSerializerOptions { PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
    Converters = { new JsonStringEnumConverter() }, WriteIndented = false };
var profileBytes = await File.ReadAllBytesAsync(args[1]);
var profile = JsonSerializer.Deserialize<Profile>(profileBytes, json) ?? throw new InvalidDataException("Missing profile.");
profile.Validate();
var parent = Guard(args[0]);
Directory.CreateDirectory(parent);
Guard(parent);
var drive = new DriveInfo(Path.GetPathRoot(parent)!);
Check(drive.AvailableFreeSpace >= profile.MinFreeBytes, "Insufficient initial free space.");
var root = Path.Combine(parent, "queue-soak-" + Guid.NewGuid().ToString("N"));
Directory.CreateDirectory(root);
Guard(root);
await File.WriteAllBytesAsync(Path.Combine(root, "profile.json"), profileBytes);
await File.WriteAllTextAsync(Path.Combine(root, "synthetic.marker"), "SafeUpload QueueSoakProbe v1");
var queue = Path.Combine(root, "queue.jsonl");
var samplesFile = Path.Combine(root, "samples.jsonl");
var operationsFile = Path.Combine(root, "operations.jsonl");
var sink = new LocalQueueAuditSink(queue);
var timer = Stopwatch.StartNew();
var started = DateTimeOffset.UtcNow;
using var process = Process.GetCurrentProcess();
var phases = new List<object>();
long events = 0, eventAck = 0, overrideAck = 0, samples = 0;
double previousSampleMs = 0;
bool cancelled = false;
Console.CancelKeyPress += (_, e) => { e.Cancel = true; cancelled = true; };
Console.WriteLine("Synthetic directory: " + root);
try
{
    foreach (var phase in new[] { "offline", "recovery", "mixed" })
    {
        var phaseStart = timer.Elapsed.TotalMilliseconds;
        double nextWrite = phaseStart, nextAck = phaseStart, nextSample = phaseStart;
        var phaseEnd = phaseStart + profile.PhaseSeconds * 1000d;
        while (timer.Elapsed.TotalMilliseconds < phaseEnd)
        {
            Check(!cancelled, "Operator cancelled; evidence retained, not a completed run.");
            Budget();
            var now = timer.Elapsed.TotalMilliseconds;
            if (phase != "recovery" && now >= nextWrite)
            {
                Check(events < profile.MaxEvents, "Event budget reached; incomplete run.");
                var index = events + 1;
                var watch = Stopwatch.StartNew();
                await sink.WriteAsync(Event(index), CancellationToken.None);
                events = index;
                if (index % 10 == 0) await sink.RecordOverrideAsync(Override(index), CancellationToken.None);
                await Log(operationsFile, new { operation = "append", phase, index,
                    elapsedMs = watch.Elapsed.TotalMilliseconds, scheduleDelayMs = now - nextWrite });
                // No catch-up burst after a slow operation: record actual rate and lag.
                nextWrite = timer.Elapsed.TotalMilliseconds + profile.WriteIntervalMs;
            }
            if (phase != "offline" && timer.Elapsed.TotalMilliseconds >= nextAck)
            {
                var watch = Stopwatch.StartNew();
                var pending = await sink.ReadPendingAsync(profile.BatchSize, CancellationToken.None);
                if (pending.Count > 0)
                {
                    Check(pending.Select(e => e.EventId).SequenceEqual(
                        Enumerable.Range(1, pending.Count).Select(i => Id(eventAck + i))), "Unexpected pending event order.");
                    await sink.MarkDispatchedAsync(pending.Select(e => e.EventId).ToArray(), CancellationToken.None);
                    eventAck += pending.Count;
                }
                var overrides = await sink.ReadPendingOverridesAsync(profile.BatchSize, CancellationToken.None);
                if (overrides.Count > 0)
                {
                    Check(overrides.Select(o => o.EventId).SequenceEqual(
                        Enumerable.Range(1, overrides.Count).Select(i => Id((overrideAck + i) * 10))), "Unexpected pending override order.");
                    await sink.MarkOverridesDispatchedAsync(overrides, CancellationToken.None);
                    overrideAck += overrides.Count;
                }
                await Log(operationsFile, new { operation = "synthetic-ack", phase, events = pending.Count,
                    overrides = overrides.Count, elapsedMs = watch.Elapsed.TotalMilliseconds });
                nextAck = timer.Elapsed.TotalMilliseconds + profile.AckIntervalMs;
            }
            if (timer.Elapsed.TotalMilliseconds >= nextSample)
            {
                process.Refresh();
                var at = timer.Elapsed.TotalMilliseconds;
                await Log(samplesFile, new { utc = DateTimeOffset.UtcNow, elapsedMs = at, phase,
                    intervalSincePreviousMs = samples == 0 ? (double?)null : at - previousSampleMs,
                    schedulingDelayMs = at - nextSample, workingSetBytes = process.WorkingSet64,
                    privateBytes = process.PrivateMemorySize64, totalCpuMs = process.TotalProcessorTime.TotalMilliseconds,
                    allocatedBytes = GC.GetTotalAllocatedBytes(), freeBytes = drive.AvailableFreeSpace,
                    queueBytes = Bytes(queue), events, eventAck, pendingEvents = events - eventAck,
                    overrides = events / 10, overrideAck, pendingOverrides = events / 10 - overrideAck });
                samples++;
                previousSampleMs = at;
                nextSample = timer.Elapsed.TotalMilliseconds + profile.SampleIntervalMs;
            }
            await Task.Delay(10);
        }
        // Reopen only at a quiescent phase boundary. Verify independently line by line.
        sink = new LocalQueueAuditSink(queue);
        var verificationWatch = Stopwatch.StartNew();
        var before = await Hash(queue);
        await Verify();
        var integrity = await sink.InspectIntegrityAsync(CancellationToken.None);
        Check(integrity.ValidEvents == events && integrity.ValidOverrides == events / 10 &&
            integrity.PendingEvents == events - eventAck && integrity.PendingOverrides == events / 10 - overrideAck &&
            integrity.InvalidLines == 0 && integrity.UnknownRecords == 0 && integrity.BlankLines == 0 &&
            integrity.DispatchedEvents == eventAck && integrity.DispatchedOverrides == overrideAck,
            "Integrity counts mismatch.");
        Check(before == await Hash(queue), "Verification changed bytes.");
        phases.Add(new { phase, elapsedMs = timer.Elapsed.TotalMilliseconds - phaseStart,
            verificationMs = verificationWatch.Elapsed.TotalMilliseconds, events, eventAck, overrideAck,
            bytes = Bytes(queue), sha256 = before, metadataVerified = true, integrity });
        Console.WriteLine($"{phase}: {events} events, {events - eventAck} pending; metadata preserved.");
    }
    Check(!cancelled, "Operator cancelled before completion.");
    await Report("passed", null);
    Console.WriteLine("PASS: " + Path.Combine(root, "result.json"));
}
catch (Exception e)
{
    await Report("incomplete", e.GetType().Name + ": " + e.Message);
    throw;
}

void Budget()
{
    Check(drive.AvailableFreeSpace >= profile.MinFreeBytes, "Free-space stop threshold reached.");
    Check(Directory.EnumerateFiles(root).Sum(Bytes) < profile.MaxOutputBytes, "Output budget reached.");
}
async Task Verify()
{
    long eventIndex = 0, overrideIndex = 0;
    using var input = new StreamReader(queue, new UTF8Encoding(false, true));
    while (await input.ReadLineAsync() is { } line)
    {
        var actual = JsonNode.Parse(line)?.AsObject() ?? throw new InvalidDataException("Non-object queue line.");
        JsonNode expected;
        if (actual.ContainsKey("type"))
        {
            var index = ++overrideIndex * 10;
            Check(index <= events && eventIndex == index, "Unexpected override position/count.");
            var value = Override(index);
            expected = JsonSerializer.SerializeToNode(new { type = "override", value.EventId,
                value.Justification, value.OccurredAtUtc, value.UserName, value.EndpointId }, json)!;
            var sent = actual["dispatched"]?.GetValue<bool>() ?? false;
            Check(sent == (overrideIndex <= overrideAck), "Override acknowledgement mismatch.");
            actual.Remove("dispatched");
        }
        else
        {
            var index = ++eventIndex;
            Check(index <= events, "Unexpected extra event.");
            expected = JsonSerializer.SerializeToNode(Event(index) with { Dispatched = index <= eventAck }, json)!;
        }
        Check(JsonNode.DeepEquals(actual, expected), "ID or metadata changed in queue.");
    }
    Check(eventIndex == events && overrideIndex == events / 10, "Missing queue records.");
}
async Task Report(string status, string? error)
{
    var files = new List<object>();
    foreach (var file in Directory.EnumerateFiles(root).Order(StringComparer.Ordinal))
        files.Add(new { file = Path.GetFileName(file), bytes = Bytes(file), sha256 = await Hash(file) });
    var result = new { status, error, startedAtUtc = started, finishedAtUtc = DateTimeOffset.UtcNow,
        elapsedSeconds = timer.Elapsed.TotalSeconds, profile, profileSha256 = Convert.ToHexString(SHA256.HashData(profileBytes)),
        coreAssemblySha256 = await Hash(typeof(LocalQueueAuditSink).Assembly.Location),
        probeAssemblySha256 = await Hash(typeof(Profile).Assembly.Location),
        os = RuntimeInformation.OSDescription, framework = RuntimeInformation.FrameworkDescription,
        architecture = RuntimeInformation.ProcessArchitecture.ToString(), samples, events, eventAck, overrideAck, phases,
        serviceQualified = false, physicalDurabilityQualified = false, realApiQualified = false,
        retentionChanged = false, deleted = false,
        note = "Sequential Core harness with synthetic confirmations. Samples include generator, logs and verification; not service-only resources. No HTTP, lost response, 503, crash, concurrent producer or power loss. Phase boundaries verify after a quiescent reopen, not process restart. Budget checks occur between operations, not a hard filesystem quota. Gaps include operation/verification time. No latency SLA. Long-duration qualification requires an agreed profile and actual completed duration.",
        files };
    await File.WriteAllTextAsync(Path.Combine(root, "result.json"), JsonSerializer.Serialize(result,
        new JsonSerializerOptions(json) { WriteIndented = true }));
}
async Task Log(string path, object value) =>
    await File.AppendAllTextAsync(path, JsonSerializer.Serialize(value, json) + "\n", new UTF8Encoding(false));
Guid Id(long index) => new(SHA256.HashData(Encoding.UTF8.GetBytes(profile.Seed + ":" + index))[..16]);
AuditEvent Event(long index) => new(Id(index), new DateTimeOffset(2026, 1, 1, 0, 0, 0, TimeSpan.Zero).AddSeconds(index),
    "PC-SINTETICO", "usuario-sintetico", $"sintetico-{index}.txt", ".txt", 42, Verdict.Blocked,
    [Category.Cpf], ["mascarado-sintetico"], "processo-sintetico", 123, "destino-sintetico", null, 1, index % 13, false);
AuditOverride Override(long index) => new(Id(index), "justificativa-sintetica-" + index,
    Event(index).OccurredAtUtc.AddMilliseconds(100), "usuario-sintetico", "PC-SINTETICO");
static long Bytes(string path) => File.Exists(path) ? new FileInfo(path).Length : 0;
static async Task<string> Hash(string path)
{
    await using var input = File.OpenRead(path);
    return Convert.ToHexString(await SHA256.HashDataAsync(input));
}
static string Guard(string path)
{
    var full = Path.GetFullPath(path).TrimEnd(Path.DirectorySeparatorChar);
    Check(Path.IsPathFullyQualified(full) && !full.StartsWith(@"\\"), "Use a local absolute directory.");
    var installed = Path.GetFullPath(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "SafeUpload"));
    Check(!full.Equals(installed, StringComparison.OrdinalIgnoreCase) &&
        !full.StartsWith(installed + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase), "Installed data refused.");
    for (var d = new DirectoryInfo(full); d is not null; d = d.Parent)
        if (d.Exists) Check((d.Attributes & FileAttributes.ReparsePoint) == 0, "Reparse ancestor refused.");
    return full;
}
static void Check(bool condition, string message)
{
    if (!condition) throw new InvalidDataException(message);
}
internal sealed record Profile(int PhaseSeconds, int WriteIntervalMs, int AckIntervalMs,
    int SampleIntervalMs, int BatchSize, long MaxEvents, long MaxOutputBytes, long MinFreeBytes, string Seed)
{
    public void Validate()
    {
        if (PhaseSeconds is < 1 or > 86400 || WriteIntervalMs is < 10 or > 60000 ||
            AckIntervalMs is < 10 or > 60000 || SampleIntervalMs is < 10 or > 900000 ||
            BatchSize is < 1 or > 1000 || MaxEvents is < 1 or > 1_000_000 ||
            MaxOutputBytes is < 1048576 or > 10737418240 || MinFreeBytes < 2147483648 ||
            string.IsNullOrWhiteSpace(Seed) || Seed.Length > 128)
            throw new ArgumentException("Invalid bounded synthetic profile.");
    }
}
