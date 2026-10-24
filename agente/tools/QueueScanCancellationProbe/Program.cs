using System.Diagnostics;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using SafeUpload.Agent.Core.Domain;
using SafeUpload.Agent.Core.Infrastructure;

// Synthetic, isolated Windows probe. Never installs, loads a driver, opens the
// installed queue, deletes data or terminates a process it did not create.
if (!OperatingSystem.IsWindows()) throw new PlatformNotSupportedException("Windows I/O counters required.");
const string Marker = "SafeUpload synthetic scan cancellation v1";
var options = new JsonSerializerOptions { PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
    Converters = { new JsonStringEnumConverter() } };
var reportOptions = new JsonSerializerOptions { WriteIndented = true };
var cutoff = new DateTimeOffset(2030, 1, 1, 0, 0, 0, TimeSpan.Zero);
var hostPath = Environment.ProcessPath ?? throw new InvalidOperationException("Missing process host path.");
if (args.Length == 3 && args[0] == "--worker")
{
    var trial = Guard(args[1]);
    Check(args[2] is "integrity" or "preview", "Unknown query.");
    Check(File.ReadAllText(Path.Combine(Directory.GetParent(trial)!.FullName, "probe.marker")) == Marker, "Missing synthetic marker.");
    await Worker(trial, args[2]);
    return;
}
if (args.Length is < 1 or > 2) throw new ArgumentException("Usage: QueueScanCancellationProbe <output-parent> [repeats: 1..3]");
var repeats = args.Length == 2 ? int.Parse(args[1]) : 3;
Check(repeats is >= 1 and <= 3, "Repeats must be 1..3.");
var parent = Guard(args[0]);
Directory.CreateDirectory(parent); Guard(parent);
Check(new DriveInfo(Path.GetPathRoot(parent)!).AvailableFreeSpace >= 2L * 1024 * 1024 * 1024, "At least 2 GiB free space required.");
var root = Path.Combine(parent, "scan-cancel-" + Guid.NewGuid().ToString("N"));
Directory.CreateDirectory(root);
await File.WriteAllTextAsync(Path.Combine(root, "probe.marker"), Marker);
var seed = Path.Combine(root, "seed.jsonl");
var pair = Encoding.UTF8.GetBytes(JsonSerializer.Serialize(Event(false), options) + "\n" +
    JsonSerializer.Serialize(Event(true), options) + "\n");
long pairs = 0;
await using (var output = new FileStream(seed, FileMode.CreateNew, FileAccess.Write, FileShare.None, 1024 * 1024, true))
{
    while (output.Position < 64L * 1024 * 1024) { await output.WriteAsync(pair); pairs++; }
}
var manifest = new Manifest(pairs * 2, pairs, pairs, new FileInfo(seed).Length, await Hash(seed));
var results = new List<JsonElement>();
Console.WriteLine("Diagnostic directory: " + root);
try
{
    foreach (var query in new[] { "integrity", "preview" })
    for (var repeat = 1; repeat <= repeats; repeat++)
    {
        var trial = Path.Combine(root, query + "-" + repeat);
        Directory.CreateDirectory(trial);
        File.Copy(seed, Path.Combine(trial, "queue.jsonl"));
        await File.WriteAllTextAsync(Path.Combine(trial, "manifest.json"), JsonSerializer.Serialize(manifest));
        var start = new ProcessStartInfo(hostPath) { UseShellExecute = false };
        if (Path.GetFileNameWithoutExtension(hostPath).Equals("dotnet", StringComparison.OrdinalIgnoreCase))
            start.ArgumentList.Add(Assembly.GetExecutingAssembly().Location);
        start.ArgumentList.Add("--worker"); start.ArgumentList.Add(trial); start.ArgumentList.Add(query);
        using var child = Process.Start(start) ?? throw new IOException("Worker did not start.");
        try
        {
            using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(90));
            await child.WaitForExitAsync(timeout.Token);
            Check(child.ExitCode == 0, "Worker failed: " + query);
            using var json = JsonDocument.Parse(await File.ReadAllTextAsync(Path.Combine(trial, "result.json")));
            results.Add(json.RootElement.Clone());
        }
        finally
        {
            if (!child.HasExited) { child.Kill(entireProcessTree: true); await child.WaitForExitAsync(); }
        }
    }
    await File.WriteAllTextAsync(Path.Combine(root, "result.json"), JsonSerializer.Serialize(new
    {
        result = "passed", framework = RuntimeInformation.FrameworkDescription, os = RuntimeInformation.OSDescription,
        architecture = RuntimeInformation.ProcessArchitecture.ToString(), sourceCoreSha256 = await Hash(typeof(LocalQueueAuditSink).Assembly.Location),
        seed = manifest, repeatsPerQuery = repeats, observation = "pending scan + conflicting queue reader + process read-byte increase after warmup",
        limitation = "Process-wide read counters are not file-specific offsets or proof of a parsed line. No pipe deadline, power-loss, real server or durability claim.",
        trials = results
    }, reportOptions));
    Console.WriteLine("PASS: " + Path.Combine(root, "result.json"));
}
catch (Exception exception)
{
    await File.WriteAllTextAsync(Path.Combine(root, "failure.json"), JsonSerializer.Serialize(new { result = "failed", error = exception.ToString(), trials = results }, reportOptions));
    throw;
}

async Task Worker(string trial, string query)
{
    var path = Path.Combine(trial, "queue.jsonl");
    Check((File.GetAttributes(path) & FileAttributes.ReparsePoint) == 0, "Queue links refused.");
    var expected = JsonSerializer.Deserialize<Manifest>(await File.ReadAllTextAsync(Path.Combine(trial, "manifest.json")))!;
    Check(new FileInfo(path).Length == expected.Bytes && await Hash(path) == expected.Sha256, "Seed identity mismatch.");
    // Warm the same JSON/parser branches and query before taking an I/O baseline.
    var warm = new LocalQueueAuditSink(Path.Combine(trial, "warmup.jsonl"));
    for (var i = 0; i < 1000; i++) await warm.WriteAsync(Event(i % 2 == 0), CancellationToken.None);
    await Scan(warm, query, CancellationToken.None);
    var sink = new LocalQueueAuditSink(path);
    using var process = Process.GetCurrentProcess();
    var handle = process.Handle;
    var beforeIo = ReadBytes(handle);
    using var cancel = new CancellationTokenSource();
    var scan = Task.Run(() => Scan(sink, query, cancel.Token));
    var watch = Stopwatch.StartNew();
    ulong observedReadBytes = 0;
    bool observed = false;
    while (!scan.IsCompleted && watch.Elapsed < TimeSpan.FromSeconds(10))
    {
        var delta = ReadBytes(handle) - beforeIo;
        if (delta >= 256 * 1024 && QueueReaderOpen(path) && !scan.IsCompleted)
        { observed = true; observedReadBytes = delta; break; }
        await Task.Delay(1);
    }
    // Cancellation happens only after observation, never on a fixed blind delay.
    var observationMs = watch.Elapsed.TotalMilliseconds;
    cancel.Cancel();
    bool canceled = false;
    try { await scan.WaitAsync(TimeSpan.FromSeconds(15)); }
    catch (OperationCanceledException) { canceled = true; }
    Check(observed, "Scan completed or no active-read evidence was observed; cannot pass this trial.");
    Check(canceled && scan.IsCanceled, "Scan returned a complete/partial result instead of cancellation.");
    var unchangedHash = await Hash(path);
    Check(unchangedHash == expected.Sha256 && new FileInfo(path).Length == expected.Bytes, "Canceled query changed bytes.");
    var added = Event(false) with { OccurredAtUtc = new DateTimeOffset(2026, 10, 24, 12, 0, 0, TimeSpan.Zero) };
    using var recoveryDeadline = new CancellationTokenSource(TimeSpan.FromSeconds(30));
    await sink.WriteAsync(added, recoveryDeadline.Token);
    var recovered = await Scan(sink, query, recoveryDeadline.Token);
    var inventory = recovered is AuditQueueRetentionPreview preview ? preview.Integrity : (AuditQueueIntegritySnapshot)recovered;
    Check(inventory.ValidEvents == expected.Lines + 1 && inventory.PendingEvents == expected.Pending + 1 &&
        inventory.DispatchedEvents == expected.Confirmed && !inventory.RequiresAttention, "Recovery inventory mismatch.");
    if (recovered is AuditQueueRetentionPreview p)
        Check(p.ConfirmedEventsBeforeCutoff == expected.Confirmed && p.PreviewOnly && !p.DeletionSupported, "Recovery preview mismatch.");
    var latest = await new LocalQueueAuditSink(path).ReadRecentAsync(1, recoveryDeadline.Token);
    Check(latest.Count == 1 && latest[0].EventId == added.EventId, "Recovery event ID missing after reopen.");
    await File.WriteAllTextAsync(Path.Combine(trial, "result.json"), JsonSerializer.Serialize(new
    {
        result = "passed", query, ownedWorkerPid = process.Id, observedReadBytes, observationMs,
        queueReaderObserved = true, operationPendingAtObservation = true, cancellationObserved = canceled,
        queueBytesBefore = expected.Bytes, queueSha256Before = expected.Sha256, queueSha256AfterCancellation = unchangedHash,
        validLinesAfterRecovery = inventory.ValidEvents, pendingAfterRecovery = inventory.PendingEvents,
        confirmedAfterRecovery = inventory.DispatchedEvents, recoveryEventId = added.EventId,
        queueSha256AfterRecovery = await Hash(path), peakWorkingSetBytes = process.PeakWorkingSet64
    }, reportOptions));
}

async Task<object> Scan(LocalQueueAuditSink sink, string query, CancellationToken token) => query == "integrity"
    ? await sink.InspectIntegrityAsync(token) : await sink.PreviewRetentionAsync(cutoff, token);
static bool QueueReaderOpen(string path)
{
    try { using var file = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.None); return false; }
    catch (IOException e) when ((e.HResult & 0xffff) == 32) { return true; }
}
static ulong ReadBytes(IntPtr handle)
{
    if (!Native.GetProcessIoCounters(handle, out var counters)) throw new System.ComponentModel.Win32Exception();
    return counters.ReadTransferCount;
}
static async Task<string> Hash(string path)
{
    await using var stream = File.OpenRead(path);
    return Convert.ToHexString(await SHA256.HashDataAsync(stream));
}
static string Guard(string path)
{
    var full = Path.GetFullPath(path);
    var installed = Path.GetFullPath(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "SafeUpload"));
    Check(!full.Equals(installed, StringComparison.OrdinalIgnoreCase) && !full.StartsWith(installed + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase), "Installed agent data refused.");
    for (var d = new DirectoryInfo(full); d is not null; d = d.Parent)
        if (d.Exists) Check((d.Attributes & FileAttributes.ReparsePoint) == 0, "Reparse ancestors refused.");
    return full;
}
static void Check(bool condition, string message) { if (!condition) throw new InvalidDataException(message); }
static AuditEvent Event(bool sent) => new(Guid.NewGuid(), new DateTimeOffset(2020, 1, 1, 0, 0, 0, TimeSpan.Zero),
    "PC-SINTETICO", "usuario-sintetico", "sintetico.txt", ".txt", 42, Verdict.Approved, [], [],
    "processo-sintetico", 1, "destino-sintetico", null, 1, 1, sent);
internal sealed record Manifest(long Lines, long Pending, long Confirmed, long Bytes, string Sha256);
internal static class Native
{
    [StructLayout(LayoutKind.Sequential)] internal struct Counters
    {
        public ulong ReadOperationCount, WriteOperationCount, OtherOperationCount;
        public ulong ReadTransferCount, WriteTransferCount, OtherTransferCount;
    }
    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern bool GetProcessIoCounters(IntPtr process, out Counters counters);
}
