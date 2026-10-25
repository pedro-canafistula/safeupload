using System.Diagnostics;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using SafeUpload.Agent.Core.Domain;
using SafeUpload.Agent.Core.Infrastructure;

const string Marker = "SafeUpload controlled append interruption v1";
var json = new JsonSerializerOptions { WriteIndented = true };
var cuts = new[] { 1, 4096, 65536 };
if (args.Length == 4 && args[0] == "--worker")
{
    var trial = Guard(args[1]);
    Check(File.ReadAllText(Path.Combine(Directory.GetParent(trial)!.FullName, "probe.marker")) == Marker,
        "Missing synthetic marker.");
    Check(args[2] is "event" or "override" && int.TryParse(args[3], out var cut) && cuts.Contains(cut), "Invalid worker arguments.");
    await Worker(trial, args[2], int.Parse(args[3]));
    return;
}
Check(args.Length is 1 or 2, "Usage: QueueAppendInterruptionProbe <output-parent> [repeats:1..3]");
var repeats = args.Length == 2 ? int.Parse(args[1]) : 1;
Check(repeats is >= 1 and <= 3, "Repeats must be 1..3.");
var parent = Guard(args[0]);
Directory.CreateDirectory(parent); Guard(parent);
Check(new DriveInfo(Path.GetPathRoot(parent)!).AvailableFreeSpace >= 512L * 1024 * 1024, "512 MiB free required.");
var root = Path.Combine(parent, "append-interruption-" + Guid.NewGuid().ToString("N"));
Directory.CreateDirectory(root);
await File.WriteAllTextAsync(Path.Combine(root, "probe.marker"), Marker);
var trials = new List<object>();
Console.WriteLine("Synthetic directory: " + root);
try
{
    foreach (var kind in new[] { "event", "override" })
    foreach (var cut in cuts)
    for (var repeat = 1; repeat <= repeats; repeat++)
    {
        var trial = Path.Combine(root, $"{kind}-{cut}-{repeat}");
        Directory.CreateDirectory(trial);
        var path = Path.Combine(trial, "queue.jsonl");
        var sink = new LocalQueueAuditSink(path);
        var originals = Enumerable.Range(0, 32).Select(Event).ToArray();
        var reasons = originals.Take(4).Select(e => new AuditOverride(e.EventId, "justificativa sintetica",
            e.OccurredAtUtc, e.UserName, e.EndpointId)).ToArray();
        foreach (var item in originals) await sink.WriteAsync(item, CancellationToken.None);
        foreach (var reason in reasons) await sink.RecordOverrideAsync(reason, CancellationToken.None);
        var before = await File.ReadAllBytesAsync(path);
        var operationId = Guid.NewGuid();
        await File.WriteAllTextAsync(Path.Combine(trial, "operation-id.txt"), operationId.ToString());
        var start = new ProcessStartInfo(Environment.ProcessPath!)
        {
            UseShellExecute = false, CreateNoWindow = true,
            RedirectStandardInput = true, RedirectStandardOutput = true, RedirectStandardError = true
        };
        if (Path.GetFileNameWithoutExtension(Environment.ProcessPath!).Equals("dotnet", StringComparison.OrdinalIgnoreCase))
            start.ArgumentList.Add(Assembly.GetExecutingAssembly().Location);
        foreach (var arg in new[] { "--worker", trial, kind, cut.ToString() }) start.ArgumentList.Add(arg);
        using var worker = Process.Start(start) ?? throw new IOException("Worker did not start.");
        var stderr = worker.StandardError.ReadToEndAsync();
        using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(30));
        try
        {
            Check(await worker.StandardOutput.ReadLineAsync(deadline.Token) == "ready", "Worker not ready.");
            await worker.StandardInput.WriteLineAsync("go");
            await worker.StandardInput.FlushAsync(deadline.Token);
            var reportLine = await worker.StandardOutput.ReadLineAsync(deadline.Token);
            Check(reportLine is not null, "No partial-write receipt.");
            var boundary = JsonSerializer.Deserialize<Boundary>(reportLine!)!;
            Check(boundary.Written == cut && boundary.Total > cut && boundary.FinalByte != 10, "No incomplete line at controlled cut.");
            Check(await worker.StandardOutput.ReadLineAsync(deadline.Token) == "operation-pending", "Operation returned or did not reach pending boundary.");
            // Observe actual bytes while the worker remains blocked inside WriteAsync.
            byte[] observed;
            await using (var reader = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite))
            {
                Check(reader.Length == before.Length + cut, "Live file length mismatch.");
                observed = new byte[checked((int)reader.Length)];
                await reader.ReadExactlyAsync(observed, deadline.Token);
            }
            Check(observed.Length == before.Length + cut && observed.AsSpan(0, before.Length).SequenceEqual(before), "Live prefix/length mismatch.");
            Check(Hash(observed.AsSpan(before.Length)) == boundary.PrefixSha256, "Live tail differs from written prefix.");
            Check(!worker.HasExited, "Worker exited before interruption.");
            worker.Kill(entireProcessTree: true);
            await worker.WaitForExitAsync(deadline.Token);
            Check(string.IsNullOrWhiteSpace(await stderr), "Worker error before interruption.");
            Check(await worker.StandardOutput.ReadLineAsync(deadline.Token) is null, "Unexpected completion receipt.");
            var afterKill = await File.ReadAllBytesAsync(path);
            Check(afterKill.AsSpan().SequenceEqual(observed), "Bytes changed between observation and exit.");
            // Recovery uses only the public, uninstrumented production constructor.
            var reopened = new LocalQueueAuditSink(path);
            var integrity = await reopened.InspectIntegrityAsync(deadline.Token);
            Check(integrity.ValidEvents == 32 && integrity.ValidOverrides == 4 && integrity.InvalidLines == 1 && integrity.UnknownRecords == 0,
                "Partial line not isolated to one invalid record.");
            await Baseline(reopened, originals, reasons, deadline.Token);
            Check((await File.ReadAllBytesAsync(path)).AsSpan().SequenceEqual(afterKill), "Read/diagnostic changed bytes.");
            var recovered = Event(100);
            var recoveredReason = new AuditOverride(recovered.EventId, "recuperacao sintetica", recovered.OccurredAtUtc, recovered.UserName, recovered.EndpointId);
            await reopened.WriteAsync(recovered, deadline.Token);
            await reopened.RecordOverrideAsync(recoveredReason, deadline.Token);
            var recoveredBytes = await File.ReadAllBytesAsync(path);
            Check(recoveredBytes.AsSpan(0, afterKill.Length).SequenceEqual(afterKill), "Recovery changed preserved tail/prefix.");
            Check(recoveredBytes.AsSpan(afterKill.Length, Encoding.UTF8.GetByteCount(Environment.NewLine)).SequenceEqual(Encoding.UTF8.GetBytes(Environment.NewLine)),
                "Recovery did not separate partial line before new record.");
            var final = new LocalQueueAuditSink(path);
            await Baseline(final, originals, reasons, deadline.Token);
            var events = await final.ReadPendingAsync(0, deadline.Token);
            var overrides = await final.ReadPendingOverridesAsync(0, deadline.Token);
            Check(events.Count == 33 && events.Count(e => e.EventId == recovered.EventId) == 1 && events.All(e => e.EventId != operationId), "Recovery event lost/duplicated or partial event promoted.");
            Check(overrides.Count == 5 && overrides.Contains(recoveredReason) && overrides.All(o => o.EventId != operationId), "Recovery override lost or partial override promoted.");
            var inventory = await final.InspectIntegrityAsync(deadline.Token);
            Check(inventory.InvalidLines == 1 && inventory.UnknownRecords == 0 && inventory.ValidEvents == 33 && inventory.ValidOverrides == 5,
                "Recovery hid corruption or added invalid records.");
            await final.MarkDispatchedAsync([recovered.EventId], deadline.Token);
            await final.MarkOverridesDispatchedAsync([recoveredReason], deadline.Token);
            var afterConfirm = new LocalQueueAuditSink(path);
            await Baseline(afterConfirm, originals, reasons, deadline.Token);
            Check((await afterConfirm.ReadPendingAsync(0, deadline.Token)).Count == 32 &&
                (await afterConfirm.ReadPendingOverridesAsync(0, deadline.Token)).Count == 4 &&
                (await afterConfirm.InspectIntegrityAsync(deadline.Token)).InvalidLines == 1, "Confirmation retry changed baseline or hid partial line.");
            var confirmHash = Hash(await File.ReadAllBytesAsync(path));
            await afterConfirm.MarkDispatchedAsync([recovered.EventId], deadline.Token);
            await afterConfirm.MarkOverridesDispatchedAsync([recoveredReason], deadline.Token);
            Check(Hash(await File.ReadAllBytesAsync(path)) == confirmHash, "Repeated confirmation not content-idempotent.");
            var result = new
            {
                result = "passed", kind, cut, repeat, ownedWorkerPid = worker.Id, exitCode = worker.ExitCode,
                injection = "real FileStream prefix + controlled pending WriteAsync; owned process killed",
                boundary, liveBytesObserved = observed.Length, operationPendingAtObservation = true,
                completionReceived = false, seedBytes = before.Length, seedSha256 = Hash(before),
                queueBytesAfterKill = afterKill.Length, queueSha256AfterKill = Hash(afterKill),
                tailSha256 = Hash(afterKill.AsSpan(before.Length)), tailHex = Convert.ToHexString(afterKill.AsSpan(before.Length, Math.Min(cut, 32))),
                baselineEventsPreserved = 32, baselineOverridesPreserved = 4,
                invalidAfterKill = integrity.InvalidLines, invalidAfterRecovery = inventory.InvalidLines,
                recoveredEventId = recovered.EventId, finalSha256 = confirmHash,
                rawTailPreservedThroughRecoveryAppend = true, confirmationContentIdempotent = true
            };
            await File.WriteAllTextAsync(Path.Combine(trial, "result.json"), JsonSerializer.Serialize(result, json));
            trials.Add(result);
            Console.WriteLine($"PASS {kind} cut={cut} repeat={repeat}; partial bytes observed before Kill; recovery preserved baseline.");
        }
        finally
        {
            // Own only this Process object, never search/kill by executable name.
            if (!worker.HasExited) { worker.Kill(entireProcessTree: true); await worker.WaitForExitAsync(); }
        }
    }
    await File.WriteAllTextAsync(Path.Combine(root, "result.json"), JsonSerializer.Serialize(new
    {
        result = "passed", finishedUtc = DateTimeOffset.UtcNow, repeats, cuts, trials,
        framework = RuntimeInformation.FrameworkDescription, os = RuntimeInformation.OSDescription,
        coreAssemblySha256 = Hash(await File.ReadAllBytesAsync(typeof(LocalQueueAuditSink).Assembly.Location)),
        probeAssemblySha256 = Hash(await File.ReadAllBytesAsync(Assembly.GetExecutingAssembly().Location)),
        limitation = "Controlled I/O fault injection, not uninstrumented native-write interruption, physical durability or power loss. No partial record promoted/repaired; invalid tail remains. No installed service, VM, driver or API accessed. Synthetic queues retained."
    }, json));
    Console.WriteLine("PASS receipt: " + Path.Combine(root, "result.json"));
}
catch (Exception ex)
{
    await File.WriteAllTextAsync(Path.Combine(root, "failure.json"), JsonSerializer.Serialize(new { result = "failed", error = ex.ToString(), trials }, json));
    throw;
}

async Task Worker(string trial, string kind, int cut)
{
    var id = Guid.Parse(await File.ReadAllTextAsync(Path.Combine(trial, "operation-id.txt")));
    var sink = new LocalQueueAuditSink(Path.Combine(trial, "queue.jsonl"), path => new PausedAppendStream(path, cut));
    var item = Event(99) with { EventId = id, MaskedSnippets = [new string('x', 128 * 1024)] };
    Console.WriteLine("ready");
    Check(await Console.In.ReadLineAsync() == "go", "Missing handshake.");
    var operation = kind == "event" ? sink.WriteAsync(item, CancellationToken.None) :
        sink.RecordOverrideAsync(new AuditOverride(id, new string('x', 128 * 1024), item.OccurredAtUtc, item.UserName, item.EndpointId), CancellationToken.None);
    // PausedAppendStream emits its byte receipt first; wait until that boundary.
    await PausedAppendStream.Partial.Task;
    Check(!operation.IsCompleted, "Append completed before pending observation.");
    Console.WriteLine("operation-pending");
    await operation;
    Console.WriteLine("completed");
}

static async Task Baseline(LocalQueueAuditSink sink, AuditEvent[] originals, AuditOverride[] reasons, CancellationToken token)
{
    var events = await sink.ReadPendingAsync(0, token);
    foreach (var e in originals)
        Check(events.Count(a => a.EventId == e.EventId && JsonSerializer.Serialize(a) == JsonSerializer.Serialize(e)) == 1,
            "Baseline event lost, duplicated or metadata changed.");
    var overrides = await sink.ReadPendingOverridesAsync(0, token);
    Check(reasons.All(r => overrides.Count(o => o == r) == 1), "Baseline override lost/duplicated/changed.");
}
static string Guard(string path)
{
    var full = Path.GetFullPath(path);
    var installed = Path.GetFullPath(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "SafeUpload"));
    Check(!full.Equals(installed, StringComparison.OrdinalIgnoreCase) && !full.StartsWith(installed + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase), "Installed data refused.");
    for (var item = new DirectoryInfo(full); item is not null; item = item.Parent)
        if (item.Exists) Check((item.Attributes & FileAttributes.ReparsePoint) == 0, "Reparse-point directories refused.");
    var queue = Path.Combine(full, "queue.jsonl");
    if (File.Exists(queue)) Check((File.GetAttributes(queue) & FileAttributes.ReparsePoint) == 0, "Queue link refused.");
    return full;
}
static AuditEvent Event(int index) => new(Guid.NewGuid(), new DateTimeOffset(2026, 10, 25, 12, 0, 0, TimeSpan.Zero).AddSeconds(index),
    "PC-SINTETICO", "usuario-sintetico", $"sintetico-{index}.txt", ".txt", 42, Verdict.Blocked,
    [Category.Cpf], ["mascarado-sintetico"], "processo-sintetico", 123, "destino-sintetico", null, 1, 10, false);
static string Hash(ReadOnlySpan<byte> bytes) => Convert.ToHexString(SHA256.HashData(bytes));
static void Check(bool condition, string message) { if (!condition) throw new InvalidDataException(message); }
internal sealed record Boundary(int Written, int Total, int FinalByte, string PrefixSha256);
internal sealed class PausedAppendStream(string path, int cut)
    : FileStream(path, FileMode.OpenOrCreate, FileAccess.ReadWrite, FileShare.Read, 4096, FileOptions.Asynchronous)
{
    internal static readonly TaskCompletionSource Partial = new(TaskCreationOptions.RunContinuationsAsynchronously);
    public override async ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken token = default)
    {
        if (buffer.Length <= cut) throw new InvalidDataException("Payload too short for partial write.");
        await base.WriteAsync(buffer[..cut], token);
        await base.FlushAsync(token);
        Console.WriteLine(JsonSerializer.Serialize(new Boundary(cut, buffer.Length, buffer.Span[cut - 1],
            Convert.ToHexString(SHA256.HashData(buffer.Span[..cut])))));
        Console.Out.Flush();
        Partial.TrySetResult();
        await Task.Delay(Timeout.InfiniteTimeSpan, token);
        throw new InvalidOperationException("Controlled write must never resume.");
    }
}
