using System.Diagnostics;
using System.Security.Cryptography;
using System.Text.Json;
using SafeUpload.Agent.Core.Application;
using SafeUpload.Agent.Core.Domain;
if (args.Length != 1) throw new ArgumentException("Supply one synthetic input. Use a fresh process per case.");
string path = Path.GetFullPath(args[0]);
await using var input = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read, 64 * 1024, FileOptions.SequentialScan);
long allocatedBefore = GC.GetTotalAllocatedBytes(true);
using var deadline = new CancellationTokenSource(TimeSpan.FromMinutes(10));
var clock = Stopwatch.StartNew();
var result = await StagedParserExecution.InspectAsync(input, Path.GetExtension(path), 4096,
    Enum.GetValues<Category>().ToHashSet(), deadline.Token);
clock.Stop();
long allocated = GC.GetTotalAllocatedBytes(true) - allocatedBefore;
using var process = Process.GetCurrentProcess();
long peak = process.PeakWorkingSet64;
input.Position = 0;
string sha256 = Convert.ToHexString(await SHA256.HashDataAsync(input));
Console.WriteLine(JsonSerializer.Serialize(new {
    file = Path.GetFileName(path), bytes = input.Length, sha256,
    coreAssemblySha256 = Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(typeof(StagedParserExecution).Assembly.Location))),
    seconds = clock.Elapsed.TotalSeconds, MiBPerSecond = input.Length / (1024d * 1024) / clock.Elapsed.TotalSeconds,
    peakWorkingSetBytes = peak, managedAllocatedBytes = allocated,
    failure = result.Failure, findings = result.Findings.Count,
    cache = "fresh process; filesystem/host cache uncontrolled; hash computed after timing",
    scope = "Core parser + all-category full streaming scan; excludes stage/seed/snapshot/publication/hand-back and Windows Job Object"
}));
Environment.ExitCode = result.Failure is null && result.Findings.Count == 0 ? 0 : 1;
