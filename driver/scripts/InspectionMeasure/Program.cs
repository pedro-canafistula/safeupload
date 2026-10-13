using System.Diagnostics;
using System.Security.Cryptography;
using System.Text.Json;
using SafeUpload.Agent.Core.Application;
using SafeUpload.Agent.Core.Domain;
using SafeUpload.Agent.Core.Infrastructure;
using SafeUpload.Agent.Core.Infrastructure.Extraction;

// Read-only component measurements in a fresh process per retained fixture.
// No filter, policy-file edit, publication, purge, or source modification.
internal static class Program
{
    private static async Task<int> Main(string[] args)
    {
        if (args.Length != 3 || args[1] is not ("clean" or "cpf") ||
            args[2].Length != 40 || args[2].Any(c => !char.IsAsciiHexDigit(c))) return 2;
        try
        {
            string path = Path.GetFullPath(args[0]);
            if (!OperatingSystem.IsWindows() || (File.GetAttributes(path) & FileAttributes.ReparsePoint) != 0)
                throw new IOException("A regular Windows fixture is required.");
            // Deny name replacement/writes while hashing and inspecting. Each
            // scanner opens an owned read lease on this same stable fixture.
            await using var held = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read,
                64 * 1024, FileOptions.Asynchronous | FileOptions.SequentialScan);
            string original = await DigestAsync(held);
            var policy = LocalPolicyStore.CreateDefault();
            var service = new InspectionService(new FixedPolicy(policy), new NoAudit(),
                ExtractorRegistry.CreateDefault(), new VerdictCache());
            var operation = new FileOperation(path, Path.GetFileName(path), Path.GetExtension(path).ToLowerInvariant(),
                held.Length, File.GetLastWriteTimeUtc(path), "explorer.exe", Environment.ProcessId,
                @"E:\inspection-measure-fixture", DestinationKind.RemovableDrive);
            using var process = Process.GetCurrentProcess();
            var rows = new List<object>();
            bool matched = true;
            for (int scan = 0; scan < 2; scan++)
            {
                process.Refresh();
                long beforePeak = process.PeakWorkingSet64;
                TimeSpan beforeCpu = process.TotalProcessorTime;
                var elapsed = Stopwatch.StartNew();
                var result = await service.InspectStagedAsync(operation, CancellationToken.None);
                elapsed.Stop();
                process.Refresh();
                bool expected = result.InScope && !result.FromCache && result.Reason is null &&
                    result.Verdict == (args[1] == "cpf" ? Verdict.Blocked : Verdict.Approved) &&
                    (args[1] == "cpf" ? result.Findings.Count == 1 && result.Findings[0].Category == Category.Cpf
                        : result.Findings.Count == 0);
                matched &= expected;
                rows.Add(new
                {
                    Scan = scan == 0 ? "fresh-process-first" : "same-process-repeat",
                    WallMs = elapsed.Elapsed.TotalMilliseconds,
                    CpuMs = (process.TotalProcessorTime - beforeCpu).TotalMilliseconds,
                    EngineElapsedMs = result.ElapsedMs,
                    PeakWorkingSetBytes = process.PeakWorkingSet64,
                    PeakWorkingSetBeforeBytes = beforePeak,
                    WorkingSetAfterBytes = process.WorkingSet64,
                    PrivateBytesAfter = process.PrivateMemorySize64,
                    ManagedBytesAfter = GC.GetTotalMemory(forceFullCollection: false),
                    Verdict = result.Verdict.ToString(), result.Reason,
                    FailureKind = result.FailureKind?.ToString(), result.FromCache,
                    FindingCount = result.Findings.Count, ExpectedResult = expected
                });
                if (result.FailureKind == InspectionFailureKind.Timeout) break;
            }
            bool unchanged = original == await DigestAsync(held);
            Console.WriteLine(JsonSerializer.Serialize(new
            {
                SourceCommit = args[2], ProcessId = Environment.ProcessId,
                ProcessStartUtcTicks = process.StartTime.ToUniversalTime().Ticks,
                CoreAssemblySha256 = Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(typeof(InspectionService).Assembly.Location))),
                FileName = operation.FileName, Extension = operation.Extension, InputBytes = held.Length,
                SourceSha256 = original, SourceUnchanged = unchanged,
                PolicyFingerprint = PolicyContentFingerprint.Compute(policy), policy.MaxFileSizeBytes,
                InspectionTimeoutMs = policy.InspectionTimeout.TotalMilliseconds,
                Scope = "Inspector-only fresh-process/repeat measurements; filesystem cache is uncontrolled. Process peak is cumulative. No publisher copy, policy I/O, hostile-format bound or protected qualification.",
                Rows = rows, Gate = matched && unchanged ? "PASS" : "FAIL"
            }));
            return matched && unchanged ? 0 : 1;
        }
        catch (Exception error)
        {
            Console.Error.WriteLine("InspectionMeasure failed: " + error.GetType().Name);
            return 1;
        }
    }

    private static async Task<string> DigestAsync(FileStream input)
    {
        input.Position = 0;
        string digest = Convert.ToHexString(await SHA256.HashDataAsync(input));
        input.Position = 0;
        return digest;
    }

    private sealed class FixedPolicy(Policy policy) : IPolicyStore
    {
        public Task<Policy> LoadAsync(CancellationToken token) => Task.FromResult(policy);
        public Task<Policy> LoadCurrentAsync(CancellationToken token) => LoadAsync(token);
    }

    private sealed class NoAudit : IAuditSink
    {
        public Task WriteAsync(AuditEvent auditEvent, CancellationToken token)
            => throw new InvalidOperationException("Staged classification must not record an operation outcome.");
        public Task RecordOverrideAsync(string eventId, string justification, CancellationToken token)
            => throw new InvalidOperationException("The measurement cannot justify content.");
        public Task<IReadOnlyList<AuditEvent>> ReadRecentAsync(int maxEvents, CancellationToken token)
            => Task.FromResult<IReadOnlyList<AuditEvent>>([]);
        public Task<IReadOnlyList<AuditEvent>> ReadPendingAsync(int maxEvents, CancellationToken token)
            => Task.FromResult<IReadOnlyList<AuditEvent>>([]);
        public Task MarkDispatchedAsync(IReadOnlyCollection<Guid> eventIds, CancellationToken token)
            => throw new InvalidOperationException("The measurement cannot dispatch audit events.");
    }
}
