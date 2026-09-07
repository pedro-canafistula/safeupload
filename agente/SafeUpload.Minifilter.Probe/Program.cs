// Probe for the SafeUpload minifilter - a test instrument, not the agent.
//
// The real detection lives in SafeUpload.Agent.Core: RN-001 to RN-004,
// the extractors, the masking, the InspectionService. This program does
// none of that on purpose. The battery it serves exists to test the
// DRIVER, and that needs a client whose behaviour is entirely
// predictable; a probe that ran the real rules would make every failure
// ambiguous between the two sides.
//
// What it does demonstrate is the shape any client has to keep:
//
//   1. Verify the contract before connecting.
//   2. Push the policy. Until that lands the driver inspects nothing.
//   3. Answer every request inside the driver's 500 ms budget.
//   4. Never let a failure to inspect become a block (RN-013).
//
// The service wires the same port to InspectionService instead - see
// MinifilterInterceptor in SafeUpload.Agent.Service.

using System;
using System.Diagnostics;
using System.IO;
using System.Threading;
using SafeUpload.Agent.Minifilter;

namespace SafeUpload.Minifilter.Probe;

public static class Program
{
    private const string BlockToken = "BLOQUEAR_TESTE";

    /// <summary>
    /// Signalled once the port is connected and the policy is in. The test
    /// harness creates this before starting the process and waits on it.
    ///
    /// It exists because the obvious alternative - watching the log for a
    /// "connected" line - is file I/O, and file I/O on that machine goes
    /// through the very filter this process answers for. The watcher ends
    /// up waiting on the agent that is waiting on the watcher.
    /// </summary>
    private const string ReadyEventName = @"Global\SafeUploadInspectorReady";

    /// <summary>
    /// The driver waits this long for a verdict before giving up and
    /// allowing the operation. Measuring against it locally is the only
    /// way to notice that inspection has started silently failing, since
    /// a blown budget looks exactly like a permitted file.
    /// </summary>
    private static readonly TimeSpan VerdictBudget = TimeSpan.FromMilliseconds(500);

    public static int Main(string[] args)
    {
        // Console output is buffered when redirected, and the harness reads
        // this process's log while it runs. Without this the log stays
        // empty until the buffer fills or the process exits, and every
        // assertion that waits for a request line times out against a file
        // that is correct but not yet written.
        Console.SetOut(new StreamWriter(Console.OpenStandardOutput()) { AutoFlush = true });

        bool verifyOnly = Array.Exists(args, a => a == "--verify");

        try
        {
            Contract.Verify();

            if (verifyOnly)
            {
                PrintContract();
                return 0;
            }
        }
        catch (InvalidOperationException ex)
        {
            Console.Error.WriteLine("Contrato incompativel: " + ex.Message);
            return 2;
        }

        try
        {
            using FilterPort port = FilterPort.Connect();

            if (Array.Exists(args, a => a == "--counters"))
            {
                PrintCounters(port.GetCounters());
                return 0;
            }

            SendPolicy(port);
            Console.WriteLine("Conectado. Aguardando requisicoes. Ctrl+C para sair.");
            SignalReady();
            RunMessageLoop(port);
            return 0;
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine(ex.Message);
            return 1;
        }
    }

    /// <summary>
    /// Prints what the managed side believes the contract to be. Runs
    /// without a driver, so it can be part of a build check rather than
    /// something only the target VM can answer.
    /// </summary>
    private static unsafe void PrintContract()
    {
        Console.WriteLine($"Protocolo versao {Contract.Version}, porta {Contract.PortName}");
        Console.WriteLine($"  SAFEUPLOAD_REQUEST        {sizeof(SafeUploadRequest),6} bytes");
        Console.WriteLine($"  SAFEUPLOAD_RESPONSE       {sizeof(SafeUploadResponse),6} bytes");
        Console.WriteLine($"  SAFEUPLOAD_CONTROL        {sizeof(SafeUploadControl),6} bytes");
        Console.WriteLine($"  SAFEUPLOAD_POLICY_MESSAGE {sizeof(SafeUploadPolicyMessage),6} bytes");
        Console.WriteLine($"  SAFEUPLOAD_COUNTERS       {sizeof(SafeUploadCounters),6} bytes");
        Console.WriteLine("Todos batem com os C_ASSERT de Protocol.h.");
    }

    /// <summary>
    /// Tells the harness the agent is ready. Signalled only after the
    /// policy is in, because a driver with no policy inspects nothing -
    /// reporting ready any earlier would let the first test case run
    /// against a filter that cannot answer it.
    ///
    /// Absence of the event is normal: it means nobody is waiting.
    /// </summary>
    private static void SignalReady()
    {
        try
        {
            if (EventWaitHandle.TryOpenExisting(ReadyEventName, out EventWaitHandle? ready))
            {
                using (ready) { ready.Set(); }
            }
        }
        catch (UnauthorizedAccessException)
        {
            // The event exists but belongs to a session this process
            // cannot touch. Not fatal, and not this program's business.
        }
        catch (WaitHandleCannotBeOpenedException)
        {
        }
    }

    private static void SendPolicy(FilterPort port)
    {
        // Mirrors what SafeUpload.Inspector pushes, so the existing test
        // battery exercises this client unchanged.
        SafeUploadPolicyMessage policy = new PolicyBuilder()
            .WithExtension(".txt")
            .WithExtension(".csv")
            .WithExtension(".docx")
            .WithExtension(".xlsx")
            .WithDestination(@"C:\safeupload-teste")
            .WithSource(@"C:\safeupload-origem")
            .WithVolumeKinds(removable: true, network: true)
            .Build();

        port.SetPolicy(policy);

        Console.WriteLine("Politica enviada.");
    }

    private static void RunMessageLoop(FilterPort port)
    {
        var stopwatch = new Stopwatch();
        long sequence = 0;

        while (port.TryGetMessage(out SafeUploadRequest request, out ulong messageId))
        {
            stopwatch.Restart();

            uint verdict = Decide(request);

            port.Reply(messageId, request.RequestId, verdict);

            stopwatch.Stop();
            sequence += 1;

            string scope = request.TypedFlags.HasFlag(RequestFlags.ScopeSource) ? "origem"
                         : request.TypedFlags.HasFlag(RequestFlags.ScopeDestination) ? "destino"
                         : "indefinido";

            Console.WriteLine(
                $"[{sequence}] {(verdict == Verdict.Deny ? "NEGADO " : "liberado")} " +
                $"escopo:{scope} pid:{request.RequestorProcessId} " +
                $"{stopwatch.Elapsed.TotalMilliseconds:F1}ms {request.GetPath()}");

            if (stopwatch.Elapsed > VerdictBudget)
            {
                // Past this point the driver has already stopped waiting
                // and allowed the operation. The file was NOT inspected,
                // whatever this loop decided.
                Console.WriteLine(
                    $"      ATENCAO: {stopwatch.Elapsed.TotalMilliseconds:F0}ms excede o orcamento de " +
                    $"{VerdictBudget.TotalMilliseconds:F0}ms. A operacao passou sem inspecao.");
            }
        }
    }

    /// <summary>
    /// Where the real rules go. Everything this function does must be
    /// cheap and local: no hashing, no disk, no network, no lock that a
    /// slower thread can hold. Work that cannot meet the budget belongs
    /// behind a cache that this function only reads.
    /// </summary>
    private static uint Decide(SafeUploadRequest request)
    {
        if (request.Version != Contract.Version)
        {
            // An unrecognised message is allowed, never blocked - rule 5
            // of the contract, and the same reasoning as RN-013.
            return Verdict.Allow;
        }

        string path = request.GetPath();

        return path.Contains(BlockToken, StringComparison.OrdinalIgnoreCase)
            ? Verdict.Deny
            : Verdict.Allow;
    }

    /// <summary>
    /// Decodes the class bitmap into names.
    ///
    /// The harness parses this line, and its absence is not a cosmetic
    /// loss: the diagnostic that asks whether a hard link ever reached the
    /// SET_INFORMATION hook decides by looking for class 11 or 72 here.
    /// With no line to match, it reports "did not reach" for both the case
    /// where nothing arrived and the case where something did - the exact
    /// answer it exists to tell apart.
    /// </summary>
    private static void PrintClassesSeen(SafeUploadCounters c)
    {
        (uint Class, string Name)[] known =
        [
            (4, "FileBasicInformation"),
            (10, "FileRenameInformation"),
            (11, "FileLinkInformation"),
            (13, "FileDispositionInformation"),
            (14, "FilePositionInformation"),
            (19, "FileEndOfFileInformation"),
            (20, "FileAllocationInformation"),
            (64, "FileDispositionInformationEx"),
            (65, "FileRenameInformationEx"),
            (72, "FileLinkInformationEx"),
        ];

        Console.Write("  classes vistas        :");

        foreach ((uint bit, string name) in known)
        {
            ulong word = bit < 64 ? c.ClassesSeenLow : c.ClassesSeenHigh;
            int shift = (int) (bit < 64 ? bit : bit - 64);

            if (((word >> shift) & 1) != 0)
            {
                Console.Write($" {bit}={name}");
            }
        }

        Console.WriteLine();
    }

    private static void PrintCounters(SafeUploadCounters c)
    {
        Console.WriteLine($"CreatesSeen             : {c.CreatesSeen}");
        Console.WriteLine($"CreatesPastCheapGates   : {c.CreatesPastCheapGates}");
        Console.WriteLine($"ScopeEvaluations        : {c.ScopeEvaluations}");
        Console.WriteLine($"UserModeRoundTrips      : {c.UserModeRoundTrips}");
        Console.WriteLine($"CacheHits               : {c.CacheHits}");
        Console.WriteLine($"DeniedPreCreate         : {c.DeniedPreCreate}");
        Console.WriteLine($"DeniedPostCreate        : {c.DeniedPostCreate}");
        Console.WriteLine($"DeniedRename            : {c.DeniedRename}");
        Console.WriteLine($"AllowedWithoutInspection: {c.AllowedWithoutInspection}");
        Console.WriteLine($"TaintsRecorded          : {c.TaintsRecorded}");
        Console.WriteLine($"TaintLookups            : {c.TaintLookups}");
        Console.WriteLine($"TaintHits               : {c.TaintHits}");
        Console.WriteLine($"SetInformationSeen      : {c.SetInformationSeen}");
        Console.WriteLine($"RenamesSeen             : {c.RenamesSeen}");
        Console.WriteLine($"RenamesFromTainted      : {c.RenamesFromTainted}");
        Console.WriteLine($"LinksSeen               : {c.LinksSeen}");
        Console.WriteLine($"LinksFromTainted        : {c.LinksFromTainted}");
        Console.WriteLine($"ClassesSeen             : {c.ClassesSeenHigh:X16} {c.ClassesSeenLow:X16}");
        PrintClassesSeen(c);

        if (c.CreatesSeen > 0)
        {
            double past = 100.0 * c.CreatesPastCheapGates / c.CreatesSeen;
            Console.WriteLine($"\nPassaram das portas baratas: {past:F4}% dos creates");
        }

        ulong lookups = c.CacheHits + c.UserModeRoundTrips;

        if (lookups > 0)
        {
            Console.WriteLine($"Acerto de cache            : {100.0 * c.CacheHits / lookups:F1}%");
        }

        if (c.AllowedWithoutInspection > 0)
        {
            Console.WriteLine(
                $"\nATENCAO: {c.AllowedWithoutInspection} operacoes passaram sem inspecao (RN-013). " +
                "O servico nao esta respondendo dentro do orcamento.");
        }
    }
}
