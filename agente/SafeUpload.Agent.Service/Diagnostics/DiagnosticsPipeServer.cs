using System.IO.Pipes;
using System.Globalization;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using SafeUpload.Agent.Service.Notifications;
using SafeUpload.Agent.Core.Infrastructure;

namespace SafeUpload.Agent.Service.Diagnostics;

/// <summary>
/// Administrator-only field diagnostics: one JSON request line in, one JSON reply line out, then the pipe closes.
///
/// <para>The driver's filter port accepts a single client and this service holds it, so the Inspector cannot read
/// driver state while the product runs. This pipe relays read-only queries over the service's own connection:
/// <c>{"query":"counters"}</c> and <c>{"query":"deny-ring","after":0}</c>.
/// <c>{"query":"audit-health"}</c> reads process-local queue health without accessing the driver or queue file. It changes nothing and is not reachable by
/// standard users: the DACL grants only SYSTEM and Administrators. (There is deliberately no deny entry for the
/// NETWORK group: a logon created for an administrator over SSH or a scheduled task carries it, and the harness and
/// support staff read this pipe from such sessions. A remote reader must authenticate as an administrator anyway.)</para>
///
/// <para>Replies can include the tail of a requested file path, which is why the pipe is administrator-only.</para>
/// </summary>
public sealed class DiagnosticsPipeServer : BackgroundService
{
    public const string PipeName = "SafeUpload.Agent.Diagnostics";

    private static readonly TimeSpan RequestTimeout = TimeSpan.FromSeconds(5);
    private static readonly UTF8Encoding Utf8 = new(encoderShouldEmitUTF8Identifier: false);

    private readonly DriverDiagnosticsSource _source;
    private readonly ILogger<DiagnosticsPipeServer> _logger;
    private readonly string _pipeName;
    private readonly AuditQueueHealth? _auditHealth;
    private readonly LocalQueueAuditSink? _auditQueue;

    /// <param name="pipeName">Only tests pass a name; the service always uses <see cref="PipeName"/>.</param>
    public DiagnosticsPipeServer(DriverDiagnosticsSource source, ILogger<DiagnosticsPipeServer> logger,
        string pipeName = PipeName, AuditQueueHealth? auditHealth = null, LocalQueueAuditSink? auditQueue = null)
    {
        _source = source ?? throw new ArgumentNullException(nameof(source));
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        _pipeName = pipeName;
        _auditHealth = auditHealth;
        _auditQueue = auditQueue;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        while (!stoppingToken.IsCancellationRequested)
        {
            NamedPipeServerStream? pipe = null;
            try
            {
                pipe = CreatePipe(_pipeName);
                await pipe.WaitForConnectionAsync(stoppingToken).ConfigureAwait(false);
                await ServeAsync(pipe, stoppingToken).ConfigureAwait(false);
            }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
            {
                return;
            }
            catch (Exception ex)
            {
                // A broken client or a pipe that could not be created must not stop the service or spin.
                _logger.LogWarning(ex, "Diagnostics pipe request failed.");
                try { await Task.Delay(TimeSpan.FromSeconds(1), stoppingToken).ConfigureAwait(false); }
                catch (OperationCanceledException) { return; }
            }
            finally
            {
                if (pipe is not null) await pipe.DisposeAsync().ConfigureAwait(false);
            }
        }
    }

    private async Task ServeAsync(NamedPipeServerStream pipe, CancellationToken stoppingToken)
    {
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(stoppingToken);
        deadline.CancelAfter(RequestTimeout);

        using var reader = new StreamReader(pipe, Utf8, detectEncodingFromByteOrderMarks: false,
            bufferSize: 1024, leaveOpen: true);
        string? line = await BoundedPipeLine.ReadAsync(reader, deadline.Token).ConfigureAwait(false);

        JsonObject reply = await HandleAsync(line, deadline.Token).ConfigureAwait(false);
        byte[] payload = Utf8.GetBytes(reply.ToJsonString() + "\n");
        await pipe.WriteAsync(payload, deadline.Token).ConfigureAwait(false);
        await pipe.FlushAsync(deadline.Token).ConfigureAwait(false);
    }

    private async Task<JsonObject> HandleAsync(string? line, CancellationToken cancellationToken)
    {
        string query = "";
        try
        {
            if (string.IsNullOrWhiteSpace(line)) return Error("", "Empty or oversized request.");
            if (JsonNode.Parse(line) is not JsonObject request) return Error("", "Request must be a JSON object.");
            query = request["query"]?.GetValue<string>() ?? "";

            switch (query)
            {
                case "audit-integrity":
                case "audit-temporaries":
                case "audit-retention-preview":
                    if (_auditQueue is null) return Error(query, "Audit storage is unavailable.");
                    DateTimeOffset cutoff = default;
                    if (query == "audit-retention-preview" && !TryReadCutoff(request, out cutoff))
                        return Error(query, "occurredBeforeUtc must be an explicit ISO 8601 UTC timestamp, excluding the default date.");
                    try
                    {
                        object integrity = query switch
                        {
                            "audit-temporaries" => await _auditQueue.InspectTemporaryFilesAsync(cancellationToken).ConfigureAwait(false),
                            "audit-retention-preview" => await _auditQueue.PreviewRetentionAsync(cutoff, cancellationToken).ConfigureAwait(false),
                            _ => await _auditQueue.InspectIntegrityAsync(cancellationToken).ConfigureAwait(false)
                        };
                        return Ok(query, JsonSerializer.SerializeToNode(integrity, new JsonSerializerOptions
                        { PropertyNamingPolicy = JsonNamingPolicy.CamelCase })!);
                    }
                    catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) { throw; }
                    catch (Exception exception)
                    {
                        // A queue exception can contain a path or record content. Never relay it.
                        return Error(query, "Audit scan failed (" + AuditQueueHealth.Classify(exception) + ").");
                    }
                case "audit-health":
                    return _auditHealth is null ? Error(query, "Audit monitoring is unavailable.") :
                        Ok(query, JsonSerializer.SerializeToNode(_auditHealth.Read(), new JsonSerializerOptions
                        { PropertyNamingPolicy = JsonNamingPolicy.CamelCase })!);
                case "counters":
                    return Ok(query, _source.ReadCounters());
                case "m2-counters":
                    return Ok(query, _source.ReadM2Counters());
                case "m2-stage-streams":
                    return Ok(query, _source.ReadM2StageStreams());
                case "deny-ring":
                    ulong after = request["after"]?.GetValue<ulong>() ?? 0;
                    return Ok(query, _source.ReadDenyRing(after));
                case "help":
                    return Ok(query, new JsonObject
                    {
                        ["queries"] = new JsonArray("counters", "deny-ring", "m2-counters", "m2-stage-streams", "audit-health", "audit-integrity", "audit-temporaries", "audit-retention-preview", "help"),
                        ["m2Diagnostics"] = "explicit pinned m2-e0df8d1c layout; no fallback, capability negotiation or proof of protection; names may include path tails",
                        ["retentionPreview"] = "requires occurredBeforeUtc in UTC; occurrence-age counts only, never deletion eligibility",
                        ["denyRingCursor"] = "pass the previous reply's nextSequence minus one as after; 0 reads from the start",
                        ["connected"] = _source.IsConnected,
                    });
                default:
                    return Error(query, "Unknown query.");
            }
        }
        catch (Exception ex) when (ex is JsonException or InvalidOperationException or FormatException or InvalidDataException)
        {
            return Error(query, ex.Message);
        }
        catch (System.ComponentModel.Win32Exception ex)
        {
            return Error(query, ex.Message);
        }
    }

    private static bool TryReadCutoff(JsonObject request, out DateTimeOffset cutoff)
    {
        cutoff = default;
        return request["occurredBeforeUtc"] is JsonValue value && value.TryGetValue<string>(out var text) &&
            DateTimeOffset.TryParseExact(text,
                ["yyyy-MM-dd'T'HH:mm:ss'Z'", "yyyy-MM-dd'T'HH:mm:ss.FFFFFFF'Z'",
                 "yyyy-MM-dd'T'HH:mm:sszzz", "yyyy-MM-dd'T'HH:mm:ss.FFFFFFFzzz"],
                CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal, out cutoff) &&
            cutoff.Offset == TimeSpan.Zero && cutoff != default;
    }

    private static JsonObject Ok(string query, JsonNode data) =>
        new() { ["ok"] = true, ["query"] = query, ["data"] = data };

    private static JsonObject Error(string query, string message) =>
        new() { ["ok"] = false, ["query"] = query, ["error"] = message };

    private static NamedPipeServerStream CreatePipe(string pipeName)
    {
        var security = new PipeSecurity();

        // SYSTEM runs the service; Administrators may query; nothing else. A supplied PipeSecurity replaces the
        // default DACL, so the account running the process (a console session during debugging) gets full control
        // explicitly, as the other pipes do.
        security.AddAccessRule(new PipeAccessRule(
            new SecurityIdentifier(WellKnownSidType.LocalSystemSid, domainSid: null),
            PipeAccessRights.FullControl, AccessControlType.Allow));
        security.AddAccessRule(new PipeAccessRule(
            new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, domainSid: null),
            PipeAccessRights.ReadWrite, AccessControlType.Allow));

        using var current = WindowsIdentity.GetCurrent();
        if (current.User is { } owner)
        {
            security.AddAccessRule(new PipeAccessRule(owner, PipeAccessRights.FullControl, AccessControlType.Allow));
        }

        return NamedPipeServerStreamAcl.Create(
            pipeName,
            PipeDirection.InOut,
            maxNumberOfServerInstances: 1,
            PipeTransmissionMode.Byte,
            PipeOptions.Asynchronous,
            inBufferSize: 4096,
            outBufferSize: 64 * 1024,
            security);
    }
}
