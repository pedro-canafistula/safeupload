using System.Text.Json;
using System.Text.Json.Nodes;
using SafeUpload.Agent.Minifilter;

namespace SafeUpload.Agent.Service.Diagnostics;

public sealed partial class DriverDiagnosticsSource
{
    private static readonly JsonSerializerOptions M2Json = new()
    {
        IncludeFields = true,
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
    };

    // Explicit queries only: never called by readiness, background monitoring or
    // legacy counters. WithPort holds the existing binding lock during the query.
    public JsonObject ReadM2Counters() => WithPort(port => QueryM2Counters(port));
    public JsonObject ReadM2StageStreams() => WithPort(port => QueryM2StageStreams(port));

    internal static JsonObject QueryM2Counters(IM2DiagnosticTransport transport)
    {
        var snapshot = new M2DiagnosticClient(transport).ReadCounters();
        var data = Envelope();
        data["atomic"] = false; // Two sequential native replies.
        data["snapshot"] = JsonSerializer.SerializeToNode(snapshot, M2Json);
        return data;
    }

    internal static JsonObject QueryM2StageStreams(IM2DiagnosticTransport transport)
    {
        var snapshot = new M2DiagnosticClient(transport).ReadStageStreams();
        var data = Envelope();
        data["atomic"] = false;
        data["total"] = snapshot.Total;
        data["count"] = snapshot.Records.Count;
        data["truncated"] = snapshot.Truncated;
        var records = new JsonArray();
        foreach (var record in snapshot.Records)
        {
            var node = JsonSerializer.SerializeToNode(record, M2Json)!.AsObject();
            // JSON display strings may replace an unpaired WCHAR surrogate.
            // Preserve every original code unit separately, including NUL.
            var units = new JsonArray();
            foreach (char unit in record.Name) units.Add((int)unit);
            node["nameCodeUnits"] = units;
            records.Add(node);
        }
        data["records"] = records;
        return data;
    }

    private static JsonObject Envelope() => new()
    {
        ["profile"] = "m2-e0df8d1c",
        ["referenceDriverCommit"] = "e0df8d1c1f889418a133d3ae66a87a6c76a7bd5f",
        ["protocolVersion"] = M2DiagnosticContract.ProtocolVersion,
        ["compatibilityVerified"] = false,
        ["protectionVerified"] = false,
    };
}
