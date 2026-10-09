using System.IO.Pipes;
using System.Text;
using System.Text.Json.Nodes;
using Microsoft.Extensions.Logging.Abstractions;
using SafeUpload.Agent.Minifilter;
using SafeUpload.Agent.Service.Diagnostics;

namespace SafeUpload.Agent.Tests;

/// <summary>
/// The field-diagnostics channel: the wire layouts that must match Protocol.h, the readable names given to codes,
/// and the administrator pipe's behavior with and without a connected driver.
/// </summary>
public sealed class DriverDiagnosticsTests
{
    [Fact]
    public void Wire_layouts_match_the_protocol_header()
    {
        DiagnosticsContract.Verify();
    }

    [Fact]
    public void Refusal_flags_are_listed_by_name()
    {
        JsonArray names = DriverDiagnosticsSource.FlagNames(
            DiagnosticsContract.FlagTopLevelIrp | DiagnosticsContract.FlagNameIsRenameTarget |
            DiagnosticsContract.FlagServiceProcess);

        Assert.Equal(new[] { "topLevelIrp", "nameIsRenameTarget", "serviceProcess" },
            names.Select(node => node!.GetValue<string>()).ToArray());
        Assert.Empty(DriverDiagnosticsSource.FlagNames(0));
    }

    [Theory]
    [InlineData(0xC0000022u, "STATUS_ACCESS_DENIED")]
    [InlineData(0xC000022Du, "STATUS_RETRY")]
    [InlineData(0xC0000904u, "STATUS_FILE_TOO_LARGE")]
    [InlineData(0xC00000D4u, "STATUS_NOT_SAME_DEVICE")]
    [InlineData(0xC0001234u, "")]
    public void Status_codes_get_their_ntstatus_names(uint status, string expected)
    {
        Assert.Equal(expected, DriverDiagnosticsSource.StatusName(status));
    }

    [Theory]
    [InlineData(0xC0000022u, "STATUS_ACCESS_DENIED")]
    [InlineData(0xE5000002u, "noRegistryEntry")]
    [InlineData(0xE5000106u, "entryState=1")]
    [InlineData(0xE5000007u, "entryClass=0")]
    [InlineData(0xE5000B0Bu, "entryRenameInFlight")]
    [InlineData(0xE50000FFu, "why255")]
    public void Aux_values_name_the_status_or_the_reason_a_stream_was_not_known_outside(uint aux, string expected)
    {
        Assert.Equal(expected, DriverDiagnosticsSource.AuxName(aux));
    }

    [Theory]
    [InlineData(0u, "CREATE")]
    [InlineData(4u, "WRITE")]
    [InlineData(6u, "SET_INFORMATION")]
    [InlineData(0xFFu, "ACQUIRE_FOR_SECTION_SYNCHRONIZATION")]
    [InlineData(99u, "99")]
    public void Major_functions_get_their_irp_names(uint major, string expected)
    {
        Assert.Equal(expected, DriverDiagnosticsSource.MajorName(major));
    }

    [Theory]
    [InlineData(0u, "")]
    [InlineData(1u, "nameUnresolved")]
    [InlineData(3u, "policyScope")]
    [InlineData(6u, "aliasCheckFailed")]
    [InlineData(10u, "deleteOnClose")]
    [InlineData(99u, "99")]
    public void Refusal_reasons_get_readable_names(uint reason, string expected)
    {
        Assert.Equal(expected, DriverDiagnosticsSource.ReasonName(reason));
    }

    [Fact]
    public void Queries_fail_cleanly_while_the_driver_is_not_connected()
    {
        var source = new DriverDiagnosticsSource();

        Assert.False(source.IsConnected);
        Assert.Throws<InvalidOperationException>(() => source.ReadCounters());
        Assert.Throws<InvalidOperationException>(() => source.ReadDenyRing(0));
    }

    [Fact]
    public async Task Pipe_answers_help_and_reports_errors_as_json()
    {
        string pipeName = "SafeUpload.Agent.Diagnostics.Test." + Guid.NewGuid().ToString("N");
        var server = new DiagnosticsPipeServer(new DriverDiagnosticsSource(),
            NullLogger<DiagnosticsPipeServer>.Instance, pipeName);
        await server.StartAsync(CancellationToken.None);
        try
        {
            JsonObject help = await ExchangeAsync(pipeName, "{\"query\":\"help\"}");
            Assert.True(help["ok"]!.GetValue<bool>());
            Assert.False(help["data"]!["connected"]!.GetValue<bool>());
            Assert.Contains(help["data"]!["queries"]!.AsArray(), node => node!.GetValue<string>() == "deny-ring");

            JsonObject counters = await ExchangeAsync(pipeName, "{\"query\":\"counters\"}");
            Assert.False(counters["ok"]!.GetValue<bool>());
            Assert.Contains("not connected", counters["error"]!.GetValue<string>());

            JsonObject unknown = await ExchangeAsync(pipeName, "{\"query\":\"nope\"}");
            Assert.False(unknown["ok"]!.GetValue<bool>());

            JsonObject badCursor = await ExchangeAsync(pipeName, "{\"query\":\"deny-ring\",\"after\":\"x\"}");
            Assert.False(badCursor["ok"]!.GetValue<bool>());

            JsonObject malformed = await ExchangeAsync(pipeName, "{ not json");
            Assert.False(malformed["ok"]!.GetValue<bool>());
        }
        finally
        {
            await server.StopAsync(CancellationToken.None);
            server.Dispose();
        }
    }

    private static async Task<JsonObject> ExchangeAsync(string pipeName, string requestLine)
    {
        using var cancellation = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        await using var client = new NamedPipeClientStream(".", pipeName, PipeDirection.InOut, PipeOptions.Asynchronous);
        await client.ConnectAsync(cancellation.Token);

        var utf8 = new UTF8Encoding(false);
        await client.WriteAsync(utf8.GetBytes(requestLine + "\n"), cancellation.Token);
        await client.FlushAsync(cancellation.Token);

        using var reader = new StreamReader(client, utf8, false, 1024, leaveOpen: true);
        string? line = await reader.ReadLineAsync(cancellation.Token);
        Assert.NotNull(line);
        return JsonNode.Parse(line)!.AsObject();
    }
}
