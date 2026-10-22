using System.IO.Pipes;
using System.Runtime.InteropServices;
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
    public void Writer_state_wire_size_and_every_offset_are_exact()
    {
        Assert.Equal(304, Marshal.SizeOf<SafeUploadWriterStateStatus>());
        Assert.Equal(304, DiagnosticsContract.WriterStateStatusSize);
        (string Field, int Offset)[] expected =
        {
            (nameof(SafeUploadWriterStateStatus.StructSize), 0),
            (nameof(SafeUploadWriterStateStatus.SectionInFlightNow), 4),
            (nameof(SafeUploadWriterStateStatus.PostCreateRuns), 8),
            (nameof(SafeUploadWriterStateStatus.WriteObjectsCounted), 16),
            (nameof(SafeUploadWriterStateStatus.WriteObjectsReleased), 24),
            (nameof(SafeUploadWriterStateStatus.UntrackedCreates), 32),
            (nameof(SafeUploadWriterStateStatus.CleanupUnmatched), 40),
            (nameof(SafeUploadWriterStateStatus.DirectoryCreatesSkipped), 48),
            (nameof(SafeUploadWriterStateStatus.SectionInFlightInserted), 56),
            (nameof(SafeUploadWriterStateStatus.SectionInFlightReleased), 64),
            (nameof(SafeUploadWriterStateStatus.RetiredSectionOverflow), 72),
            (nameof(SafeUploadWriterStateStatus.SectionInFlightStuck), 80),
            (nameof(SafeUploadWriterStateStatus.SectionInFlightRemovedOnFailure), 88),
            (nameof(SafeUploadWriterStateStatus.SectionInFlightMaxDepth), 96),
            (nameof(SafeUploadWriterStateStatus.CleanupDirectoriesSkipped), 100),
            (nameof(SafeUploadWriterStateStatus.PagingCreatesSkipped), 104),
            (nameof(SafeUploadWriterStateStatus.VolumeCreatesSkipped), 112),
            (nameof(SafeUploadWriterStateStatus.StageStreams), 120),
            (nameof(SafeUploadWriterStateStatus.StageFileObjects), 124),
            (nameof(SafeUploadWriterStateStatus.LastUnloadVeto), 128),
            (nameof(SafeUploadWriterStateStatus.LastUnloadStatus), 132),
            (nameof(SafeUploadWriterStateStatus.WritersDroppedAtTeardown), 136),
            (nameof(SafeUploadWriterStateStatus.WritersDroppedWhileMounted), 144),
            (nameof(SafeUploadWriterStateStatus.InstanceTeardownsDismount), 152),
            (nameof(SafeUploadWriterStateStatus.InstanceTeardownsOther), 160),
            (nameof(SafeUploadWriterStateStatus.TxfRefused), 168),
            (nameof(SafeUploadWriterStateStatus.RegistryCapacityFailures), 176),
            (nameof(SafeUploadWriterStateStatus.RegistryAllocationFailures), 184),
            (nameof(SafeUploadWriterStateStatus.RegistryIdentityFailures), 192),
            (nameof(SafeUploadWriterStateStatus.RegistryTransactionFailures), 200),
            (nameof(SafeUploadWriterStateStatus.RegistryRenameFailures), 208),
            (nameof(SafeUploadWriterStateStatus.RegistryDroppedAtDismount), 216),
            (nameof(SafeUploadWriterStateStatus.RegistryDroppedWhileMounted), 224),
            (nameof(SafeUploadWriterStateStatus.RegistryEntries), 232),
            (nameof(SafeUploadWriterStateStatus.RegistryReservations), 236),
            (nameof(SafeUploadWriterStateStatus.RegistryOverflow), 240),
            (nameof(SafeUploadWriterStateStatus.RegistryUnknownReasons), 244),
            (nameof(SafeUploadWriterStateStatus.RegistryInstanceUnknown), 248),
            (nameof(SafeUploadWriterStateStatus.RegistryCapacity), 252),
            (nameof(SafeUploadWriterStateStatus.TransactionAssociations), 256),
            (nameof(SafeUploadWriterStateStatus.Reserved2), 260),
            (nameof(SafeUploadWriterStateStatus.RegistryPruned), 264),
            (nameof(SafeUploadWriterStateStatus.RegistryReclaimPasses), 272),
            (nameof(SafeUploadWriterStateStatus.RegistryNameTierEntries), 280),
            (nameof(SafeUploadWriterStateStatus.RegistryCompactTierEntries), 284),
            (nameof(SafeUploadWriterStateStatus.WriterGlobalFirstUnknown), 288),
            (nameof(SafeUploadWriterStateStatus.WriterEntryFirstUnknown), 292),
            (nameof(SafeUploadWriterStateStatus.WriterSopFirstUnknown), 296),
            (nameof(SafeUploadWriterStateStatus.WriterSopUnknownCount), 300),
        };
        foreach (var (field, offset) in expected)
            Assert.Equal(offset, Marshal.OffsetOf<SafeUploadWriterStateStatus>(field).ToInt32());
        Assert.Equal(expected.Length, typeof(SafeUploadWriterStateStatus).GetFields().Length);
    }

    [Theory]
    [InlineData(0u, 0u, 0u)]
    [InlineData(0x12340046u, 0x46u, 0x1234u)]
    [InlineData(0xFEDC8002u, 0x8002u, 0xFEDCu)]
    [InlineData(uint.MaxValue, 0xFFFFu, 0xFFFFu)]
    public void Unknown_origin_json_decodes_both_unsigned_halves(uint packed, uint reason, uint site)
    {
        JsonObject origin = DriverDiagnosticsSource.UnknownOrigin(packed);
        Assert.Equal(2, origin.Count);
        Assert.Equal(reason, origin["reason"]!.GetValue<uint>());
        Assert.Equal(site, origin["site"]!.GetValue<uint>());
    }

    [Fact]
    public void Writer_state_json_reports_loss_counters_and_each_origin()
    {
        var writer = new SafeUploadWriterStateStatus
        {
            RegistryAllocationFailures = 0x100000001UL,
            RegistryIdentityFailures = 0x100000002UL,
            RegistryTransactionFailures = 0x100000003UL,
            RegistryRenameFailures = 0x100000004UL,
            RegistryDroppedAtDismount = 0x100000005UL,
            RegistryDroppedWhileMounted = 0x100000006UL,
            WritersDroppedAtTeardown = 0x100000007UL,
            WritersDroppedWhileMounted = 0x100000008UL,
            CleanupUnmatched = 0x100000009UL,
            WriterGlobalFirstUnknown = 0x12340002u,
            WriterEntryFirstUnknown = 0x23450004u,
            WriterSopFirstUnknown = 0x34560001u,
            WriterSopUnknownCount = 7,
        };
        // Serialize and parse the same writerState projection used by ReadCounters.
        JsonObject json = JsonNode.Parse(DriverDiagnosticsSource.WriterStateJson(writer).ToJsonString())!.AsObject();
        string[] counters =
        {
            "registryAllocationFailures", "registryIdentityFailures", "registryTransactionFailures",
            "registryRenameFailures", "registryDroppedAtDismount", "registryDroppedWhileMounted",
            "writersDroppedAtTeardown", "writersDroppedWhileMounted", "cleanupUnmatched",
        };
        for (int index = 0; index < counters.Length; ++index)
            Assert.Equal(0x100000001UL + (ulong)index, json[counters[index]]!.GetValue<ulong>());
        Assert.Equal(7u, json["writerSopUnknownCount"]!.GetValue<uint>());
        Assert.Equal(2u, json["writerGlobalFirstUnknown"]!["reason"]!.GetValue<uint>());
        Assert.Equal(0x1234u, json["writerGlobalFirstUnknown"]!["site"]!.GetValue<uint>());
        Assert.Equal(4u, json["writerEntryFirstUnknown"]!["reason"]!.GetValue<uint>());
        Assert.Equal(0x2345u, json["writerEntryFirstUnknown"]!["site"]!.GetValue<uint>());
        Assert.Equal(1u, json["writerSopFirstUnknown"]!["reason"]!.GetValue<uint>());
        Assert.Equal(0x3456u, json["writerSopFirstUnknown"]!["site"]!.GetValue<uint>());
        Assert.DoesNotContain("reserved2", json.Select(pair => pair.Key));
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
    [InlineData(0xE500000Cu, "scopeTransition")]
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
    [InlineData(14u, "registryScope")]
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
        Assert.Throws<InvalidOperationException>(() => source.ReadStageStreams());
    }

    [Fact]
    public void Stage_stream_snapshot_layout_is_exact()
    {
        Assert.Equal(160, Marshal.SizeOf<SafeUploadStageStreamRecord>());
        Assert.Equal(160, DiagnosticsContract.StageStreamRecordSize);
        Assert.Equal(16 + 16 * 160, Marshal.SizeOf<SafeUploadStageStreams>());
        (string Field, int Offset)[] expected =
        {
            (nameof(SafeUploadStageStreamRecord.TransferId), 0),
            (nameof(SafeUploadStageStreamRecord.Flags), 16),
            (nameof(SafeUploadStageStreamRecord.FileObjects), 20),
            (nameof(SafeUploadStageStreamRecord.ShareOpenCount), 24),
            (nameof(SafeUploadStageStreamRecord.RpcReferences), 28),
            (nameof(SafeUploadStageStreamRecord.OwnerProcessId), 32),
            (nameof(SafeUploadStageStreamRecord.Wait), 36),
            (nameof(SafeUploadStageStreamRecord.SectionBits), 40),
            (nameof(SafeUploadStageStreamRecord.DestinationGeneration), 48),
            (nameof(SafeUploadStageStreamRecord.NameChars), 56),
            (nameof(SafeUploadStageStreamRecord.Name), 64),
        };
        foreach (var (field, offset) in expected)
            Assert.Equal(offset, Marshal.OffsetOf<SafeUploadStageStreamRecord>(field).ToInt32());
        Assert.Equal(16, Marshal.OffsetOf<SafeUploadStageStreams>(nameof(SafeUploadStageStreams.Entries)).ToInt32());
        Assert.Equal(29u, DiagnosticsCommand.StageStreams);
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
            Assert.Contains(help["data"]!["queries"]!.AsArray(), node => node!.GetValue<string>() == "stage-streams");

            JsonObject counters = await ExchangeAsync(pipeName, "{\"query\":\"counters\"}");
            Assert.False(counters["ok"]!.GetValue<bool>());
            Assert.Contains("not connected", counters["error"]!.GetValue<string>());

            JsonObject streams = await ExchangeAsync(pipeName, "{\"query\":\"stage-streams\"}");
            Assert.False(streams["ok"]!.GetValue<bool>());
            Assert.Contains("not connected", streams["error"]!.GetValue<string>());

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
