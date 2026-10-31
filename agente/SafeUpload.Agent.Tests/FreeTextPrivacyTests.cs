using System.Net;
using System.Text;
using System.Text.Json;
using Microsoft.Extensions.Logging.Abstractions;
using SafeUpload.Agent.Core.Application;
using SafeUpload.Agent.Core.Domain;
using SafeUpload.Agent.Core.Infrastructure;
using SafeUpload.Agent.Core.Infrastructure.Extraction;
using SafeUpload.Agent.Service.Dispatch;
using SafeUpload.Agent.Service.Interception;
using SafeUpload.Agent.App.ViewModels;

namespace SafeUpload.Agent.Tests;

public sealed class FreeTextPrivacyTests : IDisposable
{
    private const string Cpf = "52998224725";
    private readonly TestWorkspace _workspace = new();

    [Theory]
    [InlineData("CPF 529.982.247-25")]
    [InlineData("CNPJ 04.252.011/0001-10")]
    [InlineData("cartao 4111 1111 1111 1111")]
    [InlineData("senha=synthetic-only-value")]
    [InlineData("ghp_abcdefghijklmnopqrstuvwxyz0123456789")]
    [InlineData("AKIAABCDEFGHIJKLMNOP")]
    public void Recognized_values_omit_the_whole_field(string text) => Assert.Equal(AuditTextPrivacy.Redacted, AuditTextPrivacy.Sanitize(text));

    [Theory]
    [InlineData(null, "")] [InlineData("", "")]
    [InlineData("motivo de negocio sem valores", "motivo de negocio sem valores")]
    [InlineData("relatorio-v3.txt", "relatorio-v3.txt")]
    public void Ordinary_fields_remain_unchanged(string? text, string expected) => Assert.Equal(expected, AuditTextPrivacy.Sanitize(text));

    [Fact]
    public void Oversized_fields_are_omitted_before_scanning()
    {
        Assert.Equal(AuditTextPrivacy.Oversized, AuditTextPrivacy.Sanitize(new string('x', AuditTextPrivacy.MaximumTextLength + 1)));
        Assert.Equal(new string('x', AuditTextPrivacy.MaximumTextLength), AuditTextPrivacy.Sanitize(new string('x', AuditTextPrivacy.MaximumTextLength)));
    }

    private LocalPolicyStore Policies()
    {
        _workspace.WritePolicy("""{"version":7,"activeCategories":["Cnpj"]}"""); // Privacy is independent of active categories.
        return new LocalPolicyStore(_workspace.PolicyFile);
    }

    [Fact]
    public async Task New_file_metadata_is_private_and_operational_paths_are_unchanged()
    {
        var sink = new LocalQueueAuditSink(_workspace.QueueFile);
        var engine = new InspectionService(Policies(), sink, ExtractorRegistry.CreateDefault(), new VerdictCache(), "SYNTHETIC", "SYNTHETIC");
        string path = _workspace.WriteText("report_" + Cpf + ".txt", "ordinary text");
        var operation = TestWorkspace.Operation(path) with { DestinationPath = "E:\\" + Cpf, ProcessName = Cpf + ".exe" };
        var result = await engine.InspectAsync(operation, default);
        Assert.Equal(Verdict.Approved, result.Verdict);
        Assert.Equal(AuditTextPrivacy.Redacted, result.RecordedEvent!.FileName);
        Assert.Equal(AuditTextPrivacy.Redacted, result.RecordedEvent.DestinationPath);
        Assert.Equal(AuditTextPrivacy.Redacted, result.RecordedEvent.ProcessName);
        Assert.Equal(path, operation.FilePath);
        Assert.True(File.Exists(path));
        Assert.Equal("E:\\" + Cpf, operation.DestinationPath);
        Assert.DoesNotContain(Cpf, await File.ReadAllTextAsync(_workspace.QueueFile));
        Assert.Equal(result.RecordedEvent.EventId, Assert.Single(await sink.ReadPendingAsync(10, default)).EventId);
    }

    [Fact]
    public async Task Web_metadata_is_private_without_changing_format_resolution()
    {
        var sink = new LocalQueueAuditSink(_workspace.QueueFile);
        var engine = new WebInspectionService(Policies(), sink, ExtractorRegistry.CreateDefault(), "SYNTHETIC", "SYNTHETIC");
        var result = await engine.InspectAsync(new WebUpload("https://" + Cpf + ".example.test/private?secret=unused", Cpf + ".exe", 42,
            [new WebUploadPart("report_" + Cpf + ".txt", Encoding.UTF8.GetBytes("ordinary text"), true)]), default);
        var record = Assert.Single(result.Records).Event;
        Assert.Equal(Verdict.Approved, record.Verdict);
        Assert.Equal(".txt", record.Extension);
        Assert.Equal(AuditTextPrivacy.Redacted, record.FileName);
        Assert.Equal(AuditTextPrivacy.Redacted, record.ProcessName);
        Assert.Equal(AuditTextPrivacy.Redacted, record.DestinationPath);
        Assert.DoesNotContain(Cpf, await File.ReadAllTextAsync(_workspace.QueueFile));
    }

    [Theory]
    [InlineData(null)] [InlineData(1)]
    public async Task Fixed_transfer_identity_uses_its_original_metadata_projection(int? version)
    {
        var sink = new LocalQueueAuditSink(_workspace.QueueFile);
        var engine = new InspectionService(Policies(), sink, ExtractorRegistry.CreateDefault(), new VerdictCache());
        var operation = TestWorkspace.Operation(_workspace.WriteText("report_" + Cpf + ".txt", "ordinary text")) with { AuditMetadataVersion = version };
        var id = Guid.NewGuid();
        var result = new InspectionResult(Verdict.Retained, [], "synthetic", 0, false, 7, true);
        await engine.RecordTransferOutcomeAsync(operation, result, Verdict.Retained, "synthetic", default, id);
        var record = Assert.Single(await sink.ReadPendingAsync(10, default));
        Assert.Equal(id, record.EventId);
        Assert.Equal(version == 1 ? AuditTextPrivacy.Redacted : operation.FileName, record.FileName);
    }

    [Theory]
    [InlineData(false)] [InlineData(true)]
    public async Task New_override_is_sanitized_once_and_legacy_override_replay_is_unchanged(bool legacy)
    {
        var sink = new LocalQueueAuditSink(_workspace.QueueFile);
        var policy = Policies();
        var id = Guid.NewGuid(); var when = DateTimeOffset.UtcNow;
        string text = "motivo CPF " + Cpf;
        var record = legacy ? new AuditOverride(id, text, when, "SYNTHETIC", "SYNTHETIC")
            : AuditOverride.FromNewSubmission(id, text, when, "SYNTHETIC", "SYNTHETIC");
        await sink.RecordOverrideAsync(record, default);
        var wire = new Wire();
        using var http = new HttpClient(wire) { BaseAddress = new Uri("https://central.example.test/agent/") };
        var dispatcher = new HttpAgentDispatcher(sink, policy, http, "SYNTHETIC", TimeSpan.FromHours(1), NullLogger<HttpAgentDispatcher>.Instance);
        await dispatcher.RunCycleAsync(default); // A lost receipt leaves the original record pending.
        Assert.Single(await sink.ReadPendingOverridesAsync(10, default));
        await dispatcher.RunCycleAsync(default);
        Assert.Equal(2, wire.Bodies.Count);
        Assert.Equal(wire.Bodies[0], wire.Bodies[1]);
        using var sent = JsonDocument.Parse(wire.Bodies[0]);
        var item = sent.RootElement.GetProperty("overrides")[0];
        Assert.Equal(id, item.GetProperty("eventId").GetGuid());
        Assert.Equal(legacy ? text : AuditTextPrivacy.Redacted, item.GetProperty("justification").GetString());
        Assert.Empty(await sink.ReadPendingOverridesAsync(10, default));
        if (!legacy) Assert.DoesNotContain(Cpf, await File.ReadAllTextAsync(_workspace.QueueFile));
    }

    [Fact]
    public async Task Legacy_history_display_is_private_without_modifying_its_payload()
    {
        var sink = new LocalQueueAuditSink(_workspace.QueueFile);
        var engine = new InspectionService(Policies(), sink, ExtractorRegistry.CreateDefault(), new VerdictCache());
        var operation = TestWorkspace.Operation(_workspace.WriteText("report_" + Cpf + ".txt", "ordinary text"))
            with { ProcessName = Cpf + ".exe", DestinationPath = "E:\\" + Cpf };
        await engine.RecordTransferOutcomeAsync(operation, new(Verdict.Retained, [], "synthetic", 0, false, 7, true),
            Verdict.Retained, "synthetic", default, Guid.NewGuid());
        var original = Assert.Single(await sink.ReadPendingAsync(10, default));
        byte[] bytes = await File.ReadAllBytesAsync(_workspace.QueueFile);
        var history = new HistoryRowViewModel(original);
        var queue = new QueueRowViewModel(original);
        Assert.Equal(AuditTextPrivacy.Redacted, history.FileName);
        Assert.Equal(AuditTextPrivacy.Redacted, history.Process);
        Assert.Equal(AuditTextPrivacy.Redacted, history.Destination);
        Assert.Equal(history.FileName, queue.FileName);
        Assert.Equal(history.Process, queue.Process);
        Assert.Equal(history.Destination, queue.Destination);
        Assert.Contains(Cpf, original.FileName);
        Assert.Equal(bytes, await File.ReadAllBytesAsync(_workspace.QueueFile));
    }

    [Theory]
    [InlineData(null)] [InlineData(1)]
    public async Task Journal_restart_preserves_legacy_or_new_projection(int? version)
    {
        string root = Path.Combine(_workspace.Root, "journal");
        var transfer = new StagedTransfer(Guid.NewGuid(), Path.Combine(_workspace.Root, "stage.txt"),
            Path.Combine(_workspace.Root, "report.txt"), DestinationKind.Cloud, "synthetic", 42, null) { AuditMetadataVersion = version };
        await new StagedTransferJournal(root).CreateAsync(transfer, default);
        Assert.Equal(version, (await new StagedTransferJournal(root).ReadAsync(transfer.TransferId, default)).Transfer.AuditMetadataVersion);
        if (version is null) Assert.DoesNotContain("AuditMetadataVersion", JsonSerializer.Serialize(transfer));
    }

    [Fact]
    public async Task Unknown_journal_projection_is_refused()
    {
        var transfer = new StagedTransfer(Guid.NewGuid(), Path.Combine(_workspace.Root, "stage.txt"),
            Path.Combine(_workspace.Root, "report.txt"), DestinationKind.Cloud, "synthetic", 42, null) { AuditMetadataVersion = 2 };
        await Assert.ThrowsAsync<InvalidDataException>(() => new StagedTransferJournal(Path.Combine(_workspace.Root, "journal")).CreateAsync(transfer, default));
    }

    private sealed class Wire : HttpMessageHandler
    {
        public readonly List<string> Bodies = [];
        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken token)
        {
            if (!request.RequestUri!.AbsolutePath.EndsWith("/events")) return new(HttpStatusCode.OK) { Content = new StringContent("{}") };
            Bodies.Add(await request.Content!.ReadAsStringAsync(token));
            return Bodies.Count == 1 ? new(HttpStatusCode.ServiceUnavailable)
                : new(HttpStatusCode.OK) { Content = new StringContent("{\"acceptedEvents\":0,\"acceptedOverrides\":1}") };
        }
    }
    public void Dispose() => _workspace.Dispose();
}
