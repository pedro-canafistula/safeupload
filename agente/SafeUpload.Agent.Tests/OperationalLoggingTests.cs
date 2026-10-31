using System.Collections.Concurrent;
using System.ComponentModel;
using System.Net;
using System.Text.Json;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using SafeUpload.Agent.Core.Application;
using SafeUpload.Agent.Core.Contracts;
using SafeUpload.Agent.Core.Domain;
using SafeUpload.Agent.Core.Infrastructure;
using SafeUpload.Agent.Core.Infrastructure.Extraction;
using SafeUpload.Agent.Service.Diagnostics;
using SafeUpload.Agent.Service.Interception;
using SafeUpload.Agent.Service.Notifications;

namespace SafeUpload.Agent.Tests;

public sealed class OperationalLoggingTests
{
    private const string Secret = "SYNTHETIC-NOT-FOR-LOGS";

    [Fact]
    public void Exception_message_data_and_inner_objects_never_reach_the_log_provider()
    {
        var logger = new Capture<object>();
        var error = new IOException("C:\\" + Secret, new Win32Exception(5, "https://example.test/" + Secret));
        error.Data["secret"] = Secret;
        var id = Guid.NewGuid();
        logger.LogSafeError(error, "Falha na transferencia {TransferId}.", id);
        var entry = Assert.Single(logger.Entries);
        Safe(entry);
        Assert.Equal(LogLevel.Error, entry.Level);
        Assert.Equal(3301, entry.Id.Id);
        Assert.Equal(id, entry.Fields.Single(e => e.Key == "TransferId").Value);
        Assert.Equal(error.HResult, entry.Fields.Single(e => e.Key == "HResult").Value);
        Assert.Equal(5, entry.Fields.Single(e => e.Key == "NativeError").Value);
        Assert.Equal("IoError", entry.Fields.Single(e => e.Key == "FailureType").Value);
    }

    [Fact]
    public void Http_status_and_request_identity_are_retained_without_address_or_body()
    {
        var logger = new Capture<object>();
        var error = new HttpRequestException(Secret, new IOException(Secret), HttpStatusCode.Unauthorized);
        logger.LogSafeWarning(error, "Resposta da requisicao {RequestId}.", 42UL);
        var entry = Assert.Single(logger.Entries);
        Safe(entry);
        Assert.Equal(401, entry.Fields.Single(e => e.Key == "HttpStatus").Value);
        Assert.Equal(42UL, entry.Fields.Single(e => e.Key == "RequestId").Value);
    }

    [Fact]
    public void Custom_exception_and_unknown_metadata_are_never_formatted()
    {
        var logger = new Capture<object>();
        logger.LogSafeCritical(new HostileException(), "Falha {Detail}.", new HostileValue());
        var entry = Assert.Single(logger.Entries);
        Safe(entry);
        Assert.Equal(OperationalLog.OmittedValue, entry.Fields.Single(e => e.Key == "Detail").Value);
        Assert.Equal("UnexpectedError", entry.Fields.Single(e => e.Key == "FailureType").Value);
        Assert.DoesNotContain(Secret, OperationalLog.DescribeFailure(new HostileException()));
    }

    [Theory]
    [InlineData("Path")] [InlineData("Arquivo")] [InlineData("Pasta")]
    [InlineData("FileName")] [InlineData("Folder")] [InlineData("HandbackPath")]
    [InlineData("DestinationPath")] [InlineData("NtPath")]
    public void Path_fields_are_omitted_even_if_no_detector_recognizes_the_content(string field)
    {
        var logger = new Capture<object>();
        logger.LogSafeInformation("Operacao {" + field + "}.", Secret);
        var entry = Assert.Single(logger.Entries);
        Safe(entry);
        Assert.Equal(OperationalLog.OmittedPath, entry.Fields.Single(e => e.Key == field).Value);
    }

    [Theory]
    [InlineData("https://user:SYNTHETIC-NOT-FOR-LOGS@example.test/private?token=SYNTHETIC-NOT-FOR-LOGS#secret", "https://example.test")]
    [InlineData("http://example.test:8080/private/SYNTHETIC-NOT-FOR-LOGS", "http://example.test:8080")]
    [InlineData("https://[::1]:8443/private/SYNTHETIC-NOT-FOR-LOGS", "https://[::1]:8443")]
    [InlineData("ftp://user:SYNTHETIC-NOT-FOR-LOGS@example.test/private", OperationalLog.OmittedValue)]
    [InlineData("C:\\SYNTHETIC-NOT-FOR-LOGS\\report.txt", OperationalLog.OmittedPath)]
    [InlineData("https://52998224725.example.test/private", AuditTextPrivacy.Redacted)]
    public void Addresses_only_keep_supported_origin_and_paths_are_never_kept(string value, string expected)
    {
        var logger = new Capture<object>();
        logger.LogSafeInformation("Destino {Destination}.", value);
        var entry = Assert.Single(logger.Entries);
        Safe(entry);
        Assert.Equal(expected, entry.Fields.Single(e => e.Key == "Destination").Value);
    }

    [Fact]
    public void Public_certificate_fingerprint_is_kept_as_a_diagnostic_identifier()
    {
        const string fingerprint = "52998224725AAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
        Assert.Equal(40, fingerprint.Length);
        var logger = new Capture<object>();
        logger.LogSafeInformation("CA {Thumbprint}.", fingerprint);
        Assert.Equal(fingerprint, Assert.Single(logger.Entries).Fields.Single(e => e.Key == "Thumbprint").Value);
    }

    [Fact]
    public void Unexpected_http_method_and_oversized_text_are_not_forwarded()
    {
        var logger = new Capture<object>();
        logger.LogSafeInformation("Metodo {Method} detalhe {Detail}.", Secret, new string('x', AuditTextPrivacy.MaximumTextLength + 1));
        var entry = Assert.Single(logger.Entries);
        Safe(entry);
        Assert.Equal(OperationalLog.OmittedValue, entry.Fields.Single(e => e.Key == "Method").Value);
        Assert.Equal(AuditTextPrivacy.Oversized, entry.Fields.Single(e => e.Key == "Detail").Value);
    }

    [Fact]
    public void Escaped_braces_numeric_formats_and_typed_fields_keep_their_diagnostic_meaning()
    {
        var logger = new Capture<object>();
        var id = Guid.NewGuid();
        logger.LogSafeDebug("{{literal}} {TransferId:D} status 0x{Status:X8}", id, 0xC0000022U);
        var entry = Assert.Single(logger.Entries);
        Assert.Contains("{literal}", entry.Message);
        Assert.Contains("0xC0000022", entry.Message);
        Assert.Equal(id, entry.Fields.Single(e => e.Key == "TransferId").Value);
    }

    [Theory]
    [InlineData("Falha {Path} {RequestId}")]
    [InlineData("Falha {Path")]
    [InlineData("Falha } {Path}")]
    public void Malformed_or_mismatched_templates_omit_arguments_instead_of_exposing_them(string template)
    {
        var logger = new Capture<object>();
        logger.LogSafeWarning(new IOException(Secret), template, new HostileValue());
        var entry = Assert.Single(logger.Entries);
        Safe(entry);
        Assert.Contains("invalid template", entry.Message);
    }

    [Fact]
    public void Disabled_log_level_does_not_prepare_or_format_anything()
    {
        var logger = new Capture<object> { Enabled = false };
        logger.LogSafeError(new HostileException(), "Falha {Detail}", new HostileValue());
        Assert.Empty(logger.Entries);
    }

    [Fact]
    public void Failure_of_notification_recording_still_suppresses_delivery_and_logs_only_codes()
    {
        var logger = new Capture<NotificationHub>();
        var hub = new NotificationHub(new FailingRecord(), logger);
        using var subscriber = hub.Subscribe();
        hub.Publish(new StatusNotification(7, 1, ProtectionActive: true));
        Assert.Null(hub.GetRecordedStatus());
        Assert.False(subscriber.Reader.TryRead(out _));
        Safe(Assert.Single(logger.Entries));
    }

    [Fact]
    public async Task Watcher_does_not_log_file_or_scope_names_and_keeps_the_exact_event_id()
    {
        using var workspace = new TestWorkspace();
        string scope = Path.Combine(workspace.Root, Secret);
        Directory.CreateDirectory(scope);
        var document = PolicyDocument.Default with { MonitoredScopes = new MonitoredScopesDocument
            { Extensions = [".txt"], DestinationPaths = [scope], RemovableDrives = false, NetworkPaths = false } };
        File.WriteAllText(workspace.PolicyFile, JsonSerializer.Serialize(document));
        var policies = new LocalPolicyStore(workspace.PolicyFile);
        var queue = new LocalQueueAuditSink(workspace.QueueFile);
        var engine = new InspectionService(policies, queue, ExtractorRegistry.CreateDefault(), new VerdictCache());
        var logger = new Capture<FileSystemInterceptor>();
        var hub = new NotificationHub(new NoRecord(), NullLogger<NotificationHub>.Instance);
        using var service = new FileSystemInterceptor(engine, policies, queue, hub, logger,
            Path.Combine(workspace.Root, "quarantine"), workspace.PolicyFile);
        await service.StartAsync(default);
        using var stop = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        try
        {
            while (hub.CurrentStatus?.ProtectionActive != true) await Task.Delay(20, stop.Token);
            await File.WriteAllTextAsync(Path.Combine(scope, Secret + ".txt"), "ordinary text", stop.Token);
            await logger.EventLogged.Task.WaitAsync(stop.Token);
            Assert.All(logger.Entries, Safe);
            var entry = Assert.Single(logger.Entries, e => e.Fields.Any(f => f.Key == "EventId"));
            var id = Assert.IsType<Guid>(entry.Fields.Single(f => f.Key == "EventId").Value);
            Assert.Contains(await queue.ReadPendingAsync(10, stop.Token), item => item.EventId == id);
        }
        finally { await service.StopAsync(default).WaitAsync(TimeSpan.FromSeconds(5)); }
    }

    private static void Safe(Entry entry)
    {
        Assert.Null(entry.Error);
        Assert.DoesNotContain(Secret, entry.Message);
        Assert.All(entry.Fields, field => { Assert.False(field.Value is Exception or HostileValue); Assert.DoesNotContain(Secret, field.Value?.ToString() ?? ""); });
    }
    private sealed record Entry(LogLevel Level, EventId Id, string Message, Exception? Error, KeyValuePair<string, object?>[] Fields);
    private sealed class Capture<T> : ILogger<T>
    {
        public bool Enabled = true;
        public readonly ConcurrentQueue<Entry> Entries = new();
        public readonly TaskCompletionSource EventLogged = new(TaskCreationOptions.RunContinuationsAsynchronously);
        public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;
        public bool IsEnabled(LogLevel level) => Enabled;
        public void Log<TState>(LogLevel level, EventId id, TState state, Exception? error, Func<TState, Exception?, string> formatter)
        {
            var fields = state is IEnumerable<KeyValuePair<string, object?>> values ? values.ToArray() : [];
            Entries.Enqueue(new(level, id, formatter(state, error), error, fields));
            if (fields.Any(f => f.Key == "EventId" && f.Value is Guid)) EventLogged.TrySetResult();
        }
    }
    private sealed class HostileValue { public override string ToString() => throw new InvalidOperationException(Secret); }
    private sealed class HostileException : Exception
    {
        public override string Message => throw new InvalidOperationException(Secret);
        public override string ToString() => throw new InvalidOperationException(Secret);
    }
    private sealed class FailingRecord : INotificationRecord { public void Append(AgentNotification notification, uint? session) => throw new IOException(Secret); }
    private sealed class NoRecord : INotificationRecord { public void Append(AgentNotification notification, uint? session) { } }
}
