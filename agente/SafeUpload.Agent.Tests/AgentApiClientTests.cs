using System.Net;
using System.Text;
using System.Text.Json;
using SafeUpload.Agent.Core.Infrastructure;

namespace SafeUpload.Agent.Tests;

public sealed class AgentApiClientTests
{
    [Fact]
    public async Task Explicit_registration_matches_java_and_returns_both_ids()
    {
        var handler = new Handler(201, "{\"status\":\"CREATED\",\"id_host\":7,\"id_usuario_so\":23}");
        using var http = Client(handler);
        var registration = await new AgentApiClient(http).SynchronizeAsync(Request(), CancellationToken.None);
        Assert.Equal(new AgentRegistration(7, 23), registration);
        Assert.Equal("/context/agent/api/synchronize", handler.Path);
        Assert.Equal(HttpMethod.Post, handler.Method);
        using var body = JsonDocument.Parse(handler.Body!);
        Assert.Equal(new[] { "host", "usuarioSo" }, body.RootElement.EnumerateObject().Select(p => p.Name));
        Assert.Equal("PC-SINTETICO", body.RootElement.GetProperty("host").GetProperty("hostname").GetString());
        Assert.Equal("Windows", body.RootElement.GetProperty("host").GetProperty("sistema_operacional").GetString());
        Assert.Equal("S-1-5-21-1234", body.RootElement.GetProperty("usuarioSo").GetProperty("sid").GetString());
        Assert.Equal(0, body.RootElement.GetProperty("usuarioSo").GetProperty("admin").GetInt32());
        Assert.Equal(1, handler.Calls);
    }

    [Fact]
    public async Task Registered_heartbeat_sends_only_existing_database_id()
    {
        var handler = new Handler(200, "{\"status\":\"OK\",\"mensagem\":\"Heartbeat contabilizado\"}");
        using var http = Client(handler);
        await new RegisteredAgentHeartbeat(new AgentApiClient(http), 23).SendAsync(CancellationToken.None);
        Assert.Equal("/context/agent/api/heartbeat", handler.Path);
        Assert.Equal("{\"id_usuario_so\":23}", handler.Body);
        Assert.Equal(1, handler.Calls);
    }

    [Theory]
    [InlineData(301)] [InlineData(302)] [InlineData(400)] [InlineData(401)]
    [InlineData(403)] [InlineData(404)] [InlineData(409)] [InlineData(500)] [InlineData(503)]
    public async Task Http_failure_never_registers_or_retries(int status)
    {
        var handler = new Handler(status, "SECRET-BODY");
        using var http = Client(handler);
        var ex = await Assert.ThrowsAsync<AgentApiException>(() => new AgentApiClient(http).HeartbeatAsync(23, CancellationToken.None));
        Assert.Equal("http_status", ex.Code);
        Assert.Equal(status, ex.StatusCode);
        Assert.Equal(1, handler.Calls);
        Assert.DoesNotContain("SECRET", ex.ToString());
        Assert.Null(ex.InnerException);
    }

    [Theory]
    [InlineData("null")]
    [InlineData("[]")]
    [InlineData("not-json")]
    [InlineData("{}")]
    [InlineData("{\"status\":200}")]
    [InlineData("{\"status\":\"CREATED\"}")]
    [InlineData("{\"status\":\"OK\",\"status\":\"OK\"}")]
    [InlineData("{\"status\":\"OK\",\"STATUS\":\"OK\"}")]
    [InlineData("{\"sta\\u0074us\":\"OK\",\"status\":\"OK\"}")]
    public async Task Invalid_or_ambiguous_heartbeat_is_not_success(string body)
    {
        using var http = Client(new Handler(200, body));
        var ex = await Assert.ThrowsAsync<AgentApiException>(() => new AgentApiClient(http).HeartbeatAsync(23, CancellationToken.None));
        Assert.Equal("invalid_receipt", ex.Code);
    }

    [Theory]
    [InlineData("{\"status\":\"CREATED\",\"id_host\":7}")]
    [InlineData("{\"status\":\"CREATED\",\"id_host\":0,\"id_usuario_so\":23}")]
    [InlineData("{\"status\":\"CREATED\",\"id_host\":7,\"id_usuario_so\":\"23\"}")]
    [InlineData("{\"status\":\"CREATED\",\"id_host\":7,\"id_usuario_so\":-1}")]
    [InlineData("{\"status\":\"CREATED\",\"id_host\":7,\"id_usuario_so\":23,\"ID_USUARIO_SO\":24}")]
    public async Task Registration_requires_unambiguous_positive_ids(string body)
    {
        var handler = new Handler(201, body);
        using var http = Client(handler);
        var ex = await Assert.ThrowsAsync<AgentApiException>(() => new AgentApiClient(http).SynchronizeAsync(Request(), CancellationToken.None));
        Assert.Equal("invalid_receipt", ex.Code);
        Assert.Equal(1, handler.Calls);
    }

    [Fact]
    public async Task Receipt_size_is_bounded()
    {
        using var http = Client(new Handler(200, new string('x', 16385)));
        var ex = await Assert.ThrowsAsync<AgentApiException>(() => new AgentApiClient(http).HeartbeatAsync(23, CancellationToken.None));
        Assert.Equal("receipt_too_large", ex.Code);
    }

    [Fact]
    public async Task Transport_error_drops_original_url_and_message_without_retrying_registration()
    {
        var handler = new Handler(201, "") { Failure = new HttpRequestException("SECRET-URL?token=secret") };
        using var http = Client(handler);
        var ex = await Assert.ThrowsAsync<AgentApiException>(() => new AgentApiClient(http).SynchronizeAsync(Request(), CancellationToken.None));
        Assert.Equal("transport", ex.Code);
        Assert.DoesNotContain("secret", ex.ToString(), StringComparison.OrdinalIgnoreCase);
        Assert.Null(ex.InnerException);
        Assert.Equal(1, handler.Calls);
    }

    [Fact]
    public async Task Caller_cancellation_is_propagated()
    {
        using var http = Client(new Handler(200, "{}"));
        using var cancelled = new CancellationTokenSource(); cancelled.Cancel();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => new AgentApiClient(http).HeartbeatAsync(23, cancelled.Token));
    }

    [Fact]
    public async Task Timeout_is_sanitized()
    {
        using var http = Client(new Handler(200, "") { Failure = new TaskCanceledException("SECRET") });
        var ex = await Assert.ThrowsAsync<AgentApiException>(() => new AgentApiClient(http).HeartbeatAsync(23, CancellationToken.None));
        Assert.Equal("timeout", ex.Code);
        Assert.DoesNotContain("SECRET", ex.ToString());
    }

    [Fact]
    public async Task Timeout_also_covers_body_after_response_headers()
    {
        using var http = Client(new Handler(200, "") { ResponseContent = new SlowContent() });
        http.Timeout = TimeSpan.FromMilliseconds(100);
        var ex = await Assert.ThrowsAsync<AgentApiException>(() => new AgentApiClient(http).HeartbeatAsync(23, CancellationToken.None));
        Assert.Equal("timeout", ex.Code);
    }

    [Theory]
    [InlineData(0)] [InlineData(-1)]
    public async Task Invalid_id_is_rejected_before_network(int id)
    {
        var handler = new Handler(200, "{}");
        using var http = Client(handler);
        await Assert.ThrowsAsync<ArgumentOutOfRangeException>(() => new AgentApiClient(http).HeartbeatAsync(id, CancellationToken.None));
        Assert.Equal(0, handler.Calls);
    }

    [Fact]
    public async Task Invalid_registration_field_is_rejected_before_network()
    {
        var handler = new Handler(201, "{}"); using var http = Client(handler);
        var request = Request();
        await Assert.ThrowsAsync<ArgumentException>(() => new AgentApiClient(http).SynchronizeAsync(
            request with { Host = request.Host with { Hostname = new string('x', 101) } }, CancellationToken.None));
        Assert.Equal(0, handler.Calls);
    }

    [Theory]
    [InlineData("http://localhost/agent")]
    [InlineData("http://localhost/agent/api/")]
    [InlineData("http://user:secret@localhost/agent/")]
    [InlineData("http://localhost/agent/?token=secret")]
    [InlineData("http://localhost/agent/#secret")]
    [InlineData("ftp://localhost/agent/")]
    public void Invalid_base_is_rejected_without_echoing_it(string uri)
    {
        using var http = new HttpClient { BaseAddress = new Uri(uri) };
        var ex = Assert.Throws<ArgumentException>(() => new AgentApiClient(http));
        Assert.DoesNotContain("secret", ex.ToString());
    }

    [Theory]
    [InlineData(null, null)] [InlineData("Legacy", null)]
    public void Existing_configuration_keeps_legacy(string? protocol, string? id)
    {
        using var http = new HttpClient();
        Assert.Null(AgentHeartbeatConfiguration.Parse(protocol, id).CreateSender(http));
    }

    [Theory]
    [InlineData("AgentApi", null)] [InlineData("AgentApi", "0")]
    [InlineData("AgentApi", "-1")] [InlineData("AgentApi", "2147483648")]
    [InlineData("AgentApi", "SID-23")] [InlineData("AgentApi", "23 ")]
    [InlineData("Unknown", "23")] [InlineData("Legacy", "23")]
    public void Invalid_opt_in_fails_explicitly(string protocol, string? id)
        => Assert.Throws<InvalidOperationException>(() => AgentHeartbeatConfiguration.Parse(protocol, id));

    [Fact]
    public async Task Opt_in_builds_sender_for_existing_id()
    {
        var handler = new Handler(200, "{\"status\":\"OK\",\"futureField\":true}");
        using var http = Client(handler);
        await AgentHeartbeatConfiguration.Parse("AgentApi", "23").CreateSender(http)!.SendAsync(CancellationToken.None);
        Assert.Equal("{\"id_usuario_so\":23}", handler.Body);
    }

    private static AgentSynchronization Request() => new(
        new AgentHost("192.0.2.1", 24, "PC-SINTETICO", "Windows", "10", null, null, null, null),
        new AgentOsUser("S-1-5-21-1234", "usuario-teste", "TEST", 0));
    private static HttpClient Client(Handler handler) => new(handler) { BaseAddress = new Uri("http://localhost/context/agent/") };
    private sealed class Handler(int status, string responseBody) : HttpMessageHandler
    {
        public int Calls { get; private set; }
        public string? Path { get; private set; }
        public HttpMethod? Method { get; private set; }
        public string? Body { get; private set; }
        public Exception? Failure { get; init; }
        public HttpContent? ResponseContent { get; init; }
        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken token)
        {
            token.ThrowIfCancellationRequested();
            Calls++; Path = request.RequestUri!.AbsolutePath; Method = request.Method;
            Body = await request.Content!.ReadAsStringAsync(token);
            if (Failure is {} exception) throw exception;
            return new((HttpStatusCode)status) { Content = ResponseContent ?? new StringContent(responseBody, Encoding.UTF8, "application/json") };
        }
    }

    private sealed class SlowContent : HttpContent
    {
        protected override Task<Stream> CreateContentReadStreamAsync() => Task.FromResult<Stream>(new SlowStream());
        protected override Task SerializeToStreamAsync(Stream stream, TransportContext? context) => throw new NotSupportedException();
        protected override bool TryComputeLength(out long length) { length = 0; return false; }
    }

    private sealed class SlowStream : Stream
    {
        public override bool CanRead => true;
        public override bool CanSeek => false;
        public override bool CanWrite => false;
        public override long Length => throw new NotSupportedException();
        public override long Position { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }
        public override async ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken token = default)
        {
            await Task.Delay(Timeout.InfiniteTimeSpan, token);
            return 0;
        }
        public override int Read(byte[] buffer, int offset, int count) => throw new NotSupportedException();
        public override void Flush() => throw new NotSupportedException();
        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
        public override void SetLength(long value) => throw new NotSupportedException();
        public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
    }
}
