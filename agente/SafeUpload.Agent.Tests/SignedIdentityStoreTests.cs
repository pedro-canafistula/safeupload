using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using SafeUpload.Agent.Core.Infrastructure;

namespace SafeUpload.Agent.Tests;

/// <summary>Identidade gravada pelo "cadastrar" (DPAPI real; precisa de Windows).</summary>
public sealed class SignedIdentityStoreTests : IDisposable
{
    private static readonly Uri Server = new("https://console.test/agent/");
    private static readonly AgentHeartbeatHost Host = new("10.0.0.5", 24, "PC-01", "Windows 10 Pro", "22H2", null);
    private readonly TestWorkspace _workspace = new();
    private string File => Path.Combine(_workspace.Root, "authentication", "ed25519-identity.dat");
    public void Dispose() => _workspace.Dispose();

    [Fact]
    public async Task Enrollment_persists_server_host_pin_and_a_key_that_signs()
    {
        string? sentKey = null;
        var store = new SignedHostIdentityStore(File, enforceAcl: false);
        using var http = new HttpClient(new Wire(body =>
        {
            using var json = JsonDocument.Parse(body);
            sentKey = json.RootElement.GetProperty("chave_publica").GetString();
            Assert.Equal("TOKEN123", json.RootElement.GetProperty("token").GetString());
            return (HttpStatusCode.Created, "{\"id_host\":9}");
        })) { BaseAddress = Server };
        var pin = new string('b', 64);

        var enrolled = await store.EnrollAsync(new AgentApiClient(http), pin, "TOKEN123", Host, replace: false, default);
        var loaded = new SignedHostIdentityStore(File, enforceAcl: false).Load()!;

        Assert.Equal(9, loaded.HostId);
        Assert.Equal(Server, loaded.Server);
        Assert.Equal(pin, loaded.CertificateSha256);
        Assert.Equal(sentKey, loaded.PublicKey);
        Assert.Equal(enrolled.Sign(Encoding.UTF8.GetBytes("m")), loaded.Sign(Encoding.UTF8.GetBytes("m")));
        Assert.DoesNotContain("TOKEN123", Encoding.Latin1.GetString(await System.IO.File.ReadAllBytesAsync(File)));
    }

    [Theory]
    [InlineData(HttpStatusCode.Unauthorized, "{}", "http_status")]
    [InlineData(HttpStatusCode.Created, "{}", "invalid_receipt")]
    public async Task Failed_replacement_keeps_the_existing_enrollment(HttpStatusCode status, string body, string code)
    {
        var store = new SignedHostIdentityStore(File, enforceAcl: false);
        SignedAgentIdentity original;
        using (var ok = new HttpClient(new Wire(_ => (HttpStatusCode.Created, "{\"id_host\":9}"))) { BaseAddress = Server })
        {
            original = await store.EnrollAsync(new AgentApiClient(ok), null, "A", Host, false, default);
            var again = await Assert.ThrowsAsync<AgentIdentityException>(() =>
                store.EnrollAsync(new AgentApiClient(ok), null, "B", Host, false, default));
            Assert.Equal("already_registered", again.Code);
        }
        byte[] originalFile = await System.IO.File.ReadAllBytesAsync(File);
        byte[] message = Encoding.UTF8.GetBytes("heartbeat");
        string signature = original.Sign(message);

        using (var refused = new HttpClient(new Wire(_ => (status, body))) { BaseAddress = new("https://other.test/agent/") })
        {
            var error = await Assert.ThrowsAsync<AgentApiException>(() =>
                store.EnrollAsync(new AgentApiClient(refused), null, "C", Host, true, default));
            Assert.Equal(code, error.Code);
        }
        var retained = store.Load()!;
        Assert.Equal(original.HostId, retained.HostId);
        Assert.Equal(Server, retained.Server);
        Assert.Equal(original.PublicKey, retained.PublicKey);
        Assert.Equal(signature, original.Sign(message));
        Assert.Equal(originalFile, await System.IO.File.ReadAllBytesAsync(File));

        using var retry = new HttpClient(new Wire(_ => (HttpStatusCode.Created, "{\"id_host\":10}"))) { BaseAddress = Server };
        Assert.Equal(10, (await store.EnrollAsync(new AgentApiClient(retry), null, "D", Host, true, default)).HostId);
        Assert.Equal(10, store.Load()!.HostId);
        Assert.Equal("identity_changed", Assert.Throws<AgentIdentityException>(() => original.Sign(message)).Code);
    }

    [Fact]
    public void No_file_means_not_enrolled() => Assert.Null(new SignedHostIdentityStore(File, enforceAcl: false).Load());

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task Retrying_an_interrupted_enrollment_uses_the_same_key_without_replacing_the_active_identity(bool replace)
    {
        const string enrollmentToken = "TOKEN123";
        var store = new SignedHostIdentityStore(File, enforceAcl: false);
        byte[]? previous = null;
        if (replace)
        {
            using var first = new HttpClient(new Wire(_ => (HttpStatusCode.Created, "{\"id_host\":9}"))) { BaseAddress = Server };
            await store.EnrollAsync(new AgentApiClient(first), null, "OLD", Host, false, default);
            previous = await System.IO.File.ReadAllBytesAsync(File);
        }

        string? attemptedKey = null;
        using var dropped = new HttpClient(new Wire(body =>
        {
            using var json = JsonDocument.Parse(body);
            attemptedKey = json.RootElement.GetProperty("chave_publica").GetString();
            Assert.False(json.RootElement.TryGetProperty("prova_recuperacao", out _));
            throw new HttpRequestException("response lost after commit");
        })) { BaseAddress = Server };
        var lost = await Assert.ThrowsAsync<AgentApiException>(() =>
            store.EnrollAsync(new AgentApiClient(dropped), null, enrollmentToken, Host, replace, default));
        Assert.Equal("transport", lost.Code);
        if (previous is null) Assert.Null(store.Load());
        else Assert.Equal(previous, await System.IO.File.ReadAllBytesAsync(File));

        using var retry = new HttpClient(new Wire(body =>
        {
            using var json = JsonDocument.Parse(body);
            Assert.Equal(attemptedKey, json.RootElement.GetProperty("chave_publica").GetString());
            Assert.Equal(enrollmentToken, json.RootElement.GetProperty("token").GetString());
            Assert.NotEmpty(json.RootElement.GetProperty("prova_recuperacao").GetString()!);
            return (HttpStatusCode.Created, "{\"id_host\":10}");
        })) { BaseAddress = Server };
        var reopened = new SignedHostIdentityStore(File, enforceAcl: false);
        var recovered = await reopened.EnrollAsync(new AgentApiClient(retry), null, enrollmentToken, Host, replace, default);
        Assert.Equal(10, recovered.HostId);
        Assert.Equal(attemptedKey, reopened.Load()!.PublicKey);
        Assert.False(System.IO.File.Exists(File + ".pending"));
    }

    [Theory]
    [InlineData("valid", HttpStatusCode.OK, 9, null)]
    [InlineData("wrong-pin", HttpStatusCode.OK, 9, "transport")]
    [InlineData("revoked", HttpStatusCode.Forbidden, 9, "http_status")]
    [InlineData("wrong-host", HttpStatusCode.OK, 10, "invalid_receipt")]
    [InlineData("old-server", HttpStatusCode.NotFound, 9, "http_status")]
    public async Task Certificate_update_preserves_the_enrollment_and_only_saves_a_verified_pin(
        string scenario, HttpStatusCode status, int receiptId, string? errorCode)
    {
        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        var address = new Uri($"https://127.0.0.1:{((IPEndPoint)listener.LocalEndpoint).Port}/agent/");
        using var enrollment = new HttpClient(new Wire(_ => (HttpStatusCode.Created, "{\"id_host\":9}"))) { BaseAddress = address };
        var store = new SignedHostIdentityStore(File, enforceAcl: false);
        var oldPin = new string('a', 64);
        var original = await store.EnrollAsync(new AgentApiClient(enrollment), oldPin, "A", Host, false, default);
        byte[] before = await System.IO.File.ReadAllBytesAsync(File);
        byte[] message = Encoding.UTF8.GetBytes("auditoria pendente");

        using var key = RSA.Create(2048);
        var request = new CertificateRequest("CN=SafeUpload local", key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        using var generated = request.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(1));
        // Schannel needs the same PKCS#12 key import used by the local TLS proxy.
        using var certificate = X509CertificateLoader.LoadPkcs12(generated.Export(X509ContentType.Pkcs12), password: null);
        using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        var server = ReplyOverTlsAsync(listener, certificate, status, receiptId, scenario == "wrong-pin", deadline.Token);
        var newPin = scenario == "wrong-pin" ? new string('b', 64) : AgentHttp.Fingerprint(certificate);
        if (errorCode is null)
        {
            var updated = await store.UpdateCertificateAsync(newPin, deadline.Token);
            Assert.Equal(newPin, updated.CertificateSha256);
        }
        else
        {
            var error = await Assert.ThrowsAsync<AgentApiException>(() => store.UpdateCertificateAsync(newPin, deadline.Token));
            Assert.Equal(errorCode, error.Code);
            Assert.Equal(before, await System.IO.File.ReadAllBytesAsync(File));
        }
        var signedRequest = await server;
        if (scenario != "wrong-pin")
        {
            Assert.NotNull(signedRequest);
            Assert.StartsWith("GET /agent/identity HTTP/1.1", signedRequest);
            Assert.Contains("X-SafeUpload-Host: 9", signedRequest, StringComparison.OrdinalIgnoreCase);
            Assert.Contains("X-SafeUpload-Signature:", signedRequest, StringComparison.OrdinalIgnoreCase);
        }
        else Assert.Null(signedRequest);

        var loaded = store.Load()!;
        Assert.Equal(errorCode is null ? newPin : oldPin, loaded.CertificateSha256);
        Assert.Equal(original.HostId, loaded.HostId);
        Assert.Equal(original.PublicKey, loaded.PublicKey);
        Assert.Equal(original.Server, loaded.Server);
        Assert.Equal(original.Sign(message), loaded.Sign(message));
    }

    private static async Task<string?> ReplyOverTlsAsync(TcpListener listener, X509Certificate2 certificate,
        HttpStatusCode status, int hostId, bool expectRejectedTls, CancellationToken token)
    {
        using var connection = await listener.AcceptTcpClientAsync(token);
        await using var tls = new SslStream(connection.GetStream());
        try
        {
            await tls.AuthenticateAsServerAsync(new SslServerAuthenticationOptions { ServerCertificate = certificate }, token);
            using var reader = new StreamReader(tls, Encoding.ASCII, leaveOpen: true);
            var headers = new StringBuilder();
            while (await reader.ReadLineAsync(token) is { Length: > 0 } line) headers.AppendLine(line);
            if (headers.Length == 0) return null;
            string body = $"{{\"id_host\":{hostId}}}";
            byte[] response = Encoding.ASCII.GetBytes(
                $"HTTP/1.1 {(int)status} Response\r\nContent-Length: {body.Length}\r\nContent-Type: application/json\r\nConnection: close\r\n\r\n{body}");
            await tls.WriteAsync(response, token);
            return headers.ToString();
        }
        catch (Exception error) when (expectRejectedTls && error is AuthenticationException or IOException)
        {
            return null;
        }
    }

    private sealed class Wire(Func<string, (HttpStatusCode, string)> respond) : HttpMessageHandler
    {
        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken token)
        {
            var (status, body) = respond(request.Content is null ? "" : await request.Content.ReadAsStringAsync(token));
            return new HttpResponseMessage(status) { Content = new StringContent(body, Encoding.UTF8, "application/json") };
        }
    }
}
