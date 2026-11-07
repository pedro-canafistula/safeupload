using System.Net;
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

    private sealed class Wire(Func<string, (HttpStatusCode, string)> respond) : HttpMessageHandler
    {
        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken token)
        {
            var (status, body) = respond(request.Content is null ? "" : await request.Content.ReadAsStringAsync(token));
            return new HttpResponseMessage(status) { Content = new StringContent(body, Encoding.UTF8, "application/json") };
        }
    }
}
