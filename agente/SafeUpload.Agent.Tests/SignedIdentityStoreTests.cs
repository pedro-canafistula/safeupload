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

    [Fact]
    public async Task Enrolled_machine_needs_replace_and_a_failed_attempt_stays_pending_until_retried()
    {
        var store = new SignedHostIdentityStore(File, enforceAcl: false);
        using (var ok = new HttpClient(new Wire(_ => (HttpStatusCode.Created, "{\"id_host\":9}"))) { BaseAddress = Server })
        {
            await store.EnrollAsync(new AgentApiClient(ok), null, "A", Host, false, default);
            var again = await Assert.ThrowsAsync<AgentIdentityException>(() =>
                store.EnrollAsync(new AgentApiClient(ok), null, "B", Host, false, default));
            Assert.Equal("already_registered", again.Code);
        }

        using (var refused = new HttpClient(new Wire(_ => (HttpStatusCode.Unauthorized, "{}"))) { BaseAddress = Server })
        {
            var error = await Assert.ThrowsAsync<AgentApiException>(() =>
                store.EnrollAsync(new AgentApiClient(refused), null, "C", Host, true, default));
            Assert.Equal(401, error.StatusCode);
        }
        Assert.Equal("registration_pending", Assert.Throws<AgentIdentityException>(() => store.Load()).Code);

        // Cadastro pela metade é substituído sem --substituir.
        using var retry = new HttpClient(new Wire(_ => (HttpStatusCode.Created, "{\"id_host\":10}"))) { BaseAddress = Server };
        Assert.Equal(10, (await store.EnrollAsync(new AgentApiClient(retry), null, "D", Host, false, default)).HostId);
        Assert.Equal(10, store.Load()!.HostId);
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
