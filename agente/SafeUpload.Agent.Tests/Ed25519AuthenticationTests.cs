using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.Extensions.Configuration;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;
using Org.BouncyCastle.Security;
using SafeUpload.Agent.Core.Infrastructure;
using SafeUpload.Agent.Service.Dispatch;

namespace SafeUpload.Agent.Tests;

public sealed class Ed25519AuthenticationTests
{
    private static readonly Uri Server = new("https://example.test/context/agent/");
    private const string TestToken = "SYNTHETIC-TEST-ONLY";
    private static readonly AgentHeartbeatHost Host = new("10.95.0.51", 24, "PC-SYNTHETIC", "Windows", "10.0", "001122334455");

    [Fact]
    public async Task Enrollment_and_restart_preserve_dpapi_protected_key_and_exact_signed_contract()
    {
        using var workspace = new TestWorkspace();
        var backend = new Backend();
        using var http = Client(backend);
        var store = Store(workspace);
        var identity = await store.RegisterAsync(new(http), TestToken, Host, default);
        byte[] encrypted = await File.ReadAllBytesAsync(PathFor(workspace));
        Assert.Equal(43, identity.HostId);
        Assert.DoesNotContain(TestToken, Encoding.UTF8.GetString(encrypted));
        Assert.DoesNotContain("Seed", Encoding.UTF8.GetString(encrypted));
        Assert.DoesNotContain(identity.PublicKey, Encoding.UTF8.GetString(encrypted));
        Assert.StartsWith("302A300506032B6570032100", Convert.ToHexString(Convert.FromBase64String(identity.PublicKey)));
        var reopened = Store(workspace).Load(Server, 43);
        Assert.Equal(identity.PublicKey, reopened.PublicKey);
        Assert.Equal(identity.SignHost(), reopened.SignHost());
        Assert.True(Verify(identity.PublicKey, 43, identity.SignHost()));
        await AgentHeartbeatConfiguration.Parse("AgentApiEd25519", "43", signingIdentity: reopened, host: Host)
            .CreateSender(http)!.SendAsync(default);
        using var sent = JsonDocument.Parse(backend.LastBody!);
        Assert.Equal(new[] { "autenticacao", "host" }, sent.RootElement.EnumerateObject().Select(p => p.Name));
        Assert.Equal(6, sent.RootElement.GetProperty("host").EnumerateObject().Count());
        Assert.Equal(new[] { "id_host", "assinatura" }, sent.RootElement.GetProperty("autenticacao").EnumerateObject().Select(p => p.Name));
        Assert.Equal(1, backend.Registrations);
        Assert.Equal(1, backend.Authentications);
        Assert.Equal(encrypted, await File.ReadAllBytesAsync(PathFor(workspace)));
        Assert.Equal("already_registered", (await Assert.ThrowsAsync<AgentIdentityException>(() =>
            store.RegisterAsync(new(http), TestToken, Host, default))).Code);
        Assert.Equal(2, backend.Calls);
    }

    [Fact]
    public async Task Lost_response_never_reenrolls_and_explicit_recovery_proves_the_same_key()
    {
        using var workspace = new TestWorkspace();
        var backend = new Backend { LoseEnrollmentResponse = true };
        using var http = Client(backend);
        var store = Store(workspace);
        Assert.Equal("transport", (await Assert.ThrowsAsync<AgentApiException>(() =>
            store.RegisterAsync(new(http), TestToken, Host, default))).Code);
        byte[] pending = await File.ReadAllBytesAsync(PathFor(workspace));
        Assert.Equal("registration_pending", Assert.Throws<AgentIdentityException>(() => Store(workspace).Load(Server)).Code);
        Assert.Equal("registration_pending", (await Assert.ThrowsAsync<AgentIdentityException>(() =>
            Store(workspace).RegisterAsync(new(http), TestToken, Host, default))).Code);
        Assert.Equal(1, backend.Calls);
        Assert.Equal(pending, await File.ReadAllBytesAsync(PathFor(workspace)));
        await Assert.ThrowsAsync<AgentApiException>(() => store.RecoverAsync(new(http), 44, Host, default));
        Assert.Equal(pending, await File.ReadAllBytesAsync(PathFor(workspace)));
        var recovered = await Store(workspace).RecoverAsync(new(http), 43, Host, default);
        Assert.Equal(backend.PublicKey, recovered.PublicKey);
        Assert.Equal(43, Store(workspace).Load(Server).HostId);
        Assert.Equal(1, backend.Registrations);
        Assert.Equal("already_registered", (await Assert.ThrowsAsync<AgentIdentityException>(() =>
            store.RecoverAsync(new(http), 44, Host, default))).Code);
    }

    [Fact]
    public async Task Invalid_token_does_not_retry_or_replace_pending_key_and_errors_do_not_contain_the_token()
    {
        using var workspace = new TestWorkspace();
        var backend = new Backend();
        using var http = Client(backend);
        var error = await Assert.ThrowsAsync<AgentApiException>(() => Store(workspace).RegisterAsync(new(http), "INVALID-SYNTHETIC", Host, default));
        Assert.Equal(400, error.StatusCode);
        Assert.DoesNotContain("INVALID-SYNTHETIC", error.ToString());
        byte[] pending = await File.ReadAllBytesAsync(PathFor(workspace));
        await Assert.ThrowsAsync<AgentIdentityException>(() => Store(workspace).RegisterAsync(new(http), TestToken, Host, default));
        Assert.Equal(pending, await File.ReadAllBytesAsync(PathFor(workspace)));
        Assert.Equal(0, backend.Registrations);
        Assert.Equal(1, backend.Calls);
    }

    [Theory]
    [InlineData("{\"status\":\"OK\",\"id_host\":43}")]
    [InlineData("{\"resposta\":{\"status\":\"CREATED\"},\"id_host\":43}")]
    [InlineData("{\"resposta\":{\"status\":\"OK\"},\"id_host\":0}")]
    [InlineData("{\"resposta\":{\"status\":\"OK\"},\"id_host\":43,\"id_host\":44}")]
    public async Task Malformed_enrollment_receipt_leaves_pending_identity_without_another_registration(string receipt)
    {
        using var workspace = new TestWorkspace();
        var backend = new Backend { EnrollmentReceipt = receipt };
        using var http = Client(backend);
        await Assert.ThrowsAsync<AgentApiException>(() => Store(workspace).RegisterAsync(new(http), TestToken, Host, default));
        Assert.Equal("registration_pending", Assert.Throws<AgentIdentityException>(() => Store(workspace).Load(Server)).Code);
        await Assert.ThrowsAsync<AgentIdentityException>(() => Store(workspace).RegisterAsync(new(http), TestToken, Host, default));
        Assert.Equal(1, backend.Calls);
    }

    [Fact]
    public async Task Incorrect_signature_and_mismatched_response_id_are_rejected()
    {
        using var workspace = new TestWorkspace();
        var backend = new Backend();
        using var http = Client(backend);
        var identity = await Store(workspace).RegisterAsync(new(http), TestToken, Host, default);
        var client = new AgentApiClient(http);
        string invalid = Convert.ToBase64String(new byte[64]);
        Assert.Equal(401, (await Assert.ThrowsAsync<AgentApiException>(() => client.HeartbeatAuthenticatedAsync(43, invalid, Host, default))).StatusCode);
        backend.WrongResponseId = true;
        Assert.Equal("invalid_receipt", (await Assert.ThrowsAsync<AgentApiException>(() =>
            client.HeartbeatAuthenticatedAsync(43, identity.SignHost(), Host, default))).Code);
        Assert.Equal(43, Store(workspace).Load(Server).HostId);
    }

    [Fact]
    public async Task Store_refuses_server_id_key_and_encrypted_payload_changes_without_silent_replacement()
    {
        using var workspace = new TestWorkspace();
        using var otherWorkspace = new TestWorkspace();
        using var http = Client(new Backend());
        var identity = await Store(workspace).RegisterAsync(new(http), TestToken, Host, default);
        Assert.Equal("server_mismatch", Assert.Throws<AgentIdentityException>(() =>
            Store(workspace).Load(new Uri("https://other.test/agent/"))).Code);
        Assert.Equal("host_mismatch", Assert.Throws<AgentIdentityException>(() => Store(workspace).Load(Server, 44)).Code);
        await Store(otherWorkspace).RegisterAsync(new(http), TestToken, Host, default);
        File.Copy(PathFor(otherWorkspace), PathFor(workspace), overwrite: true);
        Assert.Equal("identity_changed", Assert.Throws<AgentIdentityException>(() => identity.SignHost()).Code);
        byte[] bytes = await File.ReadAllBytesAsync(PathFor(workspace));
        bytes[^1] ^= 1;
        await File.WriteAllBytesAsync(PathFor(workspace), bytes);
        Assert.Equal("key_unavailable", Assert.Throws<AgentIdentityException>(() => Store(workspace).Load(Server)).Code);
        Assert.Equal(bytes, await File.ReadAllBytesAsync(PathFor(workspace)));
    }

    [Fact]
    public async Task Pending_enrollment_excludes_concurrent_attempt_before_sending_http()
    {
        using var workspace = new TestWorkspace();
        var backend = new Backend { WaitEnrollment = new(TaskCreationOptions.RunContinuationsAsynchronously) };
        using var http = Client(backend);
        var first = Store(workspace).RegisterAsync(new(http), TestToken, Host, default);
        await backend.Started.Task.WaitAsync(TimeSpan.FromSeconds(5));
        try
        {
            await Assert.ThrowsAsync<AgentIdentityException>(() => Store(workspace).RegisterAsync(new(http), TestToken, Host, default));
            Assert.Equal(1, backend.Calls);
        }
        finally { backend.WaitEnrollment.SetResult(); }
        await first;
    }

    [Fact]
    public async Task Service_configuration_uses_only_provisioned_signed_identity_and_no_legacy_bootstrap()
    {
        using var workspace = new TestWorkspace();
        using var http = Client(new Backend());
        var signed = Store(workspace);
        await signed.RegisterAsync(new(http), TestToken, Host, default);
        var values = new Dictionary<string, string?>
        {
            ["CentroAdministracao:BaseUrl"] = Server.AbsoluteUri,
            ["CentroAdministracao:HeartbeatProtocol"] = "AgentApiEd25519",
            ["CentroAdministracao:HostIp"] = Host.Ip, ["CentroAdministracao:HostMask"] = "24",
            ["CentroAdministracao:PolicyProtocol"] = "ConsoleByIp", ["CentroAdministracao:PolicyHostIp"] = Host.Ip
        };
        var legacy = new RegisteredHostIdentityStore(Path.Combine(workspace.Root, "legacy.json"), false);
        AdministrationConfiguration Parse() => AdministrationConfiguration.Parse(new ConfigurationBuilder().AddInMemoryCollection(values).Build(), legacy, signed);
        var parsed = Parse();
        Assert.Equal(43, parsed.Heartbeat.RegisteredHostId);
        Assert.NotNull(parsed.Heartbeat.SigningIdentity);
        Assert.Equal(43, parsed.ConsolePolicy!.RegisteredHostId);
        Assert.False(File.Exists(Path.Combine(workspace.Root, "legacy.json")));
        values["CentroAdministracao:RegisteredHostId"] = "44";
        Assert.Throws<InvalidOperationException>(() => Parse());
        values.Remove("CentroAdministracao:RegisteredHostId");
        values["CentroAdministracao:HostIp"] = "10.95.0.52";
        Assert.Throws<InvalidOperationException>(() => Parse());
    }

    [Fact]
    public async Task Timed_out_registration_keeps_pending_key_and_restart_never_retries_the_token()
    {
        using var workspace = new TestWorkspace();
        var backend = new Backend { WaitEnrollment = new(TaskCreationOptions.RunContinuationsAsynchronously) };
        using var http = Client(backend);
        http.Timeout = TimeSpan.FromMilliseconds(100);
        var error = await Assert.ThrowsAsync<AgentApiException>(() => Store(workspace).RegisterAsync(new(http), TestToken, Host, default));
        Assert.Equal("timeout", error.Code);
        byte[] pending = await File.ReadAllBytesAsync(PathFor(workspace));
        await Assert.ThrowsAsync<AgentIdentityException>(() => Store(workspace).RegisterAsync(new(http), TestToken, Host, default));
        Assert.Equal(1, backend.Calls);
        Assert.Equal(pending, await File.ReadAllBytesAsync(PathFor(workspace)));
        Assert.Equal("registration_pending", Assert.Throws<AgentIdentityException>(() => Store(workspace).Load(Server)).Code);
    }

    [Fact]
    public async Task Production_store_refuses_unprotected_existing_directory_before_creating_key_or_sending_token()
    {
        using var workspace = new TestWorkspace();
        var backend = new Backend();
        using var http = Client(backend);
        // The caller-owned inherited ACL is deliberately NOT repaired and trusted.
        var store = new SignedHostIdentityStore(PathFor(workspace));
        var error = await Assert.ThrowsAsync<AgentIdentityException>(() => store.RegisterAsync(new(http), TestToken, Host, default));
        Assert.Equal("unsafe_permissions", error.Code);
        Assert.False(File.Exists(PathFor(workspace)));
        Assert.Equal(0, backend.Calls);
    }

    [Fact]
    public async Task Nonloopback_plaintext_enrollment_is_refused_before_generating_a_key_or_sending_a_token()
    {
        using var workspace = new TestWorkspace();
        var backend = new Backend();
        using var http = Client(backend);
        http.BaseAddress = new Uri("http://example.test/agent/");
        await Assert.ThrowsAsync<ArgumentException>(() => Store(workspace).RegisterAsync(new(http), TestToken, Host, default));
        Assert.False(File.Exists(PathFor(workspace)));
        Assert.Equal(0, backend.Calls);
    }

    private static SignedHostIdentityStore Store(TestWorkspace workspace) => new(PathFor(workspace), false);
    private static string PathFor(TestWorkspace workspace) => Path.Combine(workspace.Root, "signing.dat");
    private static HttpClient Client(HttpMessageHandler backend) => new(backend) { BaseAddress = Server };
    private static bool Verify(string publicKey, int id, string signature)
    {
        var verifier = new Ed25519Signer();
        verifier.Init(false, (Ed25519PublicKeyParameters)PublicKeyFactory.CreateKey(Convert.FromBase64String(publicKey)));
        byte[] message = Encoding.UTF8.GetBytes(id.ToString(System.Globalization.CultureInfo.InvariantCulture));
        verifier.BlockUpdate(message, 0, message.Length);
        return verifier.VerifySignature(Convert.FromBase64String(signature));
    }

    private sealed class Backend : HttpMessageHandler
    {
        public int Calls, Registrations, Authentications;
        public bool LoseEnrollmentResponse, WrongResponseId;
        public string? PublicKey, LastBody, EnrollmentReceipt;
        public TaskCompletionSource? WaitEnrollment;
        public TaskCompletionSource Started = new(TaskCreationOptions.RunContinuationsAsynchronously);
        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken token)
        {
            Calls++;
            Assert.Equal("/context/agent/heartbeat", request.RequestUri!.AbsolutePath);
            LastBody = await request.Content!.ReadAsStringAsync(token);
            using var document = JsonDocument.Parse(LastBody);
            var root = document.RootElement;
            Assert.Equal(Host.Ip, root.GetProperty("host").GetProperty("ip").GetString());
            if (root.TryGetProperty("cadastro", out var enrollment))
            {
                Assert.False(root.TryGetProperty("autenticacao", out _));
                if (enrollment.GetProperty("token").GetString() != TestToken) return Reply(400, "{}");
                PublicKey = enrollment.GetProperty("chave_publica").GetString();
                Registrations++;
                Started.TrySetResult();
                if (WaitEnrollment is not null) await WaitEnrollment.Task.WaitAsync(token);
                if (LoseEnrollmentResponse) throw new HttpRequestException("Lost response");
                return Reply(200, EnrollmentReceipt ?? "{\"resposta\":{\"status\":\"OK\"},\"id_host\":43,\"politica\":null}");
            }
            var auth = root.GetProperty("autenticacao");
            int id = auth.GetProperty("id_host").GetInt32();
            if (id != 43 || !Verify(PublicKey!, id, auth.GetProperty("assinatura").GetString()!)) return Reply(401, "{}");
            Authentications++;
            return Reply(200, "{\"resposta\":{\"status\":\"OK\"},\"id_host\":" + (WrongResponseId ? "44" : "43") + "}");
        }
        private static HttpResponseMessage Reply(int code, string body) => new((HttpStatusCode)code) { Content = new StringContent(body) };
    }
}
