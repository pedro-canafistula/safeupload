using System.Net;
using System.Net.Http.Json;
using System.Text.Json;

// Prepares only the isolated API fixture. SYSTEM/SCM assertions belong to the guarded PowerShell case.
internal static class ConsoleServiceFixture
{
    private const string Ip = "10.90.0.21", Email = "console-system@example.test", Password = "synthetic-system-123";
    private static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web) { WriteIndented = true };
    private sealed record State(int HostId, int ControlId, string HostIp, string Endpoint, int Revision, string Rule);

    internal static async Task RunAsync(string phase, string statePath)
    {
        if (phase is not ("setup" or "recover")) throw new ArgumentException("Expected setup or recover.");
        string path = Path.GetFullPath(statePath);
        if (!Directory.Exists(Path.GetDirectoryName(path))) throw new ArgumentException("Existing fixture directory required.");
        if ((phase == "setup") == File.Exists(path)) throw new IOException("Fixture state does not match phase.");
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(45));
        var token = timeout.Token;
        using var http = new HttpClient(new HttpClientHandler { AllowAutoRedirect = false })
            { BaseAddress = new Uri("http://127.0.0.1:18080/"), Timeout = TimeSpan.FromSeconds(5) };
        void Check(string name, bool passed)
        {
            if (!passed) throw new InvalidOperationException("Console service fixture failed: " + name);
            Console.WriteLine("CONSOLE_SERVICE_FIXTURE_PASS=" + name);
        }
        async Task<JsonElement> Get(string route)
        {
            using var response = await http.GetAsync(route, token);
            response.EnsureSuccessStatusCode();
            return await response.Content.ReadFromJsonAsync<JsonElement>(token);
        }
        async Task<JsonElement> Post(string route, object body, HttpStatusCode status = HttpStatusCode.OK, bool readJson = false)
        {
            using var response = await http.PostAsJsonAsync(route, body, token);
            Check("POST " + route, response.StatusCode == status);
            if (!readJson) return default;
            string text = await response.Content.ReadAsStringAsync(token);
            return string.IsNullOrWhiteSpace(text) ? default : JsonSerializer.Deserialize<JsonElement>(text);
        }
        State state;
        if (phase == "setup")
        {
            Check("fresh isolated database", !(await Get("auth/decision")).GetProperty("existemUsuarios").GetBoolean());
            var address = new { cep = "70000-000", logradouro = "Rua Sintetica", numero = 1, complemento = "", bairro = "Teste", cidade = "Brasilia", estado = "DF" };
            await Post("auth/firstregister", new { username = "console-system", email = Email, cpf = "52998224725", senha = Password,
                nome_completo = "Teste SYSTEM", data_nascimento = "1990-01-01", endereco = address,
                empresa = new { razao_social = "Empresa Sintetica", nome_fantasia = "Teste", cnpj = "11222333000181", email_contato = Email, telefone_contato = "61999999999", endereco = address } }, HttpStatusCode.Created);
            await Post("auth/login", new { email = Email, senha = Password });
            async Task<int> Register(string name, string ip)
            {
                var host = await Post("agent/synchronize", new {
                    host = new { ip, mascara = 24, hostname = name, sistema_operacional = "Windows", versao_so = "test" },
                    usuarioSo = new { sid = "S-TEST-" + name, usuario_so = name, dominio = "SYNTHETIC", admin = 0 } }, HttpStatusCode.Created, readJson: true);
                return host.GetProperty("id_host").GetInt32();
            }
            int target = await Register(Environment.MachineName, Ip), control = await Register("CONSOLE-SYSTEM-CONTROL", "10.90.0.22");
            Check("two distinct explicit hosts", target > 0 && control > 0 && target != control);
            state = new(target, control, Ip, Environment.MachineName, 0, "");
            int first = await Publish("cpf");
            int second = await Publish("cnpj");
            Check("CNPJ policy has a distinct newer revision", second > first && first > 0);
            state = state with { Revision = second, Rule = "cnpj" };
        }
        else
        {
            state = JsonSerializer.Deserialize<State>(await File.ReadAllTextAsync(path, token), Json)
                ?? throw new IOException("Missing fixture state.");
            if (state.HostId <= 0 || state.HostIp != Ip || state.Endpoint != Environment.MachineName || state.Rule != "cnpj")
                throw new IOException("Fixture context mismatch.");
            await Post("auth/login", new { email = Email, senha = Password });
            int revision = await Publish("cpf");
            Check("recovered CPF policy advances the revision", revision > state.Revision);
            state = state with { Revision = revision, Rule = "cpf" };
        }
        using (var other = await http.GetAsync("agent/api/policy?ip=10.90.0.22", token))
            Check("control host has no target policy", other.StatusCode == HttpStatusCode.NotFound);
        if (phase == "setup")
        {
            await using var file = new FileStream(path, FileMode.CreateNew, FileAccess.Write, FileShare.None);
            await JsonSerializer.SerializeAsync(file, state, Json, token);
        }
        else await File.WriteAllTextAsync(path, JsonSerializer.Serialize(state, Json), token);
        Check("fixture metadata matches the published revision", (await Get("agent/api/policy?ip=" + Ip)).GetProperty("idPolitica").GetInt32() == state.Revision);
        Console.WriteLine("ConsoleServiceFixture=" + phase + ";ScmExecuted=False;DriverQualified=False");

        async Task<int> Publish(string rule)
        {
            await Post("politicas", new { versao = "1.0", nome = "Console SYSTEM fixture", destino = new { ip = Ip }, acao = "bloquear",
                regras = new[] { new { tipo = rule, nome = rule } }, criadaEm = DateTimeOffset.UtcNow, origem = "console-system-fixture" }, HttpStatusCode.Created);
            var policy = await Get("agent/api/policy?ip=" + Ip);
            Check("publication has the explicit target context", policy.GetProperty("destino").GetProperty("idHost").GetInt32() == state.HostId &&
                policy.GetProperty("destino").GetProperty("ip").GetString() == state.HostIp && policy.GetProperty("regras")[0].GetProperty("tipo").GetString() == rule);
            return policy.GetProperty("idPolitica").GetInt32();
        }
    }
}
