using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using System.Text.Json.Serialization;
using SafeUpload.Agent.Core.Application;

namespace SafeUpload.Agent.Core.Infrastructure;

/// <summary>Contrato publicado em AgentController/AgentContracts na main d6605e4d.
/// O HttpClient aponta para /agent/; cadastro NÃO tem retentativa automática.
/// Não é cliente de política, tickets ou consulta administrativa.
/// </summary>
public sealed class AgentApiClient
{
    private readonly HttpClient _http;
    private const int MaxReceiptBytes = 16 * 1024;

    public AgentApiClient(HttpClient http)
    {
        ArgumentNullException.ThrowIfNull(http);
        var uri = http.BaseAddress;
        if (uri is null || !uri.IsAbsoluteUri ||
            (uri.Scheme != Uri.UriSchemeHttp && uri.Scheme != Uri.UriSchemeHttps) ||
            !uri.AbsolutePath.EndsWith("/agent/", StringComparison.Ordinal) ||
            uri.UserInfo.Length != 0 || uri.Query.Length != 0 || uri.Fragment.Length != 0)
            throw new ArgumentException("Cliente AgentApi exige base HTTP(S) terminada em /agent/, sem credenciais, query ou fragmento.", nameof(http));
        _http = http;
    }

    /// <summary>Somente para provisionamento controlado. Resposta perdida não autoriza novo cadastro.</summary>
    public async Task<AgentRegistration> SynchronizeAsync(AgentSynchronization request, CancellationToken token)
    {
        ArgumentNullException.ThrowIfNull(request);
        request.EnsureValid();
        using var document = await SendAsync("synchronize", request, HttpStatusCode.Created, token).ConfigureAwait(false);
        var root = document.RootElement;
        RequireStatus(root, "CREATED");
        return new AgentRegistration(PositiveInt(root, "id_host"), PositiveInt(root, "id_usuario_so"));
    }

    public async Task HeartbeatAsync(int registeredHostId, CancellationToken token)
    {
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(registeredHostId);
        using var document = await SendAsync("heartbeat", new HeartbeatBody(registeredHostId),
            HttpStatusCode.OK, token).ConfigureAwait(false);
        RequireStatus(document.RootElement, "OK");
    }

    private async Task<JsonDocument> SendAsync<T>(string path, T body, HttpStatusCode expected, CancellationToken token)
    {
        // ResponseHeadersRead encerra o timeout padrão ao receber cabeçalhos.
        // Estende o mesmo orçamento à leitura do recibo para evitar corpo lento infinito.
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(token);
        if (_http.Timeout != Timeout.InfiniteTimeSpan) deadline.CancelAfter(_http.Timeout);
        var boundedToken = deadline.Token;
        try
        {
            using var request = new HttpRequestMessage(HttpMethod.Post, path) { Content = JsonContent.Create(body) };
            using var response = await _http.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, boundedToken).ConfigureAwait(false);
            if (response.StatusCode != expected)
                throw new AgentApiException("http_status", (int)response.StatusCode);
            await using var stream = await response.Content.ReadAsStreamAsync(boundedToken).ConfigureAwait(false);
            using var buffer = new MemoryStream();
            byte[] chunk = new byte[4096];
            int count;
            while ((count = await stream.ReadAsync(chunk, boundedToken).ConfigureAwait(false)) != 0)
            {
                if (buffer.Length + count > MaxReceiptBytes) throw new AgentApiException("receipt_too_large");
                buffer.Write(chunk, 0, count);
            }
            return JsonDocument.Parse(buffer.ToArray());
        }
        catch (OperationCanceledException) when (token.IsCancellationRequested) { throw; }
        catch (OperationCanceledException) { throw new AgentApiException("timeout"); }
        catch (HttpRequestException ex) { throw new AgentApiException("transport", ex.StatusCode is {} status ? (int)status : null); }
        catch (IOException) { throw new AgentApiException("transport"); }
        catch (JsonException) { throw new AgentApiException("invalid_receipt"); }
    }

    private static JsonElement UniqueField(JsonElement root, string name)
    {
        if (root.ValueKind != JsonValueKind.Object) throw new AgentApiException("invalid_receipt");
        JsonElement found = default;
        int matches = 0;
        foreach (var property in root.EnumerateObject())
        {
            if (!string.Equals(property.Name, name, StringComparison.OrdinalIgnoreCase)) continue;
            matches++;
            found = property.Value;
        }
        if (matches != 1) throw new AgentApiException("invalid_receipt");
        return found;
    }

    private static int PositiveInt(JsonElement root, string name)
    {
        var value = UniqueField(root, name);
        if (value.ValueKind != JsonValueKind.Number || !value.TryGetInt32(out int result) || result <= 0)
            throw new AgentApiException("invalid_receipt");
        return result;
    }

    private static void RequireStatus(JsonElement root, string expected)
    {
        var value = UniqueField(root, "status");
        if (value.ValueKind != JsonValueKind.String || value.GetString() != expected)
            throw new AgentApiException("invalid_receipt");
    }

    private sealed record HeartbeatBody([property: JsonPropertyName("id_host")] int HostId);
}

/// <summary>Erro sanitizado: não guarda URL, corpo HTTP, SID, mensagem do servidor ou exceção interna.</summary>
public sealed class AgentApiException(string code, int? statusCode = null)
    : Exception($"AgentApi: {code}; HTTP={statusCode?.ToString() ?? "none"}.")
{
    public string Code { get; } = code;
    public int? StatusCode { get; } = statusCode;
}

public sealed record AgentRegistration(int HostId, int UserId);

public sealed record AgentSynchronization(
    [property: JsonPropertyName("host")] AgentHost Host,
    [property: JsonPropertyName("usuarioSo")] AgentOsUser User)
{
    internal void EnsureValid()
    {
        ArgumentNullException.ThrowIfNull(Host);
        ArgumentNullException.ThrowIfNull(User);
        ArgumentOutOfRangeException.ThrowIfNegative(Host.Mask);
        ArgumentOutOfRangeException.ThrowIfGreaterThan(Host.Mask, 32);
        if (User.Admin is not (0 or 1)) throw new ArgumentOutOfRangeException(nameof(User.Admin));
        Check(Host.Ip, 15); Check(Host.Hostname, 100); Check(Host.OperatingSystem, 40);
        Check(Host.OsVersion, 20); Check(Host.Manufacturer, 50); Check(Host.Model, 50);
        Check(Host.MacAddress, 20); Check(Host.SerialNumber, 30);
        Check(User.Sid, 50); Check(User.Username, 40); Check(User.Domain, 50);
    }

    private static void Check(string? value, int maximum)
    {
        if (value?.Length > maximum) throw new ArgumentException("Campo de cadastro excede o limite do contrato AgentApi.");
    }
}

public sealed record AgentHost(
    [property: JsonPropertyName("ip")] string? Ip,
    [property: JsonPropertyName("mascara")] int Mask,
    [property: JsonPropertyName("hostname")] string? Hostname,
    [property: JsonPropertyName("sistema_operacional")] string? OperatingSystem,
    [property: JsonPropertyName("versao_so")] string? OsVersion,
    [property: JsonPropertyName("fabricante")] string? Manufacturer,
    [property: JsonPropertyName("modelo")] string? Model,
    [property: JsonPropertyName("mac_address")] string? MacAddress,
    [property: JsonPropertyName("numero_serie")] string? SerialNumber);

public sealed record AgentOsUser(
    [property: JsonPropertyName("sid")] string? Sid,
    [property: JsonPropertyName("usuario_so")] string? Username,
    [property: JsonPropertyName("dominio")] string? Domain,
    [property: JsonPropertyName("admin")] int Admin);

/// <summary>Identificador fornecido pelo provisionamento; não confundir com SID ou endpointId.</summary>
public sealed class RegisteredAgentHeartbeat(AgentApiClient client, int registeredHostId) : IAgentHeartbeat
{
    private readonly AgentApiClient _client = client ?? throw new ArgumentNullException(nameof(client));
    private readonly int _hostId = registeredHostId > 0 ? registeredHostId :
        throw new ArgumentOutOfRangeException(nameof(registeredHostId));

    public Task SendAsync(CancellationToken cancellationToken) => _client.HeartbeatAsync(_hostId, cancellationToken);
}
