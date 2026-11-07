using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using System.Text.Json.Serialization;
using SafeUpload.Agent.Core.Application;

namespace SafeUpload.Agent.Core.Infrastructure;

/// <summary>
/// Cadastro e heartbeat (docs/console-agente.md). O HttpClient aponta para .../agent/; o heartbeat precisa de um
/// cliente com <see cref="SignedRequestHandler"/>. Cadastro é uma tentativa só, sem retentativa automática.
/// </summary>
public sealed class AgentApiClient
{
    private readonly HttpClient _http;
    private readonly ICommunicationObserver? _observer;
    private const int MaxReceiptBytes = 16 * 1024;
    internal Uri BaseUri => _http.BaseAddress!;

    public AgentApiClient(HttpClient http, ICommunicationObserver? observer = null)
    {
        ArgumentNullException.ThrowIfNull(http);
        if (http.BaseAddress is null) throw new ArgumentException("Cliente sem BaseAddress.", nameof(http));
        AgentHttp.ServerUri(http.BaseAddress.AbsoluteUri);
        _http = http;
        _observer = observer;
    }

    /// <summary>POST enroll: token de uso único + chave pública → id_host.</summary>
    public async Task<int> EnrollAsync(string enrollmentToken, string publicKey, AgentHeartbeatHost host, CancellationToken token)
    {
        using var response = await SendAsync("enroll",
            new { token = enrollmentToken, chave_publica = publicKey, host }, HttpStatusCode.Created, token).ConfigureAwait(false);
        return HostId(response.RootElement);
    }

    /// <summary>POST heartbeat assinado, com a versão da política do console em uso (null = política local).</summary>
    public async Task HeartbeatAsync(int hostId, AgentHeartbeatHost host, int? appliedPolicy, string agentVersion,
        CancellationToken token)
    {
        using var observation = new CommunicationObservation(_observer, CommunicationOperation.Heartbeat);
        try
        {
            using var response = await SendAsync("heartbeat",
                new HeartbeatBody(host, appliedPolicy, agentVersion), HttpStatusCode.OK, token).ConfigureAwait(false);
            if (HostId(response.RootElement) != hostId) throw new AgentApiException("invalid_receipt");
            observation.Success(200);
        }
        catch (AgentApiException error)
        {
            var failure = error.Code switch
            {
                "http_status" => CommunicationFailure.HttpRejected,
                "transport" => CommunicationFailure.TransportError,
                "timeout" => CommunicationFailure.Timeout,
                "invalid_receipt" or "receipt_too_large" => CommunicationFailure.InvalidResponse,
                _ => CommunicationFailure.UnexpectedError
            };
            observation.Failure(failure, error.StatusCode ??
                (error.Code is "invalid_receipt" or "receipt_too_large" ? 200 : null));
            throw;
        }
        catch (Exception error) { observation.Exception(error, token); throw; }
    }

    private async Task<JsonDocument> SendAsync<T>(string path, T body, HttpStatusCode expected, CancellationToken token)
    {
        // O mesmo prazo do HttpClient vale para a leitura do recibo: corpo lento não prende o laço.
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
            return JsonDocument.Parse(buffer.ToArray(), new JsonDocumentOptions { AllowDuplicateProperties = false, MaxDepth = 16 });
        }
        catch (OperationCanceledException) when (token.IsCancellationRequested) { throw; }
        catch (OperationCanceledException) { throw new AgentApiException("timeout"); }
        catch (HttpRequestException ex) { throw new AgentApiException("transport", ex.StatusCode is {} status ? (int)status : null); }
        catch (IOException) { throw new AgentApiException("transport"); }
        catch (JsonException) { throw new AgentApiException("invalid_receipt"); }
    }

    private static int HostId(JsonElement root)
    {
        if (root.ValueKind != JsonValueKind.Object || !root.TryGetProperty("id_host", out var value) ||
            value.ValueKind != JsonValueKind.Number || !value.TryGetInt32(out int id) || id <= 0)
            throw new AgentApiException("invalid_receipt");
        return id;
    }

    private sealed record HeartbeatBody(
        [property: JsonPropertyName("host")] AgentHeartbeatHost Host,
        [property: JsonPropertyName("politica_aplicada")] int? AppliedPolicy,
        [property: JsonPropertyName("versao_agente")] string AgentVersion)
    {
        /// <summary>Formato de regras personalizadas que este agente entende; o servidor não publica um mais novo.</summary>
        [JsonPropertyName("formato_regras")]
        public int RulesFormat => SafeUpload.Agent.Core.Domain.CustomRuleSet.SupportedFormat;
    }
}

/// <summary>Erro sanitizado: não guarda URL, corpo HTTP, mensagem do servidor ou exceção interna.</summary>
public sealed class AgentApiException(string code, int? statusCode = null)
    : Exception($"AgentApi: {code}; HTTP={statusCode?.ToString() ?? "none"}.")
{
    public string Code { get; } = code;
    public int? StatusCode { get; } = statusCode;
}

/// <summary>Heartbeat periódico: dados atuais da máquina + versão da política do console em uso.</summary>
public sealed class SignedAgentHeartbeat(AgentApiClient client, int hostId, Func<int?> appliedPolicy, string agentVersion)
    : IAgentHeartbeat
{
    public Task SendAsync(CancellationToken token) =>
        client.HeartbeatAsync(hostId, AgentHeartbeatHost.Detect(), appliedPolicy(), agentVersion, token);
}
