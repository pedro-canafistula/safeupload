using System.Text.Json;
using System.Text.Json.Serialization;
using SafeUpload.Agent.Core.Application;
using SafeUpload.Agent.Core.Domain;

namespace SafeUpload.Agent.Core.Infrastructure;

/// <summary>
/// Busca a política publicada pelo Centro de Administração (HU-10).
///
/// É a outra implementação da IPolicyStore prevista no comentário da
/// interface. O formato do documento é o mesmo do arquivo local — o painel
/// publica exatamente o JSON que a LocalPolicyStore já sabia ler — então a
/// tradução é a mesma <see cref="PolicyDocument"/>, e o domínio não percebe
/// diferença entre uma origem e outra.
///
/// FALHA DE REDE NUNCA DESPROTEGE O ENDPOINT (RN-013). Servidor fora do ar,
/// DNS errado, timeout, 500, JSON corrompido: tudo cai no padrão embutido e o
/// agente segue inspecionando. O oposto — deixar de carregar política porque o
/// painel não respondeu — transformaria uma indisponibilidade do servidor em
/// uma janela sem proteção em toda a frota ao mesmo tempo, que é o pior
/// desfecho possível para um DLP.
///
/// Esta entrega não guarda cache em disco: o fallback é o padrão, não a última
/// política vista. Cache local é o próximo passo natural (a doc da interface
/// já o sugere) e cabe inteiro dentro desta classe, sem tocar quem a consome.
/// </summary>
public sealed class HttpPolicyStore : IPolicyStore
{
    private static readonly JsonSerializerOptions ReadOptions = new()
    {
        PropertyNameCaseInsensitive = true,
        Converters = { new JsonStringEnumConverter() }
    };

    private readonly HttpClient _client;
    private readonly string _endpointId;

    /// <summary>
    /// </summary>
    /// <param name="client">
    /// Cliente já configurado com BaseAddress apontando para a raiz da API do
    /// agente (por exemplo http://servidor:8000/agent/) e com timeout definido.
    /// </param>
    /// <param name="endpointId">Identificador desta máquina, ecoado na consulta.</param>
    public HttpPolicyStore(HttpClient client, string endpointId)
    {
        ArgumentNullException.ThrowIfNull(client);
        ArgumentException.ThrowIfNullOrWhiteSpace(endpointId);

        _client = client;
        _endpointId = endpointId;
    }

    /// <summary>Endereço consultado, para exibição na interface e em log.</summary>
    public string PolicyEndpoint => new Uri(_client.BaseAddress!, "policy").ToString();

    /// <summary>
    /// Política publicada pelo painel, ou o padrão embutido quando o painel não
    /// puder ser consultado. Nunca lança por causa da rede.
    /// </summary>
    public async Task<Policy> LoadAsync(CancellationToken cancellationToken)
    {
        PolicyDocument? document;

        try
        {
            document = await _client
                .GetFromJsonSafeAsync(
                    $"policy?endpointId={Uri.EscapeDataString(_endpointId)}",
                    ReadOptions,
                    cancellationToken)
                .ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            // Desligamento do serviço não é falha de rede: deixa subir para o
            // host encerrar o que estiver em andamento.
            throw;
        }
        catch (Exception)
        {
            // Qualquer outra coisa — HttpRequestException, timeout que virou
            // TaskCanceledException sem cancelamento nosso, JsonException — é
            // indisponibilidade do painel, e indisponibilidade não pode virar
            // ausência de política.
            document = null;
        }

        var policy = document is null
            ? LocalPolicyStore.CreateDefault()
            : document.ToPolicy();

        // Mesma regra da versão local: valida no carregamento, não no uso. Uma
        // política publicada sem categoria ativa é erro de configuração do
        // painel e precisa aparecer como tal (RN-009).
        policy.EnsureValid();

        return policy;
    }
}

/// <summary>
/// Leitura JSON sem trazer o pacote System.Net.Http.Json para o domínio: são
/// poucas linhas e evitam uma dependência a mais na lista que este projeto
/// publica.
/// </summary>
internal static class HttpClientJsonExtensions
{
    public static async Task<PolicyDocument?> GetFromJsonSafeAsync(
        this HttpClient client,
        string requestUri,
        JsonSerializerOptions options,
        CancellationToken cancellationToken)
    {
        using var response = await client.GetAsync(requestUri, cancellationToken).ConfigureAwait(false);

        response.EnsureSuccessStatusCode();

        await using var stream = await response.Content
            .ReadAsStreamAsync(cancellationToken)
            .ConfigureAwait(false);

        return await JsonSerializer
            .DeserializeAsync<PolicyDocument>(stream, options, cancellationToken)
            .ConfigureAwait(false);
    }
}
