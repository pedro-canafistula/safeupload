using System.Net.Http.Json;
using System.Runtime.InteropServices;
using System.Text.Json;
using System.Text.Json.Serialization;
using SafeUpload.Agent.Core.Application;
using SafeUpload.Agent.Core.Domain;

namespace SafeUpload.Agent.Service.Dispatch;

/// <summary>
/// Leva ao Centro de Administração o que este endpoint já decidiu (HU-10).
///
/// Não é uma terceira IAuditSink: a fila local continua sendo a
/// LocalQueueAuditSink, e este serviço apenas a consome — lê os pendentes por
/// ReadPendingAsync, faz o POST, e confirma por MarkDispatchedAsync só o que o
/// servidor aceitou. É exatamente a divisão que o comentário da interface
/// descreve, e é o que permite o endpoint continuar decidindo e registrando com
/// a rede fora do ar: gravar em disco e enviar são etapas separadas, nunca uma
/// chamada remota no caminho da decisão.
///
/// Falha de envio não é tratada como erro do agente. O lote continua pendente
/// no queue.jsonl e é tentado de novo na próxima volta — sem retentativa
/// exponencial, sem fila em memória, sem estado extra: o arquivo já é a fila.
/// </summary>
public sealed class HttpAgentDispatcher : BackgroundService
{
    /// <summary>Quantos eventos vão em um POST. A fila sobrevive entre voltas.</summary>
    private const int BatchSize = 100;

    private static readonly JsonSerializerOptions SendOptions = new()
    {
        // Mesmas opções que a LocalQueueAuditSink usa para gravar o
        // queue.jsonl: o corpo do POST é o mesmo objeto, no mesmo formato que o
        // Centro de Administração já espera receber.
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        Converters = { new JsonStringEnumConverter() }
    };

    private readonly IAuditSink _auditSink;
    private readonly IPolicyStore _policyStore;
    private readonly HttpClient _client;
    private readonly string _endpointId;
    private readonly TimeSpan _interval;
    private readonly ILogger<HttpAgentDispatcher> _logger;

    /// <summary>Monta o despachante.</summary>
    public HttpAgentDispatcher(
        IAuditSink auditSink,
        IPolicyStore policyStore,
        HttpClient client,
        string endpointId,
        TimeSpan interval,
        ILogger<HttpAgentDispatcher> logger)
    {
        ArgumentNullException.ThrowIfNull(auditSink);
        ArgumentNullException.ThrowIfNull(policyStore);
        ArgumentNullException.ThrowIfNull(client);
        ArgumentException.ThrowIfNullOrWhiteSpace(endpointId);
        ArgumentNullException.ThrowIfNull(logger);
        ArgumentOutOfRangeException.ThrowIfLessThanOrEqual(interval, TimeSpan.Zero);

        _auditSink = auditSink;
        _policyStore = policyStore;
        _client = client;
        _endpointId = endpointId;
        _interval = interval;
        _logger = logger;
    }

    /// <inheritdoc />
    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        _logger.LogInformation(
            "Despachante ativo: {BaseAddress}, a cada {Seconds:F0} s, como {EndpointId}.",
            _client.BaseAddress,
            _interval.TotalSeconds,
            _endpointId);

        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                await RunCycleAsync(stoppingToken).ConfigureAwait(false);
            }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
            {
                break;
            }
            catch (Exception ex)
            {
                // Servidor fora do ar é estado esperado, não incidente: o que
                // não pode acontecer é o laço morrer e o endpoint parar de
                // tentar para sempre.
                _logger.LogWarning(ex, "Ciclo de despacho falhou. Nova tentativa na próxima volta.");
            }

            try
            {
                await Task.Delay(_interval, stoppingToken).ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
                break;
            }
        }
    }

    private async Task SendHeartbeatAsync(CancellationToken cancellationToken)
    {
        var policy = await _policyStore.LoadAsync(cancellationToken).ConfigureAwait(false);

        var heartbeat = new HeartbeatRequest(
            _endpointId,
            Environment.MachineName,
            RuntimeInformation.OSDescription,
            AgentVersion,
            policy.Version);

        using var response = await _client
            .PostAsJsonAsync("heartbeat", heartbeat, SendOptions, cancellationToken)
            .ConfigureAwait(false);

        if (!response.IsSuccessStatusCode)
        {
            _logger.LogWarning("Heartbeat recusado pelo servidor: {Status}.", (int)response.StatusCode);
        }
    }

    internal async Task RunCycleAsync(CancellationToken cancellationToken)
    {
        try { await SendHeartbeatAsync(cancellationToken).ConfigureAwait(false); }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) { throw; }
        catch (Exception exception)
        {
            _logger.LogWarning(exception, "Heartbeat falhou; o envio da auditoria será tentado independentemente.");
        }
        await DispatchPendingAsync(cancellationToken).ConfigureAwait(false);
    }

    internal async Task DispatchPendingAsync(CancellationToken cancellationToken)
    {
        var pending = await _auditSink.ReadPendingAsync(BatchSize, cancellationToken).ConfigureAwait(false);
        var overrides = _auditSink is IOverrideQueue queue
            ? await queue.ReadPendingOverridesAsync(BatchSize, cancellationToken).ConfigureAwait(false)
            : Array.Empty<AuditOverride>();

        if (pending.Count == 0 && overrides.Count == 0)
        {
            return;
        }

        var payload = new SubmitEventsRequest(pending, overrides);

        using var response = await _client
            .PostAsJsonAsync("events", payload, SendOptions, cancellationToken)
            .ConfigureAwait(false);

        if (!response.IsSuccessStatusCode)
        {
            _logger.LogWarning(
                "Servidor recusou {Count} evento(s): {Status}. Continuam pendentes.",
                pending.Count,
                (int)response.StatusCode);
            return;
        }

        var acknowledgement = await response.Content.ReadFromJsonAsync<JsonElement>(cancellationToken)
            .ConfigureAwait(false);
        if (!IsCompleteAcknowledgement(acknowledgement, pending.Count, overrides.Count))
        {
            _logger.LogWarning("Confirmação inválida ou incompleta do lote. Registros continuam pendentes.");
            return;
        }

        // Só marca como entregue o que o servidor confirmou ter aceitado. Marcar
        // antes do 2xx trocaria uma falha de rede por perda silenciosa de
        // trilha, que é o erro caro: o evento sumiria da fila sem nunca ter
        // chegado ao painel.
        var dispatched = new List<Guid>(pending.Count);
        foreach (var auditEvent in pending)
        {
            dispatched.Add(auditEvent.EventId);
        }

        await _auditSink.MarkDispatchedAsync(dispatched, cancellationToken).ConfigureAwait(false);
        if (_auditSink is IOverrideQueue overrideQueue)
            await overrideQueue.MarkOverridesDispatchedAsync(overrides, cancellationToken).ConfigureAwait(false);

        _logger.LogInformation("{Count} evento(s) entregues ao Centro de Administração.", dispatched.Count);
    }

    /// <summary>
    /// Versão informada no heartbeat. Constante por enquanto: o agente ainda não
    /// carrega versão de assembly própria, e inventar uma leitura de metadado
    /// aqui esconderia que este número não é mantido em lugar nenhum ainda.
    /// </summary>
    private const string AgentVersion = "1.0.0";

    private sealed record HeartbeatRequest(
        string EndpointId,
        string Hostname,
        string Os,
        string AgentVersion,
        int PolicyVersion);

    /// <summary>
    /// O corpo já aceito por POST /agent/events, incluindo justificativas pendentes.
    /// </summary>
    private sealed record SubmitEventsRequest(
        IReadOnlyList<AuditEvent> Events,
        IReadOnlyList<AuditOverride> Overrides);

    private static bool IsCompleteAcknowledgement(JsonElement receipt, int events, int overrides)
    {
        if (receipt.ValueKind != JsonValueKind.Object) return false;
        bool sawEvents = false, sawOverrides = false;
        foreach (var property in receipt.EnumerateObject())
        {
            // Decode escaped names and preserve case-insensitive matching, while rejecting duplicate counts.
            if (property.Name.Equals("acceptedEvents", StringComparison.OrdinalIgnoreCase))
            {
                if (sawEvents || property.Value.ValueKind != JsonValueKind.Number ||
                    !property.Value.TryGetInt32(out int count) || count != events) return false;
                sawEvents = true;
            }
            else if (property.Name.Equals("acceptedOverrides", StringComparison.OrdinalIgnoreCase))
            {
                if (sawOverrides || property.Value.ValueKind != JsonValueKind.Number ||
                    !property.Value.TryGetInt32(out int count) || count != overrides) return false;
                sawOverrides = true;
            }
        }
        // Both top-level counts must exist, even when the corresponding batch is empty.
        return sawEvents && sawOverrides;
    }
}
