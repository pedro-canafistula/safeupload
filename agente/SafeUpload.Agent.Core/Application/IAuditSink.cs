using SafeUpload.Agent.Core.Domain;

namespace SafeUpload.Agent.Core.Application;

/// <summary>
/// Para onde vão os eventos de auditoria.
///
/// PONTO DE TROCA PARA O SERVIDOR CENTRAL.
///
/// Nesta entrega a única implementação é a LocalQueueAuditSink, que grava uma
/// linha JSON por evento em %ProgramData%\SafeUpload\queue.jsonl com
/// dispatched igual a falso. A integração (HU-10) não substitui esta
/// implementação: acrescenta um despachante que lê os eventos pendentes por
/// ReadPendingAsync, faz o POST para o Centro de Administração e chama
/// MarkDispatchedAsync nos que o servidor aceitou.
///
/// A fila em disco é justamente o que permite que o endpoint continue
/// decidindo e registrando com a rede fora do ar; por isso a escrita local e o
/// envio são etapas separadas, e não uma chamada remota síncrona no caminho da
/// decisão.
/// </summary>
public interface IAuditSink
{
    /// <summary>Registra um evento. Nunca deve lançar no caminho da decisão.</summary>
    Task WriteAsync(AuditEvent auditEvent, CancellationToken cancellationToken);

    /// <summary>
    /// Registra que um bloqueio foi liberado por justificativa do usuário.
    ///
    /// Vai como um evento próprio, e não como alteração do bloqueio original:
    /// a trilha precisa mostrar que houve uma recusa <b>e</b> que ela foi
    /// contornada, com o motivo. Reescrever o evento anterior apagaria
    /// exatamente a parte que interessa numa investigação.
    /// </summary>
    /// <param name="eventId">O bloqueio que está sendo justificado.</param>
    /// <param name="justification">O motivo, como o usuário escreveu.</param>
    Task RecordOverrideAsync(string eventId, string justification, CancellationToken cancellationToken);

    /// <summary>Registra a identidade obtida pelo serviço a partir da conexão autenticada.</summary>
    Task RecordOverrideAsync(AuditOverride record, CancellationToken cancellationToken)
        => RecordOverrideAsync(record.EventId.ToString(), record.Justification, cancellationToken);

    /// <summary>
    /// Últimos eventos registrados, do mais recente para o mais antigo. É o que
    /// alimenta a grade do simulador.
    /// </summary>
    /// <param name="maxEvents">Limite de registros; zero ou negativo mantém a consulta completa legada.</param>
    Task<IReadOnlyList<AuditEvent>> ReadRecentAsync(int maxEvents, CancellationToken cancellationToken);

    /// <summary>Bounded recent records after a trusted service-side visibility filter.</summary>
    Task<IReadOnlyList<AuditEvent>> ReadRecentMatchingAsync(int maxEvents, Func<AuditEvent, bool> visible,
        CancellationToken cancellationToken) => throw new NotSupportedException("Filtered history is unavailable.");

    /// <summary>
    /// Eventos ainda não entregues ao servidor central, na ordem em que foram
    /// registrados. O despachante usa esta leitura para preparar o próximo lote.
    /// </summary>
    /// <param name="maxEvents">Limite de registros; zero ou negativo mantém a consulta completa legada.</param>
    Task<IReadOnlyList<AuditEvent>> ReadPendingAsync(int maxEvents, CancellationToken cancellationToken);

    /// <summary>
    /// Marca como entregues os eventos que o servidor confirmou. Contraparte de
    /// ReadPendingAsync, chamada somente após o recibo de entrega.
    /// </summary>
    Task MarkDispatchedAsync(IReadOnlyCollection<Guid> eventIds, CancellationToken cancellationToken);
}
