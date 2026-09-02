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
    /// Últimos eventos registrados, do mais recente para o mais antigo. É o que
    /// alimenta a grade do simulador.
    /// </summary>
    Task<IReadOnlyList<AuditEvent>> ReadRecentAsync(int maxEvents, CancellationToken cancellationToken);

    /// <summary>
    /// Eventos ainda não entregues ao servidor central. Existe para o
    /// despachante da HU-10, que ainda não foi implementado.
    /// </summary>
    Task<IReadOnlyList<AuditEvent>> ReadPendingAsync(int maxEvents, CancellationToken cancellationToken);

    /// <summary>
    /// Marca como entregues os eventos que o servidor confirmou. Contraparte de
    /// ReadPendingAsync, também à espera da HU-10.
    /// </summary>
    Task MarkDispatchedAsync(IReadOnlyCollection<Guid> eventIds, CancellationToken cancellationToken);
}
