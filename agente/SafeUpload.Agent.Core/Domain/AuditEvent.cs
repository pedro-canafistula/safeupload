namespace SafeUpload.Agent.Core.Domain;

/// <summary>
/// O registro de auditoria de uma operação julgada — a HU-04.
///
/// Este é o único artefato que sairia do endpoint rumo ao Centro de
/// Administração. Ele é feito só de metadados e de trechos já mascarados:
/// nenhum arquivo trafega, e não há campo capaz de carregar conteúdo. Se um
/// dia o despachante HTTP for implementado, é este objeto que ele envia, e a
/// garantia de que nada sensível vaza está na forma do tipo, não na disciplina
/// de quem o preenche.
/// </summary>
/// <param name="EventId">Identificador único do evento.</param>
/// <param name="OccurredAtUtc">Quando a operação foi julgada, em UTC.</param>
/// <param name="EndpointId">Máquina onde o agente roda.</param>
/// <param name="UserName">Usuário dono da sessão.</param>
/// <param name="FileName">Nome do arquivo, sem o caminho.</param>
/// <param name="Extension">Extensão do arquivo.</param>
/// <param name="SizeBytes">Tamanho em bytes.</param>
/// <param name="Verdict">Desfecho da operação.</param>
/// <param name="Categories">Categorias encontradas, sem repetição.</param>
/// <param name="MaskedSnippets">Trechos mascarados (RN-007).</param>
/// <param name="ProcessName">Processo que originou a operação.</param>
/// <param name="ProcessId">PID desse processo.</param>
/// <param name="DestinationPath">Destino da operação.</param>
/// <param name="NotInspectedReason">
/// Por que não houve inspeção: file_too_large, unsupported_format,
/// inspection_timeout, parse_error:Tipo ou out_of_scope. Nulo quando houve
/// inspeção de verdade.
/// </param>
/// <param name="PolicyVersion">Versão da política aplicada.</param>
/// <param name="ElapsedMs">Duração da decisão, em milissegundos.</param>
/// <param name="Dispatched">
/// Se o evento já foi entregue ao servidor central. Nasce falso e assim
/// permanece nesta entrega, porque o despachante ainda não existe. O campo
/// existe desde já para que a fila local seja a mesma antes e depois da
/// integração.
/// </param>
public sealed record AuditEvent(
    Guid EventId,
    DateTimeOffset OccurredAtUtc,
    string EndpointId,
    string UserName,
    string FileName,
    string Extension,
    long SizeBytes,
    Verdict Verdict,
    IReadOnlyList<Category> Categories,
    IReadOnlyList<string> MaskedSnippets,
    string ProcessName,
    int ProcessId,
    string DestinationPath,
    string? NotInspectedReason,
    int PolicyVersion,
    long ElapsedMs,
    bool Dispatched);
