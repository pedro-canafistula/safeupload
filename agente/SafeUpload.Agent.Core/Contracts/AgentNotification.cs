using System.Text.Json.Serialization;
using SafeUpload.Agent.Core.Domain;

namespace SafeUpload.Agent.Core.Contracts;

/// <summary>
/// Uma mensagem do serviço para o aplicativo de bandeja.
///
/// O canal é de mão única, e isso é a regra de arquitetura, não uma limitação
/// de implementação: o serviço decide, o aplicativo apenas mostra. Não existe
/// tipo de mensagem no sentido inverso, então nada que o usuário clique na
/// interface tem como alterar um veredito — a ausência do caminho de volta é a
/// garantia.
///
/// Os contratos vivem no <c>Core</c> para que os dois processos compartilhem a
/// mesma definição sem um terceiro projeto só para isso. Continuam livres de
/// arquivo, pipe e HTTP: são apenas a forma dos dados.
/// </summary>
[JsonPolymorphic(TypeDiscriminatorPropertyName = "type")]
[JsonDerivedType(typeof(StatusNotification), StatusNotification.TypeName)]
[JsonDerivedType(typeof(EventNotification), EventNotification.TypeName)]
public abstract record AgentNotification;

/// <summary>
/// O estado da proteção agora.
///
/// Enviada assim que um cliente conecta e sempre que a política mudar. É o que
/// alimenta os três cartões da tela de status: sem ela o aplicativo não teria
/// como saber a versão da política, já que quem carrega política passou a ser
/// o serviço.
/// </summary>
/// <param name="PolicyVersion">Versão da política em vigor.</param>
/// <param name="ActiveCategories">Quantas categorias estão ativas.</param>
/// <param name="ProtectionActive">
/// Se o interceptador está de fato vigiando. Falso quando o serviço subiu mas
/// não conseguiu observar as pastas — o aplicativo precisa poder distinguir
/// "protegido" de "serviço no ar, mas cego".
/// </param>
public sealed record StatusNotification(
    int PolicyVersion,
    int ActiveCategories,
    bool ProtectionActive) : AgentNotification
{
    /// <summary>Discriminador desta mensagem no NDJSON.</summary>
    public const string TypeName = "status";
}

/// <summary>
/// Uma operação julgada.
///
/// Alimenta a atividade recente e, quando o veredito é bloqueio, dispara a
/// notificação. O <see cref="AuditEvent"/> vai aninhado, e não achatado na
/// raiz da mensagem, para que exista uma definição só dos dezessete campos da
/// HU-04: achatar exigiria repetir todos eles aqui e abriria espaço para os
/// dois lados divergirem com o tempo. O discriminador continua na raiz, então
/// quem lê decide o que fazer com a linha sem desserializar o resto.
/// </summary>
/// <param name="Event">O evento de auditoria, exatamente como foi gravado.</param>
public sealed record EventNotification(AuditEvent Event) : AgentNotification
{
    /// <summary>Discriminador desta mensagem no NDJSON.</summary>
    public const string TypeName = "event";
}
