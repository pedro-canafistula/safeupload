using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace SafeUpload.Agent.Core.Contracts;

/// <summary>
/// Justificativa que o usuário informa para prosseguir com uma operação que
/// foi bloqueada.
///
/// <para><b>O que este canal é, e o que ele não é.</b> O canal de notificação
/// é de mão única de propósito, e o comentário dele diz por quê: "é a garantia
/// de que nada que o usuário faça na interface pode alterar um veredito". Este
/// canal não revoga essa garantia — ele a reformula. A interface continua sem
/// alterar veredito nenhum; ela <b>submete uma justificativa para um bloqueio
/// que o próprio serviço registrou</b>, identificado por um
/// <see cref="EventId"/> que só o serviço emite.</para>
///
/// <para>Disso decorrem as validações do lado do serviço, e nenhuma delas
/// depende de o cliente se comportar: o evento tem de existir, tem de ser
/// recente, tem de ter sido entregue àquela sessão, e tem de ser um bloqueio.
/// Um cliente que invente um identificador não encontra nada; um que repita
/// um antigo encontra um evento já consumido.</para>
/// </summary>
/// <param name="EventId">
/// Identificador do evento de auditoria do bloqueio, como veio na notificação.
/// </param>
/// <param name="Justification">
/// O motivo de negócio, em texto livre. Vai para a trilha de auditoria como o
/// usuário escreveu.
/// </param>
public sealed record JustificationRequest(
    [property: JsonPropertyName("eventId")] string EventId,
    [property: JsonPropertyName("justification")] string Justification);

/// <summary>
/// Formato do canal de justificativas.
///
/// Uma linha JSON por pedido, como no canal de notificações — mesmo formato
/// pelo mesmo motivo: dá para ler com um <c>StreamReader</c> e depurar com os
/// olhos.
/// </summary>
public static class JustificationProtocol
{
    /// <summary>
    /// Nome do pipe. Separado do de notificações, e não uma segunda direção
    /// no mesmo: canais com propósitos opostos merecem ACLs que podem divergir
    /// sem que ninguém precise lembrar disso.
    /// </summary>
    public const string PipeName = "SafeUpload.Agent.Justification";

    /// <summary>
    /// Teto do texto da justificativa, em caracteres.
    ///
    /// Existe porque o outro lado do canal é um processo do usuário, e um
    /// campo de texto sem limite vira memória do serviço. Generoso o
    /// suficiente para um parágrafo de explicação.
    /// </summary>
    public const int MaxJustificationLength = 1000;

    /// <summary>Uma linha nunca legítima passa deste tamanho.</summary>
    public const int MaxLineLength = 4096;

    public static readonly UTF8Encoding Encoding = new(encoderShouldEmitUTF8Identifier: false);

    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
    };

    /// <summary>Serializa um pedido numa linha.</summary>
    public static string Serialize(JustificationRequest request)
    {
        ArgumentNullException.ThrowIfNull(request);

        return JsonSerializer.Serialize(request, JsonOptions);
    }

    /// <summary>
    /// Lê um pedido de uma linha, ou devolve <c>null</c> quando a linha não
    /// serve.
    ///
    /// Devolve null em vez de lançar porque a origem desta linha é um processo
    /// do usuário: entrada malformada é o caso comum, não a exceção, e um
    /// serviço que lança a cada linha estranha é um serviço que o usuário
    /// derruba de propósito.
    /// </summary>
    public static JustificationRequest? Deserialize(string? line)
    {
        if (string.IsNullOrWhiteSpace(line) || line.Length > MaxLineLength)
        {
            return null;
        }

        try
        {
            JustificationRequest? request =
                JsonSerializer.Deserialize<JustificationRequest>(line, JsonOptions);

            if (request is null ||
                string.IsNullOrWhiteSpace(request.EventId) ||
                string.IsNullOrWhiteSpace(request.Justification) ||
                request.Justification.Length > MaxJustificationLength)
            {
                return null;
            }

            return request;
        }
        catch (JsonException)
        {
            return null;
        }
    }
}
