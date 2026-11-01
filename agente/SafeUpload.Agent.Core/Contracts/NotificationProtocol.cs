using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace SafeUpload.Agent.Core.Contracts;

/// <summary>
/// O protocolo do canal entre o serviço e o aplicativo de bandeja: NDJSON —
/// uma mensagem JSON por linha, em UTF-8, sobre named pipe.
///
/// NDJSON em vez de um formato com enquadramento próprio porque a mensagem já
/// tem delimitador natural: a quebra de linha. O leitor não precisa de
/// cabeçalho de tamanho nem de máquina de estados, e o canal pode ser
/// inspecionado com qualquer ferramenta de texto durante a depuração. É o mesmo
/// formato do <c>queue.jsonl</c>, o que evita duas convenções no mesmo projeto.
/// </summary>
public static class NotificationProtocol
{
    /// <summary>
    /// Nome do named pipe. O caminho completo é
    /// <c>\\.\pipe\SafeUpload.Agent</c>.
    /// </summary>
    public const string PipeName = "SafeUpload.Agent";

    /// <summary>
    /// UTF-8 sem BOM, pelo mesmo motivo da fila em disco: a marca ficaria
    /// colada no início da primeira linha e quebraria um leitor estrito.
    /// </summary>
    public static readonly UTF8Encoding Encoding = new(encoderShouldEmitUTF8Identifier: false);

    /// <summary>
    /// Opções de serialização usadas pelos dois lados. Precisam ser as mesmas:
    /// é a razão de estarem aqui, e não duplicadas em cada processo.
    /// </summary>
    public static readonly JsonSerializerOptions JsonOptions = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        DefaultIgnoreCondition = JsonIgnoreCondition.Never,
        Converters = { new JsonStringEnumConverter() }
    };

    /// <summary>
    /// Serializa uma mensagem como uma linha NDJSON, já com a quebra de linha.
    /// </summary>
    public static string Serialize(AgentNotification notification)
    {
        ArgumentNullException.ThrowIfNull(notification);

        // \n e não Environment.NewLine: o delimitador é do protocolo, não do
        // sistema operacional de quem escreve.
        if (notification is HistoryNotification history && !ValidHistory(history))
            throw new InvalidDataException("Invalid history snapshot.");
        string line = JsonSerializer.Serialize(notification, JsonOptions) + "\n";
        if (notification is HistoryNotification && Encoding.GetByteCount(line) > HistoryNotification.MaximumPayloadBytes)
            throw new InvalidDataException("History snapshot is too large.");
        return line;
    }

    /// <summary>
    /// Interpreta uma linha NDJSON.
    /// </summary>
    /// <returns>
    /// A mensagem, ou <c>null</c> se a linha estiver vazia ou malformada. Linha
    /// inválida não derruba o cliente: descartar uma mensagem é melhor do que
    /// perder a conexão e ficar sem as seguintes.
    /// </returns>
    public static AgentNotification? Deserialize(string line)
    {
        if (string.IsNullOrWhiteSpace(line))
        {
            return null;
        }

        try
        {
            var notification = JsonSerializer.Deserialize<AgentNotification>(line, JsonOptions);
            return notification is HistoryNotification history &&
                (!ValidHistory(history) || Encoding.GetByteCount(line) > HistoryNotification.MaximumPayloadBytes)
                ? null : notification;
        }
        catch (JsonException)
        {
            return null;
        }
    }

    private static bool ValidHistory(HistoryNotification history) => history.Events is not null &&
        history.Events.Count <= HistoryNotification.MaximumEvents && (history.Available || history.Events.Count == 0) &&
        history.Events.All(e => e is not null && e.EventId != Guid.Empty && e.Categories is not null && e.MaskedSnippets is not null);
}
