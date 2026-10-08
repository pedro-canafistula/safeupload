using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using SafeUpload.Agent.Core.Domain;

namespace SafeUpload.Agent.Core.Contracts;

/// <summary>
/// Pedido do App ao serviço, numa linha NDJSON.
///
/// <para>Duas perguntas pelo mesmo canal, distinguidas por <see cref="Type"/>:</para>
/// <list type="bullet">
/// <item><c>classify</c>, no Ctrl+C: "este texto suja o clipboard?". Leva o
/// texto, o tamanho real e quem copiou.</item>
/// <item><c>paste</c>, no Ctrl+V de um clipboard sujo: "pode colar aqui?". Leva
/// só o <see cref="CopyId"/> devolvido na classificação e o processo de
/// destino. O texto não viaja de novo: quem guarda o estado da cópia é o
/// serviço.</item>
/// </list>
///
/// <para>Um record só, e não dois, porque o leitor do pipe precisa decidir o
/// que fazer depois de ler a linha, e um campo de tipo explícito é mais fácil
/// de validar do que adivinhar pela forma do JSON.</para>
/// </summary>
public sealed record ClipboardRequest(
    [property: JsonPropertyName("type")] string Type,
    [property: JsonPropertyName("text")] string? Text = null,
    [property: JsonPropertyName("textLength")] int TextLength = 0,
    [property: JsonPropertyName("sourceProcess")] string? SourceProcess = null,
    [property: JsonPropertyName("copyId")] string? CopyId = null,
    [property: JsonPropertyName("destinationProcess")] string? DestinationProcess = null)
{
    /// <summary>Monta um pedido de classificação, cortando o texto no teto do protocolo.</summary>
    public static ClipboardRequest Classify(string text, string? sourceProcess)
    {
        ArgumentNullException.ThrowIfNull(text);

        // O tamanho real vai à parte: o serviço precisa saber que o texto era
        // maior do que o que chegou, para aplicar a regra de texto grande
        // demais em vez de varrer só o começo e chamar de limpo.
        var sent = text.Length > ClipboardProtocol.MaxTextChars
            ? text[..ClipboardProtocol.MaxTextChars]
            : text;

        return new ClipboardRequest(ClipboardProtocol.ClassifyType, sent, text.Length, sourceProcess);
    }

    /// <summary>Monta um pedido de colagem.</summary>
    public static ClipboardRequest Paste(string copyId, string? destinationProcess) =>
        new(ClipboardProtocol.PasteType, CopyId: copyId, DestinationProcess: destinationProcess);
}

/// <summary>
/// Resposta do serviço, numa linha NDJSON.
///
/// <para>Para <c>classify</c>: <see cref="CopyId"/>, <see cref="Dirty"/>,
/// <see cref="Categories"/> e <see cref="Findings"/> (já mascarados). Para
/// <c>paste</c>: <see cref="Verdict"/> e, quando houve registro,
/// <see cref="EventId"/>.</para>
///
/// <para>Nenhum campo carrega o texto copiado (RN-006).</para>
/// </summary>
public sealed record ClipboardResponse(
    [property: JsonPropertyName("type")] string Type,
    [property: JsonPropertyName("copyId")] string? CopyId = null,
    [property: JsonPropertyName("dirty")] bool Dirty = false,
    [property: JsonPropertyName("categories")] IReadOnlyList<Category>? Categories = null,
    [property: JsonPropertyName("findings")] IReadOnlyList<string>? Findings = null,
    [property: JsonPropertyName("verdict")] ClipboardPasteVerdict Verdict = ClipboardPasteVerdict.Allow,
    [property: JsonPropertyName("eventId")] string? EventId = null);

/// <summary>
/// Formato do canal de clipboard: NDJSON sobre named pipe, como os outros dois.
///
/// <para>Um pipe próprio, e não uma direção a mais nos existentes, pelo mesmo
/// motivo que a justificativa tem o dela: canais com propósitos diferentes
/// merecem ACLs e limites que possam divergir sem ninguém precisar lembrar.</para>
///
/// <para><b>A falha sempre libera (RN-013).</b> Linha malformada, pedido
/// desconhecido, serviço que não responde a tempo: em todos, o App cola
/// normalmente. O aplicativo que está colando fica parado esperando a resposta,
/// e um DLP que trava o Ctrl+V do usuário é desinstalado na primeira semana.</para>
/// </summary>
public static class ClipboardProtocol
{
    /// <summary>Nome do pipe: <c>\\.\pipe\SafeUpload.Agent.Clipboard</c>.</summary>
    public const string PipeName = "SafeUpload.Agent.Clipboard";

    /// <summary>Tipo do pedido feito no Ctrl+C.</summary>
    public const string ClassifyType = "classify";

    /// <summary>Tipo do pedido feito no Ctrl+V.</summary>
    public const string PasteType = "paste";

    /// <summary>
    /// Teto de caracteres de texto que o protocolo transporta.
    ///
    /// Maior que o teto padrão da política (100 mil), para que a política
    /// possa subir o próprio limite sem mudar o protocolo; menor que o que
    /// faria o serviço alocar sem controle por pedido de um processo do
    /// usuário.
    /// </summary>
    public const int MaxTextChars = 200_000;

    /// <summary>
    /// Teto de uma linha. Folga sobre <see cref="MaxTextChars"/> porque o JSON
    /// escapa aspas, barras e caracteres de controle, e um escape vira até seis
    /// caracteres.
    /// </summary>
    public const int MaxLineLength = MaxTextChars * 6 + 4096;

    /// <summary>Teto do nome de processo, bem acima de qualquer nome real.</summary>
    public const int MaxProcessNameLength = 260;

    /// <summary>
    /// Prazo que o App espera pela resposta de uma colagem antes de colar
    /// normalmente. Curto de propósito: é o tempo que o aplicativo do usuário
    /// fica parado.
    /// </summary>
    public static readonly TimeSpan PasteTimeout = TimeSpan.FromMilliseconds(500);

    /// <summary>
    /// Prazo da classificação. Mais folgado que a colagem: no Ctrl+C ninguém
    /// está esperando, e um texto grande leva mais para varrer.
    /// </summary>
    public static readonly TimeSpan ClassifyTimeout = TimeSpan.FromSeconds(2);

    /// <summary>UTF-8 sem BOM, como os outros canais.</summary>
    public static readonly UTF8Encoding Encoding = new(encoderShouldEmitUTF8Identifier: false);

    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
        Converters = { new JsonStringEnumConverter() }
    };

    /// <summary>Serializa um pedido numa linha, sem a quebra.</summary>
    public static string Serialize(ClipboardRequest request)
    {
        ArgumentNullException.ThrowIfNull(request);
        return JsonSerializer.Serialize(request, JsonOptions);
    }

    /// <summary>Serializa uma resposta numa linha, sem a quebra.</summary>
    public static string Serialize(ClipboardResponse response)
    {
        ArgumentNullException.ThrowIfNull(response);
        return JsonSerializer.Serialize(response, JsonOptions);
    }

    /// <summary>
    /// Lê um pedido, ou devolve <c>null</c> quando a linha não serve.
    ///
    /// Devolve null em vez de lançar porque a linha vem de um processo do
    /// usuário: entrada malformada é o caso comum, e o serviço responde a ela
    /// liberando, não caindo.
    /// </summary>
    public static ClipboardRequest? DeserializeRequest(string? line)
    {
        if (string.IsNullOrWhiteSpace(line) || line.Length > MaxLineLength)
        {
            return null;
        }

        ClipboardRequest? request;
        try
        {
            request = JsonSerializer.Deserialize<ClipboardRequest>(line, JsonOptions);
        }
        catch (JsonException)
        {
            return null;
        }

        if (request is null || TooLong(request.SourceProcess) || TooLong(request.DestinationProcess))
        {
            return null;
        }

        return request.Type switch
        {
            ClassifyType when request.Text is not null &&
                              request.Text.Length <= MaxTextChars &&
                              request.TextLength >= request.Text.Length => request,
            PasteType when !string.IsNullOrWhiteSpace(request.CopyId) &&
                           request.CopyId.Length <= 64 => request,
            _ => null
        };
    }

    /// <summary>
    /// Lê uma resposta, ou devolve <c>null</c> quando a linha não serve. O App
    /// trata null como "cola normalmente".
    /// </summary>
    public static ClipboardResponse? DeserializeResponse(string? line)
    {
        if (string.IsNullOrWhiteSpace(line) || line.Length > MaxLineLength)
        {
            return null;
        }

        try
        {
            var response = JsonSerializer.Deserialize<ClipboardResponse>(line, JsonOptions);
            return response is not null && response.Type is ClassifyType or PasteType ? response : null;
        }
        catch (JsonException)
        {
            return null;
        }
    }

    /// <summary>
    /// Lê uma linha sem deixá-la passar de <see cref="MaxLineLength"/>.
    ///
    /// <c>ReadLineAsync</c> não tem teto: um processo do usuário que escrevesse
    /// sem nunca mandar a quebra faria o serviço acumular memória até o limite
    /// do processo. Aqui, estourar o teto devolve <c>null</c> sem ler o resto.
    /// Os dois lados usam esta leitura, porque o limite do protocolo vale para
    /// quem pergunta e para quem responde.
    ///
    /// Cada conexão carrega uma única linha, então o que vier depois da quebra
    /// no mesmo bloco lido é descartado de propósito.
    /// </summary>
    /// <returns>A linha sem a quebra, ou <c>null</c> se estourou o teto ou o fluxo acabou vazio.</returns>
    public static async Task<string?> ReadLineAsync(TextReader reader, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(reader);

        var line = new StringBuilder();
        var buffer = new char[4096];

        while (true)
        {
            var read = await reader.ReadAsync(buffer.AsMemory(), cancellationToken).ConfigureAwait(false);

            if (read == 0)
            {
                // Fim do fluxo sem quebra: vale o que chegou, se chegou algo.
                return line.Length == 0 ? null : line.ToString();
            }

            var newline = Array.IndexOf(buffer, '\n', 0, read);
            var take = newline >= 0 ? newline : read;

            if (line.Length + take > MaxLineLength)
            {
                return null;
            }

            line.Append(buffer, 0, take);

            if (newline >= 0)
            {
                // Tira o \r de quem escreveu "\r\n".
                if (line.Length > 0 && line[^1] == '\r')
                {
                    line.Length--;
                }

                return line.ToString();
            }
        }
    }

    private static bool TooLong(string? value) => value is not null && value.Length > MaxProcessNameLength;
}
