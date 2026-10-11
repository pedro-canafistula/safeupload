using System.Buffers;
using System.IO.Compression;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.Json;
using SafeUpload.Agent.Network.Http;

namespace SafeUpload.Agent.Network.Inspection;

/// <summary>O que uma parte do corpo é para a inspeção.</summary>
public enum UploadPartKind
{
    /// <summary>Texto digitado: campo de formulário, prompt, corpo de mensagem.</summary>
    Text,

    /// <summary>Conteúdo de arquivo. O formato é descoberto depois, pelos bytes.</summary>
    File,
}

/// <summary>Uma parte do corpo de uma requisição, já decodificada.</summary>
/// <param name="Kind">Texto ou arquivo.</param>
/// <param name="FileName">Nome do arquivo, quando o site informou.</param>
/// <param name="Content">Os bytes como o usuário os mandou, sem a codificação de transporte.</param>
public sealed record UploadPart(UploadPartKind Kind, string? FileName, ReadOnlyMemory<byte> Content);

/// <summary>
/// Desmonta o corpo de uma requisição nas partes que interessam à inspeção
/// (Fase 5 do plano).
///
/// O proxy entrega o corpo como uma sequência de bytes. O que o usuário mandou
/// está dentro dele, embrulhado de um jeito que depende do site (ver o estudo
/// da Fase 0):
///
/// - <c>multipart/form-data</c>: formulário com arquivos e campos de texto,
///   cada um numa parte separada por uma linha de fronteira;
/// - <c>multipart/related</c>: o que o Google Drive usa para arquivo pequeno,
///   com o arquivo em base64 numa das partes;
/// - <c>application/json</c>: prompt de IA e chamadas de API;
/// - <c>application/x-www-form-urlencoded</c>: formulário simples;
/// - corpo bruto: o arquivo inteiro num <c>PUT</c> ou <c>POST</c>.
///
/// O tipo declarado não é confiável: o Drive manda um arquivo de 40 MB
/// dizendo <c>x-www-form-urlencoded</c>. Por isso este parser só separa as
/// partes e desfaz as codificações de transporte; decidir que formato de
/// arquivo é cada parte fica para o motor, que olha os bytes.
///
/// Nada aqui lança por corpo malformado: o que não é entendido vira uma parte
/// de arquivo com os bytes como vieram, e o motor decide.
/// </summary>
public static class UploadBodyParser
{
    /// <summary>
    /// Teto do corpo depois de descomprimido. Sem ele, poucos quilobytes
    /// comprimidos poderiam virar gigabytes em memória.
    /// </summary>
    public const int MaxDecompressedBytes = 128 * 1024 * 1024;

    private const int MaxNesting = 2;

    /// <summary>Separa o corpo em partes.</summary>
    /// <param name="head">Primeira linha e cabeçalhos da requisição.</param>
    /// <param name="body">Corpo inteiro, já sem a moldura de pedaços.</param>
    public static IReadOnlyList<UploadPart> Parse(HttpRequestHead head, ReadOnlyMemory<byte> body)
    {
        ArgumentNullException.ThrowIfNull(head);

        if (body.IsEmpty)
        {
            return [];
        }

        body = Decompress(body, head.Headers.Get("Content-Encoding"));

        var parts = new List<UploadPart>();
        string? fileName = FileNameFromHeaders(head.Headers);

        AddContent(parts, head.Headers.Get("Content-Type"), fileName, body, IsUploadProtocol(head.Headers), depth: 0);
        return parts;
    }

    /// <summary>
    /// Cabeçalhos dos protocolos de upload de arquivo: o retomável do Google
    /// (Drive, Gmail), o tus e o envio em faixas. Com eles o corpo é conteúdo
    /// de arquivo, mesmo sem nome e com o tipo declarado errado.
    /// </summary>
    private static bool IsUploadProtocol(HttpHeaders headers) =>
        headers.Get("X-Goog-Upload-Command") is not null
        || headers.Get("Upload-Offset") is not null
        || headers.Get("Content-Range") is not null;

    private static void AddContent(
        List<UploadPart> parts, string? contentType, string? fileName, ReadOnlyMemory<byte> content, bool isUpload, int depth)
    {
        if (content.IsEmpty)
        {
            return;
        }

        MediaType type = MediaType.Parse(contentType);

        if (type.IsMultipart && depth < MaxNesting && type.Parameter("boundary") is { Length: > 0 } boundary)
        {
            AddMultipart(parts, content, boundary, depth);
            return;
        }

        // Com nome de arquivo, num protocolo de upload ou com cara de binário,
        // é arquivo, diga o que disser o tipo declarado.
        if (fileName is not null || isUpload || LooksBinary(content.Span))
        {
            parts.Add(new UploadPart(UploadPartKind.File, fileName, content));
            return;
        }

        if (type.Is("application/x-www-form-urlencoded") && LooksUrlEncoded(content.Span))
        {
            parts.Add(Text(UrlDecode(content.Span)));
        }
        else if (type.IsJson && TryJsonText(content.Span) is { } json)
        {
            parts.Add(Text(json));
        }
        else
        {
            // Sem nome, sem protocolo de upload e sem cara de binário: é
            // texto, seja qual for o tipo declarado. É assim que sai a
            // telemetria das páginas (sendBeacon com text/plain ou sem tipo),
            // e tratá-la como arquivo geraria um evento por requisição.
            parts.Add(new UploadPart(UploadPartKind.Text, null, content));
        }
    }

    /// <summary>
    /// Separa um corpo multipart. Cada parte tem os próprios cabeçalhos,
    /// depois uma linha em branco, depois o conteúdo, até a próxima fronteira.
    /// </summary>
    private static void AddMultipart(List<UploadPart> parts, ReadOnlyMemory<byte> body, string boundary, int depth)
    {
        byte[] delimiter = Encoding.ASCII.GetBytes("--" + boundary);
        ReadOnlySpan<byte> span = body.Span;

        int position = span.IndexOf(delimiter);

        while (position >= 0)
        {
            int start = position + delimiter.Length;

            // "--fronteira--" encerra o corpo.
            if (span[start..].StartsWith("--"u8))
            {
                return;
            }

            int lineEnd = span[start..].IndexOf((byte)'\n');

            if (lineEnd < 0)
            {
                return;
            }

            start += lineEnd + 1;

            int next = span[start..].IndexOf(delimiter);
            int end = next < 0 ? span.Length : start + next;

            AddPart(parts, body[start..TrimLineBreak(span, start, end)], depth);

            position = next < 0 ? -1 : start + next;
        }
    }

    private static void AddPart(List<UploadPart> parts, ReadOnlyMemory<byte> part, int depth)
    {
        ReadOnlySpan<byte> span = part.Span;
        int headerEnd = span.IndexOf("\r\n\r\n"u8);
        int separator = 4;

        if (headerEnd < 0)
        {
            headerEnd = span.IndexOf("\n\n"u8);
            separator = 2;
        }

        // Parte que começa direto na linha em branco não tem cabeçalhos.
        if (span.StartsWith("\r\n"u8))
        {
            headerEnd = 0;
            separator = 2;
        }

        if (headerEnd < 0)
        {
            return;
        }

        string? contentType = null;
        string? disposition = null;
        string? transferEncoding = null;

        foreach (string line in Encoding.UTF8.GetString(span[..headerEnd]).Split('\n'))
        {
            int colon = line.IndexOf(':');

            if (colon <= 0)
            {
                continue;
            }

            string name = line[..colon].Trim();
            string value = line[(colon + 1)..].Trim();

            if (name.Equals("Content-Type", StringComparison.OrdinalIgnoreCase))
            {
                contentType = value;
            }
            else if (name.Equals("Content-Disposition", StringComparison.OrdinalIgnoreCase))
            {
                disposition = value;
            }
            else if (name.Equals("Content-Transfer-Encoding", StringComparison.OrdinalIgnoreCase))
            {
                transferEncoding = value;
            }
        }

        ReadOnlyMemory<byte> content = DecodeTransfer(part[(headerEnd + separator)..], transferEncoding);

        AddContent(parts, contentType, FileNameFromDisposition(disposition), content, isUpload: false, depth + 1);
    }

    /// <summary>A quebra de linha antes da fronteira pertence à fronteira, não ao conteúdo.</summary>
    private static int TrimLineBreak(ReadOnlySpan<byte> span, int start, int end)
    {
        if (end > start && span[end - 1] == (byte)'\n')
        {
            end--;
        }

        if (end > start && span[end - 1] == (byte)'\r')
        {
            end--;
        }

        return end;
    }

    /// <summary>
    /// Desfaz o <c>Content-Transfer-Encoding</c> da parte. É como o Drive
    /// manda arquivo pequeno: o conteúdo sai em base64, e sem decodificar o
    /// CPF dentro dele não aparece.
    /// </summary>
    private static ReadOnlyMemory<byte> DecodeTransfer(ReadOnlyMemory<byte> content, string? encoding)
    {
        if (string.Equals(encoding, "base64", StringComparison.OrdinalIgnoreCase))
        {
            // Base64 de e-mail vem quebrado em linhas; tira os espaços antes
            // de decodificar, numa cópia que depois recebe o resultado.
            byte[] buffer = new byte[content.Length];
            int length = 0;

            foreach (byte value in content.Span)
            {
                if (value is not ((byte)'\r' or (byte)'\n' or (byte)' ' or (byte)'\t'))
                {
                    buffer[length++] = value;
                }
            }

            return System.Buffers.Text.Base64.DecodeFromUtf8InPlace(buffer.AsSpan(0, length), out int written) == OperationStatus.Done
                ? buffer.AsMemory(0, written)
                : content;
        }

        if (string.Equals(encoding, "quoted-printable", StringComparison.OrdinalIgnoreCase))
        {
            return DecodeQuotedPrintable(content.Span);
        }

        return content;
    }

    private static byte[] DecodeQuotedPrintable(ReadOnlySpan<byte> content)
    {
        var decoded = new ArrayBufferWriter<byte>(content.Length);

        for (int i = 0; i < content.Length; i++)
        {
            byte current = content[i];

            if (current != (byte)'=')
            {
                decoded.Write([current]);
                continue;
            }

            // "=" no fim da linha é só continuação.
            if (i + 1 < content.Length && content[i + 1] == (byte)'\n')
            {
                i++;
            }
            else if (i + 2 < content.Length && content[i + 1] == (byte)'\r' && content[i + 2] == (byte)'\n')
            {
                i += 2;
            }
            else if (i + 2 < content.Length && TryHex(content[i + 1], content[i + 2], out byte value))
            {
                decoded.Write([value]);
                i += 2;
            }
            else
            {
                decoded.Write([current]);
            }
        }

        return decoded.WrittenSpan.ToArray();
    }

    /// <summary>
    /// Desfaz o <c>Content-Encoding</c> da requisição. Corpo comprimido que não
    /// abre, ou que passa do teto, segue como veio.
    /// </summary>
    private static ReadOnlyMemory<byte> Decompress(ReadOnlyMemory<byte> body, string? encoding)
    {
        if (string.IsNullOrWhiteSpace(encoding) || encoding.Trim().Equals("identity", StringComparison.OrdinalIgnoreCase))
        {
            return body;
        }

        try
        {
            using Stream input = AsStream(body);
            using Stream? inflater = encoding.Trim().ToLowerInvariant() switch
            {
                "gzip" or "x-gzip" => new GZipStream(input, CompressionMode.Decompress),
                "deflate" => new ZLibStream(input, CompressionMode.Decompress),
                "br" => new BrotliStream(input, CompressionMode.Decompress),
                _ => null,
            };

            if (inflater is null)
            {
                return body;
            }

            using var output = new MemoryStream();
            byte[] buffer = new byte[81920];
            int read;

            while ((read = inflater.Read(buffer, 0, buffer.Length)) > 0)
            {
                if (output.Length + read > MaxDecompressedBytes)
                {
                    return body;
                }

                output.Write(buffer, 0, read);
            }

            return output.ToArray();
        }
        catch (Exception ex) when (ex is InvalidDataException or IOException)
        {
            return body;
        }
    }

    /// <summary>
    /// Junta os textos de um JSON, um por linha, já sem as barras de escape.
    /// Varrer o JSON cru funcionaria para um CPF, mas um texto com acento sai
    /// como <c>é</c> e as regras por palavra deixariam de casar.
    /// </summary>
    private static string? TryJsonText(ReadOnlySpan<byte> json)
    {
        try
        {
            var reader = new Utf8JsonReader(json, new JsonReaderOptions { AllowTrailingCommas = true, CommentHandling = JsonCommentHandling.Skip });
            var text = new StringBuilder();

            while (reader.Read())
            {
                switch (reader.TokenType)
                {
                    case JsonTokenType.String:
                    case JsonTokenType.PropertyName:
                        text.Append(reader.GetString()).Append('\n');
                        break;

                    case JsonTokenType.Number:
                        text.Append(Encoding.UTF8.GetString(reader.ValueSpan)).Append('\n');
                        break;
                }
            }

            return text.ToString();
        }
        catch (JsonException)
        {
            return null;
        }
    }

    /// <summary>
    /// Formulário simples de verdade (<c>a=1&amp;b=2</c>) não tem espaço nem
    /// quebra de linha crus. Um arquivo de texto declarado com esse tipo tem.
    /// </summary>
    private static bool LooksUrlEncoded(ReadOnlySpan<byte> content) =>
        content.IndexOf((byte)'=') >= 0 && content.IndexOfAny((byte)' ', (byte)'\n', (byte)'\r') < 0;

    private static string UrlDecode(ReadOnlySpan<byte> content)
    {
        var decoded = new ArrayBufferWriter<byte>(content.Length);

        for (int i = 0; i < content.Length; i++)
        {
            byte current = content[i];

            if (current == (byte)'+')
            {
                decoded.Write(" "u8);
            }
            else if (current == (byte)'&')
            {
                decoded.Write("\n"u8);
            }
            else if (current == (byte)'%' && i + 2 < content.Length && TryHex(content[i + 1], content[i + 2], out byte value))
            {
                decoded.Write([value]);
                i += 2;
            }
            else
            {
                decoded.Write([current]);
            }
        }

        return Encoding.UTF8.GetString(decoded.WrittenSpan);
    }

    /// <summary>
    /// Assinatura de PDF ou de ZIP (docx, xlsx), ou byte nulo no começo: não é
    /// texto digitado.
    /// </summary>
    private static bool LooksBinary(ReadOnlySpan<byte> content)
    {
        if (content.StartsWith("%PDF-"u8) || content.StartsWith("PK\u0003\u0004"u8))
        {
            return true;
        }

        return content[..Math.Min(content.Length, 1024)].IndexOf((byte)0) >= 0;
    }

    private static string? FileNameFromHeaders(HttpHeaders headers) =>
        FileNameFromDisposition(headers.Get("Content-Disposition"))
        ?? NullIfEmpty(headers.Get("X-Goog-Upload-File-Name"))
        ?? NullIfEmpty(headers.Get("X-File-Name"));

    /// <summary><c>form-data; name="arquivo"; filename="folha.xlsx"</c> → <c>folha.xlsx</c>.</summary>
    private static string? FileNameFromDisposition(string? disposition)
    {
        if (disposition is null)
        {
            return null;
        }

        MediaType parsed = MediaType.Parse(disposition);

        // "filename*" é a forma com acentos (RFC 5987): UTF-8''nome%20do%20arquivo.
        if (parsed.Parameter("filename*") is { } extended)
        {
            int quotes = extended.IndexOf("''", StringComparison.Ordinal);

            if (quotes >= 0)
            {
                return NullIfEmpty(Uri.UnescapeDataString(extended[(quotes + 2)..]));
            }
        }

        return NullIfEmpty(parsed.Parameter("filename"));
    }

    private static UploadPart Text(string text) => new(UploadPartKind.Text, null, Encoding.UTF8.GetBytes(text));

    private static string? NullIfEmpty(string? value) => string.IsNullOrWhiteSpace(value) ? null : value.Trim();

    private static bool TryHex(byte high, byte low, out byte value)
    {
        int h = HexValue(high);
        int l = HexValue(low);
        value = (byte)((h << 4) | l);
        return h >= 0 && l >= 0;
    }

    private static int HexValue(byte digit) => digit switch
    {
        >= (byte)'0' and <= (byte)'9' => digit - '0',
        >= (byte)'a' and <= (byte)'f' => digit - 'a' + 10,
        >= (byte)'A' and <= (byte)'F' => digit - 'A' + 10,
        _ => -1,
    };

    private static MemoryStream AsStream(ReadOnlyMemory<byte> content) =>
        MemoryMarshal.TryGetArray(content, out ArraySegment<byte> segment)
            ? new MemoryStream(segment.Array!, segment.Offset, segment.Count, writable: false)
            : new MemoryStream(content.ToArray(), writable: false);

    /// <summary>Um valor de cabeçalho no formato <c>tipo; chave=valor; chave="valor"</c>.</summary>
    private readonly record struct MediaType(string Name, IReadOnlyList<KeyValuePair<string, string>> Parameters)
    {
        public bool IsEmpty => Name.Length == 0;

        public bool IsMultipart => Name.StartsWith("multipart/", StringComparison.Ordinal);

        public bool IsText => Name.StartsWith("text/", StringComparison.Ordinal);

        public bool IsJson => Name == "application/json" || Name.EndsWith("+json", StringComparison.Ordinal);

        public bool Is(string name) => Name == name;

        public string? Parameter(string name)
        {
            foreach ((string key, string value) in Parameters)
            {
                if (key.Equals(name, StringComparison.OrdinalIgnoreCase))
                {
                    return value;
                }
            }

            return null;
        }

        public static MediaType Parse(string? header)
        {
            if (string.IsNullOrWhiteSpace(header))
            {
                return new MediaType(string.Empty, []);
            }

            var parameters = new List<KeyValuePair<string, string>>();
            List<string> pieces = SplitOutsideQuotes(header);

            for (int i = 1; i < pieces.Count; i++)
            {
                int equals = pieces[i].IndexOf('=');

                if (equals > 0)
                {
                    parameters.Add(new(pieces[i][..equals].Trim(), Unquote(pieces[i][(equals + 1)..].Trim())));
                }
            }

            return new MediaType(pieces[0].Trim().ToLowerInvariant(), parameters);
        }

        /// <summary>Separa por ";" sem cortar um nome de arquivo que tenha ";" entre aspas.</summary>
        private static List<string> SplitOutsideQuotes(string header)
        {
            var pieces = new List<string>();
            var current = new StringBuilder();
            bool quoted = false;

            for (int i = 0; i < header.Length; i++)
            {
                char c = header[i];

                if (c == '\\' && quoted && i + 1 < header.Length)
                {
                    current.Append(c).Append(header[++i]);
                }
                else if (c == '"')
                {
                    quoted = !quoted;
                    current.Append(c);
                }
                else if (c == ';' && !quoted)
                {
                    pieces.Add(current.ToString());
                    current.Clear();
                }
                else
                {
                    current.Append(c);
                }
            }

            pieces.Add(current.ToString());
            return pieces;
        }

        private static string Unquote(string value) =>
            value.Length >= 2 && value[0] == '"' && value[^1] == '"'
                ? value[1..^1].Replace("\\\"", "\"", StringComparison.Ordinal).Replace("\\\\", "\\", StringComparison.Ordinal)
                : value;
    }
}
