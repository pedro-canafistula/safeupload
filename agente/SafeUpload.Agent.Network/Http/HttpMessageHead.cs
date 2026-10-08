using System.Globalization;
using System.Text;

namespace SafeUpload.Agent.Network.Http;

/// <summary>Como o corpo de uma mensagem é delimitado (RFC 9112, seção 6).</summary>
public enum BodyFraming
{
    /// <summary>Sem corpo.</summary>
    None,

    /// <summary>Corpo com tamanho declarado em <c>Content-Length</c>.</summary>
    ContentLength,

    /// <summary>Corpo em pedaços (<c>Transfer-Encoding: chunked</c>), tamanho desconhecido de antemão.</summary>
    Chunked,

    /// <summary>
    /// Só em respostas: o corpo vai até o servidor fechar a conexão. Formato
    /// antigo, mas ainda existe.
    /// </summary>
    UntilClose,
}

/// <summary>Primeira linha e cabeçalhos de uma requisição.</summary>
/// <param name="Method">GET, POST, CONNECT...</param>
/// <param name="Target">
/// Alvo como chegou: <c>/caminho?x=1</c> (forma de origem), <c>http://host/caminho</c>
/// (forma absoluta, usada com proxy em HTTP sem TLS) ou <c>host:443</c> (CONNECT).
/// </param>
/// <param name="Version">HTTP/1.1 ou HTTP/1.0.</param>
public sealed record HttpRequestHead(string Method, string Target, string Version, HttpHeaders Headers)
{
    /// <summary>Indica se é o pedido de túnel do navegador ao proxy.</summary>
    public bool IsConnect => string.Equals(Method, "CONNECT", StringComparison.OrdinalIgnoreCase);

    /// <summary>
    /// Como o corpo da requisição é delimitado. Requisição sem
    /// <c>Content-Length</c> nem <c>chunked</c> não tem corpo; ao contrário da
    /// resposta, ela nunca vai "até fechar".
    /// </summary>
    public BodyFraming Framing => HttpFraming.For(Headers, allowUntilClose: false, out _);

    /// <summary>Tamanho declarado do corpo, quando há <c>Content-Length</c>.</summary>
    public long? ContentLength
    {
        get
        {
            HttpFraming.For(Headers, allowUntilClose: false, out long? length);
            return length;
        }
    }

    /// <summary>Indica se o cliente espera <c>100 Continue</c> antes de mandar o corpo.</summary>
    public bool ExpectsContinue => Headers.HasToken("Expect", "100-continue");

    /// <summary>Indica se a conexão deve fechar depois desta troca.</summary>
    public bool WantsClose =>
        Headers.HasToken("Connection", "close")
        || (string.Equals(Version, "HTTP/1.0", StringComparison.OrdinalIgnoreCase) && !Headers.HasToken("Connection", "keep-alive"));

    /// <summary>Serializa a primeira linha e os cabeçalhos, terminando na linha em branco.</summary>
    public byte[] Serialize()
    {
        var builder = new StringBuilder();
        builder.Append(Method).Append(' ').Append(Target).Append(' ').Append(Version).Append("\r\n");
        Headers.WriteTo(builder);
        builder.Append("\r\n");
        return Encoding.Latin1.GetBytes(builder.ToString());
    }
}

/// <summary>Primeira linha e cabeçalhos de uma resposta.</summary>
public sealed record HttpResponseHead(string Version, int StatusCode, string Reason, HttpHeaders Headers)
{
    /// <summary>Indica se é uma resposta provisória (1xx), seguida de outra resposta.</summary>
    public bool IsInterim => StatusCode is >= 100 and < 200 && StatusCode != 101;

    /// <summary>Indica se a resposta troca de protocolo (WebSocket).</summary>
    public bool IsSwitchingProtocols => StatusCode == 101;

    /// <summary>Indica se a conexão deve fechar depois desta resposta.</summary>
    public bool WantsClose =>
        Headers.HasToken("Connection", "close")
        || (string.Equals(Version, "HTTP/1.0", StringComparison.OrdinalIgnoreCase) && !Headers.HasToken("Connection", "keep-alive"));

    /// <summary>
    /// Como o corpo é delimitado. Depende da requisição: resposta a HEAD, e as
    /// respostas 1xx, 204 e 304, nunca têm corpo, mesmo que declarem tamanho.
    /// </summary>
    public BodyFraming FramingFor(HttpRequestHead request)
    {
        if (string.Equals(request.Method, "HEAD", StringComparison.OrdinalIgnoreCase)
            || StatusCode is >= 100 and < 200 or 204 or 304)
        {
            return BodyFraming.None;
        }

        return HttpFraming.For(Headers, allowUntilClose: true, out _);
    }

    /// <summary>Serializa a primeira linha e os cabeçalhos, terminando na linha em branco.</summary>
    public byte[] Serialize()
    {
        var builder = new StringBuilder();
        builder.Append(Version).Append(' ').Append(StatusCode.ToString(CultureInfo.InvariantCulture)).Append(' ').Append(Reason).Append("\r\n");
        Headers.WriteTo(builder);
        builder.Append("\r\n");
        return Encoding.Latin1.GetBytes(builder.ToString());
    }

    /// <summary>Resposta simples gerada pelo próprio proxy (403, 502...), sempre fechando a conexão.</summary>
    public static byte[] Simple(int statusCode, string reason, string body)
    {
        byte[] content = Encoding.UTF8.GetBytes(body);
        var headers = new HttpHeaders();
        headers.Add("Content-Type", "text/plain; charset=utf-8");
        headers.Add("Content-Length", content.Length.ToString(CultureInfo.InvariantCulture));
        headers.Add("Connection", "close");
        headers.Add("Cache-Control", "no-store");

        byte[] head = new HttpResponseHead("HTTP/1.1", statusCode, reason, headers).Serialize();
        return [.. head, .. content];
    }
}

/// <summary>Regras de delimitação de corpo (RFC 9112, seção 6.3).</summary>
internal static class HttpFraming
{
    public static BodyFraming For(HttpHeaders headers, bool allowUntilClose, out long? contentLength)
    {
        contentLength = null;

        // Transfer-Encoding vence Content-Length. Os dois juntos são um sinal
        // clássico de tentativa de "request smuggling"; aqui vale o chunked e o
        // Content-Length é descartado ao repassar.
        if (headers.Get("Transfer-Encoding") is { } transferEncoding)
        {
            if (transferEncoding.TrimEnd().EndsWith("chunked", StringComparison.OrdinalIgnoreCase))
            {
                return BodyFraming.Chunked;
            }

            if (allowUntilClose)
            {
                return BodyFraming.UntilClose;
            }

            throw new HttpMessageException($"Transfer-Encoding não suportado: {transferEncoding}");
        }

        if (headers.Get("Content-Length") is { } value)
        {
            if (!long.TryParse(value.Trim(), NumberStyles.None, CultureInfo.InvariantCulture, out long length))
            {
                throw new HttpMessageException($"Content-Length inválido: {value}");
            }

            contentLength = length;
            return length == 0 ? BodyFraming.None : BodyFraming.ContentLength;
        }

        return allowUntilClose ? BodyFraming.UntilClose : BodyFraming.None;
    }
}

/// <summary>Mensagem HTTP malformada ou fora do que o proxy aceita.</summary>
public sealed class HttpMessageException(string message) : Exception(message);
