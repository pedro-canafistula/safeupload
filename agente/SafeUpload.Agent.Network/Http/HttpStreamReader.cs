using System.Globalization;
using System.Text;

namespace SafeUpload.Agent.Network.Http;

/// <summary>
/// Lê mensagens HTTP/1.1 de um fluxo (a conexão TLS já aberta).
///
/// É um parser próprio, e não o do ASP.NET ou do HttpClient, porque um proxy
/// interceptador precisa de duas coisas que eles não dão: ver a mensagem
/// exatamente como chegou (para repassar sem alterar o que não precisa) e
/// segurar o corpo antes de decidir se ele segue.
///
/// O leitor mantém um buffer próprio: os bytes lidos da rede depois do fim de
/// uma mensagem já são o começo da próxima (keep-alive), e não podem se perder.
/// </summary>
public sealed class HttpStreamReader
{
    /// <summary>
    /// Teto para primeira linha + cabeçalhos. Navegadores mandam poucos KB; o
    /// teto existe para que um cliente defeituoso não faça o proxy acumular
    /// memória sem fim esperando a linha em branco.
    /// </summary>
    public const int MaxHeadBytes = 64 * 1024;

    private readonly Stream _stream;
    private readonly byte[] _buffer = new byte[16 * 1024];
    private int _start;
    private int _end;

    public HttpStreamReader(Stream stream)
    {
        ArgumentNullException.ThrowIfNull(stream);
        _stream = stream;
    }

    /// <summary>Bytes já lidos da rede e ainda não consumidos.</summary>
    public int Buffered => _end - _start;

    /// <summary>
    /// Lê uma requisição. Devolve nulo se a conexão fechar antes do primeiro
    /// byte, que é o fim normal de uma conexão keep-alive.
    /// </summary>
    public async Task<HttpRequestHead?> ReadRequestHeadAsync(CancellationToken cancellationToken)
    {
        string[]? lines = await ReadHeadLinesAsync(cancellationToken).ConfigureAwait(false);

        if (lines is null)
        {
            return null;
        }

        string[] start = lines[0].Split(' ', 3);

        if (start.Length != 3 || !start[2].StartsWith("HTTP/1.", StringComparison.Ordinal))
        {
            throw new HttpMessageException($"Linha de requisição inválida: {Truncate(lines[0])}");
        }

        return new HttpRequestHead(start[0], start[1], start[2], ParseHeaders(lines));
    }

    /// <summary>Lê uma resposta. Lança se a conexão fechar antes.</summary>
    public async Task<HttpResponseHead> ReadResponseHeadAsync(CancellationToken cancellationToken)
    {
        string[] lines = await ReadHeadLinesAsync(cancellationToken).ConfigureAwait(false)
            ?? throw new HttpMessageException("O servidor fechou a conexão sem responder.");

        string[] start = lines[0].Split(' ', 3);

        if (start.Length < 2
            || !start[0].StartsWith("HTTP/1.", StringComparison.Ordinal)
            || !int.TryParse(start[1], NumberStyles.None, CultureInfo.InvariantCulture, out int status))
        {
            throw new HttpMessageException($"Linha de status inválida: {Truncate(lines[0])}");
        }

        return new HttpResponseHead(start[0], status, start.Length == 3 ? start[2] : string.Empty, ParseHeaders(lines));
    }

    /// <summary>
    /// Lê o corpo e entrega cada trecho de dados (já sem a moldura de
    /// pedaços) a <paramref name="onData"/>. Devolve o total de bytes de dados.
    /// </summary>
    public async Task<long> ReadBodyAsync(
        BodyFraming framing,
        long? contentLength,
        Func<ReadOnlyMemory<byte>, CancellationToken, ValueTask> onData,
        CancellationToken cancellationToken)
    {
        switch (framing)
        {
            case BodyFraming.None:
                return 0;

            case BodyFraming.ContentLength:
                return await ReadFixedAsync(contentLength!.Value, onData, cancellationToken).ConfigureAwait(false);

            case BodyFraming.Chunked:
                return await ReadChunkedAsync(onData, cancellationToken).ConfigureAwait(false);

            case BodyFraming.UntilClose:
                return await ReadUntilCloseAsync(onData, cancellationToken).ConfigureAwait(false);

            default:
                throw new ArgumentOutOfRangeException(nameof(framing));
        }
    }

    /// <summary>
    /// Tira do buffer os bytes ainda não consumidos. Usado quando a conexão
    /// muda de dono, como na passagem do CONNECT para o TLS.
    /// </summary>
    public byte[] TakeBuffered()
    {
        byte[] leftover = _buffer.AsSpan(_start, Buffered).ToArray();
        _start = _end = 0;
        return leftover;
    }

    /// <summary>
    /// Entrega e descarta o que já está no buffer. Usado ao trocar para túnel
    /// cru (WebSocket): esses bytes já são do novo protocolo.
    /// </summary>
    public async Task FlushBufferedAsync(Stream destination, CancellationToken cancellationToken)
    {
        if (Buffered > 0)
        {
            await destination.WriteAsync(_buffer.AsMemory(_start, Buffered), cancellationToken).ConfigureAwait(false);
            _start = _end = 0;
        }
    }

    private async Task<long> ReadFixedAsync(
        long length, Func<ReadOnlyMemory<byte>, CancellationToken, ValueTask> onData, CancellationToken cancellationToken)
    {
        long remaining = length;

        while (remaining > 0)
        {
            if (Buffered == 0 && !await FillAsync(cancellationToken).ConfigureAwait(false))
            {
                throw new HttpMessageException("A conexão fechou no meio do corpo.");
            }

            int take = (int)Math.Min(remaining, Buffered);
            await onData(_buffer.AsMemory(_start, take), cancellationToken).ConfigureAwait(false);
            _start += take;
            remaining -= take;
        }

        return length;
    }

    private async Task<long> ReadChunkedAsync(
        Func<ReadOnlyMemory<byte>, CancellationToken, ValueTask> onData, CancellationToken cancellationToken)
    {
        long total = 0;

        while (true)
        {
            string sizeLine = await ReadLineAsync(cancellationToken).ConfigureAwait(false)
                ?? throw new HttpMessageException("A conexão fechou no meio do corpo em pedaços.");

            // "1a3f;extensão=valor": as extensões são ignoradas.
            string hex = sizeLine.Split(';', 2)[0].Trim();

            if (!long.TryParse(hex, NumberStyles.AllowHexSpecifier, CultureInfo.InvariantCulture, out long size) || size < 0)
            {
                throw new HttpMessageException($"Tamanho de pedaço inválido: {Truncate(sizeLine)}");
            }

            if (size == 0)
            {
                // Trailers (raros) até a linha em branco; são descartados.
                while (!string.IsNullOrEmpty(await ReadLineAsync(cancellationToken).ConfigureAwait(false)))
                {
                }

                return total;
            }

            total += await ReadFixedAsync(size, onData, cancellationToken).ConfigureAwait(false);

            if (await ReadLineAsync(cancellationToken).ConfigureAwait(false) != string.Empty)
            {
                throw new HttpMessageException("Pedaço sem a quebra de linha final.");
            }
        }
    }

    private async Task<long> ReadUntilCloseAsync(
        Func<ReadOnlyMemory<byte>, CancellationToken, ValueTask> onData, CancellationToken cancellationToken)
    {
        long total = 0;

        while (Buffered > 0 || await FillAsync(cancellationToken).ConfigureAwait(false))
        {
            int take = Buffered;
            await onData(_buffer.AsMemory(_start, take), cancellationToken).ConfigureAwait(false);
            _start += take;
            total += take;
        }

        return total;
    }

    /// <summary>
    /// Lê linhas até a linha em branco. Devolve nulo se a conexão fechar sem
    /// nenhum byte (fim normal de keep-alive).
    /// </summary>
    private async Task<string[]?> ReadHeadLinesAsync(CancellationToken cancellationToken)
    {
        var lines = new List<string>();
        int consumed = 0;

        while (true)
        {
            string? line = await ReadLineAsync(cancellationToken).ConfigureAwait(false);

            if (line is null)
            {
                if (lines.Count == 0 && consumed == 0)
                {
                    return null;
                }

                throw new HttpMessageException("A conexão fechou no meio dos cabeçalhos.");
            }

            consumed += line.Length + 2;

            if (consumed > MaxHeadBytes)
            {
                throw new HttpMessageException("Cabeçalhos maiores que o limite.");
            }

            if (line.Length == 0)
            {
                // Linhas em branco antes da primeira linha são toleradas (RFC 9112, 2.2).
                if (lines.Count == 0)
                {
                    continue;
                }

                return [.. lines];
            }

            lines.Add(line);
        }
    }

    private static HttpHeaders ParseHeaders(string[] lines)
    {
        var headers = new HttpHeaders();

        for (int i = 1; i < lines.Length; i++)
        {
            int colon = lines[i].IndexOf(':');

            // Sem dois-pontos, ou com espaço antes deles, é cabeçalho malformado
            // (e outro vetor de request smuggling). Recusar é mais seguro que adivinhar.
            if (colon <= 0 || char.IsWhiteSpace(lines[i][colon - 1]))
            {
                throw new HttpMessageException($"Cabeçalho inválido: {Truncate(lines[i])}");
            }

            headers.Add(lines[i][..colon], lines[i][(colon + 1)..].Trim());
        }

        return headers;
    }

    /// <summary>Lê até CRLF (aceita LF sozinho). Nulo se a conexão fechar antes de qualquer byte da linha.</summary>
    private async Task<string?> ReadLineAsync(CancellationToken cancellationToken)
    {
        StringBuilder? partial = null;

        while (true)
        {
            int newline = Array.IndexOf(_buffer, (byte)'\n', _start, Buffered);

            if (newline >= 0)
            {
                int length = newline - _start;
                string piece = Encoding.Latin1.GetString(_buffer, _start, length);
                _start = newline + 1;

                string line = partial is null ? piece : partial.Append(piece).ToString();
                return line.EndsWith('\r') ? line[..^1] : line;
            }

            if (Buffered > 0)
            {
                partial ??= new StringBuilder();
                partial.Append(Encoding.Latin1.GetString(_buffer, _start, Buffered));
                _start = _end;

                if (partial.Length > MaxHeadBytes)
                {
                    throw new HttpMessageException("Linha maior que o limite.");
                }
            }

            if (!await FillAsync(cancellationToken).ConfigureAwait(false))
            {
                if (partial is null)
                {
                    return null;
                }

                throw new HttpMessageException("A conexão fechou no meio de uma linha.");
            }
        }
    }

    /// <summary>Lê mais bytes da rede. Falso quando a conexão fechou.</summary>
    private async Task<bool> FillAsync(CancellationToken cancellationToken)
    {
        if (_start == _end)
        {
            _start = _end = 0;
        }
        else if (_start > 0)
        {
            Buffer.BlockCopy(_buffer, _start, _buffer, 0, Buffered);
            _end -= _start;
            _start = 0;
        }

        int read = await _stream.ReadAsync(_buffer.AsMemory(_end), cancellationToken).ConfigureAwait(false);
        _end += read;
        return read > 0;
    }

    private static string Truncate(string text) => text.Length <= 120 ? text : text[..120] + "...";
}
