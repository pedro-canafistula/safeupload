using System.Text;
using SafeUpload.Agent.Network.Http;

namespace SafeUpload.Agent.Tests;

/// <summary>
/// Parser HTTP/1.1 do proxy de inspeção (Fase 2).
/// </summary>
public class HttpStreamReaderTests
{
    private static HttpStreamReader Reader(string raw) =>
        new(new MemoryStream(Encoding.Latin1.GetBytes(raw)));

    private static async Task<(long Total, string Body)> ReadBodyAsync(HttpStreamReader reader, BodyFraming framing, long? length)
    {
        var body = new MemoryStream();
        long total = await reader.ReadBodyAsync(framing, length, (data, _) =>
        {
            body.Write(data.Span);
            return ValueTask.CompletedTask;
        }, CancellationToken.None);
        return (total, Encoding.Latin1.GetString(body.ToArray()));
    }

    [Fact]
    public async Task Le_requisicao_com_Content_Length()
    {
        var reader = Reader("POST /upload?x=1 HTTP/1.1\r\nHost: drive.google.com\r\nContent-Length: 5\r\n\r\nolá!!");

        HttpRequestHead head = (await reader.ReadRequestHeadAsync(CancellationToken.None))!;

        Assert.Equal("POST", head.Method);
        Assert.Equal("/upload?x=1", head.Target);
        Assert.Equal("drive.google.com", head.Headers.Get("host"));
        Assert.Equal(BodyFraming.ContentLength, head.Framing);
        Assert.Equal(5, head.ContentLength);

        var (total, _) = await ReadBodyAsync(reader, head.Framing, head.ContentLength);
        Assert.Equal(5, total);
    }

    /// <summary>
    /// Corpo em pedaços: o leitor entrega só os dados, sem a moldura, que é o
    /// que a inspeção precisa ver.
    /// </summary>
    [Fact]
    public async Task Decodifica_corpo_em_pedacos()
    {
        var reader = Reader(
            "POST / HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n" +
            "4\r\nCPF \r\n" +
            "e;ext=1\r\n529.982.247-25\r\n" +
            "0\r\nTrailer: x\r\n\r\n");

        HttpRequestHead head = (await reader.ReadRequestHeadAsync(CancellationToken.None))!;
        Assert.Equal(BodyFraming.Chunked, head.Framing);

        var (total, body) = await ReadBodyAsync(reader, head.Framing, null);
        Assert.Equal("CPF 529.982.247-25", body);
        Assert.Equal(18, total);
    }

    /// <summary>
    /// Keep-alive: duas requisições seguidas no mesmo fluxo. O que sobra da
    /// leitura da primeira é o começo da segunda.
    /// </summary>
    [Fact]
    public async Task Le_duas_requisicoes_seguidas_na_mesma_conexao()
    {
        var reader = Reader(
            "POST /a HTTP/1.1\r\nContent-Length: 3\r\n\r\nabc" +
            "GET /b HTTP/1.1\r\nHost: x\r\n\r\n");

        HttpRequestHead first = (await reader.ReadRequestHeadAsync(CancellationToken.None))!;
        await ReadBodyAsync(reader, first.Framing, first.ContentLength);
        HttpRequestHead second = (await reader.ReadRequestHeadAsync(CancellationToken.None))!;

        Assert.Equal("/b", second.Target);
        Assert.Equal(BodyFraming.None, second.Framing);
        Assert.Null(await reader.ReadRequestHeadAsync(CancellationToken.None));
    }

    [Fact]
    public async Task Conexao_fechada_antes_de_tudo_devolve_nulo()
    {
        Assert.Null(await Reader(string.Empty).ReadRequestHeadAsync(CancellationToken.None));
    }

    /// <summary>
    /// Transfer-Encoding e Content-Length juntos: vale o chunked. É a regra
    /// da RFC e a defesa contra "request smuggling".
    /// </summary>
    [Fact]
    public async Task Chunked_vence_Content_Length()
    {
        var reader = Reader("POST / HTTP/1.1\r\nContent-Length: 999\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n");

        HttpRequestHead head = (await reader.ReadRequestHeadAsync(CancellationToken.None))!;

        Assert.Equal(BodyFraming.Chunked, head.Framing);
    }

    [Theory]
    [InlineData("GET / HTTP/1.1\r\nHost : x\r\n\r\n")]
    [InlineData("GET / HTTP/1.1\r\nsem-dois-pontos\r\n\r\n")]
    [InlineData("GET /\r\n\r\n")]
    [InlineData("POST / HTTP/1.1\r\nContent-Length: -1\r\n\r\n")]
    public async Task Recusa_mensagens_malformadas(string raw)
    {
        await Assert.ThrowsAsync<HttpMessageException>(async () =>
        {
            HttpRequestHead head = (await Reader(raw).ReadRequestHeadAsync(CancellationToken.None))!;
            _ = head.Framing;
        });
    }

    [Fact]
    public async Task Recusa_cabecalhos_acima_do_limite()
    {
        string huge = "GET / HTTP/1.1\r\nX: " + new string('a', HttpStreamReader.MaxHeadBytes) + "\r\n\r\n";

        await Assert.ThrowsAsync<HttpMessageException>(() => Reader(huge).ReadRequestHeadAsync(CancellationToken.None));
    }

    [Fact]
    public async Task Resposta_a_HEAD_e_204_nao_tem_corpo_mesmo_com_tamanho()
    {
        var head = new HttpRequestHead("HEAD", "/", "HTTP/1.1", new HttpHeaders());
        var get = new HttpRequestHead("GET", "/", "HTTP/1.1", new HttpHeaders());

        HttpResponseHead ok = (await Reader("HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\n").ReadResponseHeadAsync(CancellationToken.None));
        HttpResponseHead noContent = (await Reader("HTTP/1.1 204 No Content\r\n\r\n").ReadResponseHeadAsync(CancellationToken.None));
        HttpResponseHead untilClose = (await Reader("HTTP/1.0 200 OK\r\n\r\n").ReadResponseHeadAsync(CancellationToken.None));

        Assert.Equal(BodyFraming.None, ok.FramingFor(head));
        Assert.Equal(BodyFraming.ContentLength, ok.FramingFor(get));
        Assert.Equal(BodyFraming.None, noContent.FramingFor(get));
        Assert.Equal(BodyFraming.UntilClose, untilClose.FramingFor(get));
        Assert.True(untilClose.WantsClose);
    }

    [Fact]
    public void Cabecalhos_preservam_ordem_e_buscam_sem_diferenciar_maiusculas()
    {
        var headers = new HttpHeaders();
        headers.Add("Host", "a");
        headers.Add("Connection", "keep-alive, Upgrade");
        headers.Add("X-Custom", "1");

        Assert.True(headers.HasToken("connection", "upgrade"));
        Assert.Equal("Host: a\r\nConnection: keep-alive, Upgrade\r\nX-Custom: 1\r\n\r\n",
            Encoding.Latin1.GetString(new HttpRequestHead("GET", "/", "HTTP/1.1", headers).Serialize()).Split("\r\n", 2)[1]);
    }
}
