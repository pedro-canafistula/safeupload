using System.IO.Compression;
using System.Text;
using SafeUpload.Agent.Network.Http;
using SafeUpload.Agent.Network.Inspection;

namespace SafeUpload.Agent.Tests;

/// <summary>
/// O desmonte do corpo de uma requisição em partes (Fase 5 da inspeção TLS).
/// Os formatos são os que o estudo da Fase 0 encontrou em sites reais.
/// </summary>
public sealed class UploadBodyParserTests
{
    private const string Cpf = "529.982.247-25";

    private static IReadOnlyList<UploadPart> Parse(string? contentType, byte[] body, params (string Name, string Value)[] headers)
    {
        var fields = new HttpHeaders();

        if (contentType is not null)
        {
            fields.Add("Content-Type", contentType);
        }

        foreach ((string name, string value) in headers)
        {
            fields.Add(name, value);
        }

        return UploadBodyParser.Parse(new HttpRequestHead("POST", "/upload", "HTTP/1.1", fields), body);
    }

    private static string TextOf(UploadPart part) => Encoding.UTF8.GetString(part.Content.Span);

    [Fact]
    public void Formulario_multipart_separa_arquivo_e_campo_de_texto()
    {
        byte[] body = Encoding.UTF8.GetBytes(
            "--XyZ\r\n"
            + "Content-Disposition: form-data; name=\"observacao\"\r\n\r\n"
            + $"cliente {Cpf}\r\n"
            + "--XyZ\r\n"
            + "Content-Disposition: form-data; name=\"arquivo\"; filename=\"folha; maio.csv\"\r\n"
            + "Content-Type: text/csv\r\n\r\n"
            + "nome;cpf\r\nAna;1\r\n"
            + "--XyZ--\r\n");

        IReadOnlyList<UploadPart> parts = Parse("multipart/form-data; boundary=XyZ", body);

        Assert.Equal(2, parts.Count);
        Assert.Equal(UploadPartKind.Text, parts[0].Kind);
        Assert.Equal($"cliente {Cpf}", TextOf(parts[0]));
        Assert.Equal(UploadPartKind.File, parts[1].Kind);
        Assert.Equal("folha; maio.csv", parts[1].FileName);
        Assert.Equal("nome;cpf\r\nAna;1", TextOf(parts[1]));
    }

    /// <summary>
    /// O formato do Google Drive para arquivo pequeno: metadados em JSON e o
    /// arquivo em base64. Sem decodificar, o CPF não aparece no corpo.
    /// </summary>
    [Fact]
    public void Multipart_related_com_arquivo_em_base64_e_decodificado()
    {
        byte[] pdf = [.. "%PDF-1.7\n"u8, .. Encoding.UTF8.GetBytes(Cpf)];
        string base64 = Convert.ToBase64String(pdf, Base64FormattingOptions.InsertLineBreaks);

        byte[] body = Encoding.UTF8.GetBytes(
            "--lim\r\n"
            + "Content-Type: application/json; charset=UTF-8\r\n\r\n"
            + "{\"title\":\"relat\\u00f3rio.pdf\"}\r\n"
            + "--lim\r\n"
            + "Content-Type: application/pdf\r\n"
            + "Content-Transfer-Encoding: base64\r\n\r\n"
            + base64 + "\r\n"
            + "--lim--");

        Assert.DoesNotContain(Cpf, Encoding.UTF8.GetString(body));

        IReadOnlyList<UploadPart> parts = Parse("multipart/related; boundary=\"lim\"", body);

        Assert.Equal(2, parts.Count);
        Assert.Equal(UploadPartKind.Text, parts[0].Kind);
        Assert.Contains("relatório.pdf", TextOf(parts[0]));
        Assert.Equal(UploadPartKind.File, parts[1].Kind);
        Assert.Equal(pdf, parts[1].Content.ToArray());
    }

    [Fact]
    public void Json_vira_texto_sem_as_barras_de_escape()
    {
        byte[] body = Encoding.UTF8.GetBytes("{\"messages\":[{\"content\":\"meu cpf \\u00e9 " + Cpf + "\"}],\"n\":52998224725}");

        UploadPart part = Assert.Single(Parse("application/json", body));

        Assert.Equal(UploadPartKind.Text, part.Kind);
        Assert.Contains($"meu cpf é {Cpf}", TextOf(part));
        Assert.Contains("52998224725", TextOf(part));
    }

    [Fact]
    public void Json_invalido_segue_como_texto_cru()
    {
        byte[] body = Encoding.UTF8.GetBytes("{\"cpf\": \"" + Cpf);

        UploadPart part = Assert.Single(Parse("application/json", body));

        Assert.Equal(UploadPartKind.Text, part.Kind);
        Assert.Contains(Cpf, TextOf(part));
    }

    [Fact]
    public void Formulario_simples_e_decodificado()
    {
        byte[] body = Encoding.UTF8.GetBytes("nome=Ana+Silva&cpf=529%2E982%2E247-25");

        UploadPart part = Assert.Single(Parse("application/x-www-form-urlencoded", body));

        Assert.Equal(UploadPartKind.Text, part.Kind);
        Assert.Equal($"nome=Ana Silva\ncpf={Cpf}", TextOf(part));
    }

    /// <summary>
    /// O Drive envia o arquivo inteiro num PUT que se declara formulário. O
    /// tipo declarado não manda: o conteúdo tem assinatura de PDF.
    /// </summary>
    [Fact]
    public void Arquivo_declarado_como_formulario_e_tratado_como_arquivo()
    {
        byte[] pdf = [.. "%PDF-1.7\n"u8, .. new byte[64]];

        UploadPart part = Assert.Single(Parse(
            "application/x-www-form-urlencoded;charset=utf-8", pdf, ("X-Goog-Upload-File-Name", "contrato.pdf")));

        Assert.Equal(UploadPartKind.File, part.Kind);
        Assert.Equal("contrato.pdf", part.FileName);
        Assert.Equal(pdf, part.Content.ToArray());
    }

    [Fact]
    public void Corpo_bruto_sem_tipo_de_texto_e_arquivo()
    {
        UploadPart part = Assert.Single(Parse("application/octet-stream", Encoding.UTF8.GetBytes($"linha 1\nCPF {Cpf}\n")));

        Assert.Equal(UploadPartKind.File, part.Kind);
        Assert.Null(part.FileName);
    }

    [Fact]
    public void Corpo_comprimido_e_aberto()
    {
        using var compressed = new MemoryStream();

        using (var gzip = new GZipStream(compressed, CompressionLevel.Fastest, leaveOpen: true))
        {
            gzip.Write(Encoding.UTF8.GetBytes($"{{\"cpf\":\"{Cpf}\"}}"));
        }

        UploadPart part = Assert.Single(Parse("application/json", compressed.ToArray(), ("Content-Encoding", "gzip")));

        Assert.Contains(Cpf, TextOf(part));
    }

    [Fact]
    public void Nome_de_arquivo_com_acento_na_forma_estendida()
    {
        byte[] body = Encoding.UTF8.GetBytes(
            "--b\r\nContent-Disposition: form-data; name=\"f\"; filename=\"x\"; filename*=UTF-8''relat%C3%B3rio.txt\r\n\r\nconteudo\r\n--b--");

        UploadPart part = Assert.Single(Parse("multipart/form-data; boundary=b", body));

        Assert.Equal("relatório.txt", part.FileName);
    }

    [Theory]
    [InlineData("multipart/form-data; boundary=b", "--b\r\nsem linha em branco")]
    [InlineData("multipart/form-data; boundary=b", "nenhuma fronteira aqui")]
    [InlineData("multipart/form-data", "--b\r\n\r\nsem boundary declarado\r\n--b--")]
    [InlineData("application/x-www-form-urlencoded", "%zz=%")]
    [InlineData("text/plain", "")]
    public void Corpo_malformado_nao_lanca(string contentType, string body)
    {
        IReadOnlyList<UploadPart> parts = Parse(contentType, Encoding.UTF8.GetBytes(body));

        Assert.True(parts.Count <= 1);
    }
}
