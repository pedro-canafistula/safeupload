using System.Text.Json;
using SafeUpload.Agent.Core.Contracts;
using SafeUpload.Agent.Core.Domain;

namespace SafeUpload.Agent.Tests;

/// <summary>
/// O protocolo NDJSON entre o serviço e o aplicativo de bandeja.
///
/// São dois processos que sobem separados e podem ser atualizados em momentos
/// diferentes, então a forma da mensagem é contrato de verdade: um campo
/// renomeado de um lado só aparece como falha em produção. Estes testes fixam
/// a forma.
/// </summary>
public class NotificationProtocolTests
{
    private static IReadOnlyList<Finding> SampleFindings() =>
        [new Finding(Category.Cpf, "•••••••••25")];

    private static AuditEvent SampleEvent() => new(
        Guid.Parse("11111111-2222-3333-4444-555555555555"),
        new DateTimeOffset(2026, 9, 3, 12, 0, 0, TimeSpan.Zero),
        "PC-TESTE",
        "usuario.teste",
        "cadastro.txt",
        ".txt",
        1024,
        Verdict.Blocked,
        [Category.Cpf],
        ["•••••••••25"],
        "explorer.exe",
        4242,
        @"C:\SafeUpload\Escopo Monitorado",
        null,
        7,
        12,
        false);

    [Fact]
    public void Status_leva_o_discriminador_na_raiz()
    {
        var linha = NotificationProtocol.Serialize(new StatusNotification(7, 4, true));

        using var documento = JsonDocument.Parse(linha);

        Assert.Equal("status", documento.RootElement.GetProperty("type").GetString());
        Assert.Equal(7, documento.RootElement.GetProperty("policyVersion").GetInt32());
        Assert.Equal(4, documento.RootElement.GetProperty("activeCategories").GetInt32());
        Assert.True(documento.RootElement.GetProperty("protectionActive").GetBoolean());
    }

    [Fact]
    public void Evento_leva_o_discriminador_na_raiz_e_a_auditoria_aninhada()
    {
        var linha = NotificationProtocol.Serialize(new EventNotification(SampleEvent(), SampleFindings()));

        using var documento = JsonDocument.Parse(linha);
        var raiz = documento.RootElement;

        Assert.Equal("event", raiz.GetProperty("type").GetString());
        Assert.Equal("cadastro.txt", raiz.GetProperty("event").GetProperty("fileName").GetString());
        Assert.Equal("Blocked", raiz.GetProperty("event").GetProperty("verdict").GetString());
    }

    /// <summary>
    /// Cada mensagem ocupa exatamente uma linha e termina em quebra de linha —
    /// é o enquadramento do NDJSON. Sem isso o leitor do outro lado juntaria
    /// duas mensagens numa só.
    /// </summary>
    [Fact]
    public void Mensagem_ocupa_uma_linha_e_termina_em_quebra()
    {
        var linha = NotificationProtocol.Serialize(new EventNotification(SampleEvent(), SampleFindings()));

        Assert.EndsWith("\n", linha, StringComparison.Ordinal);
        Assert.Single(linha.TrimEnd('\n').Split('\n'));
    }

    [Fact]
    public void Status_sobrevive_ao_percurso_completo()
    {
        var original = new StatusNotification(9, 2, ProtectionActive: false);
        var lido = NotificationProtocol.Deserialize(NotificationProtocol.Serialize(original).TrimEnd('\n'));

        var status = Assert.IsType<StatusNotification>(lido);
        Assert.Equal(original, status);
    }

    /// <summary>
    /// Todo campo da HU-04 precisa atravessar o canal intacto.
    ///
    /// A comparação é campo a campo, e não pela igualdade do record: os dois
    /// campos de coleção do <see cref="AuditEvent"/> são
    /// <c>IReadOnlyList</c>, que compara por referência, então dois eventos com
    /// exatamente o mesmo conteúdo saem desiguais. Comparar o record inteiro
    /// daria um teste que falha sem que nada esteja errado.
    /// </summary>
    [Fact]
    public void Evento_sobrevive_ao_percurso_completo()
    {
        var original = SampleEvent();
        var lido = NotificationProtocol.Deserialize(
            NotificationProtocol.Serialize(new EventNotification(original, SampleFindings())).TrimEnd('\n'));

        var evento = Assert.IsType<EventNotification>(lido).Event;

        Assert.Equal(original.EventId, evento.EventId);
        Assert.Equal(original.OccurredAtUtc, evento.OccurredAtUtc);
        Assert.Equal(original.EndpointId, evento.EndpointId);
        Assert.Equal(original.UserName, evento.UserName);
        Assert.Equal(original.FileName, evento.FileName);
        Assert.Equal(original.Extension, evento.Extension);
        Assert.Equal(original.SizeBytes, evento.SizeBytes);
        Assert.Equal(original.Verdict, evento.Verdict);
        Assert.Equal(original.Categories, evento.Categories);
        Assert.Equal(original.MaskedSnippets, evento.MaskedSnippets);
        Assert.Equal(original.ProcessName, evento.ProcessName);
        Assert.Equal(original.ProcessId, evento.ProcessId);
        Assert.Equal(original.DestinationPath, evento.DestinationPath);
        Assert.Equal(original.NotInspectedReason, evento.NotInspectedReason);
        Assert.Equal(original.PolicyVersion, evento.PolicyVersion);
        Assert.Equal(original.ElapsedMs, evento.ElapsedMs);
        Assert.Equal(original.Dispatched, evento.Dispatched);

        Assert.Equal("•••••••••25", Assert.Single(evento.MaskedSnippets));
    }

    /// <summary>
    /// Os achados atravessam o canal com o par categoria/trecho preservado.
    ///
    /// É o motivo de eles irem no contrato em vez de serem recompostos do outro
    /// lado: o evento de auditoria guarda categorias e trechos como duas listas
    /// distintas, e um arquivo com dois CPFs diferentes registra uma categoria e
    /// dois trechos. Quem casasse por posição mostraria a categoria errada
    /// justamente no caso de mais de um achado.
    /// </summary>
    [Fact]
    public void Achados_preservam_o_par_categoria_e_trecho()
    {
        IReadOnlyList<Finding> achados =
        [
            new Finding(Category.Cpf, "•••••••••25"),
            new Finding(Category.Cpf, "•••••••••35"),
            new Finding(Category.Password, "senha: ••••••••")
        ];

        var lido = NotificationProtocol.Deserialize(
            NotificationProtocol.Serialize(new EventNotification(SampleEvent(), achados)).TrimEnd('\n'));

        var recebidos = Assert.IsType<EventNotification>(lido).Findings;

        Assert.Equal(3, recebidos.Count);
        Assert.Equal(achados[0], recebidos[0]);
        Assert.Equal(achados[1], recebidos[1]);
        Assert.Equal(achados[2], recebidos[2]);

        // Duas categorias iguais com trechos diferentes continuam distinguiveis
        // do outro lado, que e exatamente o caso que a posicao quebraria.
        Assert.Equal(Category.Cpf, recebidos[1].Category);
        Assert.Equal("•••••••••35", recebidos[1].MaskedSnippet);
    }

    /// <summary>
    /// O que trafega no canal é o mesmo que vai para o log: metadados e trechos
    /// já mascarados. Não existe campo capaz de carregar conteúdo, e é isso que
    /// permite tratar o pipe como um canal de notificação e não como um canal
    /// de dados.
    /// </summary>
    [Fact]
    public void Mensagem_nao_carrega_valor_original()
    {
        var linha = NotificationProtocol.Serialize(new EventNotification(SampleEvent(), SampleFindings()));

        Assert.DoesNotContain("52998224725", linha, StringComparison.Ordinal);
        Assert.DoesNotContain("529.982.247-25", linha, StringComparison.Ordinal);
    }

    /// <summary>
    /// Linha malformada devolve nulo em vez de lançar. Uma mensagem perdida é
    /// aceitável; perder a conexão e ficar sem todas as seguintes não é.
    /// </summary>
    [Theory]
    [InlineData("")]
    [InlineData("   ")]
    [InlineData("{\"type\":\"status\"")]
    [InlineData("nao e json")]
    public void Linha_invalida_devolve_nulo(string linha) =>
        Assert.Null(NotificationProtocol.Deserialize(linha));

    /// <summary>
    /// Tipo desconhecido também não pode derrubar o cliente: um serviço mais
    /// novo pode enviar uma mensagem que esta versão do aplicativo ainda não
    /// entende.
    /// </summary>
    [Fact]
    public void Tipo_desconhecido_devolve_nulo() =>
        Assert.Null(NotificationProtocol.Deserialize("{\"type\":\"telemetria\",\"x\":1}"));

    [Fact]
    public void Nome_do_pipe_e_estavel() =>
        Assert.Equal("SafeUpload.Agent", NotificationProtocol.PipeName);
}
