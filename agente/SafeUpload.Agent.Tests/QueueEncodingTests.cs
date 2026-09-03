using System.Text;
using System.Text.Json;
using SafeUpload.Agent.Core.Domain;
using SafeUpload.Agent.Core.Infrastructure;

namespace SafeUpload.Agent.Tests;

/// <summary>
/// O queue.jsonl precisa ser JSON Lines que qualquer consumidor leia, e não
/// apenas o leitor deste projeto.
/// </summary>
public class QueueEncodingTests : IDisposable
{
    private readonly TestWorkspace _workspace = new();

    /// <inheritdoc />
    public void Dispose() => _workspace.Dispose();

    private static AuditEvent Sample(string fileName) => new(
        Guid.NewGuid(),
        DateTimeOffset.UtcNow,
        "PC-TESTE",
        "usuario.teste",
        fileName,
        ".txt",
        1024,
        Verdict.Blocked,
        [Category.Cpf],
        ["•••••••••25"],
        "explorer.exe",
        4242,
        @"E:\pendrive",
        null,
        1,
        12,
        false);

    /// <summary>
    /// A regressão: Encoding.UTF8 escreve a marca EF BB BF ao criar o arquivo,
    /// e ela ficava colada no início da primeira linha. O leitor deste projeto
    /// a tolerava, mas um consumidor estrito não — foi assim que o defeito
    /// apareceu, com o json do Python recusando a primeira linha de um
    /// queue.jsonl gerado pela aplicação rodando.
    /// </summary>
    [Fact]
    public async Task Fila_e_gravada_sem_marca_de_ordem_de_bytes()
    {
        var sink = new LocalQueueAuditSink(_workspace.QueueFile);
        await sink.WriteAsync(Sample("cadastro.txt"), CancellationToken.None);

        var bytes = await File.ReadAllBytesAsync(_workspace.QueueFile, CancellationToken.None);

        Assert.True(bytes.Length >= 3);
        Assert.False(
            bytes[0] == 0xEF && bytes[1] == 0xBB && bytes[2] == 0xBF,
            "o queue.jsonl começou com BOM; um leitor estrito de JSON recusaria a primeira linha");
        Assert.Equal((byte)'{', bytes[0]);
    }

    /// <summary>
    /// Toda linha, e não só a primeira, precisa ser um documento JSON válido
    /// lido isoladamente — é assim que o despachante da HU-10 vai consumi-las.
    /// </summary>
    [Fact]
    public async Task Cada_linha_e_um_json_valido_isoladamente()
    {
        var sink = new LocalQueueAuditSink(_workspace.QueueFile);
        await sink.WriteAsync(Sample("primeiro.txt"), CancellationToken.None);
        await sink.WriteAsync(Sample("segundo.txt"), CancellationToken.None);

        var texto = await File.ReadAllTextAsync(_workspace.QueueFile, new UTF8Encoding(false), CancellationToken.None);

        foreach (var linha in texto.Split('\n', StringSplitOptions.RemoveEmptyEntries))
        {
            using var documento = JsonDocument.Parse(linha.Trim());
            Assert.True(documento.RootElement.TryGetProperty("eventId", out _));
        }
    }

    /// <summary>
    /// A reescrita feita ao marcar eventos como despachados também não pode
    /// reintroduzir a marca.
    /// </summary>
    [Fact]
    public async Task Reescrita_ao_despachar_tambem_nao_reintroduz_a_marca()
    {
        var sink = new LocalQueueAuditSink(_workspace.QueueFile);
        var evento = Sample("cadastro.txt");

        await sink.WriteAsync(evento, CancellationToken.None);
        await sink.MarkDispatchedAsync([evento.EventId], CancellationToken.None);

        var bytes = await File.ReadAllBytesAsync(_workspace.QueueFile, CancellationToken.None);

        Assert.Equal((byte)'{', bytes[0]);
    }

    /// <summary>
    /// Acentuação e os marcadores do mascaramento precisam sobreviver ao
    /// percurso completo de gravação e leitura.
    /// </summary>
    [Fact]
    public async Task Acentos_e_marcadores_sobrevivem_ao_percurso()
    {
        var sink = new LocalQueueAuditSink(_workspace.QueueFile);
        await sink.WriteAsync(Sample("relatório-anual.txt"), CancellationToken.None);

        var lido = Assert.Single(await sink.ReadRecentAsync(10, CancellationToken.None));

        Assert.Equal("relatório-anual.txt", lido.FileName);
        Assert.Equal("•••••••••25", Assert.Single(lido.MaskedSnippets));
    }
}
