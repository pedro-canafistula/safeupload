using SafeUpload.Agent.Core.Contracts;
using SafeUpload.Agent.Core.Domain;
using SafeUpload.Agent.Service.Notifications;

namespace SafeUpload.Agent.Tests;

/// <summary>
/// O ponto de encontro entre quem decide e quem mostra.
///
/// A propriedade que estes testes protegem é uma só: <b>publicar nunca
/// bloqueia</b>. O veredito já foi dado e o arquivo já foi movido quando a
/// notificação sai; se a entrega entrasse no caminho da decisão, um aplicativo
/// travado seguraria a inspeção do próximo arquivo.
/// </summary>
public class NotificationHubTests
{
    private static IReadOnlyList<Finding> Achados() =>
        [new Finding(Category.Cpf, "•••••••••25")];

    private static AuditEvent Evento(string fileName) => new(
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
        "desconhecido",
        0,
        @"C:\SafeUpload\Escopo Monitorado",
        null,
        1,
        3,
        false);

    [Fact]
    public void Sem_assinante_publicar_nao_lanca()
    {
        var hub = new NotificationHub();

        hub.Publish(new StatusNotification(1, 4, true));
        hub.Publish(new EventNotification(Evento("a.txt"), Achados()));
    }

    [Fact]
    public async Task Assinante_recebe_o_que_foi_publicado()
    {
        var hub = new NotificationHub();
        using var assinatura = hub.Subscribe();

        hub.Publish(new EventNotification(Evento("cadastro.txt"), Achados()));

        var recebido = await assinatura.Reader.ReadAsync(TestTimeout());

        var evento = Assert.IsType<EventNotification>(recebido);
        Assert.Equal("cadastro.txt", evento.Event.FileName);
    }

    [Fact]
    public async Task Todos_os_assinantes_recebem()
    {
        var hub = new NotificationHub();
        using var primeiro = hub.Subscribe();
        using var segundo = hub.Subscribe();

        hub.Publish(new EventNotification(Evento("cadastro.txt"), Achados()));

        Assert.IsType<EventNotification>(await primeiro.Reader.ReadAsync(TestTimeout()));
        Assert.IsType<EventNotification>(await segundo.Reader.ReadAsync(TestTimeout()));
    }

    /// <summary>
    /// O último estado fica retido para ser entregue a quem conectar depois.
    /// Sem isso, um aplicativo aberto após o serviço ficaria sem saber a versão
    /// da política até a próxima mudança — que pode não vir nunca.
    /// </summary>
    [Fact]
    public void Estado_atual_e_retido_para_quem_conectar_depois()
    {
        var hub = new NotificationHub();

        Assert.Null(hub.CurrentStatus);

        hub.Publish(new StatusNotification(7, 3, true));

        var status = Assert.IsType<StatusNotification>(hub.CurrentStatus);
        Assert.Equal(7, status.PolicyVersion);
        Assert.Equal(3, status.ActiveCategories);
        Assert.True(status.ProtectionActive);
    }

    [Fact]
    public void Estado_retido_e_sempre_o_mais_recente()
    {
        var hub = new NotificationHub();

        hub.Publish(new StatusNotification(1, 4, true));
        hub.Publish(new StatusNotification(2, 1, false));

        var status = Assert.IsType<StatusNotification>(hub.CurrentStatus);
        Assert.Equal(2, status.PolicyVersion);
        Assert.False(status.ProtectionActive);
    }

    /// <summary>
    /// Evento não vira estado retido: só o status é lembrado.
    /// </summary>
    [Fact]
    public void Evento_nao_substitui_o_estado_retido()
    {
        var hub = new NotificationHub();

        hub.Publish(new StatusNotification(5, 2, true));
        hub.Publish(new EventNotification(Evento("a.txt"), Achados()));

        Assert.Equal(5, Assert.IsType<StatusNotification>(hub.CurrentStatus).PolicyVersion);
    }

    /// <summary>
    /// A propriedade central: um assinante que parou de ler não segura quem
    /// publica.
    ///
    /// Muito mais mensagens do que cabem na fila são publicadas sem ninguém
    /// consumir. Se a fila fosse de espera, esta chamada travaria e o teste
    /// nunca terminaria; com descarte do mais antigo, ela retorna e as
    /// mensagens recentes sobrevivem.
    /// </summary>
    [Fact]
    public async Task Assinante_que_nao_le_nao_bloqueia_quem_publica()
    {
        var hub = new NotificationHub();
        using var assinatura = hub.Subscribe();

        for (var i = 0; i < 5_000; i++)
        {
            hub.Publish(new EventNotification(Evento($"arquivo-{i}.txt"), Achados()));
        }

        // A fila tem capacidade finita, então só as últimas sobraram — e a
        // última publicada precisa ser uma delas.
        var recebidas = new List<string>();

        while (assinatura.Reader.TryRead(out var notificacao))
        {
            recebidas.Add(((EventNotification)notificacao).Event.FileName);
        }

        Assert.NotEmpty(recebidas);
        Assert.True(recebidas.Count < 5_000, "a fila precisa ser limitada");
        Assert.Equal("arquivo-4999.txt", recebidas[^1]);

        await Task.CompletedTask;
    }

    /// <summary>
    /// Assinatura descartada para de receber, e o hub deixa de guardar a fila
    /// dela — senão o serviço acumularia filas de aplicativos já encerrados.
    /// </summary>
    [Fact]
    public void Assinatura_descartada_para_de_receber()
    {
        var hub = new NotificationHub();
        var assinatura = hub.Subscribe();

        assinatura.Dispose();
        hub.Publish(new EventNotification(Evento("depois.txt"), Achados()));

        Assert.False(assinatura.Reader.TryRead(out _));
    }

    [Fact]
    public void Descartar_duas_vezes_nao_lanca()
    {
        var hub = new NotificationHub();
        var assinatura = hub.Subscribe();

        assinatura.Dispose();
        assinatura.Dispose();
    }

    private static CancellationToken TestTimeout() =>
        new CancellationTokenSource(TimeSpan.FromSeconds(5)).Token;
}
