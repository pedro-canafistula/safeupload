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

    /// <summary>
    /// O que aconteceu enquanto ninguém ouvia é entregue a quem conectar
    /// depois, dentro da janela de reprodução.
    ///
    /// Cobre a sequência real: o usuário fecha o aplicativo, um arquivo é
    /// bloqueado, ele reabre a interface. Sem isso o bloqueio teria acontecido
    /// sem deixar rastro na tela.
    /// </summary>
    [Fact]
    public void Evento_publicado_sem_ninguem_ouvindo_e_entregue_a_quem_conecta()
    {
        var hub = new NotificationHub();

        hub.Publish(new EventNotification(Evento("perdido.txt"), Achados()));

        using var assinatura = hub.Subscribe();

        Assert.True(assinatura.Reader.TryRead(out var recebido));
        Assert.Equal("perdido.txt", ((EventNotification)recebido!).Event.FileName);
    }

    /// <summary>
    /// Passada a janela, o evento não é mais reproduzido: isto é notificação,
    /// não histórico. Histórico é o queue.jsonl, que guarda tudo.
    /// </summary>
    [Fact]
    public void Evento_antigo_nao_e_reproduzido()
    {
        var relogio = new RelogioControlado(new DateTimeOffset(2026, 9, 3, 12, 0, 0, TimeSpan.Zero));
        var hub = new NotificationHub(relogio);

        hub.Publish(new EventNotification(Evento("antigo.txt"), Achados()));

        relogio.Avancar(NotificationHub.ReplayWindow + TimeSpan.FromSeconds(1));

        using var assinatura = hub.Subscribe();

        Assert.False(assinatura.Reader.TryRead(out _));
    }

    [Fact]
    public void Estado_nao_entra_na_janela_de_reproducao()
    {
        var hub = new NotificationHub();

        hub.Publish(new StatusNotification(3, 4, true));

        using var assinatura = hub.Subscribe();

        // O estado corrente e entregue pelo servidor do pipe, e nao pela
        // reproducao: reproduzi-lo aqui mandaria a mesma mensagem duas vezes.
        Assert.False(assinatura.Reader.TryRead(out _));
        Assert.NotNull(hub.CurrentStatus);
    }

    /// <summary>
    /// Evento com sessão de destino não vai para a sessão errada. Nome de
    /// arquivo é dado: entregar o bloqueio de um usuário na tela de outro seria
    /// vazar por notificação o que o agente existe para não vazar.
    /// </summary>
    [Fact]
    public void Evento_com_sessao_nao_vaza_para_outra_sessao()
    {
        var hub = new NotificationHub();
        using var sessaoUm = hub.Subscribe(sessionId: 1);
        using var sessaoDois = hub.Subscribe(sessionId: 2);

        hub.Publish(new EventNotification(Evento("da-sessao-1.txt"), Achados()), targetSessionId: 1);

        Assert.True(sessaoUm.Reader.TryRead(out _));
        Assert.False(sessaoDois.Reader.TryRead(out _));
    }

    /// <summary>
    /// Sem sessão de destino, difusão. É o caminho percorrido na prática, já
    /// que a origem de uma operação vista pelo FileSystemWatcher não é
    /// determinável.
    /// </summary>
    [Fact]
    public void Evento_sem_sessao_vai_para_todos()
    {
        var hub = new NotificationHub();
        using var sessaoUm = hub.Subscribe(sessionId: 1);
        using var sessaoDois = hub.Subscribe(sessionId: 2);

        hub.Publish(new EventNotification(Evento("difusao.txt"), Achados()));

        Assert.True(sessaoUm.Reader.TryRead(out _));
        Assert.True(sessaoDois.Reader.TryRead(out _));
    }

    /// <summary>
    /// Assinante de sessão desconhecida recebe tudo: deixá-lo sem notificação
    /// nenhuma seria pior do que mostrar demais.
    /// </summary>
    [Fact]
    public void Assinante_sem_sessao_conhecida_recebe_tudo()
    {
        var hub = new NotificationHub();
        using var desconhecida = hub.Subscribe(sessionId: null);

        hub.Publish(new EventNotification(Evento("de-alguma-sessao.txt"), Achados()), targetSessionId: 7);

        Assert.True(desconhecida.Reader.TryRead(out _));
    }

    /// <summary>Relógio de teste, avançado à mão.</summary>
    private sealed class RelogioControlado(DateTimeOffset inicio) : TimeProvider
    {
        private DateTimeOffset _agora = inicio;

        public void Avancar(TimeSpan intervalo) => _agora += intervalo;

        public override DateTimeOffset GetUtcNow() => _agora;
    }

    private static CancellationToken TestTimeout() =>
        new CancellationTokenSource(TimeSpan.FromSeconds(5)).Token;
}
