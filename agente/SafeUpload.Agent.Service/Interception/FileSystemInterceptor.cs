using SafeUpload.Agent.Core.Application;
using SafeUpload.Agent.Core.Contracts;
using SafeUpload.Agent.Core.Domain;
using SafeUpload.Agent.Core.Infrastructure;
using SafeUpload.Agent.Service.Notifications;

namespace SafeUpload.Agent.Service.Interception;

/// <summary>
/// O gatilho de inspeção: um <see cref="FileSystemWatcher"/> sobre as pastas
/// monitoradas da política.
///
/// No produto real quem dispara é um minifiltro em modo kernel, que vê a
/// operação <b>antes</b> de ela acontecer e pode negá-la de forma síncrona.
/// Aqui a inspeção só começa depois que o arquivo já chegou ao destino, e o
/// bloqueio é uma remoção posterior — o arquivo existiu no destino por alguns
/// milissegundos. É a limitação central deste mock, e nenhum ajuste em modo
/// usuário a resolve.
///
/// O que mudou ao sair do aplicativo para o serviço: isto agora roda como
/// LocalSystem, sem sessão de usuário e sem janela. Quando o veredito é
/// bloqueio, ele publica no <see cref="NotificationHub"/> em vez de abrir uma
/// janela — o serviço não tem interface, e é justamente esse o ponto. Fechar o
/// aplicativo deixou de desligar a proteção.
/// </summary>
public sealed class FileSystemInterceptor : BackgroundService
{
    /// <summary>Quanto tempo se espera o arquivo ficar legível.</summary>
    private static readonly TimeSpan ReadyTimeout = TimeSpan.FromSeconds(3);

    private static readonly TimeSpan ReadyPollInterval = TimeSpan.FromMilliseconds(120);

    private readonly InspectionService _inspection;
    private readonly IPolicyStore _policyStore;
    private readonly IAuditSink _auditSink;
    private readonly NotificationHub _hub;
    private readonly ILogger<FileSystemInterceptor> _logger;

    private readonly List<FileSystemWatcher> _watchers = [];
    private readonly SemaphoreSlim _oneAtATime = new(1, 1);

    private FileSystemWatcher? _policyWatcher;
    private CancellationToken _stopping;

    /// <summary>Compõe o interceptador.</summary>
    public FileSystemInterceptor(
        InspectionService inspection,
        IPolicyStore policyStore,
        IAuditSink auditSink,
        NotificationHub hub,
        ILogger<FileSystemInterceptor> logger)
    {
        _inspection = inspection ?? throw new ArgumentNullException(nameof(inspection));
        _policyStore = policyStore ?? throw new ArgumentNullException(nameof(policyStore));
        _auditSink = auditSink ?? throw new ArgumentNullException(nameof(auditSink));
        _hub = hub ?? throw new ArgumentNullException(nameof(hub));
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
    }

    /// <inheritdoc />
    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        _stopping = stoppingToken;

        await ApplyPolicyAsync(stoppingToken).ConfigureAwait(false);
        WatchPolicyFile();

        try
        {
            // O trabalho real acontece nos eventos dos watchers. Este laço só
            // mantém o serviço vivo até o gerenciador pedir parada.
            await Task.Delay(Timeout.Infinite, stoppingToken).ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
            // Parada normal.
        }
    }

    /// <inheritdoc />
    public override void Dispose()
    {
        StopWatchers();

        _policyWatcher?.Dispose();
        _policyWatcher = null;
        _oneAtATime.Dispose();

        base.Dispose();
    }

    /// <summary>
    /// Lê a política, passa a vigiar cada pasta monitorada e anuncia o estado.
    ///
    /// Falhar aqui não derruba o serviço: ele sobe, mas anuncia
    /// <c>protectionActive: false</c>. Um serviço no ar que não vigia nada é
    /// pior do que um serviço fora do ar, porque o aplicativo mostraria
    /// "Protegido" e ninguém saberia — daí o estado viajar no protocolo.
    /// </summary>
    private async Task ApplyPolicyAsync(CancellationToken cancellationToken)
    {
        StopWatchers();

        Policy? policy = null;

        try
        {
            policy = await _policyStore.LoadAsync(cancellationToken).ConfigureAwait(false);

            Directory.CreateDirectory(AgentPaths.QuarantineFolder);

            foreach (var folder in policy.MonitoredScopes.DestinationPaths)
            {
                // A pasta é criada se não existir: sem ela o watcher nem sobe, e
                // o agente ficaria sem gatilho nenhum na primeira execução.
                Directory.CreateDirectory(folder);

                var watcher = new FileSystemWatcher(folder)
                {
                    IncludeSubdirectories = true,
                    NotifyFilter = NotifyFilters.FileName | NotifyFilters.LastWrite | NotifyFilters.Size
                };

                // Created cobre a cópia; Renamed cobre o padrão de gravar num
                // nome temporário e renomear no fim, que é o que vários
                // programas fazem.
                watcher.Created += OnFileAppeared;
                watcher.Renamed += OnFileAppeared;

                watcher.EnableRaisingEvents = true;
                _watchers.Add(watcher);

                _logger.LogInformation("Vigiando {Pasta}", folder);
            }

            _hub.Publish(new StatusNotification(
                policy.Version,
                policy.ActiveCategories.Count,
                ProtectionActive: _watchers.Count > 0));
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Nao foi possivel aplicar a politica; o agente nao vai interceptar");

            StopWatchers();

            _hub.Publish(new StatusNotification(
                policy?.Version ?? 0,
                policy?.ActiveCategories.Count ?? 0,
                ProtectionActive: false));
        }
    }

    /// <summary>
    /// Observa o próprio <c>policy.json</c>.
    ///
    /// O Centro de Administração vai publicar política nova nesse arquivo, e um
    /// serviço que só a lê no arranque exigiria reinício a cada mudança de
    /// regra — inaceitável numa ferramenta que roda em máquina de usuário.
    /// </summary>
    private void WatchPolicyFile()
    {
        try
        {
            Directory.CreateDirectory(AgentPaths.RootDirectory);

            _policyWatcher = new FileSystemWatcher(AgentPaths.RootDirectory, AgentPaths.PolicyFileName)
            {
                NotifyFilter = NotifyFilters.LastWrite | NotifyFilters.Size | NotifyFilters.FileName
            };

            _policyWatcher.Changed += OnPolicyChanged;
            _policyWatcher.Created += OnPolicyChanged;
            _policyWatcher.EnableRaisingEvents = true;
        }
        catch (Exception ex)
        {
            // Sem observar a política o serviço continua funcionando com a que
            // já leu; só perde a atualização automática.
            _logger.LogWarning(ex, "Nao foi possivel observar mudancas na politica");
        }
    }

    private void OnPolicyChanged(object sender, FileSystemEventArgs e) => _ = Task.Run(async () =>
    {
        try
        {
            // Quem grava o arquivo pode ainda estar escrevendo; uma pausa curta
            // evita ler política pela metade e descartá-la como inválida.
            await Task.Delay(300, _stopping).ConfigureAwait(false);
            await ApplyPolicyAsync(_stopping).ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
            // Serviço parando.
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Falha ao recarregar a politica");
        }
    });

    private void StopWatchers()
    {
        foreach (var watcher in _watchers)
        {
            watcher.EnableRaisingEvents = false;
            watcher.Created -= OnFileAppeared;
            watcher.Renamed -= OnFileAppeared;
            watcher.Dispose();
        }

        _watchers.Clear();
    }

    private void OnFileAppeared(object sender, FileSystemEventArgs e)
    {
        // O evento chega numa thread do watcher, que não pode ficar presa: o
        // FileSystemWatcher tem um buffer interno pequeno e perde eventos
        // silenciosamente se o tratador demorar.
        _ = Task.Run(() => HandleAsync(e.FullPath));
    }

    private async Task HandleAsync(string path)
    {
        try
        {
            if (ShouldIgnore(path))
            {
                return;
            }

            // Uma inspeção por vez. Copiar uma pasta inteira dispara dezenas de
            // eventos ao mesmo tempo, e deixá-los correr em paralelo faria as
            // inspeções competirem por disco sem ganhar nada.
            await _oneAtATime.WaitAsync(_stopping).ConfigureAwait(false);

            try
            {
                if (!await WaitUntilReadableAsync(path).ConfigureAwait(false))
                {
                    // Passou o prazo e o arquivo continua em uso. Não se
                    // inspeciona conteúdo parcial: um veredito de aprovado
                    // sobre meio arquivo é um falso negativo com aparência de
                    // exame.
                    return;
                }

                await InspectAsync(path).ConfigureAwait(false);
            }
            finally
            {
                _oneAtATime.Release();
            }
        }
        catch (OperationCanceledException)
        {
            // Serviço parando.
        }
        catch (Exception ex)
        {
            // Nenhuma falha do gatilho pode derrubar o serviço. Fail-open vale
            // aqui também: na dúvida, a operação do usuário segue. Mas a falha
            // vai para o log do serviço em vez de sumir.
            _logger.LogError(ex, "Falha ao interceptar {Arquivo}", Path.GetFileName(path));
        }
    }

    /// <summary>
    /// A pasta de quarentena está fora do escopo do próprio interceptador.
    ///
    /// Sem isto, mover um arquivo bloqueado para lá dispararia um novo evento,
    /// que bloquearia de novo e moveria de novo: o serviço entraria em laço
    /// sozinho, sem nenhuma ação do usuário.
    /// </summary>
    private static bool ShouldIgnore(string path)
    {
        if (Directory.Exists(path))
        {
            return true;
        }

        if (path.StartsWith(AgentPaths.QuarantineFolder, StringComparison.OrdinalIgnoreCase))
        {
            return true;
        }

        // Arquivos temporários de quem está copiando: o evento definitivo vem
        // depois, no rename.
        var name = Path.GetFileName(path);

        return name.StartsWith('~')
            || name.EndsWith(".tmp", StringComparison.OrdinalIgnoreCase)
            || name.EndsWith(".crdownload", StringComparison.OrdinalIgnoreCase)
            || name.EndsWith(".partial", StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>
    /// Espera o arquivo ficar legível.
    ///
    /// O <see cref="FileSystemWatcher"/> avisa que o arquivo <i>apareceu</i>,
    /// não que terminou de ser copiado: uma cópia de 20 MB dispara Created no
    /// primeiro byte. Inspecionar nesse instante leria um arquivo pela metade,
    /// e um CPF cortado no meio da cópia não seria encontrado.
    ///
    /// Abrir com <see cref="FileShare.None"/> é o teste: enquanto quem copia
    /// mantiver o arquivo aberto, a abertura falha. Depois de
    /// <see cref="ReadyTimeout"/> se desiste, em vez de segurar o serviço por
    /// causa de um arquivo que alguém deixou aberto.
    /// </summary>
    private static async Task<bool> WaitUntilReadableAsync(string path)
    {
        var deadline = DateTime.UtcNow + ReadyTimeout;

        while (DateTime.UtcNow < deadline)
        {
            try
            {
                await using var stream = new FileStream(
                    path, FileMode.Open, FileAccess.Read, FileShare.None);

                return true;
            }
            catch (FileNotFoundException)
            {
                // Sumiu antes de terminar: nada a inspecionar.
                return false;
            }
            catch (DirectoryNotFoundException)
            {
                return false;
            }
            catch (IOException)
            {
                // Ainda em uso por quem copia. Tenta de novo.
            }
            catch (UnauthorizedAccessException)
            {
                return false;
            }

            await Task.Delay(ReadyPollInterval).ConfigureAwait(false);
        }

        return false;
    }

    private async Task InspectAsync(string path)
    {
        var info = new FileInfo(path);

        if (!info.Exists)
        {
            return;
        }

        var operation = new FileOperation(
            info.FullName,
            info.Name,
            info.Extension.ToLowerInvariant(),
            info.Length,
            info.LastWriteTimeUtc,

            // Sem interceptação em modo kernel não há como saber que processo
            // realizou a cópia. Um nome plausível seria invenção, e ela iria
            // parar na trilha de auditoria como se fosse observação.
            "desconhecido",
            0,
            info.DirectoryName ?? string.Empty,

            // A pasta vigiada entra em escopo por casar com destinationPaths,
            // que é exatamente a regra de Cloud na política — o mesmo caminho
            // de uma pasta de sincronização no endpoint.
            DestinationKind.Cloud);

        var result = await _inspection.InspectAsync(operation, _stopping).ConfigureAwait(false);

        if (result.IsBlocked)
        {
            Quarantine(path);
        }

        if (!result.InScope)
        {
            // Fora de escopo não gera evento, e portanto não há o que anunciar.
            return;
        }

        var auditEvent = await FindAuditEventAsync(operation).ConfigureAwait(false);

        if (auditEvent is not null)
        {
            // A sessao de origem, quando determinavel, restringe a entrega a
            // quem realmente fez a operacao. Com o FileSystemWatcher ela nunca
            // e: o PID chega zero e isto sempre resolve para difusao. O caminho
            // existe para o dia em que o minifiltro informar o processo.
            var sessionId = SessionResolver.TryGetSessionId(operation.ProcessId);

            _hub.Publish(new EventNotification(auditEvent, result.Findings), sessionId);
        }

        _logger.LogInformation(
            "{Veredito} {Arquivo} em {Duracao} ms",
            result.Verdict,
            operation.FileName,
            result.ElapsedMs);
    }

    /// <summary>
    /// Move o arquivo bloqueado para a quarentena.
    ///
    /// Mover, e não apagar: o arquivo é do usuário, e o agente não tem mandato
    /// para destruí-lo. Ele sai do destino monitorado, que é o que a política
    /// exige, e continua recuperável.
    /// </summary>
    private void Quarantine(string path)
    {
        try
        {
            var name = Path.GetFileNameWithoutExtension(path);
            var extension = Path.GetExtension(path);
            var stamp = DateTime.Now.ToString("yyyyMMdd-HHmmss");
            var target = Path.Combine(AgentPaths.QuarantineFolder, $"{name}-{stamp}{extension}");

            // Nomes iguais no mesmo segundo: um sufixo numérico resolve sem
            // sobrescrever o arquivo que já está na quarentena.
            var attempt = 1;
            while (File.Exists(target))
            {
                target = Path.Combine(AgentPaths.QuarantineFolder, $"{name}-{stamp}-{attempt}{extension}");
                attempt++;
            }

            File.Move(path, target);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            // O veredito continua valendo e o evento continua sendo auditado;
            // só o arquivo permanece onde está.
            _logger.LogWarning(ex, "Nao foi possivel mover {Arquivo} para a quarentena", Path.GetFileName(path));
        }
    }

    /// <summary>
    /// Recupera da trilha o evento que o motor acabou de gravar.
    ///
    /// O <see cref="InspectionService"/> audita por dentro e devolve só o
    /// veredito, então reconstruir o evento aqui a partir do resultado abriria
    /// espaço para o aplicativo mostrar algo diferente do que foi registrado.
    /// </summary>
    private async Task<AuditEvent?> FindAuditEventAsync(FileOperation operation)
    {
        var recent = await _auditSink.ReadRecentAsync(5, _stopping).ConfigureAwait(false);

        return recent.FirstOrDefault(e =>
            string.Equals(e.FileName, operation.FileName, StringComparison.OrdinalIgnoreCase));
    }
}
