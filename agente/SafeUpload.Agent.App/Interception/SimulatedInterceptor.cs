using System.IO;
using SafeUpload.Agent.Core.Application;
using SafeUpload.Agent.Core.Domain;

namespace SafeUpload.Agent.App.Interception;

/// <summary>
/// O gatilho de inspeção do mock: um <see cref="FileSystemWatcher"/> sobre as
/// pastas monitoradas da política.
///
/// No produto real quem dispara é o minifiltro em modo kernel, que vê a
/// operação <b>antes</b> de ela acontecer e pode negá-la de forma síncrona.
/// Aqui a inspeção só começa depois que o arquivo já chegou ao destino, e o
/// bloqueio é uma remoção posterior — o arquivo existiu no destino por alguns
/// milissegundos. É a limitação central deste mock, e nenhum ajuste em modo
/// usuário a resolve.
/// </summary>
public sealed class SimulatedInterceptor : IDisposable
{
    /// <summary>Nome da pasta para onde vão os arquivos bloqueados.</summary>
    public const string QuarantineFolderName = "_bloqueados";

    /// <summary>Quanto tempo se espera o arquivo ficar legível.</summary>
    private static readonly TimeSpan ReadyTimeout = TimeSpan.FromSeconds(3);

    private static readonly TimeSpan ReadyPollInterval = TimeSpan.FromMilliseconds(120);

    private readonly InspectionService _inspection;
    private readonly IPolicyStore _policyStore;
    private readonly IAuditSink _auditSink;
    private readonly List<FileSystemWatcher> _watchers = [];
    private readonly SemaphoreSlim _oneAtATime = new(1, 1);

    private string _quarantineFolder = string.Empty;
    private bool _disposed;

    /// <summary>Compõe o interceptador.</summary>
    public SimulatedInterceptor(InspectionService inspection, IPolicyStore policyStore, IAuditSink auditSink)
    {
        _inspection = inspection ?? throw new ArgumentNullException(nameof(inspection));
        _policyStore = policyStore ?? throw new ArgumentNullException(nameof(policyStore));
        _auditSink = auditSink ?? throw new ArgumentNullException(nameof(auditSink));
    }

    /// <summary>
    /// Disparado depois de cada operação julgada, na thread de fundo do
    /// watcher. Quem escuta é responsável por levar o resultado à thread da
    /// interface.
    /// </summary>
    public event EventHandler<InterceptionEventArgs>? Intercepted;

    /// <summary>
    /// Disparado quando uma interceptação falha. O arquivo segue seu caminho —
    /// o agente é fail-open —, mas a falha precisa aparecer para alguém.
    /// </summary>
    public event EventHandler<InterceptionFailureEventArgs>? Failed;

    /// <summary>Pasta de quarentena em uso.</summary>
    public string QuarantineFolder => _quarantineFolder;

    /// <summary>
    /// Lê a política e passa a vigiar cada pasta monitorada.
    /// </summary>
    public async Task StartAsync(CancellationToken cancellationToken)
    {
        var policy = await _policyStore.LoadAsync(cancellationToken).ConfigureAwait(false);

        _quarantineFolder = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.UserProfile),
            "SafeUpload",
            QuarantineFolderName);

        Directory.CreateDirectory(_quarantineFolder);

        foreach (var folder in policy.MonitoredScopes.DestinationPaths)
        {
            // A pasta é criada se não existir: sem ela o watcher nem sobe, e o
            // agente ficaria sem gatilho nenhum na primeira execução.
            Directory.CreateDirectory(folder);

            var watcher = new FileSystemWatcher(folder)
            {
                IncludeSubdirectories = true,
                NotifyFilter = NotifyFilters.FileName | NotifyFilters.LastWrite | NotifyFilters.Size
            };

            // Created cobre a cópia; Renamed cobre o padrão de gravar num nome
            // temporário e renomear no fim, que é o que vários programas fazem.
            watcher.Created += OnFileAppeared;
            watcher.Renamed += OnFileAppeared;

            watcher.EnableRaisingEvents = true;
            _watchers.Add(watcher);
        }
    }

    /// <inheritdoc />
    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }

        _disposed = true;

        foreach (var watcher in _watchers)
        {
            watcher.EnableRaisingEvents = false;
            watcher.Created -= OnFileAppeared;
            watcher.Renamed -= OnFileAppeared;
            watcher.Dispose();
        }

        _watchers.Clear();
        _oneAtATime.Dispose();
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
            // notificações de bloqueio brigarem entre si na tela.
            await _oneAtATime.WaitAsync().ConfigureAwait(false);

            try
            {
                if (!await WaitUntilReadableAsync(path).ConfigureAwait(false))
                {
                    // Passou o prazo e o arquivo continua em uso. Não se
                    // inspeciona conteúdo parcial: seria pior que não
                    // inspecionar, porque um veredito de aprovado sobre meio
                    // arquivo é um falso negativo com aparência de exame.
                    return;
                }

                await InspectAsync(path).ConfigureAwait(false);
            }
            finally
            {
                _oneAtATime.Release();
            }
        }
        catch (Exception ex)
        {
            // Nenhuma falha do gatilho pode derrubar o agente. Fail-open vale
            // aqui também: na dúvida, a operação do usuário segue.
            //
            // Mas engolir a falha em silêncio seria pior do que a falha: o
            // agente continuaria exibindo "INTERCEPTANDO" no cartão de status
            // enquanto deixasse de examinar arquivos, e ninguém saberia. Quem
            // escuta decide como avisar.
            Failed?.Invoke(this, new InterceptionFailureEventArgs(path, ex));
        }
    }

    /// <summary>
    /// A pasta de quarentena está fora do escopo do próprio interceptador.
    ///
    /// Sem isto, mover um arquivo bloqueado para lá dispararia um novo evento,
    /// que bloquearia de novo e moveria de novo: o agente entraria em laço
    /// sozinho, sem nenhuma ação do usuário.
    /// </summary>
    private bool ShouldIgnore(string path)
    {
        if (Directory.Exists(path))
        {
            return true;
        }

        if (!string.IsNullOrEmpty(_quarantineFolder)
            && path.StartsWith(_quarantineFolder, StringComparison.OrdinalIgnoreCase))
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
    /// O FileSystemWatcher avisa que o arquivo <i>apareceu</i>, não que ele
    /// terminou de ser copiado: uma cópia de 20 MB dispara Created no primeiro
    /// byte. Inspecionar nesse instante leria um arquivo pela metade, e um CPF
    /// cortado no meio da cópia não seria encontrado.
    ///
    /// Abrir com FileShare.None é o teste: enquanto quem copia mantiver o
    /// arquivo aberto, a abertura falha. Depois de <see cref="ReadyTimeout"/>
    /// se desiste, em vez de segurar o agente indefinidamente por causa de um
    /// arquivo que alguém deixou aberto.
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

        var result = await _inspection.InspectAsync(operation, CancellationToken.None).ConfigureAwait(false);

        var quarantined = result.IsBlocked && TryQuarantine(path);

        if (!result.InScope)
        {
            // Fora de escopo não gera evento, e portanto não tem o que mostrar.
            return;
        }

        var auditEvent = await FindAuditEventAsync(operation).ConfigureAwait(false);

        Intercepted?.Invoke(this, new InterceptionEventArgs(operation, result, auditEvent, quarantined));
    }

    /// <summary>
    /// Move o arquivo bloqueado para a quarentena.
    ///
    /// Mover, e não apagar: o arquivo é do usuário, e o agente não tem mandato
    /// para destruí-lo. Ele sai do destino monitorado, que é o que a política
    /// exige, e continua recuperável.
    /// </summary>
    private bool TryQuarantine(string path)
    {
        try
        {
            var name = Path.GetFileNameWithoutExtension(path);
            var extension = Path.GetExtension(path);
            var stamp = DateTime.Now.ToString("yyyyMMdd-HHmmss");
            var target = Path.Combine(_quarantineFolder, $"{name}-{stamp}{extension}");

            // Nomes iguais no mesmo segundo: um sufixo numérico resolve sem
            // sobrescrever o arquivo que já está na quarentena.
            var attempt = 1;
            while (File.Exists(target))
            {
                target = Path.Combine(_quarantineFolder, $"{name}-{stamp}-{attempt}{extension}");
                attempt++;
            }

            File.Move(path, target);
            return true;
        }
        catch (IOException)
        {
            return false;
        }
        catch (UnauthorizedAccessException)
        {
            return false;
        }
    }

    /// <summary>
    /// Recupera da trilha o evento que o motor acabou de gravar.
    ///
    /// O InspectionService audita por dentro e devolve só o veredito, então a
    /// interface leria o disco de qualquer maneira para montar a linha. Buscar
    /// o evento aqui evita reconstruí-lo a partir do resultado e correr o risco
    /// de a tela mostrar algo diferente do que foi registrado.
    /// </summary>
    private async Task<AuditEvent?> FindAuditEventAsync(FileOperation operation)
    {
        var recent = await _auditSink.ReadRecentAsync(5, CancellationToken.None).ConfigureAwait(false);

        return recent.FirstOrDefault(e =>
            string.Equals(e.FileName, operation.FileName, StringComparison.OrdinalIgnoreCase));
    }
}

/// <summary>
/// O que aconteceu numa interceptação.
/// </summary>
/// <param name="Operation">A operação julgada.</param>
/// <param name="Result">O veredito.</param>
/// <param name="AuditEvent">O evento gravado, quando encontrado na trilha.</param>
/// <param name="Quarantined">Se o arquivo foi movido para a quarentena.</param>
public sealed record InterceptionEventArgs(
    FileOperation Operation,
    InspectionResult Result,
    AuditEvent? AuditEvent,
    bool Quarantined);

/// <summary>
/// Uma interceptação que não pôde ser concluída.
/// </summary>
/// <param name="Path">Arquivo que disparou o evento.</param>
/// <param name="Error">Falha ocorrida.</param>
public sealed record InterceptionFailureEventArgs(string Path, Exception Error);
