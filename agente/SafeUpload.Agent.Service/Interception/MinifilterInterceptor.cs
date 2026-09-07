using System.Diagnostics;
using SafeUpload.Agent.Core.Application;
using SafeUpload.Agent.Core.Contracts;
using SafeUpload.Agent.Core.Domain;
using SafeUpload.Agent.Minifilter;
using SafeUpload.Agent.Service.Notifications;
using PortVerdict = SafeUpload.Agent.Minifilter.Verdict;

namespace SafeUpload.Agent.Service.Interception;

/// <summary>
/// O gatilho real: o minifiltro em modo kernel.
///
/// Faz o mesmo papel do <see cref="FileSystemInterceptor"/> e é a razão de ele
/// existir como mock. A diferença não é de implementação, é de natureza: o
/// watcher reage depois que o arquivo já chegou ao destino e "bloqueia"
/// apagando, enquanto aqui a operação é interceptada **antes** de acontecer e
/// a negação impede que ela aconteça. Nenhum byte chega ao destino.
///
/// O <see cref="InspectionService"/> continua sendo quem decide. Este tipo
/// traduz — do que o kernel manda para <see cref="FileOperation"/>, e do
/// veredito de dominio de volta para o veredito do protocolo — e nada mais.
/// Regra de negócio aqui dentro seria regra em dois lugares.
///
/// <para><b>Prazo, e por que ele ainda não fecha.</b> O driver espera
/// <c>500 ms</c> pelo veredito e, esgotado o prazo, libera a operação sem
/// inspeção (RN-013). O motor tem orçamento de <c>5 s</c> para extração e
/// varredura (RN-012). São uma ordem de grandeza de diferença, e enquanto ela
/// existir todo arquivo que precise de extração real vai estourar o prazo e
/// passar sem inspeção. Isto está implementado de forma a tornar o problema
/// <b>visível</b> — cada estouro é contado e registrado como aviso — e não a
/// escondê-lo. A decisão de produto que resolve está pendente.</para>
/// </summary>
public sealed class MinifilterInterceptor : BackgroundService
{
    /// <summary>
    /// Quanto se dá ao motor antes de desistir. Fica abaixo dos 500 ms do
    /// driver de propósito: responder tarde é o mesmo que não responder, e
    /// ainda gasta o tempo de quem está esperando.
    /// </summary>
    private static readonly TimeSpan Budget = TimeSpan.FromMilliseconds(400);

    private readonly InspectionService _inspection;
    private readonly IPolicyStore _policyStore;
    private readonly IAuditSink _auditSink;
    private readonly NotificationHub _hub;
    private readonly ILogger<MinifilterInterceptor> _logger;

    private long _overBudget;
    private long _answered;

    /// <summary>Compõe o interceptador.</summary>
    public MinifilterInterceptor(
        InspectionService inspection,
        IPolicyStore policyStore,
        IAuditSink auditSink,
        NotificationHub hub,
        ILogger<MinifilterInterceptor> logger)
    {
        _inspection = inspection ?? throw new ArgumentNullException(nameof(inspection));
        _policyStore = policyStore ?? throw new ArgumentNullException(nameof(policyStore));
        _auditSink = auditSink ?? throw new ArgumentNullException(nameof(auditSink));
        _hub = hub ?? throw new ArgumentNullException(nameof(hub));
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
    }

    /// <inheritdoc />
    protected override Task ExecuteAsync(CancellationToken stoppingToken)
    {
        // FilterGetMessage bloqueia a thread que o chama, e não há sobreposto
        // aqui. Numa thread do pool isso prenderia um worker pelo tempo todo
        // de vida do serviço, então o laço vive numa thread própria.
        //
        // Uma thread, portanto uma operação por vez: toda abertura monitorada
        // da máquina enfileira atrás do veredito mais lento. É a limitação 3
        // do DEPLOY.md e continua verdadeira; resolvê-la é um pool sobre a
        // mesma porta, e não cabe junto da troca de gatilho.
        var thread = new Thread(() => Run(stoppingToken))
        {
            IsBackground = true,
            Name = "SafeUpload.Minifilter",
        };

        thread.Start();

        return Task.CompletedTask;
    }

    private void Run(CancellationToken stoppingToken)
    {
        try
        {
            Contract.Verify();
        }
        catch (InvalidOperationException ex)
        {
            // Descompasso de layout entre Protocol.cs e Protocol.h. Seguir
            // daqui produziria vereditos respondidos para a requisição
            // errada, sem nada no sistema reportando erro.
            _logger.LogCritical(ex, "Contrato incompativel com o driver. O gatilho de kernel nao vai subir.");
            return;
        }

        FilterPort port;

        try
        {
            port = FilterPort.Connect();
        }
        catch (Exception ex)
        {
            // Driver não carregado, ou processo sem privilégio. Nenhum dos
            // dois se resolve com nova tentativa imediata, e o serviço não
            // deve morrer por causa disso: o agente segue no ar sem o
            // gatilho de kernel, o que o log precisa deixar explícito.
            _logger.LogError(ex, "Nao foi possivel conectar na porta do minifiltro. Sem intercepcao de kernel.");
            return;
        }

        using (port)
        {
            if (!TryPushPolicy(port))
            {
                return;
            }

            _logger.LogInformation("Minifiltro conectado. Interceptando em modo kernel.");

            ReadySignal.Announce(ReadySignal.ServiceEvent);

            while (!stoppingToken.IsCancellationRequested &&
                   port.TryGetMessage(out SafeUploadRequest request, out ulong messageId))
            {
                uint verdict = Judge(request);

                try
                {
                    port.Reply(messageId, request.RequestId, verdict);
                }
                catch (Exception ex)
                {
                    _logger.LogWarning(ex, "Falha ao responder o veredito {RequestId}.", request.RequestId);
                }
            }
        }

        _logger.LogInformation(
            "Laco do minifiltro encerrado. {Answered} vereditos, {OverBudget} fora do prazo.",
            Interlocked.Read(ref _answered),
            Interlocked.Read(ref _overBudget));
    }

    /// <summary>
    /// Traduz a política do agente para a do driver e empurra.
    ///
    /// Sem isto o driver não inspeciona nada: ele sobe sem política e libera
    /// tudo. Falhar aqui é falhar em ligar a proteção, não em configurá-la.
    /// </summary>
    private bool TryPushPolicy(FilterPort port)
    {
        try
        {
            Policy policy = _policyStore.LoadAsync(CancellationToken.None).GetAwaiter().GetResult();
            MonitoredScopes scopes = policy.MonitoredScopes;
            var builder = new PolicyBuilder();

            foreach (string extension in scopes.Extensions)
            {
                builder.WithExtension(extension);
            }

            foreach (string path in scopes.DestinationPaths)
            {
                builder.WithDestination(path);
            }

            // A outra metade da cadeia. Vazia e configuracao legitima, mas
            // vale saber o que ela significa: sem origem, nenhum processo e
            // marcado, e a negacao por contaminacao nunca dispara. O driver
            // continua vigiando os destinos, so nao ha o que ligar a eles.
            foreach (string path in scopes.SourcePaths)
            {
                builder.WithSource(path);
            }

            foreach (string image in policy.ExcludedProcesses)
            {
                builder.WithExcludedImage(image);
            }

            builder.WithVolumeKinds(scopes.RemovableDrives, scopes.NetworkPaths);

            port.SetPolicy(builder.Build());

            _logger.LogInformation(
                "Politica v{Version} empurrada ao driver: {Extensions} extensoes, " +
                "{Paths} destinos, {Sources} origens.",
                policy.Version,
                scopes.Extensions.Count,
                scopes.DestinationPaths.Count,
                scopes.SourcePaths.Count);

            if (scopes.SourcePaths.Count == 0)
            {
                _logger.LogWarning(
                    "Politica sem origens: nenhum processo sera marcado e a negacao por " +
                    "contaminacao nunca vai disparar.");
            }

            return true;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Falha ao empurrar a politica. O driver ficaria carregado sem inspecionar nada.");
            return false;
        }
    }

    /// <summary>
    /// Decide uma requisição dentro do orçamento, ou libera sem inspeção.
    /// </summary>
    private uint Judge(SafeUploadRequest request)
    {
        Interlocked.Increment(ref _answered);

        if (request.Version != Contract.Version)
        {
            // Regra 5 do contrato: o que não se entende, permite-se.
            return PortVerdict.Allow;
        }

        FileOperation? operation = Translate(request);

        if (operation is null)
        {
            return PortVerdict.Allow;
        }

        var stopwatch = Stopwatch.StartNew();

        try
        {
            using var budget = new CancellationTokenSource(Budget);

            // GetAwaiter().GetResult() e não .Result: preserva a exceção
            // original em vez de embrulhá-la em AggregateException. O laço é
            // síncrono por natureza — o kernel está bloqueado esperando.
            InspectionResult result = _inspection
                .InspectAsync(operation, budget.Token)
                .GetAwaiter()
                .GetResult();

            Announce(operation, result);

            return result.IsBlocked ? PortVerdict.Deny : PortVerdict.Allow;
        }
        catch (OperationCanceledException)
        {
            Interlocked.Increment(ref _overBudget);

            _logger.LogWarning(
                "Inspecao de {Path} passou de {Budget} ms e o arquivo passou SEM INSPECAO. " +
                "Este e o descompasso conhecido entre o prazo do driver (500 ms) e o do motor (5 s).",
                operation.FileName,
                Budget.TotalMilliseconds);

            return PortVerdict.Allow;
        }
        catch (Exception ex)
        {
            // Fail-open, como o resto do agente: um DLP que bloqueia quando
            // quebra impede o usuário de trabalhar e é desligado na primeira
            // semana.
            _logger.LogError(ex, "Erro ao inspecionar {Path}. Liberado sem inspecao.", operation.FileName);
            return PortVerdict.Allow;
        }
        finally
        {
            stopwatch.Stop();
        }
    }

    /// <summary>
    /// Publica o evento para o painel, quando houver o que publicar.
    ///
    /// A sessão de origem vem do PID, e aqui ela finalmente resolve: com o
    /// <see cref="FileSystemInterceptor"/> o PID chega zero e toda notificação
    /// vira difusão. O minifiltro informa quem pediu a operação, então a
    /// entrega passa a ser dirigida a quem de fato a fez - o caminho que já
    /// existia no serviço esperando por esta informação.
    /// </summary>
    private void Announce(FileOperation operation, InspectionResult result)
    {
        if (!result.InScope)
        {
            // Fora de escopo não gera evento, e portanto não há o que anunciar.
            return;
        }

        try
        {
            IReadOnlyList<AuditEvent> recent =
                _auditSink.ReadRecentAsync(5, CancellationToken.None).GetAwaiter().GetResult();

            AuditEvent? auditEvent = recent.FirstOrDefault(e =>
                string.Equals(e.FileName, operation.FileName, StringComparison.OrdinalIgnoreCase));

            if (auditEvent is not null)
            {
                uint? sessionId = SessionResolver.TryGetSessionId(operation.ProcessId);
                _hub.Publish(new EventNotification(auditEvent, result.Findings), sessionId);
            }
        }
        catch (Exception ex)
        {
            // Falhar em avisar o painel não pode mudar o veredito nem derrubar
            // o laço: a proteção continua, o usuário é que não vê o aviso.
            _logger.LogWarning(ex, "Falha ao publicar a notificacao de {Arquivo}.", operation.FileName);
        }
    }

    /// <summary>
    /// Monta a <see cref="FileOperation"/> a partir do que o kernel mandou.
    ///
    /// Devolve null quando a operação não dá para inspecionar — caminho sem
    /// letra de unidade, arquivo que sumiu entre o pedido e a leitura. Nunca
    /// é motivo para bloquear.
    /// </summary>
    private FileOperation? Translate(SafeUploadRequest request)
    {
        string? path = NtPathTranslator.ToDosPath(request.GetPath());

        if (path is null)
        {
            return null;
        }

        // Tamanho e data não vêm na requisição, então saem do sistema de
        // arquivos — I/O dentro do caminho do veredito, que é justamente o
        // que o orçamento não comporta com folga. O driver já conhece os
        // dois (ele os usa como carimbo do cache de fluxo) e o campo
        // Reserved da requisição existe: mandá-los junto tiraria este acesso
        // do caminho quente. Fica anotado, não feito.
        FileInfo info;

        try
        {
            info = new FileInfo(path);

            if (!info.Exists)
            {
                return null;
            }
        }
        catch (Exception)
        {
            return null;
        }

        // A natureza do destino que o driver sabe (volume removível, rede,
        // caminho monitorado) não cabe no protocolo de hoje: a requisição
        // carrega só as flags de escopo. Origem e destino monitorados são
        // ambos tratados como Cloud, que é a categoria que a RN-011 aplica a
        // caminho local monitorado. Mandar o DestinationKind pelo Reserved
        // resolveria, e é a mesma anotação do parágrafo acima.
        DestinationKind destination =
            request.TypedFlags.HasFlag(RequestFlags.ScopeDestination) ||
            request.TypedFlags.HasFlag(RequestFlags.ScopeSource)
                ? DestinationKind.Cloud
                : DestinationKind.OutOfScope;

        return new FileOperation(
            FilePath: path,
            FileName: info.Name,
            Extension: info.Extension.ToLowerInvariant(),
            SizeBytes: info.Length,
            LastWriteUtc: info.LastWriteTimeUtc,
            ProcessName: request.GetImageName(),
            ProcessId: (int) request.RequestorProcessId,
            DestinationPath: path,
            Destination: destination);
    }
}
