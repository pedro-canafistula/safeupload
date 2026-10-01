using System.Diagnostics;
using SafeUpload.Agent.Core.Application;
using SafeUpload.Agent.Core.Contracts;
using SafeUpload.Agent.Core.Domain;
using SafeUpload.Agent.Minifilter;
using SafeUpload.Agent.Service.Notifications;
using SafeUpload.Agent.Core.Infrastructure;
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
/// <para><b>O prazo.</b> Havia uma ordem de grandeza entre o que o driver
/// esperava (500 ms fixos) e o que a RN-012 dá ao motor (5 s), e enquanto ela
/// existiu todo arquivo que precisasse de extração real estouraria o prazo e
/// passaria sem inspeção. O prazo do kernel passou a vir da política: o
/// serviço empurra <c>InspectionTimeout</c> mais uma margem, o motor desiste
/// antes do driver, e o número existe num lugar só.
///
/// O que isso <b>não</b> resolve é o custo: enquanto o veredito não volta, a
/// abertura do arquivo está parada. Um prazo maior protege mais e trava mais,
/// e o ponto certo dessa troca só se conhece medindo com arquivo de verdade.
/// Cada estouro continua contado e registrado.</para>
/// </summary>
public sealed class MinifilterInterceptor : BackgroundService
{
    /// <summary>
    /// Margem entre o prazo que o driver espera e o que o motor recebe.
    ///
    /// O motor tem de desistir <b>antes</b> do driver, e não junto:
    /// responder no instante em que o kernel parou de esperar é o mesmo que
    /// não responder, e ainda gastou o tempo de quem esperava.
    /// </summary>
    private static readonly TimeSpan Margin = TimeSpan.FromMilliseconds(500);

    /// <summary>
    /// O que o motor recebe, derivado da RN-012 quando a política carrega.
    /// Antes disso não há inspeção acontecendo, então o valor não importa.
    /// </summary>
    private TimeSpan _budget = TimeSpan.FromMilliseconds(400);

    private readonly InspectionService _inspection;
    private readonly IPolicyStore _policyStore;
    private readonly IAuditSink _auditSink;
    private readonly NotificationHub _hub;
    private readonly PendingOverrides _pending;
    private readonly OverrideGrantDispatcher _grants;
    private readonly StagedJustifications _stagedJustifications;
    private readonly ILogger<MinifilterInterceptor> _logger;
    private readonly bool _stagingEnabled;
    private StagedTransferAllocator? _stageAllocator;
    private StagedTransferJournal? _stageJournal;
    private StagedTransferPublisher? _stagePublisher;

    private long _overBudget;
    private long _answered;
    private bool _overrideAllowed;
    private int _policyVersion;
    private int _activeCategories;

    /// <summary>Compõe o interceptador.</summary>
    public MinifilterInterceptor(
        InspectionService inspection,
        IPolicyStore policyStore,
        IAuditSink auditSink,
        NotificationHub hub,
        PendingOverrides pending,
        OverrideGrantDispatcher grants,
        StagedJustifications stagedJustifications,
        IConfiguration configuration,
        ILogger<MinifilterInterceptor> logger)
    {
        _inspection = inspection ?? throw new ArgumentNullException(nameof(inspection));
        _policyStore = policyStore ?? throw new ArgumentNullException(nameof(policyStore));
        _auditSink = auditSink ?? throw new ArgumentNullException(nameof(auditSink));
        _hub = hub ?? throw new ArgumentNullException(nameof(hub));
        _pending = pending ?? throw new ArgumentNullException(nameof(pending));
        _grants = grants ?? throw new ArgumentNullException(nameof(grants));
        _stagedJustifications = stagedJustifications ?? throw new ArgumentNullException(nameof(stagedJustifications));
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        _stagingEnabled = configuration.GetValue<bool>("Interception:StagingPrototype");
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
        // A UI must never infer protection merely from a live service pipe.
        // It becomes active only after the driver accepts the policy.
        _hub.Publish(new StatusNotification(0, 0, ProtectionActive: false));

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
            // Establish the authenticated inspector identity before opening
            // existing private stages. Recovery while disconnected would be
            // correctly denied by the driver's direct-stage access gate.
            if (_stagingEnabled)
            {
                try
                {
                    string root = Path.Combine(AgentPaths.RootDirectory, "staging");
                    string journal = Path.Combine(AgentPaths.RootDirectory, "staging-journal");
                    _stageJournal = new StagedTransferJournal(journal, requireProtectedParent: true);
                    _stageAllocator = new StagedTransferAllocator(root, _stageJournal,
                        requireProtectedParent: true, requireSystemIdentity: true);
                    _stagePublisher = new StagedTransferPublisher(
                        _inspection, _hub, _stageJournal, root,
                        new StagedPublicationGate(port), _stagedJustifications, _logger);
                    _stageJournal.RetainInterruptedAsync(stoppingToken).GetAwaiter().GetResult();
                    _stageJournal.ReconcilePublishingAsync(stoppingToken).GetAwaiter().GetResult();
                }
                catch (Exception ex)
                {
                    _logger.LogCritical(ex, "Falha ao recuperar o diario de transferencias.");
                    return;
                }
            }
            if (!TryPushPolicy(port))
            {
                return;
            }

            _grants.Bind(port);
            using var publishCancellation =
                CancellationTokenSource.CreateLinkedTokenSource(stoppingToken);
            Task? publishTask = _stagePublisher is null ? null :
                Task.Run(() => PublishSealedLoopAsync(publishCancellation.Token),
                    publishCancellation.Token);
            try
            {
                _logger.LogInformation("Minifiltro conectado. Interceptando em modo kernel.");

                ReadySignal.Announce(ReadySignal.ServiceEvent);

                while (!stoppingToken.IsCancellationRequested &&
                       port.TryGetMessage(out SafeUploadRequest request, out ulong messageId, stoppingToken))
                {
                    uint verdict;
                    string? stageName = null;
                    if (request.Operation == Operation.StageAllocate)
                    {
                        (verdict, stageName) = AllocateStage(request);
                    }
                    else if (request.Operation == Operation.StageSeal)
                    {
                        verdict = SealStage(request);
                    }
                    else if (request.Operation == Operation.StageRename)
                    {
                        verdict = RetargetStage(request);
                    }
                    else if (request.Operation == Operation.StageDiagnostic)
                    {
                        _logger.LogWarning("Staged kernel diagnostic: phase {Phase}, status 0x{Status:X8}, path {Path}",
                            request.Flags, request.Reserved, request.GetPath());
                        verdict = PortVerdict.Deny;
                    }
                    else
                    {
                        verdict = request.Operation is Operation.Create or Operation.Read
                            ? Judge(request) : PortVerdict.Deny;
                    }

                    try
                    {
                        port.Reply(messageId, request.RequestId, verdict, stageName);
                    }
                    catch (Exception ex)
                    {
                        _logger.LogWarning(ex, "Falha ao responder o veredito {RequestId}.", request.RequestId);
                    }
                }
            }
            finally
            {
                publishCancellation.Cancel();
                if (publishTask is not null)
                {
                    try { publishTask.GetAwaiter().GetResult(); }
                    catch (OperationCanceledException) { }
                    catch (Exception ex)
                    {
                        _logger.LogCritical(ex,
                            "Processamento de transferencias seladas interrompido.");
                    }
                }
                _grants.Unbind(port);
                _stagedJustifications.Clear();
                _hub.Publish(new StatusNotification(
                    _policyVersion, _activeCategories, ProtectionActive: false));
            }
        }

        _logger.LogInformation(
            "Laco do minifiltro encerrado. {Answered} vereditos, {OverBudget} fora do prazo.",
            Interlocked.Read(ref _answered),
            Interlocked.Read(ref _overBudget));
    }

    private uint RetargetStage(SafeUploadRequest request)
    {
        if (_stageJournal is null || request.Version != Contract.Version ||
            request.TypedFlags.HasFlag(RequestFlags.PathTruncated) ||
            request.TypedFlags.HasFlag(RequestFlags.PathNotNormalized)) return PortVerdict.Deny;
        try
        {
            if (!Guid.TryParseExact(request.GetImageName(), "N", out Guid id)) return PortVerdict.Deny;
            string? destination = NtPathTranslator.ToDosPath(request.GetPath());
            if (destination is null) return PortVerdict.Deny;
            var entry = _stageJournal.ReadAsync(id, CancellationToken.None).GetAwaiter().GetResult();
            var policy = _policyStore.LoadAsync(CancellationToken.None).GetAwaiter().GetResult();
            var operation = new FileOperation(destination, Path.GetFileName(destination),
                Path.GetExtension(destination), 0, DateTime.MinValue, entry.Transfer.ProcessName,
                entry.Transfer.ProcessId, destination, entry.Transfer.Destination);
            if (!policy.IsMonitoredDestination(operation)) return PortVerdict.Deny;
            _stageJournal.RetargetAsync(id, checked((int)request.RequestorProcessId),
                destination, request.Reserved != 0, CancellationToken.None).GetAwaiter().GetResult();
            return PortVerdict.Allow;
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Falha ao renomear transferencia privada {RequestId}.", request.RequestId);
            return PortVerdict.Deny;
        }
    }

    private (uint Verdict, string? StageName) AllocateStage(SafeUploadRequest request)
    {
        if (_stageAllocator is null || request.Version != Contract.Version ||
            request.TypedFlags.HasFlag(RequestFlags.PathTruncated) ||
            request.TypedFlags.HasFlag(RequestFlags.PathNotNormalized))
        {
            return (PortVerdict.Deny, null);
        }

        try
        {
            string? destination = NtPathTranslator.ToDosPath(request.GetPath());
            if (destination is null)
            {
                return (PortVerdict.Deny, null);
            }

            // S: is the disposable VHDX used to exercise the removable
            // destination policy path in this test-only allocation gate.
            var kind = request.TypedFlags.HasFlag(RequestFlags.StageNetwork)
                ? DestinationKind.NetworkShare
                : request.TypedFlags.HasFlag(RequestFlags.StageRemovable) ||
                  destination.StartsWith(@"S:\SafeUpload\Escopo Monitorado\", StringComparison.OrdinalIgnoreCase)
                    ? DestinationKind.RemovableDrive : DestinationKind.Cloud;
            Policy policy = _policyStore.LoadAsync(CancellationToken.None).GetAwaiter().GetResult();
            var destinationOperation = new FileOperation(destination, Path.GetFileName(destination),
                Path.GetExtension(destination), 0, DateTime.MinValue, request.GetImageName(),
                checked((int)request.RequestorProcessId), destination, kind);
            if (!policy.IsMonitoredDestination(destinationOperation)) return (PortVerdict.Deny, null);
            StagedTransfer? previous = null;
            string processName = request.GetImageName();
            if (request.TypedFlags.HasFlag(RequestFlags.StageFollowup))
            {
                if (_stageJournal is null ||
                    !Guid.TryParseExact(processName, "N", out Guid previousId))
                {
                    return (PortVerdict.Deny, null);
                }
                var prior = _stageJournal.ReadAsync(previousId, CancellationToken.None)
                    .GetAwaiter().GetResult();
                if (!prior.SealedOnce ||
                    !string.Equals(prior.Transfer.DestinationPath, destination,
                        StringComparison.OrdinalIgnoreCase) ||
                    prior.Transfer.ProcessId != checked((int)request.RequestorProcessId))
                {
                    return (PortVerdict.Deny, null);
                }
                previous = prior.Transfer;
                processName = previous.ProcessName;
            }
            var transfer = _stageAllocator.AllocateAsync(
                destination, kind, processName,
                checked((int) request.RequestorProcessId),
                SessionResolver.TryGetSessionId(checked((int) request.RequestorProcessId)),
                request.Reserved, previous,
                CancellationToken.None).GetAwaiter().GetResult();
            return (PortVerdict.Allow, Path.GetFileName(transfer.StagePath));
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Falha ao reservar estagio para a requisicao {RequestId}.",
                request.RequestId);
            return (PortVerdict.Deny, null);
        }
    }

    private uint SealStage(SafeUploadRequest request)
    {
        if (_stageJournal is null || request.Version != Contract.Version ||
            request.TypedFlags.HasFlag(RequestFlags.PathTruncated) ||
            request.TypedFlags.HasFlag(RequestFlags.PathNotNormalized))
        {
            return PortVerdict.Deny;
        }

        try
        {
            string? stage = NtPathTranslator.ToDosPath(request.GetPath());
            if (stage is null ||
                !string.Equals(Path.GetDirectoryName(stage),
                    Path.Combine(AgentPaths.RootDirectory, "staging"),
                    StringComparison.OrdinalIgnoreCase))
            {
                return PortVerdict.Deny;
            }

            string basename = Path.GetFileName(stage);
            if (basename.Length < 32 ||
                !Guid.TryParseExact(basename[..32], "N", out Guid id))
            {
                return PortVerdict.Deny;
            }

            var entry = _stageJournal.ReadAsync(id, CancellationToken.None)
                .GetAwaiter().GetResult();
            if (!string.Equals(entry.Transfer.StagePath, stage,
                    StringComparison.OrdinalIgnoreCase) ||
                entry.Transfer.ProcessId != checked((int)request.RequestorProcessId) ||
                entry.State is not (TransferJournalState.Allocated or TransferJournalState.Unsealed))
            {
                return PortVerdict.Deny;
            }

            _stageJournal.TransitionAsync(id, entry.State,
                TransferJournalState.Sealed, null, CancellationToken.None)
                .GetAwaiter().GetResult();
            return PortVerdict.Allow;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Falha ao selar estagio para a requisicao {RequestId}.",
                request.RequestId);
            return PortVerdict.Deny;
        }
    }

    private async Task PublishSealedLoopAsync(CancellationToken cancellationToken)
    {
        if (_stageJournal is null || _stagePublisher is null) return;

        while (!cancellationToken.IsCancellationRequested)
        {
            foreach (var entry in await _stageJournal.ReadPendingAsync(cancellationToken)
                         .ConfigureAwait(false))
            {
                if (entry.State != TransferJournalState.Sealed) continue;

                try
                {
                    await _stagePublisher.PublishAsync(entry.Transfer, cancellationToken)
                        .ConfigureAwait(false);
                }
                catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
                {
                    throw;
                }
                catch (Exception ex)
                {
                    _logger.LogError(ex, "Falha ao inspecionar transferencia selada {TransferId}.",
                        entry.Transfer.TransferId);
                    var current = await _stageJournal.ReadAsync(
                        entry.Transfer.TransferId, cancellationToken).ConfigureAwait(false);
                    if (current.State == TransferJournalState.Sealed &&
                        current.Transfer == entry.Transfer)
                    {
                        await _stageJournal.TransitionAsync(entry.Transfer.TransferId,
                            TransferJournalState.Sealed, TransferJournalState.Retained,
                            null, cancellationToken, entry.Transfer).ConfigureAwait(false);
                    }
                }
            }
            await Task.Delay(250, cancellationToken).ConfigureAwait(false);
        }
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

            // Classify supported files by content wherever they reside.
            // The minifilter only sets source scope for read opens. Its
            // path-sensitive stream cache is disabled in this mode.
            builder.WithAllSources();

            foreach (string image in policy.ExcludedProcesses)
            {
                builder.WithExcludedImage(image);
            }

            builder.WithVolumeKinds(scopes.RemovableDrives, scopes.NetworkPaths);

            // O prazo do kernel sai da RN-012, e nao de uma constante no
            // driver. O motor recebe menos do que o driver espera: a margem
            // e o que garante que a resposta chegue enquanto ainda ha quem
            // a receba.
            TimeSpan kernelDeadline = policy.InspectionTimeout + Margin;

            builder.WithVerdictTimeout(kernelDeadline);
            builder.WithAuditOnly(policy.AuditOnly);
            builder.WithOverrideAllowed(policy.OverrideAllowed);
            _budget = policy.InspectionTimeout;

            port.SetPolicy(builder.Build());
            _overrideAllowed = policy.OverrideAllowed;
            _policyVersion = policy.Version;
            _activeCategories = policy.ActiveCategories.Count;
            _hub.Publish(new StatusNotification(
                _policyVersion, _activeCategories, ProtectionActive: true,
                AuditOnly: policy.AuditOnly));

            _logger.LogInformation(
                "Politica v{Version} empurrada ao driver: {Extensions} extensoes, " +
                "{Paths} destinos, classificacao de fontes em todos os volumes.",
                policy.Version,
                scopes.Extensions.Count,
                scopes.DestinationPaths.Count);

            if (policy.AuditOnly)
            {
                // Em letras garrafais de proposito: uma maquina que alguem
                // acha protegida e nao esta e pior que uma sem agente.
                _logger.LogWarning(
                    "MODO AUDITORIA: nada sera negado. As operacoes sao avaliadas e contadas " +
                    "em WouldHaveDenied, que mede quanto o bloqueio custaria se fosse ligado.");
            }

            _logger.LogInformation(
                "Prazo: motor {Budget} ms (RN-012), kernel espera {Kernel} ms.",
                _budget.TotalMilliseconds,
                kernelDeadline.TotalMilliseconds);

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

        // Numa requisição de ORIGEM, negar não impede nada: o driver permite
        // a leitura e apenas marca o processo. É por isso que "não consegui
        // inspecionar" pode virar negação aqui sem custo para quem abre o
        // arquivo - e não pode do lado do destino, onde negar impede mesmo.
        bool sourceScope = request.TypedFlags.HasFlag(RequestFlags.ScopeSource);

        var stopwatch = Stopwatch.StartNew();

        try
        {
            using var budget = new CancellationTokenSource(_budget);

            // GetAwaiter().GetResult() e não .Result: preserva a exceção
            // original em vez de embrulhá-la em AggregateException. O laço é
            // síncrono por natureza — o kernel está bloqueado esperando.
            InspectionResult result = _inspection
                .InspectAsync(operation, budget.Token)
                .GetAwaiter()
                .GetResult();

            Announce(operation, result);

            if (result.IsBlocked)
            {
                return PortVerdict.Deny;
            }

            // Nao consegui inspecionar: marque, nao libere em silencio.
            //
            // Ha tres caminhos que chegam aqui - file_too_large,
            // unsupported_format e inspection_timeout - e nos tres o
            // conteudo nunca foi olhado. Liberar sem marcar significa que
            // um arquivo grande demais, ou de formato sem extrator, sai
            // livre para qualquer destino vigiado. O limite de 20 MB e
            // deliberado e previsivel, o que o torna trivial de explorar:
            // basta encher o arquivo ate passar do corte.
            //
            // O custo e um falso positivo: um arquivo legitimo que nao
            // coube na inspecao marca o processo pelo TTL da tabela. E
            // aceitavel porque a marca nao impede trabalho nenhum - so
            // escrita em destino vigiado - e porque a alternativa e um
            // buraco que a propria politica documenta como aberto.
            if (sourceScope && result.Verdict == Core.Domain.Verdict.AllowedWithoutInspection)
            {
                _logger.LogInformation(
                    "{Arquivo} nao pode ser inspecionado ({Motivo}): processo {Pid} marcado por precaucao.",
                    operation.FileName,
                    result.Reason ?? "sem motivo registrado",
                    operation.ProcessId);

                return PortVerdict.Deny;
            }

            return PortVerdict.Allow;
        }
        catch (OperationCanceledException)
        {
            Interlocked.Increment(ref _overBudget);

            _logger.LogWarning(
                "Inspecao de {Path} passou de {Budget} ms.{Consequencia}",
                operation.FileName,
                _budget.TotalMilliseconds,
                sourceScope ? " Processo marcado por precaucao." : " A operacao passou SEM INSPECAO.");

            // Mesma regra do caminho acima: na origem, marca; no destino,
            // libera, porque negar ali impede o trabalho de verdade.
            return sourceScope ? PortVerdict.Deny : PortVerdict.Allow;
        }
        catch (Exception ex)
        {
            // Fail-open, como o resto do agente: um DLP que bloqueia quando
            // quebra impede o usuário de trabalhar e é desligado na primeira
            // semana.
            _logger.LogError(
                ex,
                "Erro ao inspecionar {Path}.{Consequencia}",
                operation.FileName,
                sourceScope ? " Processo marcado por precaucao." : " Liberado sem inspecao.");

            return sourceScope ? PortVerdict.Deny : PortVerdict.Allow;
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

                // Um bloqueio fica elegivel a justificativa, e so ele. Isto e
                // o que impede a interface de liberar o que quiser: uma
                // justificativa so vale contra um identificador que o servico
                // registrou aqui, para a sessao que recebeu a notificacao.
                if (result.IsBlocked)
                {
                    _pending.Remember(auditEvent.EventId.ToString("D"), new PendingOverrides.Entry(
                        ProcessId: (uint) operation.ProcessId,
                        NtPath: PolicyBuilder.ToNtPath(operation.DestinationPath),
                        FileName: operation.FileName,
                        SessionId: sessionId,
                        ExpiresAt: DateTimeOffset.UtcNow + PendingOverrides.Window));
                }

                _hub.Publish(new EventNotification(
                    auditEvent, result.Findings,
                    OverrideAllowed: result.IsBlocked && _overrideAllowed), sessionId);
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

        // Os dois lados do escopo, e a distinção não é cosmética: o motor
        // julga origem pela lista de origens e destino pela de destinos.
        //
        // Tratar origem como Cloud - que foi a primeira versão disto - faz a
        // leitura ser julgada contra os caminhos de destino, não casar
        // nenhum e sair como fora de escopo. O arquivo nunca é aberto, o CPF
        // nunca é encontrado, nada é marcado, e a bateria vê apenas uma
        // escrita que passou.
        //
        // Origem vem primeiro porque uma requisição pode trazer as duas
        // flags, e nesse caso o que interessa é o conteúdo sendo lido.
        //
        // Sobra que o driver sabe mais do que consegue contar: ele conhece a
        // natureza do volume (removível, rede, fixo) e o protocolo não tem
        // campo para isso. O Reserved da requisição existe e resolveria.
        DestinationKind destination =
            request.TypedFlags.HasFlag(RequestFlags.ScopeSource) ? DestinationKind.SensitiveSource
            : request.TypedFlags.HasFlag(RequestFlags.ScopeDestination) ? DestinationKind.Cloud
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
