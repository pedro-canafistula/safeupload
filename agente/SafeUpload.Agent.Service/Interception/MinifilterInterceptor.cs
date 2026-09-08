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
    private readonly OverrideGrantQueue _grants;
    private readonly ILogger<MinifilterInterceptor> _logger;

    private long _overBudget;
    private long _answered;

    /// <summary>Compõe o interceptador.</summary>
    public MinifilterInterceptor(
        InspectionService inspection,
        IPolicyStore policyStore,
        IAuditSink auditSink,
        NotificationHub hub,
        PendingOverrides pending,
        OverrideGrantQueue grants,
        ILogger<MinifilterInterceptor> logger)
    {
        _inspection = inspection ?? throw new ArgumentNullException(nameof(inspection));
        _policyStore = policyStore ?? throw new ArgumentNullException(nameof(policyStore));
        _auditSink = auditSink ?? throw new ArgumentNullException(nameof(auditSink));
        _hub = hub ?? throw new ArgumentNullException(nameof(hub));
        _pending = pending ?? throw new ArgumentNullException(nameof(pending));
        _grants = grants ?? throw new ArgumentNullException(nameof(grants));
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
                // Entre uma requisicao e outra, e nao noutra thread: a porta
                // aceita um cliente, e quem o segura e este laco.
                DrainGrants(port);

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

            _logger.LogInformation(
                "Politica v{Version} empurrada ao driver: {Extensions} extensoes, " +
                "{Paths} destinos, {Sources} origens.",
                policy.Version,
                scopes.Extensions.Count,
                scopes.DestinationPaths.Count,
                scopes.SourcePaths.Count);

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
    /// Leva ao driver as concessoes que o canal de justificativas deixou.
    ///
    /// Falha aqui nao derruba o laco: uma concessao perdida significa que o
    /// usuario tentara de novo, enquanto um laco derrubado significa que
    /// ninguem mais e inspecionado.
    /// </summary>
    private void DrainGrants(FilterPort port)
    {
        while (_grants.TryDequeue(out OverrideGrantQueue.Grant grant))
        {
            try
            {
                port.GrantOverride(grant.ProcessId, grant.NtPath, grant.Duration);
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Falha ao conceder excecao para o processo {Pid}.", grant.ProcessId);
            }
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
