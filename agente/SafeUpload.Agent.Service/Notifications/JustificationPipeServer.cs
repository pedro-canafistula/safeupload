using System.IO.Pipes;
using System.Security.AccessControl;
using System.Security.Principal;
using SafeUpload.Agent.Core.Application;
using SafeUpload.Agent.Core.Contracts;
using SafeUpload.Agent.Core.Domain;

namespace SafeUpload.Agent.Service.Notifications;

/// <summary>
/// Recebe justificativas do aplicativo e, quando elas conferem, concede a
/// exceção no driver.
///
/// <para>É o único canal que vai da interface para o serviço, e o desenho
/// dele é o que preserva a garantia que o canal de notificação declara. A
/// interface não altera veredito: ela informa um motivo para um bloqueio que
/// o serviço registrou, identificado por um evento que só o serviço emite.
/// Quatro coisas são conferidas aqui, e nenhuma depende de o cliente se
/// comportar — o evento existe, está no prazo, foi entregue àquela sessão, e
/// a política permite justificativa.</para>
///
/// <para><b>A ordem importa.</b> A justificativa é gravada na auditoria
/// <b>antes</b> de a exceção ser concedida. O contrário — conceder e registrar
/// depois — deixa de registrar exatamente quando o segundo passo falha, e o
/// que sobra é o buraco sem o registro dele.</para>
/// </summary>
public sealed class JustificationPipeServer : BackgroundService
{
    private const int MaxServerInstances = 16;

    /// <summary>
    /// Prazo da exceção no driver.
    ///
    /// É o tempo entre o usuário clicar em confirmar e o programa dele tentar
    /// a operação de novo. Não precisa ser mais que isso, e o driver limita de
    /// qualquer forma.
    /// </summary>
    private static readonly TimeSpan GrantDuration = TimeSpan.FromSeconds(30);

    private readonly PendingOverrides _pending;
    private readonly IPolicyStore _policyStore;
    private readonly IAuditSink _auditSink;
    private readonly OverrideGrantQueue _grants;
    private readonly ILogger<JustificationPipeServer> _logger;

    /// <summary>Compõe o servidor.</summary>
    public JustificationPipeServer(
        PendingOverrides pending,
        IPolicyStore policyStore,
        IAuditSink auditSink,
        OverrideGrantQueue grants,
        ILogger<JustificationPipeServer> logger)
    {
        _pending = pending ?? throw new ArgumentNullException(nameof(pending));
        _policyStore = policyStore ?? throw new ArgumentNullException(nameof(policyStore));
        _auditSink = auditSink ?? throw new ArgumentNullException(nameof(auditSink));
        _grants = grants ?? throw new ArgumentNullException(nameof(grants));
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
    }

    /// <inheritdoc />
    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        while (!stoppingToken.IsCancellationRequested)
        {
            NamedPipeServerStream pipe = CreatePipe();

            try
            {
                await pipe.WaitForConnectionAsync(stoppingToken).ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
                await pipe.DisposeAsync().ConfigureAwait(false);
                return;
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Falha ao aceitar conexao no canal de justificativas.");
                await pipe.DisposeAsync().ConfigureAwait(false);
                continue;
            }

            // Sem await: um cliente lento nao pode impedir o proximo de
            // conectar. O canal e raro, entao nao ha fila a controlar.
            _ = ServeAsync(pipe, stoppingToken);
        }
    }

    private async Task ServeAsync(NamedPipeServerStream pipe, CancellationToken stoppingToken)
    {
        uint? sessionId = SessionResolver.TryGetClientSessionId(pipe.SafePipeHandle);

        try
        {
            using var reader = new StreamReader(pipe, JustificationProtocol.Encoding);

            string? line = await reader.ReadLineAsync(stoppingToken).ConfigureAwait(false);

            JustificationRequest? request = JustificationProtocol.Deserialize(line);

            if (request is null)
            {
                _logger.LogWarning("Pedido de justificativa malformado, descartado.");
                return;
            }

            await HandleAsync(request, sessionId, stoppingToken).ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Falha ao atender o canal de justificativas.");
        }
        finally
        {
            await pipe.DisposeAsync().ConfigureAwait(false);
        }
    }

    private async Task HandleAsync(
        JustificationRequest request,
        uint? sessionId,
        CancellationToken cancellationToken)
    {
        Policy policy = await _policyStore.LoadAsync(cancellationToken).ConfigureAwait(false);

        if (!policy.OverrideAllowed)
        {
            // Não é um erro do cliente: a política pode ter mudado entre a
            // notificação e a resposta. O driver recusaria de qualquer forma.
            _logger.LogInformation(
                "Justificativa recebida com a politica em modo sem justificativa. Ignorada.");
            return;
        }

        PendingOverrides.Entry? pendente = _pending.Consume(request.EventId, sessionId);

        if (pendente is null)
        {
            _logger.LogWarning(
                "Justificativa para um bloqueio que nao existe, venceu, ou e de outra sessao. Ignorada.");
            return;
        }

        // Auditar ANTES de conceder. Concedendo primeiro, uma falha aqui
        // deixaria a excecao de pe sem registro nenhum de quem a pediu.
        await _auditSink.RecordOverrideAsync(
            request.EventId,
            request.Justification,
            cancellationToken).ConfigureAwait(false);

        _grants.Enqueue(pendente.ProcessId, pendente.NtPath, GrantDuration);

        _logger.LogWarning(
            "Excecao concedida para {Arquivo}, processo {Pid}, justificada pelo usuario.",
            pendente.FileName,
            pendente.ProcessId);
    }

    /// <summary>
    /// Cria o pipe. A ACL segue a do canal de notificações pelas mesmas
    /// razões documentadas lá — inclusive o controle total para a conta que
    /// executa, sem o qual a segunda instância falha com acesso negado.
    /// </summary>
    private static NamedPipeServerStream CreatePipe()
    {
        var security = new PipeSecurity();

        // ReadWrite e não Write: um named pipe exige o direito de leitura
        // para a negociação da conexão, mesmo num canal que só recebe. A
        // direção real é imposta por PipeDirection.In abaixo.
        security.AddAccessRule(new PipeAccessRule(
            new SecurityIdentifier(WellKnownSidType.BuiltinUsersSid, domainSid: null),
            PipeAccessRights.ReadWrite,
            AccessControlType.Allow));

        security.AddAccessRule(new PipeAccessRule(
            new SecurityIdentifier(WellKnownSidType.LocalSystemSid, domainSid: null),
            PipeAccessRights.FullControl,
            AccessControlType.Allow));

        using var current = WindowsIdentity.GetCurrent();

        if (current.User is { } owner)
        {
            security.AddAccessRule(new PipeAccessRule(
                owner,
                PipeAccessRights.FullControl,
                AccessControlType.Allow));
        }

        return NamedPipeServerStreamAcl.Create(
            JustificationProtocol.PipeName,
            PipeDirection.In,
            MaxServerInstances,
            PipeTransmissionMode.Byte,
            PipeOptions.Asynchronous,
            inBufferSize: 8 * 1024,
            outBufferSize: 0,
            security);
    }
}
