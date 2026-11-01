using SafeUpload.Agent.Service.Diagnostics;
using System.IO.Pipes;
using System.Security.AccessControl;
using System.Security.Principal;
using SafeUpload.Agent.Core.Application;
using SafeUpload.Agent.Core.Contracts;
using SafeUpload.Agent.Core.Domain;

using SafeUpload.Agent.Service.Drive;

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
    private static readonly TimeSpan ReadTimeout = TimeSpan.FromSeconds(5);
    private readonly SemaphoreSlim _connections = new(MaxServerInstances, MaxServerInstances);

    private readonly IPolicyStore _policyStore;
    private readonly IAuditSink _auditSink;
    private readonly DriveJustifications _justifications;
    private readonly ILogger<JustificationPipeServer> _logger;

    /// <summary>Compõe o servidor.</summary>
    public JustificationPipeServer(
        IPolicyStore policyStore,
        IAuditSink auditSink,
        DriveJustifications justifications,
        ILogger<JustificationPipeServer> logger)
    {
        _policyStore = policyStore ?? throw new ArgumentNullException(nameof(policyStore));
        _auditSink = auditSink ?? throw new ArgumentNullException(nameof(auditSink));
        _justifications = justifications ?? throw new ArgumentNullException(nameof(justifications));
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
    }

    /// <inheritdoc />
    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        while (!stoppingToken.IsCancellationRequested)
        {
            try { await _connections.WaitAsync(stoppingToken).ConfigureAwait(false); }
            catch (OperationCanceledException) { return; }
            NamedPipeServerStream? pipe = null;

            try
            {
                pipe = CreatePipe();
                await pipe.WaitForConnectionAsync(stoppingToken).ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
                if (pipe is not null) await pipe.DisposeAsync().ConfigureAwait(false);
                _connections.Release();
                return;
            }
            catch (Exception ex)
            {
                _logger.LogSafeWarning(ex, "Falha ao aceitar conexao no canal de justificativas.");
                if (pipe is not null) await pipe.DisposeAsync().ConfigureAwait(false);
                _connections.Release();
                continue;
            }

            // Bound active requests and reserve an instance before accepting.
            // Slow readers release their slot at the request deadline.
            _ = ServeAsync(pipe, stoppingToken);
        }
    }

    private async Task ServeAsync(NamedPipeServerStream pipe, CancellationToken stoppingToken)
    {
        SessionResolver.ProcessIdentity? client = SessionResolver.TryGetClientIdentity(pipe.SafePipeHandle);
        uint? sessionId = client?.SessionId;
        string? clientSid = client?.UserSid.Value;

        try
        {
            using var reader = new StreamReader(
                pipe, JustificationProtocol.Encoding,
                detectEncodingFromByteOrderMarks: false, bufferSize: 1024,
                leaveOpen: true);

            using var readDeadline = CancellationTokenSource.CreateLinkedTokenSource(stoppingToken);
            readDeadline.CancelAfter(ReadTimeout);
            string? line = await BoundedPipeLine.ReadAsync(reader, readDeadline.Token).ConfigureAwait(false);

            JustificationRequest? request = JustificationProtocol.Deserialize(line);

            if (request is null)
            {
                _logger.LogWarning("Pedido de justificativa malformado, descartado.");
            }

            bool accepted = false;
            if (request is not null)
            {
                try { accepted = await HandleAsync(request, sessionId, clientSid, stoppingToken).ConfigureAwait(false); }
                catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested) { throw; }
                catch (Exception ex)
                {
                    // A stale generation or failed audit/publication is a
                    // rejection, not an unexplained EOF to the real client.
                    _logger.LogSafeWarning(ex, "Justificativa recusada durante auditoria ou publicacao.");
                }
            }

            await using var writer = new StreamWriter(
                pipe, JustificationProtocol.Encoding, bufferSize: 1024,
                leaveOpen: true);
            using var writeDeadline = CancellationTokenSource.CreateLinkedTokenSource(stoppingToken);
            writeDeadline.CancelAfter(TimeSpan.FromSeconds(1));
            await writer.WriteLineAsync((accepted
                ? JustificationProtocol.Accepted
                : JustificationProtocol.Rejected).AsMemory(), writeDeadline.Token).ConfigureAwait(false);
            await writer.FlushAsync(writeDeadline.Token).ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
        }
        catch (Exception ex)
        {
            _logger.LogSafeWarning(ex, "Falha ao atender o canal de justificativas.");
        }
        finally
        {
            try { await pipe.DisposeAsync().ConfigureAwait(false); }
            finally { _connections.Release(); }
        }
    }

    private async Task<bool> HandleAsync(
        JustificationRequest request,
        uint? sessionId,
        string? clientSid,
        CancellationToken cancellationToken)
    {
        Policy policy = await _policyStore.LoadAsync(cancellationToken).ConfigureAwait(false);

        if (!policy.OverrideAllowed)
        {
            // Não é um erro do cliente: a política pode ter mudado entre a
            // notificação e a resposta. O driver recusaria de qualquer forma.
            _logger.LogInformation(
                "Justificativa recebida com a politica em modo sem justificativa. Ignorada.");
            return false;
        }

        if (!_justifications.TryConsume(request.EventId, sessionId, clientSid, out var approve) || approve is null)
        {
            _logger.LogWarning(
                "Justificativa para um bloqueio que nao existe, venceu, ou e de outra sessao. Ignorada.");
            return false;
        }

        // Auditar ANTES de publicar: uma falha aqui nao pode deixar a versao publicada sem registro de quem pediu.
        await RecordJustificationAsync(request, clientSid, cancellationToken).ConfigureAwait(false);
        bool published = approve();
        _logger.LogWarning("Versao {EventId} justificada pelo usuario; publicada={Published}.", request.EventId, published);
        return published;
    }

    internal Task RecordJustificationAsync(JustificationRequest request, string? clientSid,
        CancellationToken cancellationToken)
        => _auditSink.RecordOverrideAsync(AuditOverride.FromNewSubmission(Guid.Parse(request.EventId), request.Justification,
            DateTimeOffset.UtcNow, clientSid ?? "Não identificado", Environment.MachineName), cancellationToken);

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
            PipeDirection.InOut,
            MaxServerInstances,
            PipeTransmissionMode.Byte,
            PipeOptions.Asynchronous,
            inBufferSize: 8 * 1024,
            outBufferSize: 1024,
            security);
    }
}
