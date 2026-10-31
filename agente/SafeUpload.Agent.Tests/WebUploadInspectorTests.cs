using System.Text;
using Microsoft.Extensions.Logging.Abstractions;
using SafeUpload.Agent.Core.Application;
using SafeUpload.Agent.Core.Contracts;
using SafeUpload.Agent.Core.Domain;
using SafeUpload.Agent.Core.Infrastructure;
using SafeUpload.Agent.Core.Infrastructure.Extraction;
using SafeUpload.Agent.Network.Http;
using SafeUpload.Agent.Network.Proxy;
using SafeUpload.Agent.Service.Network;
using SafeUpload.Agent.Service.Notifications;

namespace SafeUpload.Agent.Tests;

/// <summary>
/// A ponte entre o proxy e o motor, e o aviso ao usuário (Fase 6): o bloqueio
/// é anunciado só ao dono do navegador, e o evento sai no nome dele.
/// </summary>
public sealed class WebUploadInspectorTests : IDisposable
{
    private readonly TestWorkspace _workspace = new();
    private readonly LocalQueueAuditSink _sink;
    private readonly NotificationHub _hub = new(new NoRecord(), NullLogger<NotificationHub>.Instance);
    private readonly WebUploadInspector _inspector;

    public WebUploadInspectorTests()
    {
        _sink = new LocalQueueAuditSink(_workspace.QueueFile);

        _inspector = new WebUploadInspector(
            new WebInspectionService(new LocalPolicyStore(_workspace.PolicyFile), _sink, ExtractorRegistry.CreateDefault()),
            NullLogger<WebUploadInspector>.Instance,
            _hub);
    }

    public void Dispose() => _workspace.Dispose();

    private static UploadRequest Request(string body, int? processId)
    {
        var headers = new HttpHeaders();
        headers.Add("Content-Type", "application/json");

        return new UploadRequest(
            "chat.example", 443, new HttpRequestHead("POST", "/conversa?sessao=abc", "HTTP/1.1", headers),
            Encoding.UTF8.GetBytes(body), processId, Encrypted: true);
    }

    [Fact]
    public async Task Bloqueio_e_anunciado_so_ao_dono_do_navegador()
    {
        // O "navegador" é o próprio processo de teste.
        SessionResolver.ProcessIdentity owner = SessionResolver.GetRequiredProcessIdentity(Environment.ProcessId);

        using NotificationSubscription dono = _hub.Subscribe(owner.SessionId, owner.UserSid.Value);
        using NotificationSubscription outroUsuario = _hub.Subscribe(owner.SessionId, "S-1-5-21-1-2-3-1001");
        using NotificationSubscription outraSessao = _hub.Subscribe(owner.SessionId + 1, owner.UserSid.Value);

        UploadDecision decision = await _inspector.InspectAsync(
            Request("{\"prompt\":\"meu cpf 529.982.247-25\"}", Environment.ProcessId), CancellationToken.None);

        Assert.False(decision.Allowed);
        Assert.Contains("Cpf", decision.Reason);

        Assert.True(dono.Reader.TryRead(out AgentNotification? received));
        EventNotification notification = Assert.IsType<EventNotification>(received);
        Assert.Equal(AuditChannel.Web, notification.Event.Channel);
        Assert.Equal(Verdict.Blocked, notification.Event.Verdict);
        Assert.Equal("https://chat.example", notification.Event.DestinationPath);
        Assert.DoesNotContain("conversa", notification.Event.DestinationPath);
        Assert.DoesNotContain("sessao", notification.Event.DestinationPath);
        Assert.Equal(System.Security.Principal.WindowsIdentity.GetCurrent().Name, notification.Event.UserName, ignoreCase: true);
        Assert.Equal(owner.UserSid.Value, notification.Event.OwnerSid);
        var history = await new AuditHistoryReader(new LocalQueueAuditSink(_workspace.QueueFile))
            .ReadAsync("RENAMED\\same-user", CancellationToken.None, owner.UserSid.Value);
        Assert.Equal(notification.Event.EventId, Assert.Single(history.Events).EventId);
        Assert.NotEmpty(notification.Findings);
        Assert.False(notification.OverrideAllowed);

        Assert.False(outroUsuario.Reader.TryRead(out _));
        Assert.False(outraSessao.Reader.TryRead(out _));
    }

    /// <summary>
    /// Sem saber de quem é a conexão, o envio é barrado e registrado, mas não
    /// é anunciado a ninguém: difundir mostraria a um usuário o que outro fez.
    /// </summary>
    [Fact]
    public async Task Sem_dono_conhecido_bloqueia_e_registra_mas_nao_anuncia()
    {
        using NotificationSubscription qualquer = _hub.Subscribe();

        UploadDecision decision = await _inspector.InspectAsync(
            Request("{\"prompt\":\"meu cpf 529.982.247-25\"}", processId: null), CancellationToken.None);

        Assert.False(decision.Allowed);
        Assert.Single(await _sink.ReadRecentAsync(5, CancellationToken.None));
        Assert.False(qualquer.Reader.TryRead(out _));
    }

    [Fact]
    public async Task Envio_limpo_e_liberado_sem_aviso()
    {
        SessionResolver.ProcessIdentity owner = SessionResolver.GetRequiredProcessIdentity(Environment.ProcessId);
        using NotificationSubscription dono = _hub.Subscribe(owner.SessionId, owner.UserSid.Value);

        UploadDecision decision = await _inspector.InspectAsync(
            Request("{\"prompt\":\"qual a capital da França?\"}", Environment.ProcessId), CancellationToken.None);

        Assert.True(decision.Allowed);
        Assert.False(dono.Reader.TryRead(out _));
    }

    private sealed class NoRecord : INotificationRecord
    {
        public void Append(AgentNotification notification, uint? targetSessionId)
        {
        }
    }
}
