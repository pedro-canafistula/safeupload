using Microsoft.Extensions.Logging.Abstractions;
using SafeUpload.Agent.App.ViewModels;
using SafeUpload.Agent.Core.Application;
using SafeUpload.Agent.Core.Contracts;
using SafeUpload.Agent.Service.Diagnostics;
using SafeUpload.Agent.Service.Notifications;

namespace SafeUpload.Agent.Tests;

public sealed class CommunicationPresentationTests
{
    [Fact]
    public void Operacoes_independentes_nao_alteram_protecao_e_repeticao_nao_publica()
    {
        var health = new CommunicationHealth(true);
        var hub = NotificationTestHub.Create();
        var publisher = new CommunicationStatusPublisher(health, hub);
        hub.Publish(new StatusNotification(7, 2, true));
        using var subscriber = hub.Subscribe();
        using (var attempt = new CommunicationObservation(health, CommunicationOperation.Heartbeat)) attempt.Success(200);
        using (var attempt = new CommunicationObservation(health, CommunicationOperation.Policy))
            attempt.Failure(CommunicationFailure.HttpRejected, 404, PolicyLoadSource.Disk);
        publisher.PublishSnapshot();
        Assert.True(subscriber.Reader.TryRead(out var message));
        var status = Assert.IsType<StatusNotification>(message);
        Assert.True(status.ProtectionActive);
        Assert.Equal(7, status.PolicyVersion);
        Assert.Equal(AdministrationOperationState.Success, status.Communication!.Heartbeat.State);
        Assert.NotNull(status.Communication.Heartbeat.LastSuccessUtc);
        Assert.Equal(AdministrationOperationState.Failure, status.Communication.Policy.State);
        Assert.Equal(AdministrationOperationState.NotAttempted, status.Communication.Audit.State);
        Assert.DoesNotContain("httpStatus", NotificationProtocol.Serialize(status), StringComparison.OrdinalIgnoreCase);
        publisher.PublishSnapshot();
        Assert.False(subscriber.Reader.TryRead(out _));
    }

    [Fact]
    public void Recuperacao_preserva_ultima_confirmacao_e_reabertura_recebe_so_estado_atual()
    {
        var health = new CommunicationHealth(true);
        var hub = NotificationTestHub.Create();
        var publisher = new CommunicationStatusPublisher(health, hub);
        publisher.PublishSnapshot(); // Can run before an interceptor has reported protection.
        hub.Publish(new StatusNotification(3, 1, false));
        Assert.Equal(AdministrationOperationState.NotAttempted, hub.GetRecordedStatus()!.Communication!.Audit.State);
        using (var attempt = new CommunicationObservation(health, CommunicationOperation.Audit)) attempt.Success();
        publisher.PublishSnapshot();
        var confirmed = hub.GetRecordedStatus()!.Communication!.Audit.LastSuccessUtc;
        using (var attempt = new CommunicationObservation(health, CommunicationOperation.Audit))
            attempt.Failure(CommunicationFailure.TransportError);
        publisher.PublishSnapshot();
        Assert.Equal(confirmed, hub.GetRecordedStatus()!.Communication!.Audit.LastSuccessUtc);
        using (var attempt = new CommunicationObservation(health, CommunicationOperation.Audit)) attempt.Success();
        publisher.PublishSnapshot();
        using var reopened = hub.Subscribe();
        Assert.False(reopened.Reader.TryRead(out _)); // No stale status replay as file events.
        var current = hub.GetRecordedStatus()!;
        Assert.False(current.ProtectionActive);
        Assert.Equal(AdministrationOperationState.Success, current.Communication!.Audit.State);
        hub.Publish(new StatusNotification(4, 2, true));
        Assert.Equal(current.Communication, hub.CurrentStatus!.Communication);
    }

    [Fact]
    public void Falha_de_registro_suprime_entrega_e_publicador_tenta_novamente()
    {
        var record = new FailingRecord();
        var hub = new NotificationHub(record, NullLogger<NotificationHub>.Instance);
        hub.Publish(new StatusNotification(1, 1, true));
        using var subscriber = hub.Subscribe();
        var publisher = new CommunicationStatusPublisher(new CommunicationHealth(false), hub);
        record.Fail = true;
        publisher.PublishSnapshot();
        Assert.Null(hub.CurrentStatus!.Communication);
        Assert.False(subscriber.Reader.TryRead(out _));
        record.Fail = false;
        publisher.PublishSnapshot();
        Assert.True(subscriber.Reader.TryRead(out var message));
        Assert.Equal(AdministrationOperationState.NotConfigured,
            Assert.IsType<StatusNotification>(message).Communication!.Heartbeat.State);
    }

    [Fact]
    public void Contrato_aditivo_aceita_status_antigo_e_preserva_timestamps_no_roundtrip()
    {
        var old = Assert.IsType<StatusNotification>(NotificationProtocol.Deserialize(
            "{\"type\":\"status\",\"policyVersion\":1,\"activeCategories\":2,\"protectionActive\":true}"));
        Assert.Null(old.Communication);
        var health = new CommunicationHealth(true);
        var hub = NotificationTestHub.Create();
        using (var attempt = new CommunicationObservation(health, CommunicationOperation.Heartbeat)) attempt.Success();
        new CommunicationStatusPublisher(health, hub).PublishSnapshot();
        hub.Publish(old);
        var current = hub.GetRecordedStatus()!;
        Assert.Equal(current, NotificationProtocol.Deserialize(NotificationProtocol.Serialize(current)));
    }

    [Theory]
    [InlineData(AdministrationOperationState.NotConfigured, "Não configurado")]
    [InlineData(AdministrationOperationState.NotAttempted, "Aguardando tentativa")]
    [InlineData(AdministrationOperationState.InProgress, "Tentativa em andamento")]
    [InlineData(AdministrationOperationState.Success, "Última tentativa confirmada")]
    [InlineData(AdministrationOperationState.Failure, "Falha na última tentativa")]
    [InlineData(AdministrationOperationState.Cancelled, "Última tentativa cancelada")]
    [InlineData(AdministrationOperationState.Unknown, "Estado desconhecido")]
    public void Tela_descreve_tentativa_sem_afirmar_conectividade_atual(AdministrationOperationState state, string caption)
    {
        var model = new CommunicationViewModel();
        var confirmed = DateTimeOffset.Parse("2026-01-01T12:34:56Z");
        var value = new AdministrationOperationStatus(state, confirmed.AddMinutes(1), confirmed);
        model.Apply(new(value, value, value));
        Assert.StartsWith(caption, model.Heartbeat);
        Assert.Contains(confirmed.ToLocalTime().ToString("dd/MM/yyyy HH:mm:ss"), model.Heartbeat);
        Assert.Equal(model.Heartbeat, model.Audit);
        model.SetDisconnected();
        Assert.Equal("Serviço indisponível", model.Policy);
        Assert.DoesNotContain("2026", model.Audit);
        model.Apply(null);
        Assert.Contains("Informação indisponível", model.Heartbeat);
    }

    private sealed class FailingRecord : INotificationRecord
    {
        public bool Fail;
        public void Append(AgentNotification notification, uint? targetSessionId)
        {
            if (Fail) throw new IOException("Synthetic recorder failure");
        }
    }
}
