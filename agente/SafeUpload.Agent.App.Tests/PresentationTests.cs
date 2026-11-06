using SafeUpload.Agent.App.Notifications;
using SafeUpload.Agent.App.ViewModels;
using SafeUpload.Agent.Core.Contracts;
using SafeUpload.Agent.Core.Domain;

namespace SafeUpload.Agent.App.Tests;

public sealed class PresentationTests
{
    [Theory]
    [InlineData("published", "PUBLICADO", "Publicado")]
    [InlineData("blocked", "RESTRITO", "Bloqueado")]
    [InlineData("alert", "PUBLICADO COM ALERTA", "Publicado com alerta")]
    [InlineData("incomplete", "INCONCLUSIVO / BLOQUEADO", "Inconclusivo / bloqueado")]
    [InlineData("unknown", "NÃO CONFIRMADO", "Não confirmado")]
    [InlineData("pending", "PENDENTE", "Publicação pendente")]
    public void Activity_history_and_queue_agree_on_the_actual_outcome(string scenario, string label, string queueLabel)
    {
        var item = Samples.Event(scenario);
        var activity = new ActivityRowViewModel(item);
        var history = new HistoryRowViewModel(item);
        var queue = new QueueRowViewModel(item);
        Assert.Equal(label, activity.Status.Text);
        Assert.Equal(activity.Status, history.Status);
        Assert.Equal(queueLabel, queue.Verdict);
        Assert.Equal(item.EventId, activity.EventId);
        Assert.Equal(item.EventId, history.EventId);
        Assert.Equal(item.EventId, queue.EventId);
        if (scenario is "pending" or "unknown" or "incomplete")
        {
            Assert.DoesNotContain("aprovad", activity.Description, StringComparison.OrdinalIgnoreCase);
            Assert.DoesNotContain("liberado sem inspeção", history.Reason);
        }
    }

    [Theory]
    [InlineData("file_too_large")]
    [InlineData("unsupported_format")]
    [InlineData("inspection_timeout")]
    [InlineData("inspection_limit")]
    [InlineData("not_enough_staging_space")]
    [InlineData("parse_error:InvalidDataException")]
    [InlineData("archive_encrypted")]
    [InlineData("archive_unsupported_member")]
    [InlineData("archive_unsupported_structure")]
    [InlineData("archive_7z_unavailable")]
    public void Inspection_failure_explanation_does_not_claim_a_release(string reason)
    {
        Assert.True(ReasonLabels.IsInspectionFailure(reason));
        Assert.DoesNotContain("liberad", ReasonLabels.Describe(reason), StringComparison.OrdinalIgnoreCase);
        Assert.NotNull(StagedPublicationPresentation.FailureFor(reason));
    }

    [Theory]
    [InlineData("published", false)]
    [InlineData("alert", true)]
    public void Completed_balloon_distinguishes_clean_publication_and_findings(string scenario, bool alert)
    {
        var item = Samples.Event(scenario);
        var notice = Samples.Transfer(item);
        var shown = StagedPublicationPresentation.Released(item.FileName, notice);
        Assert.Contains("envio concluído", shown.Title);
        Assert.Equal(alert, shown.Title.Contains("alerta"));
        Assert.Contains(item.PublishedSha256Hex!, shown.Message);
    }

    [Theory]
    [InlineData("unknown")]
    [InlineData("pending")]
    [InlineData("incomplete")]
    [InlineData("blocked")]
    public void A_contradictory_released_message_never_becomes_a_success_balloon(string scenario)
    {
        var item = Samples.Event(scenario);
        var shown = StagedPublicationPresentation.Released(item.FileName, Samples.Transfer(item) with { PublishedSha256Hex = Samples.Hash });
        Assert.Contains("não confirmada", shown.Title);
        Assert.DoesNotContain("foi enviado", shown.Message);
    }

    [Fact]
    public void Classification_without_publication_evidence_does_not_claim_a_transfer()
    {
        var item = Samples.Event("alert") with { PublishedSha256Hex = null };
        Assert.Equal("APROVADO COM ACHADOS", new HistoryRowViewModel(item).Status.Text);
        Assert.DoesNotContain("Publicado", new ActivityRowViewModel(item).Description);
        Assert.Contains("não confirmada", StagedPublicationPresentation.Released(item.FileName, Samples.Transfer(item)).Title);
    }

    [Fact]
    public void A_justified_publication_keeps_its_inconclusive_inspection_visible()
    {
        var item = Samples.Event("published") with { NotInspectedReason = "inspection_timeout" };
        Assert.Equal("PUBLICADO COM RESSALVA", new HistoryRowViewModel(item).Status.Text);
        Assert.Equal("Publicado com ressalva", new QueueRowViewModel(item).Verdict);
        Assert.Contains("inspeção inconclusiva", new ActivityRowViewModel(item).Description);
        Assert.Contains("não foi concluída", StagedPublicationPresentation.Released(item.FileName, Samples.Transfer(item)).Message);
    }

    [Fact]
    public void Failed_backend_communication_does_not_erase_reported_local_protection()
    {
        var model = new StatusViewModel();
        model.ApplyStatus(Samples.Status(true));
        Assert.True(model.Connected);
        Assert.True(model.MonitoringActive);
        Assert.Equal("v7", model.PolicyVersion);
        Assert.Contains("falha", model.Communication.Summary);
        Assert.Equal("Proteção confirmada", model.SecurityState);
        model.SetDisconnected();
        Assert.False(model.MonitoringActive);
        Assert.False(model.Connected);
        Assert.Equal("v7", model.PolicyVersion);
        Assert.Contains("ÚLTIMA POLÍTICA", model.ActiveCategoriesCaption);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void A_running_service_without_confirmed_preventive_coverage_is_not_green(bool audit)
    {
        var model = new StatusViewModel();
        model.ApplyStatus(new StatusNotification(7, 1, true, AuditOnly: audit));
        Assert.True(model.Connected);
        Assert.False(model.MonitoringActive);
        Assert.Contains("não confirmada", model.SecurityState);
        model.ApplyStatus(Samples.Status(false) with { AuditOnly = audit });
        Assert.False(model.MonitoringActive);
        model.ApplyStatus(Samples.Status(true) with { PolicyVersion = 0 });
        Assert.False(model.MonitoringActive);
    }

    [Fact]
    public void Alert_mode_does_not_promise_that_every_failure_is_allowed()
    {
        var model = new StatusViewModel();
        model.ApplyStatus(Samples.Status(true) with { AuditOnly = true });
        Assert.Equal("Em auditoria", model.SecurityState);
        Assert.DoesNotContain("SEM BLOQUEIO", model.SecurityCaption);
        Assert.Contains("FALHAS PODEM BLOQUEAR", model.SecurityCaption);
    }

    [Fact]
    public void Replay_confirmation_and_reconnection_keep_one_event_and_update_delivery_without_an_alert()
    {
        var model = new AgentViewModel(new StatusViewModel(), new HistoryViewModel());
        Assert.Contains("desconhecidas", model.History.PendingSummary);
        var item = Samples.Event("blocked");
        Assert.True(model.ApplyEvent(item));
        Assert.False(model.ApplyEvent(item));
        Assert.Contains("1 evento(s)", model.Status.PendingAuditSummary);
        Assert.False(model.ApplyEvent(item with { Dispatched = true }));
        Assert.Contains("0 evento(s)", model.Status.PendingAuditSummary);
        Assert.True(Assert.Single(model.History.Events).Confirmed);
        Assert.False(model.ApplyEvent(item)); // Old replay must not undo a later receipt.
        Assert.True(Assert.Single(model.History.Events).Confirmed);
        model.ApplyHistory(new HistoryNotification([item]));
        Assert.True(Assert.Single(model.History.Events).Confirmed);
        var snapshot = new HistoryNotification([item with { Dispatched = true }, item with { Dispatched = true }]);
        model.ApplyHistory(snapshot);
        model.ApplyHistory(snapshot);
        Assert.False(model.ApplyEvent(item with { Dispatched = true }));
        Assert.Single(model.Status.RecentActivity);
        Assert.Single(model.History.Events);
        Assert.Contains("não é o total da fila", model.Status.PendingAuditSummary);
        model.ApplyHistory(new HistoryNotification([], Available: false));
        Assert.Contains("desconhecidas", model.Status.PendingAuditSummary);
    }

    [Fact]
    public void Legacy_transfer_replay_is_suppressed_but_a_later_phase_is_shown()
    {
        var tracker = new TransferNoticeTracker();
        var blocked = new TransferNotification(Guid.NewGuid(), "file.txt", TransferPhase.Blocked);
        Assert.True(tracker.ShouldDisplay(blocked));
        Assert.False(tracker.ShouldDisplay(blocked));
        Assert.True(tracker.ShouldDisplay(blocked with { Phase = TransferPhase.Released }));
        var item = Samples.Event("published");
        Assert.True(tracker.ShouldDisplay(Samples.Transfer(item)));
        Assert.False(tracker.ShouldDisplay(Samples.Transfer(item)));
    }

    [Fact]
    public void Display_redacts_recognized_sensitive_values_even_in_legacy_metadata_and_snippets()
    {
        const string sensitive = "529.982.247-25";
        var item = Samples.Event("blocked") with
        {
            FileName = sensitive + ".txt", DestinationPath = @"C:\" + sensitive,
            ProcessName = sensitive, MaskedSnippets = [sensitive], NotInspectedReason = "legacy:" + sensitive
        };
        var history = new HistoryRowViewModel(item);
        var queue = new QueueRowViewModel(item);
        Assert.DoesNotContain(sensitive, string.Join("|", history.FileName, history.Destination, history.Process, history.MaskedSnippets, history.Reason,
            queue.FileName, queue.Destination, queue.Process, queue.MaskedSnippets, queue.Reason,
            new ActivityRowViewModel(item).Description, new FindingViewModel("CPF", sensitive).MaskedSnippet,
            StagedPublicationPresentation.Released(sensitive, Samples.Transfer(Samples.Event("published"))).Message));
    }
}

internal static class Samples
{
    internal const string Hash = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    internal static AuditEvent Event(string scenario) => new(Guid.NewGuid(), DateTimeOffset.UtcNow, "SYNTHETIC-ENDPOINT", "synthetic-user",
        scenario + ".txt", ".txt", 20,
        scenario is "published" or "alert" ? Verdict.Approved : Verdict.Blocked,
        scenario is "blocked" or "alert" ? [Category.Cpf] : [], [], "explorer", 42, @"C:\Synthetic",
        scenario switch { "unknown" => "publication_outcome_unknown", "pending" => "publication_failed", "incomplete" => "inspection_timeout", _ => null },
        7, 2, false, scenario is "published" or "alert" ? Hash : null);

    internal static TransferNotification Transfer(AuditEvent item) => new(Guid.NewGuid(), item.FileName, TransferPhase.Released,
        PublishedSha256Hex: item.PublishedSha256Hex, Event: item);

    internal static StatusNotification Status(bool ready) => new(7, 1, ready,
        Communication: new AdministrationCommunicationStatus(Failure, Failure, Failure),
        DriveProtection: new DriveProtectionStatus(ready, 1, 1, ready ? DriveProtectionIssue.None : DriveProtectionIssue.GateUnavailable));
    private static AdministrationOperationStatus Failure => new(AdministrationOperationState.Failure, DateTimeOffset.UtcNow, DateTimeOffset.UtcNow.AddMinutes(-3));
}
