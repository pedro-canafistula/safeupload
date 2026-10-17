using System.ComponentModel;
using SafeUpload.Agent.App.Notifications;
using SafeUpload.Agent.Core.Contracts;
using SafeUpload.Agent.Service.Interception;

namespace SafeUpload.Agent.Tests;

public sealed class StagedPublicationRetryTests
{
    private static StagedPublicationBusyException Busy() => new(new Win32Exception(32));

    [Fact]
    public async Task Transient_contention_revalidates_before_each_attempt_and_stops_after_success()
    {
        var order = new List<string>(); int attempts = 0;
        await StagedPublicationRetry.ExecuteAsync(_ =>
        {
            order.Add("attempt");
            if (++attempts < 3) throw Busy();
            return Task.CompletedTask;
        }, _ => { order.Add("validate"); return Task.FromResult(true); }, () => false, CancellationToken.None,
            (wait, _) => { order.Add("delay:" + wait.TotalMilliseconds); return Task.CompletedTask; });
        Assert.Equal(["validate", "attempt", "delay:100", "validate", "attempt", "delay:200", "validate", "attempt"], order);
    }

    [Fact]
    public async Task Persistent_contention_exhausts_six_attempts_with_bounded_backoff()
    {
        int attempts = 0, checks = 0; var waits = new List<double>();
        await Assert.ThrowsAsync<StagedPublicationBusyException>(() => StagedPublicationRetry.ExecuteAsync(
            _ => { attempts++; throw Busy(); }, _ => { checks++; return Task.FromResult(true); }, () => false,
            CancellationToken.None, (wait, _) => { waits.Add(wait.TotalMilliseconds); return Task.CompletedTask; }));
        Assert.Equal(6, attempts); Assert.Equal(attempts, checks);
        Assert.Equal([100d, 200d, 400d, 800d, 1600d], waits);
        Assert.Equal(3100, waits.Sum());
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task Changed_or_unreadable_authority_during_backoff_cannot_request_another_attempt(bool unreadable)
    {
        int attempts = 0, checks = 0;
        await Assert.ThrowsAsync<IOException>(() => StagedPublicationRetry.ExecuteAsync(_ =>
        { attempts++; throw Busy(); }, _ =>
        {
            if (++checks == 1) return Task.FromResult(true);
            if (unreadable) throw new IOException("policy or identity unreadable");
            return Task.FromResult(false);
        }, () => false, CancellationToken.None, (_, _) => Task.CompletedTask));
        Assert.Equal(1, attempts); Assert.Equal(2, checks);
    }

    [Theory]
    [InlineData("copy")]
    [InlineData("flush")]
    [InlineData("identity")]
    [InlineData("cleanup")]
    [InlineData("revoke")]
    [InlineData("unknown rename")]
    public async Task Uncertain_or_noncontention_failure_is_never_retried(string phase)
    {
        int attempts = 0;
        var failure = new IOException(phase, Busy());
        Assert.Same(failure, await Assert.ThrowsAsync<IOException>(() => StagedPublicationRetry.ExecuteAsync(
            _ => { attempts++; throw failure; }, _ => Task.FromResult(true), () => false, CancellationToken.None,
            (_, _) => throw new InvalidOperationException("must not wait"))));
        Assert.Equal(1, attempts);
    }

    [Fact]
    public async Task Accepted_mutation_followed_by_failure_is_never_retried()
    {
        bool committed = false; int attempts = 0;
        await Assert.ThrowsAsync<StagedPublicationBusyException>(() => StagedPublicationRetry.ExecuteAsync(
            _ => { attempts++; committed = true; throw Busy(); }, _ => Task.FromResult(true), () => committed,
            CancellationToken.None, (_, _) => throw new InvalidOperationException("must not wait")));
        Assert.Equal(1, attempts);
    }

    [Fact]
    public async Task Cancellation_during_backoff_stops_without_another_attempt()
    {
        using var cancelled = new CancellationTokenSource(); int attempts = 0;
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => StagedPublicationRetry.ExecuteAsync(
            _ => { attempts++; throw Busy(); }, _ => Task.FromResult(true), () => false, cancelled.Token,
            (_, token) => { cancelled.Cancel(); token.ThrowIfCancellationRequested(); return Task.CompletedTask; }));
        Assert.Equal(1, attempts);
    }

    [Fact]
    public void Busy_notice_round_trips_as_pending_and_explains_another_program_without_a_content_block()
    {
        var notice = new TransferNotification(Guid.NewGuid(), "relatorio.pdf", TransferPhase.Retained,
            RecoveryAdvice: StagedRecoveryAdvice.PublicationBusy);
        var restored = Assert.IsType<TransferNotification>(NotificationProtocol.Deserialize(NotificationProtocol.Serialize(notice)));
        Assert.Equal(notice, restored);
        Assert.False(restored.OverrideAllowed); Assert.Null(restored.InspectionFailure); Assert.Null(restored.Findings);
        string text = StagedPublicationPresentation.Busy(restored.FileName);
        Assert.Contains(restored.FileName, text); Assert.Contains("aguardando envio", text);
        Assert.Contains("outro programa", text); Assert.Contains("salve novamente", text);
        Assert.DoesNotContain("conteúdo bloqueado", text);
    }
}
