using SafeUpload.Agent.Service.Notifications;

namespace SafeUpload.Agent.Service.Audit;

/// <summary>Delivers historical diagnostics outside the audit decision path.</summary>
public sealed class AuditWriteStatusPublisher(
    AuditWriteFailureDiagnostics diagnostics, NotificationHub hub,
    ILogger<AuditWriteStatusPublisher> logger) : BackgroundService
{
    internal bool PublishOnce() => hub.PublishAuditWrites(diagnostics.ForNotification());

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        while (!stoppingToken.IsCancellationRequested)
        {
            try { PublishOnce(); }
            catch (Exception) { logger.LogWarning("Local audit diagnostic notification failed."); }
            try { await Task.Delay(TimeSpan.FromSeconds(2), stoppingToken).ConfigureAwait(false); }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested) { break; }
        }
    }
}
