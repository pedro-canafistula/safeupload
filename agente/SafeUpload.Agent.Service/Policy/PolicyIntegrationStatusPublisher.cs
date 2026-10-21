using SafeUpload.Agent.Service.Notifications;

namespace SafeUpload.Agent.Service.Policies;

/// <summary>Projects diagnostics off the policy decision path, through the existing durable notification hub.</summary>
public sealed class PolicyIntegrationStatusPublisher(
    PolicyIntegrationDiagnostics diagnostics, NotificationHub hub,
    ILogger<PolicyIntegrationStatusPublisher> logger) : BackgroundService
{
    internal bool PublishOnce() => hub.PublishPolicyIntegration(diagnostics.ForNotification());

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        while (!stoppingToken.IsCancellationRequested)
        {
            try { PublishOnce(); }
            catch (Exception error) { logger.LogWarning(error, "Local policy diagnostic notification failed."); }
            try { await Task.Delay(TimeSpan.FromSeconds(2), stoppingToken).ConfigureAwait(false); }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested) { break; }
        }
    }
}
