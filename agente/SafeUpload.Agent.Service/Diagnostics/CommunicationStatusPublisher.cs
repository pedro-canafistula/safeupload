using SafeUpload.Agent.Core.Application;
using SafeUpload.Agent.Core.Contracts;
using SafeUpload.Agent.Service.Notifications;

namespace SafeUpload.Agent.Service.Diagnostics;

/// <summary>Samples process-local observations only. Does not query API, files or driver.</summary>
public sealed class CommunicationStatusPublisher(CommunicationHealth health, NotificationHub hub) : BackgroundService
{
    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        PublishSnapshot();
        using var timer = new PeriodicTimer(TimeSpan.FromSeconds(5));
        while (await timer.WaitForNextTickAsync(stoppingToken).ConfigureAwait(false))
            PublishSnapshot();
    }

    internal void PublishSnapshot()
    {
        var snapshot = health.Read();
        hub.UpdateCommunication(new(
            Read(snapshot, CommunicationOperation.Heartbeat),
            Read(snapshot, CommunicationOperation.Audit),
            Read(snapshot, CommunicationOperation.Policy)));
    }

    private static AdministrationOperationStatus Read(CommunicationHealthSnapshot snapshot, CommunicationOperation operation)
    {
        var value = snapshot.Operations.Single(item => item.Operation == operation.ToString());
        var state = value.State switch
        {
            "not_configured" => AdministrationOperationState.NotConfigured,
            "not_attempted" => AdministrationOperationState.NotAttempted,
            "in_progress" => AdministrationOperationState.InProgress,
            "Success" => AdministrationOperationState.Success,
            "Failure" => AdministrationOperationState.Failure,
            "Cancelled" => AdministrationOperationState.Cancelled,
            _ => AdministrationOperationState.Unknown
        };
        return new(state, value.LastAttemptUtc, value.LastSuccessUtc);
    }
}
