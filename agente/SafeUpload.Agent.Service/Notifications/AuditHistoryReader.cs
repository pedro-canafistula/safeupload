using SafeUpload.Agent.Core.Application;
using SafeUpload.Agent.Core.Contracts;
using SafeUpload.Agent.Core.Domain;

namespace SafeUpload.Agent.Service.Notifications;

/// <summary>
/// The service reads the private queue; the UI never receives filesystem access.
/// Legacy watcher events belong to the endpoint and were already broadcast live.
/// User-specific events require an exact qualified account obtained from the
/// connected process token. Unqualified/unknown owners are not replayed.
/// </summary>
public sealed class AuditHistoryReader(IAuditSink sink)
{
    public async Task<HistoryNotification> ReadAsync(string? authenticatedAccount, CancellationToken cancellationToken)
    {
        if (string.IsNullOrWhiteSpace(authenticatedAccount) || !authenticatedAccount.Contains('\\'))
            return new HistoryNotification([], Available: false);

        var recent = await sink.ReadRecentAsync(HistoryNotification.MaximumEvents, cancellationToken).ConfigureAwait(false);
        return new HistoryNotification(recent.Where(e => VisibleTo(e, authenticatedAccount))
            .DistinctBy(e => e.EventId).Take(HistoryNotification.MaximumEvents).ToArray());
    }

    internal static bool VisibleTo(AuditEvent item, string authenticatedAccount)
    {
        if (!string.Equals(item.EndpointId, Environment.MachineName, StringComparison.OrdinalIgnoreCase)) return false;
        if (string.Equals(item.UserName, authenticatedAccount, StringComparison.OrdinalIgnoreCase)) return true;

        // FileSystemWatcher has no trustworthy originating process/session. Keep
        // only its existing endpoint-wide scope; never broaden clipboard/web or
        // kernel/staged events to other accounts because the service wrote them.
        return item.Channel == AuditChannel.File && item.ProcessId == 0 && item.ProcessName == "desconhecido" &&
            string.Equals(item.UserName, Environment.MachineName + "$", StringComparison.OrdinalIgnoreCase);
    }
}
