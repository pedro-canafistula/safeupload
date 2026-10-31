using SafeUpload.Agent.Core.Application;
using SafeUpload.Agent.Core.Contracts;
using SafeUpload.Agent.Core.Domain;
using System.Text.Json;
using System.Security.Principal;

namespace SafeUpload.Agent.Service.Notifications;

/// <summary>
/// The service reads the private queue; the UI never receives filesystem access.
/// Legacy watcher events belong to the endpoint and were already broadcast live.
/// SID-bound events require the connected process token SID; legacy events
/// require an exact qualified account. Unknown owners are not guessed.
/// </summary>
public sealed class AuditHistoryReader(IAuditSink sink)
{
    private static readonly string SystemAccount = new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null)
        .Translate(typeof(NTAccount)).Value;
    public async Task<HistoryNotification> ReadAsync(string? authenticatedAccount, CancellationToken cancellationToken,
        string? authenticatedSid = null)
    {
        if (authenticatedSid is not null)
        {
            try { authenticatedSid = new SecurityIdentifier(authenticatedSid).Value; }
            catch (ArgumentException) { return new HistoryNotification([], Available: false); }
        }
        if (authenticatedSid is null && (string.IsNullOrWhiteSpace(authenticatedAccount) || !authenticatedAccount.Contains('\\')))
            return new HistoryNotification([], Available: false);

        if (authenticatedAccount?.Contains('\\') != true) authenticatedAccount = null;

        // Filter before limiting so another account's activity cannot hide this account's history.
        var recent = await sink.ReadRecentMatchingAsync(HistoryNotification.MaximumEvents + 1,
            e => VisibleTo(e, authenticatedAccount, authenticatedSid), cancellationToken).ConfigureAwait(false);
        var selected = new List<AuditEvent>();
        int bytes = 2048; // Conservative envelope/comma budget, measured with the actual serializer below.
        bool truncated = recent.Count > HistoryNotification.MaximumEvents;
        foreach (var item in recent.DistinctBy(e => e.EventId).Take(HistoryNotification.MaximumEvents))
        {
            cancellationToken.ThrowIfCancellationRequested();
            int size = JsonSerializer.SerializeToUtf8Bytes(item, NotificationProtocol.JsonOptions).Length + 1;
            if (size > HistoryNotification.MaximumPayloadBytes - bytes) { truncated = true; continue; }
            selected.Add(item);
            bytes += size;
        }
        return new HistoryNotification(selected.ToArray(), Truncated: truncated);
    }

    internal static bool VisibleTo(AuditEvent item, string? authenticatedAccount, string? authenticatedSid = null)
    {
        if (item.Categories is null || item.MaskedSnippets is null) return false;
        if (!string.Equals(item.EndpointId, Environment.MachineName, StringComparison.OrdinalIgnoreCase)) return false;
        // Once a trusted SID is present it is authoritative. Never fall back to
        // a matching display name or endpoint-wide watcher scope for another SID.
        if (item.OwnerSid is not null)
            return authenticatedSid is not null && string.Equals(item.OwnerSid, authenticatedSid, StringComparison.OrdinalIgnoreCase);
        if (authenticatedAccount is not null && string.Equals(item.UserName, authenticatedAccount, StringComparison.OrdinalIgnoreCase)) return true;

        // FileSystemWatcher has no trustworthy originating process/session. Keep
        // only its existing endpoint-wide scope; never broaden clipboard/web or
        // kernel/staged events to other accounts because the service wrote them.
        return item.Channel == AuditChannel.File && item.ProcessId == 0 && item.ProcessName == "desconhecido" &&
            (string.Equals(item.UserName, Environment.MachineName + "$", StringComparison.OrdinalIgnoreCase) ||
             string.Equals(item.UserName, SystemAccount, StringComparison.OrdinalIgnoreCase) ||
             string.Equals(item.UserName, SystemAccount.Split('\\')[^1], StringComparison.OrdinalIgnoreCase));
    }
}
