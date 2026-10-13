using System.Collections.Concurrent;
using SafeUpload.Agent.Service.Interception;

namespace SafeUpload.Agent.Service.Notifications;

/// <summary>One-use justification of an inspected, sealed version. Never grants process access.</summary>
public sealed class StagedJustifications
{
    private sealed record Entry(uint SessionId, string UserSid, DateTimeOffset ExpiresAt,
        Func<CancellationToken, Task<bool>> Publish);
    private readonly ConcurrentDictionary<Guid, Entry> _entries = new();

    internal async Task<bool> RememberAsync(StagedTransferJournal journal, Guid transferId, uint sessionId, string userSid,
        Func<CancellationToken, Task<bool>> publish,
        DateTimeOffset? expiresAtUtc, CancellationToken token)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(userSid);
        foreach (var pair in _entries)
            if (pair.Value.ExpiresAt <= DateTimeOffset.UtcNow)
                _entries.TryRemove(pair.Key, out _);
        DateTimeOffset expiry = expiresAtUtc ?? DateTimeOffset.UtcNow + PendingOverrides.Window;
        if (expiry.Offset != TimeSpan.Zero) throw new ArgumentException("Expiry must be UTC.", nameof(expiresAtUtc));
        bool Eligible(TransferJournalEntry e) => e.State == TransferJournalState.Blocked &&
            e.HandbackState == StagedHandbackState.Verified && !e.JustificationWindowClosed &&
            e.Sha256Hex is not null && e.BlockedPolicyVersion > 0 && e.BlockedPolicyFingerprint is not null &&
            e.JustificationExpiresAtUtc == expiry && expiry > DateTimeOffset.UtcNow &&
            e.Transfer.SessionId == sessionId && string.Equals(e.Transfer.RequestorSid, userSid, StringComparison.OrdinalIgnoreCase) &&
            StagedSeedExport.Failure(e) is null;
        var registered = await journal.EnforceSeedExportAsync(transferId, token).ConfigureAwait(false);
        if (!Eligible(registered)) return false;
        _entries[transferId] = new(sessionId, userSid, expiry, async retry =>
        {
            var current = await journal.EnforceSeedExportAsync(transferId, retry).ConfigureAwait(false);
            if (!Eligible(current) || current.Transfer != registered.Transfer ||
                current.StageIdentity != registered.StageIdentity || current.DestinationGeneration != registered.DestinationGeneration ||
                current.Sha256Hex != registered.Sha256Hex || current.BlockedPolicyVersion != registered.BlockedPolicyVersion ||
                current.BlockedPolicyFingerprint != registered.BlockedPolicyFingerprint) return false;
            return await publish(retry).ConfigureAwait(false);
        });
        return true;
    }

    public bool TryConsume(string eventId, uint? sessionId, string? userSid,
        out Func<CancellationToken, Task<bool>>? publish)
    {
        publish = null;
        if (!Guid.TryParse(eventId, out Guid id) || !_entries.TryGetValue(id, out var entry))
            return false;
        // Recognized staged IDs must never fall through to a process grant.
        if (entry.SessionId != sessionId ||
            !string.Equals(entry.UserSid, userSid, StringComparison.OrdinalIgnoreCase) ||
            entry.ExpiresAt <= DateTimeOffset.UtcNow)
            return true;
        if (_entries.TryRemove(new KeyValuePair<Guid, Entry>(id, entry))) publish = entry.Publish;
        return true;
    }

    public void Clear() => _entries.Clear();
}
