using System.Collections.Concurrent;

namespace SafeUpload.Agent.Service.Notifications;

/// <summary>One-use justification of an inspected, sealed version. Never grants process access.</summary>
public sealed class StagedJustifications
{
    private sealed record Entry(uint SessionId, DateTimeOffset ExpiresAt,
        Func<CancellationToken, Task<bool>> Publish);
    private readonly ConcurrentDictionary<Guid, Entry> _entries = new();

    public void Remember(Guid transferId, uint sessionId,
        Func<CancellationToken, Task<bool>> publish)
    {
        foreach (var pair in _entries)
            if (pair.Value.ExpiresAt <= DateTimeOffset.UtcNow)
                _entries.TryRemove(pair.Key, out _);
        _entries[transferId] = new(sessionId, DateTimeOffset.UtcNow + PendingOverrides.Window, publish);
    }

    public bool TryConsume(string eventId, uint? sessionId,
        out Func<CancellationToken, Task<bool>>? publish)
    {
        publish = null;
        if (!Guid.TryParse(eventId, out Guid id) || !_entries.TryGetValue(id, out var entry))
            return false;
        // Recognized staged IDs must never fall through to a process grant.
        if (entry.SessionId != sessionId || entry.ExpiresAt <= DateTimeOffset.UtcNow)
            return true;
        if (_entries.TryRemove(new KeyValuePair<Guid, Entry>(id, entry))) publish = entry.Publish;
        return true;
    }

    public void Clear() => _entries.Clear();
}
