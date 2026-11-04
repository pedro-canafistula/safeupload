using System.Collections.Concurrent;

namespace SafeUpload.Agent.Service.Drive;

/// <summary>
/// Blocked versions the user may still justify. The id is the version id shown in the block notification; only the
/// user and session that wrote the version can use it, once, before it expires.
/// </summary>
public sealed class DriveJustifications
{
    public static readonly TimeSpan Window = TimeSpan.FromMinutes(10);

    private sealed record Entry(uint SessionId, string UserSid, string PolicyBinding, DateTimeOffset ExpiresAt, Func<bool> Approve);
    private readonly ConcurrentDictionary<Guid, Entry> _entries = new();

    public void Remember(Guid versionId, uint sessionId, string userSid, string policyBinding, Func<bool> approve)
    {
        foreach (var pair in _entries)
            if (pair.Value.ExpiresAt <= DateTimeOffset.UtcNow)
                _entries.TryRemove(pair.Key, out _);
        ArgumentException.ThrowIfNullOrWhiteSpace(policyBinding);
        _entries[versionId] = new Entry(sessionId, userSid, policyBinding, DateTimeOffset.UtcNow + Window, approve);
    }

    /// <summary>Takes the approval for <paramref name="eventId"/> if this caller may use it.</summary>
    public bool TryConsume(string eventId, uint? sessionId, string? userSid, string policyBinding, out Func<bool>? approve)
    {
        approve = null;
        if (!Guid.TryParse(eventId, out var id) || !_entries.TryGetValue(id, out var entry)) return false;
        if (entry.SessionId != sessionId || !string.Equals(entry.UserSid, userSid, StringComparison.OrdinalIgnoreCase) ||
            !string.Equals(entry.PolicyBinding, policyBinding, StringComparison.Ordinal) || entry.ExpiresAt <= DateTimeOffset.UtcNow)
            return false;
        if (!_entries.TryRemove(new KeyValuePair<Guid, Entry>(id, entry))) return false;
        approve = entry.Approve;
        return true;
    }
}
