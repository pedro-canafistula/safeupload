using SafeUpload.Agent.Core.Domain;
using System.Collections.Concurrent;

namespace SafeUpload.Agent.Service.Drive;

/// <summary>
/// Blocked versions the user may still justify. The id is the version id shown in the block notification; only the
/// user and session that wrote the version can use it, once, before it expires.
/// </summary>
public sealed class DriveJustifications
{
    public static readonly TimeSpan Window = TimeSpan.FromMinutes(10);

    private sealed record Entry(uint SessionId, string UserSid, long CreatedAt, string PolicyFingerprint, Func<bool> Approve);
    private readonly ConcurrentDictionary<Guid, Entry> _entries = new();
    private readonly TimeProvider _clock;

    public DriveJustifications() : this(TimeProvider.System) { }
    internal DriveJustifications(TimeProvider clock) => _clock = clock ?? throw new ArgumentNullException(nameof(clock));

    public void Remember(Guid versionId, uint sessionId, string userSid, string policyFingerprint, Func<bool> approve)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(policyFingerprint);
        long now = _clock.GetTimestamp();
        foreach (var pair in _entries)
            if (_clock.GetElapsedTime(pair.Value.CreatedAt, now) >= Window)
                _entries.TryRemove(pair.Key, out _);
        _entries[versionId] = new Entry(sessionId, userSid, now, policyFingerprint, approve);
    }

    /// <summary>Takes the approval for <paramref name="eventId"/> if this caller may use it.</summary>
    public bool TryConsume(string eventId, uint? sessionId, string? userSid, Policy currentPolicy, out Func<bool>? approve)
    {
        approve = null;
        if (!Guid.TryParse(eventId, out var id) || !_entries.TryGetValue(id, out var entry)) return false;
        if (entry.SessionId != sessionId || !string.Equals(entry.UserSid, userSid, StringComparison.OrdinalIgnoreCase) ||
            _clock.GetElapsedTime(entry.CreatedAt) >= Window)
            return false;
        if (!currentPolicy.OverrideAllowed || !string.Equals(entry.PolicyFingerprint,
                PolicyContentFingerprint.Compute(currentPolicy), StringComparison.Ordinal)) return false;
        if (!_entries.TryRemove(new KeyValuePair<Guid, Entry>(id, entry))) return false;
        approve = entry.Approve;
        return true;
    }
}
