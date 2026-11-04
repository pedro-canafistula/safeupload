using System.Security.Cryptography;
using System.Text.Json;
using SafeUpload.Agent.Core.Domain;

namespace SafeUpload.Agent.Drive;

internal enum PublicationAuditPhase { Prepared, Moved, Completed, Queued }
internal sealed record PublicationAuditEntry(int Format, long Order, string State, string Backing, string RelativeTarget,
    string DestinationIdentity, string? TemporaryName, AuditEvent Event);

/// <summary>Immutable audit metadata and durable outcomes; recovery never finishes an old publication.</summary>
internal sealed class PublicationAuditJournal
{
    internal const string DirectoryName = "publication-audit";
    private const int MaximumEntryBytes = 1024 * 1024;
    private const long MaximumPendingBytes = 16 * 1024 * 1024;
    private static readonly JsonSerializerOptions Options = new() { AllowDuplicateProperties = false, MaxDepth = 16 };
    private readonly string _directory, _backing;
    private readonly DriveRecoveryStore _recovery;
    private readonly ContentInspector _inspector;
    private readonly Action<PublicationAuditPhase> _fault;
    private readonly Dictionary<Guid, PublicationAuditEntry> _entries = [];
    private readonly Dictionary<Guid, long> _sizes = [];
    private long _nextOrder;

    internal PublicationAuditJournal(string privateRoot, string backing, DriveRecoveryStore recovery,
        ContentInspector inspector, Action<PublicationAuditPhase> fault)
    {
        _directory = Path.Combine(privateRoot, DirectoryName);
        _backing = backing; _recovery = recovery; _inspector = inspector; _fault = fault;
        Directory.CreateDirectory(_directory);
        DriveRecoveryStore.RejectReparsePoint(_directory);
        foreach (string path in Directory.EnumerateFiles(_directory, "*.json"))
        {
            DriveRecoveryStore.RejectReparsePoint(path);
            using var input = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read);
            if (input.Length > MaximumEntryBytes || _sizes.Values.Sum() + input.Length > MaximumPendingBytes || _entries.Count >= 4096)
                throw new IOException("Publication audit journal exceeds its limit.");
            var entry = JsonSerializer.Deserialize<PublicationAuditEntry>(input, Options)
                ?? throw new IOException("Empty publication audit entry.");
            Validate(entry);
            if (Path.GetFileNameWithoutExtension(path) != entry.Event.EventId.ToString("N") || !_entries.TryAdd(entry.Event.EventId, entry))
                throw new IOException("Conflicting publication audit id.");
            _sizes.Add(entry.Event.EventId, input.Length);
            if (_entries.Values.Count(e => e.Order == entry.Order) != 1) throw new IOException("Conflicting publication audit order.");
            _nextOrder = Math.Max(_nextOrder, entry.Order);
        }
        ResolvePrepared();
        Retry(CancellationToken.None);
    }

    internal bool HasPending => _entries.Count != 0;
    private string EntryPath(Guid id) => Path.Combine(_directory, id.ToString("N") + ".json");

    internal PublicationAuditEntry? Prepare(DriveDecision decision, string target, string temporary, FileStream evidence)
    {
        evidence.Flush(flushToDisk: true);
        evidence.Position = 0;
        string hash = Convert.ToHexString(SHA256.HashData(evidence));
        var item = _inspector.CreatePublicationAudit(decision, target, true, Guid.NewGuid(), hash);
        if (item is null) return null;
        var entry = new PublicationAuditEntry(1, checked(++_nextOrder), "prepared", _backing, Path.GetRelativePath(_backing, target),
            _recovery.DestinationIdentity, Path.GetFileName(temporary), item);
        Save(entry);
        _fault(PublicationAuditPhase.Prepared);
        return entry;
    }

    internal PublicationAuditEntry Complete(PublicationAuditEntry entry, bool success, string reason = "publication_failed")
    {
        entry = entry with { State = "completed", Event = success ? entry.Event : entry.Event with
            { Verdict = Verdict.Blocked, NotInspectedReason = reason, PublishedSha256Hex = null } };
        Save(entry);
        _fault(PublicationAuditPhase.Completed);
        return entry;
    }

    internal PublicationAuditEntry? Failed(DriveDecision decision, string target)
    {
        var item = _inspector.CreatePublicationAudit(decision, target, false, Guid.NewGuid());
        if (item is null) return null;
        var entry = new PublicationAuditEntry(1, checked(++_nextOrder), "completed", _backing, Path.GetRelativePath(_backing, target),
            _recovery.DestinationIdentity, null, item);
        Save(entry);
        return entry;
    }

    internal void Cancel(PublicationAuditEntry entry) => Remove(entry.Event.EventId);
    internal bool OwnsPreparedTemporary(string path) => _entries.Values.Any(e => e.State == "prepared" &&
        Path.Combine(Path.GetDirectoryName(Path.Combine(_backing, e.RelativeTarget))!, e.TemporaryName!) == path);

    internal void ResolvePrepared()
    {
        foreach (var entry in _entries.Values.Where(e => e.State == "prepared").OrderBy(e => e.Order).ToArray())
        {
            _recovery.ValidateDestination();
            if (entry.DestinationIdentity != _recovery.DestinationIdentity || !entry.Backing.Equals(_backing, StringComparison.OrdinalIgnoreCase))
                throw new IOException("Unresolved publication belongs to another destination.");
            // File ids can be reused after their original handles close, and identical bytes may predate the attempt.
            // Only the outcome durably written after Move is authoritative; a prepared intent stays unconfirmed.
            Complete(entry, false, "publication_outcome_unknown");
        }
    }

    internal void Retry(CancellationToken token)
    {
        foreach (var entry in _entries.Values.Where(e => e.State == "completed").OrderBy(e => e.Order).ToArray())
            if (!TryDeliver(entry, true, token)) break;
    }

    internal void Deliver(PublicationAuditEntry entry, bool replay, CancellationToken token)
    {
        foreach (var earlier in _entries.Values.Where(e => e.State == "completed" && e.Order < entry.Order).OrderBy(e => e.Order).ToArray())
            if (!TryDeliver(earlier, true, token)) return;
        TryDeliver(entry, replay, token);
    }

    private bool TryDeliver(PublicationAuditEntry entry, bool replay, CancellationToken token)
    {
        try { _inspector.WritePublicationAuditAsync(entry.Event, replay, token).GetAwaiter().GetResult(); }
        catch (OperationCanceledException) when (token.IsCancellationRequested) { throw; }
        catch (Exception error) { DriveLog.Write($"publication audit pending: {error.GetType().Name}"); return false; }
        _fault(PublicationAuditPhase.Queued);
        try { Remove(entry.Event.EventId); return true; }
        catch (Exception error) when (error is IOException or UnauthorizedAccessException)
        { DriveLog.Write($"publication audit cleanup pending: {error.GetType().Name}"); return false; }
    }

    private void Save(PublicationAuditEntry entry)
    {
        Validate(entry);
        byte[] bytes = JsonSerializer.SerializeToUtf8Bytes(entry, Options);
        _sizes.TryGetValue(entry.Event.EventId, out long oldSize);
        if (bytes.Length > MaximumEntryBytes || _sizes.Values.Sum() - oldSize + bytes.Length > MaximumPendingBytes ||
            !_entries.ContainsKey(entry.Event.EventId) && _entries.Count >= 4096)
            throw new IOException("Publication audit journal exceeds its limit.");
        string path = EntryPath(entry.Event.EventId), temporary = path + "." + Guid.NewGuid().ToString("N") + ".tmp";
        try
        {
            using (var output = new FileStream(temporary, FileMode.CreateNew, FileAccess.Write, FileShare.None, 4096, FileOptions.WriteThrough))
            { output.Write(bytes); output.Flush(flushToDisk: true); }
            File.Move(temporary, path, overwrite: true);
            _entries[entry.Event.EventId] = entry;
            _sizes[entry.Event.EventId] = bytes.Length;
        }
        finally { if (File.Exists(temporary)) File.Delete(temporary); }
    }

    private void Remove(Guid id)
    {
        File.Delete(EntryPath(id));
        _entries.Remove(id); _sizes.Remove(id);
    }

    private static void Validate(PublicationAuditEntry entry)
    {
        if (entry.Format != 1 || entry.Order <= 0 || string.IsNullOrWhiteSpace(entry.Backing) ||
            entry.State is not ("prepared" or "completed") || entry.Event is not { } item ||
            item.EventId == Guid.Empty || item.Dispatched || item.OccurredAtUtc == default || item.Channel != AuditChannel.File ||
            !Enum.IsDefined(item.Verdict) || item.Categories is null || item.MaskedSnippets is null ||
            string.IsNullOrWhiteSpace(entry.DestinationIdentity)) throw new IOException("Invalid publication audit entry.");
        DriveRecoveryStore.ValidateRelativePath(entry.RelativeTarget);
        if (entry.State == "prepared" && (entry.TemporaryName is not { } name || !name.StartsWith(".~su-", StringComparison.Ordinal) ||
            !Guid.TryParseExact(name[5..], "N", out _) ||
            item.PublishedSha256Hex is not { Length: 64 } hash || !hash.All(Uri.IsHexDigit) ||
            item.Verdict is not (Verdict.Approved or Verdict.AllowedWithoutInspection)))
            throw new IOException("Invalid publication evidence.");
    }
}
