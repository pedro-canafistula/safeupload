using System.Text;
using System.Text.Json;
using SafeUpload.Agent.Core.Domain;

namespace SafeUpload.Agent.Core.Infrastructure;

public sealed record AuditQueueLineIssue(long LineNumber, string Reason);
public sealed record AuditQueueIntegritySnapshot(bool FileExists, long LinesScanned,
    long ValidEvents, long ValidOverrides, long InvalidLines, long UnknownRecords, long BlankLines,
    IReadOnlyList<AuditQueueLineIssue> Issues, bool IssuesTruncated)
{
    // Counts refer to valid lines, including duplicate IDs, not unique events.
    public long QueueBytes { get; init; }
    public long PendingEvents { get; init; }
    public long DispatchedEvents { get; init; }
    public long PendingOverrides { get; init; }
    public long DispatchedOverrides { get; init; }
    public DateTimeOffset? OldestPendingUtc { get; init; }
    public long PendingWithoutTimestamp { get; init; }

    // Unknown record types can belong to a newer writer; do not call them corruption.
    public bool RequiresAttention => InvalidLines > 0 || UnknownRecords > 0;
}

public sealed partial class LocalQueueAuditSink
{
    /// <summary>
    /// Explicit, read-only scan under the same process-local lock as queue operations.
    /// Returns no content, IDs, paths or exception messages. Does not repair, remove,
    /// dispatch or change the acceptance rules of existing readers. Cancellation/I/O
    /// errors propagate: a partial scan must never be reported as complete/healthy.
    /// </summary>
    public async Task<AuditQueueIntegritySnapshot> InspectIntegrityAsync(CancellationToken cancellationToken)
    {
        await _writeLock.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            FileStream stream;
            try
            {
                stream = new FileStream(_queueFile, FileMode.Open, FileAccess.Read,
                    FileShare.ReadWrite | FileShare.Delete, 4096, FileOptions.Asynchronous);
            }
            catch (FileNotFoundException) { return Missing(); }
            catch (DirectoryNotFoundException) { return Missing(); }

            await using (stream)
            using (var reader = new StreamReader(stream, Encoding.UTF8, true))
            {
                long lines = 0, events = 0, overrides = 0, invalid = 0, unknown = 0, blanks = 0;
                long pendingEvents = 0, dispatchedEvents = 0, pendingOverrides = 0, dispatchedOverrides = 0,
                    pendingWithoutTimestamp = 0;
                DateTimeOffset? oldestPending = null;
                // Same open handle and process-local lock as the scan. External writers are not locked.
                long queueBytes = stream.Length;
                void ObservePending(DateTimeOffset timestamp)
                {
                    if (timestamp == default) { pendingWithoutTimestamp++; return; }
                    var utc = timestamp.ToUniversalTime();
                    if (oldestPending is null || utc < oldestPending) oldestPending = utc;
                }
                var issues = new List<AuditQueueLineIssue>();
                while (await reader.ReadLineAsync(cancellationToken).ConfigureAwait(false) is { } line)
                {
                    cancellationToken.ThrowIfCancellationRequested();
                    lines++;
                    if (string.IsNullOrWhiteSpace(line)) { blanks++; continue; }
                    string? reason = null;
                    try
                    {
                        using var json = JsonDocument.Parse(line);
                        var root = json.RootElement;
                        if (root.ValueKind != JsonValueKind.Object) reason = "non_object";
                        else if (root.TryGetProperty("type", out var type))
                        {
                            if (type.ValueKind != JsonValueKind.String) reason = "invalid_record_type";
                            else if (type.GetString() != "override")
                            {
                                unknown++;
                                reason = "unknown_record_type";
                            }
                            else
                            {
                                var record = JsonSerializer.Deserialize<AuditOverride>(line, Options);
                                if (record is null || record.EventId == Guid.Empty ||
                                    string.IsNullOrWhiteSpace(record.Justification) ||
                                    string.IsNullOrWhiteSpace(record.UserName) ||
                                    string.IsNullOrWhiteSpace(record.EndpointId) || record.OccurredAtUtc == default ||
                                    (root.TryGetProperty("dispatched", out var sent) &&
                                     sent.ValueKind is not (JsonValueKind.True or JsonValueKind.False)))
                                    reason = "invalid_override";
                                else
                                {
                                    overrides++;
                                    if (root.TryGetProperty("dispatched", out var dispatched) &&
                                        dispatched.ValueKind == JsonValueKind.True) dispatchedOverrides++;
                                    else { pendingOverrides++; ObservePending(record.OccurredAtUtc); }
                                }
                            }
                        }
                        else if (!root.TryGetProperty("eventId", out _)) reason = "missing_event_id";
                        else
                        {
                            var record = JsonSerializer.Deserialize<AuditEvent>(line, Options);
                            if (record is null || record.EventId == Guid.Empty) reason = "invalid_event";
                            else
                            {
                                events++;
                                if (record.Dispatched) dispatchedEvents++;
                                else { pendingEvents++; ObservePending(record.OccurredAtUtc); }
                            }
                        }
                    }
                    catch (JsonException) { reason = "invalid_json_or_fields"; }
                    if (reason is not null)
                    {
                        if (reason != "unknown_record_type") invalid++;
                        if (issues.Count < 20) issues.Add(new(lines, reason));
                    }
                }
                return new(true, lines, events, overrides, invalid, unknown, blanks,
                    issues.ToArray(), invalid + unknown > issues.Count)
                {
                    QueueBytes = queueBytes, PendingEvents = pendingEvents, DispatchedEvents = dispatchedEvents,
                    PendingOverrides = pendingOverrides, DispatchedOverrides = dispatchedOverrides,
                    OldestPendingUtc = oldestPending, PendingWithoutTimestamp = pendingWithoutTimestamp
                };
            }
        }
        finally { _writeLock.Release(); }
    }

    private static AuditQueueIntegritySnapshot Missing() => new(false, 0, 0, 0, 0, 0, 0, [], false);
}
