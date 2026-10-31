using System.Text;
using System.Text.Json;
using SafeUpload.Agent.Core.Domain;

namespace SafeUpload.Agent.Core.Infrastructure;

public sealed partial class LocalQueueAuditSink
{
    public async Task<IReadOnlyList<AuditEvent>> ReadRecentMatchingAsync(int maxEvents, Func<AuditEvent, bool> visible,
        CancellationToken cancellationToken)
    {
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(maxEvents);
        ArgumentNullException.ThrowIfNull(visible);
        var recent = new Queue<AuditEvent>();
        await using var window = await OpenIntegritySnapshotAsync(cancellationToken).ConfigureAwait(false);
        if (window is null) return [];
        using var reader = new StreamReader(window, Encoding.UTF8, true);
        while (await reader.ReadLineAsync(cancellationToken).ConfigureAwait(false) is { } line)
        {
            cancellationToken.ThrowIfCancellationRequested();
            AuditEvent? item;
            try
            {
                using var json = JsonDocument.Parse(line);
                if (json.RootElement.ValueKind != JsonValueKind.Object ||
                    json.RootElement.TryGetProperty("type", out _) || !json.RootElement.TryGetProperty("eventId", out _)) continue;
                item = JsonSerializer.Deserialize<AuditEvent>(line, Options);
            }
            catch (JsonException) { continue; }
            if (item is null || item.EventId == Guid.Empty || !visible(item)) continue;
            if (recent.Count == maxEvents) recent.Dequeue();
            recent.Enqueue(item);
        }
        cancellationToken.ThrowIfCancellationRequested();
        return recent.Reverse().ToArray();
    }
}
