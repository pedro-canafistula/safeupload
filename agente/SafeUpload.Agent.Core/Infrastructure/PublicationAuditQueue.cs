using System.Text;
using System.Text.Json;
using SafeUpload.Agent.Core.Domain;

namespace SafeUpload.Agent.Core.Infrastructure;

public sealed partial class LocalQueueAuditSink
{
    public async Task WritePublicationAsync(AuditEvent item, bool replay, CancellationToken token)
    {
        ArgumentNullException.ThrowIfNull(item);
        if (item.EventId == Guid.Empty || item.Dispatched) throw new ArgumentException("Expected a pending publication event.");
        string canonical = JsonSerializer.Serialize(item, Options);
        await _writeLock.WaitAsync(token).ConfigureAwait(false);
        try
        {
            bool found = false;
            if (replay && QueueExistsChecked())
            {
                await using var input = OpenQueueRead();
                using var reader = new StreamReader(input, Encoding.UTF8, true);
                while (await reader.ReadLineAsync(token).ConfigureAwait(false) is { } line)
                {
                    AuditEvent? prior;
                    try
                    {
                        using var json = JsonDocument.Parse(line);
                        if (json.RootElement.ValueKind != JsonValueKind.Object || json.RootElement.TryGetProperty("type", out _) ||
                            !json.RootElement.TryGetProperty("eventId", out var id) || id.ValueKind != JsonValueKind.String ||
                            !id.TryGetGuid(out var parsed) || parsed != item.EventId)
                            continue;
                        try { prior = JsonSerializer.Deserialize<AuditEvent>(line,
                            new JsonSerializerOptions(Options) { AllowDuplicateProperties = false }); }
                        catch (JsonException error) { throw new IOException("Existing publication id has ambiguous audit content.", error); }
                    }
                    catch (JsonException) { continue; } // Preserve incomplete/invalid lines; do not acknowledge them.
                    if (prior is null) continue;
                    if (JsonSerializer.Serialize(prior with { Dispatched = false }, Options) != canonical)
                        throw new IOException("Publication event id already has different audit content.");
                    found = true;
                }
            }
            token.ThrowIfCancellationRequested();
            if (!found) await AppendLineAsync(canonical, token, durable: true).ConfigureAwait(false);
            else
            {
                // A previous attempt may have appended before reporting a flush failure. Confirm it without rewriting.
                using var existing = OpenQueueAppend();
                existing.Flush(flushToDisk: true);
            }
        }
        finally { _writeLock.Release(); }
    }
}
