using SafeUpload.Agent.Core.Domain;
using SafeUpload.Agent.Core.Infrastructure;

namespace SafeUpload.Agent.Tests;

public sealed class AppendInterruptionRecoveryTests
{
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task Falha_apos_prefixo_propaga_libera_stream_e_lock_e_preserva_cauda(bool justification)
    {
        using var workspace = new TestWorkspace();
        var baseline = Event();
        await new LocalQueueAuditSink(workspace.QueueFile).WriteAsync(baseline, CancellationToken.None);
        var before = await File.ReadAllBytesAsync(workspace.QueueFile);
        var calls = 0;
        var sink = new LocalQueueAuditSink(workspace.QueueFile, path =>
            ++calls == 1 ? new PartialFailureStream(path) :
                new FileStream(path, FileMode.OpenOrCreate, FileAccess.ReadWrite, FileShare.Read, 4096, FileOptions.Asynchronous));
        var interrupted = Event();
        var error = await Assert.ThrowsAsync<IOException>(() => justification
            ? sink.RecordOverrideAsync(new AuditOverride(interrupted.EventId, new string('x', 1024), interrupted.OccurredAtUtc,
                interrupted.UserName, interrupted.EndpointId), CancellationToken.None)
            : sink.WriteAsync(interrupted, CancellationToken.None));
        Assert.Equal("controlled-partial-write", error.Message);
        var partial = await File.ReadAllBytesAsync(workspace.QueueFile);
        Assert.Equal(before.Length + 13, partial.Length);
        Assert.Equal(before, partial[..before.Length]);
        // A second append on the same instance must not hang behind the failed write lock.
        using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        var recovered = Event();
        await sink.WriteAsync(recovered, deadline.Token);
        var after = await File.ReadAllBytesAsync(workspace.QueueFile);
        Assert.Equal(partial, after[..partial.Length]);
        var reopened = new LocalQueueAuditSink(workspace.QueueFile);
        var events = await reopened.ReadPendingAsync(0, deadline.Token);
        Assert.Equal(2, events.Count);
        Assert.Contains(events, e => e.EventId == baseline.EventId);
        Assert.Contains(events, e => e.EventId == recovered.EventId);
        Assert.DoesNotContain(events, e => e.EventId == interrupted.EventId);
        Assert.Empty(await reopened.ReadPendingOverridesAsync(0, deadline.Token));
        var integrity = await reopened.InspectIntegrityAsync(deadline.Token);
        Assert.Equal(1, integrity.InvalidLines);
        Assert.Equal(0, integrity.UnknownRecords);
    }

    private static AuditEvent Event() => new(Guid.NewGuid(), DateTimeOffset.UtcNow,
        "PC-SINTETICO", "usuario-sintetico", "sintetico.txt", ".txt", 42, Verdict.Blocked,
        [Category.Cpf], ["mascarado-sintetico"], "processo-sintetico", 123, "destino-sintetico", null, 1, 10, false);

    private sealed class PartialFailureStream(string path)
        : FileStream(path, FileMode.OpenOrCreate, FileAccess.ReadWrite, FileShare.Read, 4096, FileOptions.Asynchronous)
    {
        public override async ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken token = default)
        {
            await base.WriteAsync(buffer[..13], token);
            await base.FlushAsync(token);
            throw new IOException("controlled-partial-write");
        }
    }
}
