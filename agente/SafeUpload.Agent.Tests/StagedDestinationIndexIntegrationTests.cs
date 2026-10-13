using System.Diagnostics;
using System.Globalization;
using System.Text.Json;
using SafeUpload.Agent.Service.Interception;
using Xunit.Abstractions;

namespace SafeUpload.Agent.Tests;

// Real private journal files and queues, with synthetic checked namespace
// identities. These qualify indexing/lifetime, not native caller authority.
public sealed class StagedDestinationIndexIntegrationTests(ITestOutputHelper output) : IDisposable
{
    private readonly TestWorkspace _workspace = new();
    private static readonly Guid Volume = Guid.Parse("22000000-0000-0000-0000-000000000002");
    private string JournalPath => Path.Combine(_workspace.Root, "journal");
    public void Dispose() => _workspace.Dispose();

    private static StagedDestinationIdentity Destination(int index) =>
        new(new(7, 11, 12), new(7, 21, 22), false,
            "save-" + index.ToString("D5", CultureInfo.InvariantCulture) + ".txt", Volume);

    [Theory]
    [InlineData(1000)]
    [InlineData(10000)]
    public async Task Many_live_names_share_only_equivalent_turns_and_release_every_queue_cell(int count)
    {
        var journal = new StagedTransferJournal(JournalPath);
        var turns = new List<StagedTransferJournal.DestinationCommitTurn>(count);
        var elapsed = Stopwatch.StartNew();
        try
        {
            for (int i = 0; i < count; i++)
                turns.Add(await journal.EnterDestinationCommitTurnAsync(Destination(i),
                    StagedDestinationTurnPurpose.Allocation, CancellationToken.None));
            elapsed.Stop();
            output.WriteLine(FormattableString.Invariant($"DestinationIndex shape=live-queue-acquire entries={count} elapsed_ms={elapsed.Elapsed.TotalMilliseconds:F3}"));
            Assert.Equal(count, journal.DestinationQueueCells);

            var first = Destination(0);
            var alias = new StagedDestinationIdentity(first.VolumeRoot, first.Parent, false,
                first.CanonicalLeaf.ToUpperInvariant(), Volume);
            using var cancel = new CancellationTokenSource();
            var waiting = journal.EnterDestinationCommitTurnAsync(alias, StagedDestinationTurnPurpose.Allocation, cancel.Token);
            Assert.False(waiting.IsCompleted);
            cancel.Cancel();
            await Assert.ThrowsAnyAsync<OperationCanceledException>(() => waiting);
            Assert.Equal(count, journal.DestinationQueueCells);

            var sensitive = new StagedDestinationIdentity(first.VolumeRoot, first.Parent, true, first.CanonicalLeaf, Volume);
            var sensitiveAlias = new StagedDestinationIdentity(first.VolumeRoot, first.Parent, true,
                first.CanonicalLeaf.ToUpperInvariant(), Volume);
            using (await journal.EnterDestinationCommitTurnAsync(sensitive,
                       StagedDestinationTurnPurpose.Allocation, CancellationToken.None))
            using (await journal.EnterDestinationCommitTurnAsync(sensitiveAlias,
                       StagedDestinationTurnPurpose.Allocation, CancellationToken.None))
                Assert.Equal(count + 2, journal.DestinationQueueCells);
            Assert.Equal(count, journal.DestinationQueueCells);

            var otherIdentities = new[]
            {
                new StagedDestinationIdentity(first.VolumeRoot, first.Parent, false, first.CanonicalLeaf, Guid.NewGuid()),
                new StagedDestinationIdentity(first.VolumeRoot, new(7, 121, 22), false, first.CanonicalLeaf, Volume),
                new StagedDestinationIdentity(new(8, 11, 12), new(8, 21, 22), false, first.CanonicalLeaf, Volume)
            };
            foreach (var other in otherIdentities)
                using (await journal.EnterDestinationCommitTurnAsync(other,
                           StagedDestinationTurnPurpose.Allocation, CancellationToken.None))
                    Assert.Equal(count + 1, journal.DestinationQueueCells);
            Assert.Equal(count, journal.DestinationQueueCells);
        }
        finally
        {
            elapsed.Restart();
            foreach (var turn in turns) { turn.Dispose(); turn.Dispose(); }
            elapsed.Stop();
            output.WriteLine(FormattableString.Invariant($"DestinationIndex shape=live-queue-release entries={turns.Count} elapsed_ms={elapsed.Elapsed.TotalMilliseconds:F3}"));
        }
        Assert.Equal(0, journal.DestinationQueueCells);
        using (await journal.EnterDestinationCommitTurnAsync(Destination(0),
                   StagedDestinationTurnPurpose.Allocation, CancellationToken.None))
            Assert.Equal(1, journal.DestinationQueueCells);
        Assert.Equal(0, journal.DestinationQueueCells);
    }

    [Theory]
    [InlineData(1000)]
    [InlineData(10000)]
    public async Task Startup_reads_every_real_head_and_preserves_its_exact_generation_tuple(int count)
    {
        var journal = new StagedTransferJournal(JournalPath);
        var expected = new Dictionary<string, (Guid Transfer, long Generation)>(StringComparer.Ordinal);
        for (int i = count - 1; i >= 0; i--)
        {
            var destination = Destination(i); Guid transfer = Guid.NewGuid(); long generation = i % 7 + 1;
            var head = new StagedDestinationHead(destination,
                Path.Combine(_workspace.Root, "public", destination.CanonicalLeaf), generation, transfer, generation,
                0, null, 0, null, []);
            // Private inherited ACLs come from the journal directory. The real
            // reader still validates owner/writers, single links, size, JSON,
            // full namespace identity and exact storage filename for every file.
            await File.WriteAllTextAsync(Path.Combine(JournalPath, "destination-" + destination.StorageKey + ".state"),
                JsonSerializer.Serialize(head));
            expected.Add(destination.CanonicalLeaf, (transfer, generation));
        }
        var elapsed = Stopwatch.StartNew();
        var heads = await journal.ReadDestinationHeadsAsync(CancellationToken.None);
        elapsed.Stop();
        output.WriteLine(FormattableString.Invariant($"DestinationIndex shape=real-head-discovery entries={count} elapsed_ms={elapsed.Elapsed.TotalMilliseconds:F3}"));
        Assert.Equal(count, heads.Count);
        Assert.All(heads, head =>
        {
            var tuple = expected[head.Destination.CanonicalLeaf];
            Assert.Equal(Destination(int.Parse(head.Destination.CanonicalLeaf.AsSpan(5, 5), CultureInfo.InvariantCulture)), head.Destination);
            Assert.Equal(tuple.Transfer, head.CurrentSaveTransferId);
            Assert.Equal(tuple.Generation, head.MaxAllocated); Assert.Equal(tuple.Generation, head.CurrentSaveGeneration);
        });
        Assert.Equal(0, journal.DestinationQueueCells);
    }
}
