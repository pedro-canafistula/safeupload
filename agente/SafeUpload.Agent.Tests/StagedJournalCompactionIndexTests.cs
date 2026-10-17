using System.Diagnostics;
using System.Globalization;
using System.Runtime.InteropServices;
using SafeUpload.Agent.Core.Domain;
using SafeUpload.Agent.Service.Interception;
using Xunit.Abstractions;

namespace SafeUpload.Agent.Tests;

// Validated-snapshot index controls, without filesystem/authorization claims.
// The disk-backed compaction/restart controls exercise its production caller.
public sealed class StagedJournalCompactionIndexTests(ITestOutputHelper output)
{
    private static readonly Guid Driver = Guid.Parse("11000000-0000-0000-0000-000000000001");
    private static readonly Guid Volume = Guid.Parse("22000000-0000-0000-0000-000000000002");
    private static readonly DateTimeOffset Updated = new(2026, 10, 13, 0, 0, 0, TimeSpan.Zero);

    private static TransferJournalEntry Entry(long generation, string leaf = "save.txt", bool bound = false,
        bool caseSensitive = false)
    {
        Guid id = Guid.NewGuid();
        var transfer = new StagedTransfer(id, @"C:\private\" + id.ToString("N") + ".stage",
            @"C:\public\" + leaf, DestinationKind.Cloud, "writer.exe", 1234, 1)
        {
            RequestorSid = "S-1-5-21-100-200-300-1001", RequestorProcessCreationTime = 123456
        };
        var binding = bound ? new StagedAllocationBindingV23(id, Driver, Guid.Empty, 2, 0, Volume,
            new(7, 11, 12), new(7, 21, 22), caseSensitive, leaf, null) : null;
        return new(transfer, TransferJournalState.Discarded, null, Updated)
        {
            DestinationGeneration = generation, StageIdentity = new(7, 31, (ulong)generation + 1),
            StateHistory = [new(TransferJournalState.Allocated, Updated), new(TransferJournalState.Discarded, Updated)],
            CreateReservationId = id, DriverInstanceId = Driver, AllocationReferenceKind = 0, AllocationDisposition = 2,
            BoundAllocation = binding, AllocationExtensionVersion = bound ? 23u : null,
            ParentDirectoryIdentity = binding?.Parent
        };
    }

    private static HashSet<Guid> Finished(IEnumerable<TransferJournalEntry> entries) =>
        entries.Select(e => e.Transfer.TransferId).ToHashSet();

    private HashSet<Guid> Measure(string shape, IReadOnlyList<TransferJournalEntry> entries)
    {
        var finished = Finished(entries);
        var elapsed = Stopwatch.StartNew();
        var retained = StagedTransferJournal.FindCompactionProtectedTransfers(entries, finished, CancellationToken.None);
        elapsed.Stop();
        output.WriteLine("CompactionIndex shape={0} entries={1} retained={2} elapsed_ms={3:F3}",
            shape, entries.Count, retained.Count, elapsed.Elapsed.TotalMilliseconds);
        return retained;
    }

    [Theory]
    [InlineData(1000)]
    [InlineData(10000)]
    [InlineData(50000)]
    public void Reference_chains_retain_every_exact_ancestor_and_remove_unreferenced_history(int count)
    {
        var chain = Enumerable.Range(1, count).Select(i => Entry(i)).ToArray();
        for (int i = 1; i < count; i++)
        {
            var parent = chain[i - 1];
            var exact = new StagedVersionIdentity(parent.Transfer.TransferId,
                parent.DestinationGeneration, parent.StageIdentity!);
            chain[i] = (i % 3) switch
            {
                0 => chain[i] with { ParentVersionIdentity = exact },
                1 => chain[i] with { DeleteVersionIdentity = exact },
                _ => chain[i] with { AllocationReferenceId = parent.Transfer.TransferId, AllocationReferenceKind = 2 }
            };
        }
        var orphan = Entry(1);
        // The only maximum is last, and its ancestors precede it. A whole-list
        // fixed-point scan would need another pass for each predecessor.
        var retained = Measure("reference-chain", [.. chain, orphan]);
        Assert.Equal(count, retained.Count);
        Assert.All(chain, entry => Assert.Contains(entry.Transfer.TransferId, retained));
        Assert.DoesNotContain(orphan.Transfer.TransferId, retained);
    }

    [Fact]
    public void Shared_references_and_cycles_are_visited_without_losing_any_reachable_record()
    {
        var head = Entry(4); var parent = Entry(3); var owner = Entry(2); var orphan = Entry(1);
        var exact = new StagedVersionIdentity(parent.Transfer.TransferId, 3, parent.StageIdentity!);
        head = head with { ParentVersionIdentity = exact, DeleteVersionIdentity = exact, AllocationReferenceId = owner.Transfer.TransferId,
            AllocationReferenceKind = 2 };
        parent = parent with { AllocationReferenceId = owner.Transfer.TransferId, AllocationReferenceKind = 2 };
        owner = owner with { AllocationReferenceId = head.Transfer.TransferId, AllocationReferenceKind = 2 };
        var retained = Measure("shared-cycle", [owner, orphan, parent, head]);
        Assert.True(retained.SetEquals([head.Transfer.TransferId, parent.Transfer.TransferId, owner.Transfer.TransferId]));
    }

    [Fact]
    public void Every_maximum_generation_tie_keeps_its_own_reference_chain()
    {
        var first = Entry(3); var second = Entry(3); var firstParent = Entry(2); var secondParent = Entry(1);
        first = first with { AllocationReferenceId = firstParent.Transfer.TransferId, AllocationReferenceKind = 2 };
        second = second with { AllocationReferenceId = secondParent.Transfer.TransferId, AllocationReferenceKind = 2 };
        var retained = Measure("maximum-ties", [firstParent, secondParent, first, second]);
        Assert.True(retained.SetEquals([first.Transfer.TransferId, second.Transfer.TransferId,
            firstParent.Transfer.TransferId, secondParent.Transfer.TransferId]));
    }

    [Fact]
    public void Cancelled_index_selection_stops_before_creating_a_retention_result()
    {
        using var cancellation = new CancellationTokenSource(); cancellation.Cancel();
        Assert.ThrowsAny<OperationCanceledException>(() => StagedTransferJournal.FindCompactionProtectedTransfers(
            [], new HashSet<Guid>(), cancellation.Token));
    }

    [Fact]
    public void Unresolved_create_after_delete_retains_successor_and_its_transitive_reference_closure()
    {
        var pendingDelete = Entry(1); var successor = Entry(2); var allocation = Entry(3); var newest = Entry(4);
        pendingDelete = pendingDelete with { CreateAfterReservationId = successor.Transfer.TransferId };
        successor = successor with { DeleteVersionIdentity = new(pendingDelete.Transfer.TransferId, 1, pendingDelete.StageIdentity!),
            AllocationReferenceId = allocation.Transfer.TransferId, AllocationReferenceKind = 2 };
        TransferJournalEntry[] entries = [pendingDelete, successor, allocation, newest];
        var finished = Finished(entries); finished.Remove(pendingDelete.Transfer.TransferId);
        var retained = StagedTransferJournal.FindCompactionProtectedTransfers(entries, finished, default);
        Assert.True(retained.SetEquals(entries.Select(e => e.Transfer.TransferId)));
    }

#if SAFEUPLOAD_ADMISSION_EVIDENCE
    [Theory]
    [InlineData(1000)]
    [InlineData(10000)]
    [InlineData(50000)]
    public void Many_bound_names_under_one_parent_keep_only_each_name_maximum(int destinations)
    {
        var entries = new List<TransferJournalEntry>(destinations * 2);
        var expected = new HashSet<Guid>();
        for (int i = destinations - 1; i >= 0; i--)
        {
            string leaf = "save-" + i.ToString("D5", CultureInfo.InvariantCulture) + ".txt";
            entries.Add(Entry(1, leaf, bound: true));
            var maximum = Entry(2, leaf.ToUpperInvariant(), bound: true);
            entries.Add(maximum); expected.Add(maximum.Transfer.TransferId);
        }
        var retained = Measure("bound-names-one-parent", entries);
        Assert.True(retained.SetEquals(expected));
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void Ordered_bound_claims_preserve_native_unicode_name_equality_in_a_nondefault_culture(bool caseSensitive)
    {
        string[] leaves = ["I.txt", "i.txt", "\u0130.txt", "\u0131.txt", "K.txt", "\u212a.txt", "S.txt", "\u017f.txt",
            "\u03a3.txt", "\u03c3.txt", "\u03c2.txt", "\u00df.txt", "SS.txt", "\u00e9.txt", "e.txt", "\U00010400.txt", "\U00010428.txt"];
        var previous = CultureInfo.CurrentCulture;
        try
        {
            CultureInfo.CurrentCulture = CultureInfo.GetCultureInfo("tr-TR");
            var entries = leaves.Select((leaf, index) => Entry(index + 1, leaf, bound: true, caseSensitive: caseSensitive)).ToArray();
            var expected = new HashSet<Guid>();
            for (int i = 0; i < leaves.Length; i++)
            {
                bool superseded = false;
                for (int j = i + 1; j < leaves.Length; j++)
                {
                    int native = CompareStringOrdinal(leaves[i], leaves[i].Length, leaves[j], leaves[j].Length, !caseSensitive);
                    Assert.InRange(native, 1, 3);
                    if (native == 2) superseded = true;
                }
                if (!superseded) expected.Add(entries[i].Transfer.TransferId);
            }
            Assert.True(Measure("native-unicode", entries).SetEquals(expected));
        }
        finally { CultureInfo.CurrentCulture = previous; }
    }

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, ExactSpelling = true, SetLastError = true)]
    private static extern int CompareStringOrdinal(string left, int leftChars, string right, int rightChars,
        [MarshalAs(UnmanagedType.Bool)] bool ignoreCase);
#endif
}
