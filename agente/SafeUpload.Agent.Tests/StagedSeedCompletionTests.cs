using SafeUpload.Agent.Core.Domain;
using SafeUpload.Agent.Service.Interception;

namespace SafeUpload.Agent.Tests;

// Pure prerequisite controls run in normal and feature configurations. These
// synthetic receipts do not qualify kernel I/O, coherence or native authority.
public sealed class StagedSeedCompletionTests
{
    private static TransferJournalEntry Pending()
    {
        Guid id = Guid.NewGuid(), driver = Guid.NewGuid();
        var binding = new StagedAllocationBindingV23(id, driver, Guid.Empty, 2, 0, Guid.NewGuid(),
            new(7, 0, 1), new(7, 0, 2), false, "new.txt", null);
        var entry = new TransferJournalEntry(new StagedTransfer(id, "private.stage", "new.txt",
            DestinationKind.Cloud, "writer", 42, 7), TransferJournalState.Allocated, null, DateTimeOffset.UtcNow)
        {
            DriverInstanceId = driver, BoundAllocation = binding, StageIdentity = new(7, 0, 3),
            DestinationGeneration = 1, AllocationSecurity = new(Guid.NewGuid(), 100, new string('A', 64))
        };
        return entry with { SeedProvenance = StagedSeedProvenance.ForBound(entry, null) };
    }

    private static StagedSeedCompletion Completed(TransferJournalEntry entry) =>
        new(StagedTransferJournal.VersionIdentity(entry), 0)
        {
            FormatVersion = 2, ReceiptId = Guid.NewGuid(), DriverInstanceId = entry.DriverInstanceId!.Value,
            Binding = entry.BoundAllocation, Metadata = entry.AllocationSecurity,
            Origin = entry.SeedProvenance!.Origin, Predecessor = entry.SeedProvenance.Predecessor,
            EofSet = true, Flushed = true, Revalidated = true
        };

    [Fact]
    public void Empty_candidate_still_needs_completed_eof_flush_and_revalidation()
    {
        var entry = Pending();
        Assert.Equal("seed_completion_unproved", Assert.Throws<IOException>(() => StagedSeedCompletion.Require(entry)).Message);
        entry = entry with { SeedCompletion = Completed(entry) };
        StagedSeedCompletion.Require(entry);
        Assert.Equal(TransferJournalState.Allocated, entry.State); // Never implicit seal/approval.
        Assert.Null(StagedSeedExport.Failure(entry));
    }

    [Theory]
    [InlineData("legacy")]
    [InlineData("receipt")]
    [InlineData("driver")]
    [InlineData("generation")]
    [InlineData("identity")]
    [InlineData("binding")]
    [InlineData("metadata")]
    [InlineData("origin")]
    [InlineData("predecessor")]
    [InlineData("negative_length")]
    [InlineData("unexpected_bytes")]
    [InlineData("eof")]
    [InlineData("flush")]
    [InlineData("revalidation")]
    public void Incomplete_or_substituted_receipt_cannot_authorize_exposure_seal_or_export(string change)
    {
        var entry = Pending(); var receipt = Completed(entry);
        receipt = change switch
        {
            "legacy" => new(receipt.Allocation, 0),
            "receipt" => receipt with { ReceiptId = Guid.Empty },
            "driver" => receipt with { DriverInstanceId = Guid.NewGuid() },
            "generation" => receipt with { Allocation = receipt.Allocation with { DestinationGeneration = 2 } },
            "identity" => receipt with { Allocation = receipt.Allocation with { StageIdentity = new(7, 0, 4) } },
            "binding" => receipt with { Binding = receipt.Binding! with { CanonicalLeaf = "different.txt" } },
            "metadata" => receipt with { Metadata = receipt.Metadata! with { SnapshotId = Guid.NewGuid() } },
            "origin" => receipt with { Origin = StagedSeedOrigin.ExistingPublic },
            "predecessor" => receipt with { Predecessor = receipt.Allocation },
            "negative_length" => receipt with { Length = -1 },
            "unexpected_bytes" => receipt with { Length = 1 },
            "eof" => receipt with { EofSet = false },
            "flush" => receipt with { Flushed = false },
            "revalidation" => receipt with { Revalidated = false },
            _ => throw new ArgumentException(change)
        };
        entry = entry with { SeedCompletion = receipt };
        Assert.Equal("seed_completion_unproved", Assert.Throws<IOException>(() => StagedSeedCompletion.Require(entry)).Message);
        Assert.Equal("seed_export_unproven", StagedSeedExport.Failure(entry));
    }

    [Theory]
    [InlineData(StagedSeedOrigin.ExistingPublic, 0L)]
    [InlineData(StagedSeedOrigin.ExistingPublic, 65539L)]
    [InlineData(StagedSeedOrigin.PrivatePredecessor, 0L)]
    [InlineData(StagedSeedOrigin.PrivatePredecessor, 65539L)]
    public void Identity_length_and_claimed_io_success_never_establish_a_seed_interval(StagedSeedOrigin origin, long length)
    {
        var entry = Pending();
        var binding = entry.BoundAllocation! with { Disposition = 1, PublicTarget = new(7, 0, 4) };
        entry = entry with { BoundAllocation = binding };
        entry = entry with { SeedProvenance = StagedSeedProvenance.ForBound(entry, null) with { Origin = origin } };
        entry = entry with { SeedCompletion = Completed(entry) with { Length = length } };
        Assert.Equal("seed_coherence_unproved", Assert.Throws<IOException>(() => StagedSeedCompletion.Require(entry)).Message);
        Assert.Equal("seed_export_unproven", StagedSeedExport.Failure(entry));
    }

    [Fact]
    public void Legacy_allocations_keep_their_existing_seal_prerequisites()
    {
        var legacy = Pending() with { BoundAllocation = null, SeedProvenance = null };
        StagedSeedCompletion.Require(legacy);
        Assert.Null(StagedSeedExport.Failure(legacy));
    }

#if SAFEUPLOAD_ADMISSION_EVIDENCE
    [Fact]
    public void Metadata_carrier_cannot_enable_live_bound_allocation() =>
        Assert.False(MinifilterInterceptor.BoundAllocationImplemented);
#endif
}
