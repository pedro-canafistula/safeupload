namespace SafeUpload.Agent.Service.Interception;

public enum StagedSeedOrigin { None, ExistingPublic, PrivatePredecessor }
public enum StagedSeedAuthority { Unproven, Allowed, Denied }

// Versioned storage evidence, never an authority synthesized from a SYSTEM open,
// a requested access mask, a digest, or the final length. No wire producer exists
// yet. The future checked producer must independently check the retained effective
// subject and the eventual recipient against this exact source/security tuple.
public sealed record StagedSeedExportEvidence(
    int FormatVersion, Guid EvidenceId, StagedAllocationBindingV23 SourceBinding,
    StagedStageIdentity PublicSource, StagedAllocationSecurityReference Security,
    Guid EffectiveSubjectId, string EffectiveSubjectSid,
    int ProcessId, long ProcessCreationTime, string RecipientSid, uint RecipientSessionId,
    StagedSeedAuthority ReadAuthority, StagedSeedAuthority RecipientAuthority)
{
    public int? ReadStatus { get; init; }
    public int? RecipientStatus { get; init; }
}

public sealed record StagedSeedProvenance(
    int FormatVersion, StagedVersionIdentity Allocation, StagedAllocationBindingV23? AllocationBinding,
    StagedSeedOrigin Origin, bool ContainsPriorBytes, StagedVersionIdentity? Predecessor,
    StagedAllocationBindingV23? SourceBinding, StagedStageIdentity? PublicSource,
    StagedAllocationSecurityReference? SourceSecurity, StagedSeedExportEvidence? ExportEvidence,
    string? InheritedRestriction)
{
    internal static StagedSeedProvenance ForBound(TransferJournalEntry allocation,
        TransferJournalEntry? parent, StagedSeedExportEvidence? evidence = null)
    {
        var binding = allocation.BoundAllocation!;
        bool copies = binding.Disposition is 1 or 3;
        if (copies && parent is not null) return Inherit(allocation, parent);
        bool prior = copies && binding.PublicTarget is not null;
        return new(1, StagedTransferJournal.VersionIdentity(allocation), binding,
            prior ? StagedSeedOrigin.ExistingPublic : StagedSeedOrigin.None, prior, null,
            prior ? binding : null, prior ? binding.PublicTarget : null,
            prior ? allocation.AllocationSecurity : null, prior ? evidence : null, null);
    }

    internal static StagedSeedProvenance Inherit(TransferJournalEntry allocation, TransferJournalEntry parent)
    {
        var source = parent.SeedProvenance;
        return new(1, StagedTransferJournal.VersionIdentity(allocation), allocation.BoundAllocation,
            StagedSeedOrigin.PrivatePredecessor, source?.ContainsPriorBytes ?? true,
            StagedTransferJournal.VersionIdentity(parent), source?.SourceBinding, source?.PublicSource,
            source?.SourceSecurity, source?.ExportEvidence, StagedSeedExport.Failure(parent));
    }

    internal void Validate(TransferJournalEntry entry)
    {
        // Bound allocations cannot opt out of the captured intent by erasing
        // the optional JSON fields. Legacy (unbound) evidence remains readable.
        if (entry.BoundAllocation is not null && (AllocationBinding is null || entry.AllocationSecurity is null))
            throw new InvalidDataException("writer_metadata_seed_provenance_missing");
        if (FormatVersion != 1 || Allocation is null || (Allocation.TransferId != entry.Transfer.TransferId || Allocation.StageIdentity != entry.StageIdentity ||
                Allocation.DestinationGeneration <= 0 || Allocation.DestinationGeneration > entry.DestinationGeneration) ||
            !Enum.IsDefined(Origin) ||
            (!ContainsPriorBytes && (SourceBinding is not null || PublicSource is not null ||
                SourceSecurity is not null || ExportEvidence is not null)) || (AllocationBinding is { } binding &&
                (binding.ReservationId != Allocation.TransferId || binding.DriverInstanceId != entry.DriverInstanceId)) ||
            (Origin == StagedSeedOrigin.None && (ContainsPriorBytes || Predecessor is not null ||
                SourceBinding is not null || PublicSource is not null || SourceSecurity is not null || ExportEvidence is not null)) ||
            (Origin == StagedSeedOrigin.ExistingPublic && (!ContainsPriorBytes || Predecessor is not null ||
                SourceBinding is null || PublicSource is null || SourceBinding.PublicTarget != PublicSource ||
                SourceBinding.ReservationId != Allocation.TransferId ||
                (AllocationBinding is not null && (SourceBinding != AllocationBinding || SourceSecurity != entry.AllocationSecurity)))) ||
            (Origin == StagedSeedOrigin.PrivatePredecessor && (Predecessor is null ||
                Predecessor != entry.ParentVersionIdentity)) ||
            (InheritedRestriction is not null && !StagedSeedExport.IsFailure(InheritedRestriction)))
            throw new InvalidDataException("The seed provenance lost its allocation/source binding.");
        if (AllocationBinding is { } captured)
        {
            StagedSeedOrigin expected = captured.Disposition is 1 or 3
                ? captured.ReferenceKind == 1 ? StagedSeedOrigin.PrivatePredecessor
                    : captured.PublicTarget is null ? StagedSeedOrigin.None : StagedSeedOrigin.ExistingPublic
                : StagedSeedOrigin.None;
            if (Origin != expected)
                throw new InvalidDataException("Seed origin disagrees with the captured allocation result/source.");
        }
        AllocationBinding?.Validate();
        SourceBinding?.Validate();
        SourceSecurity?.Validate();
    }
}

// Immutable local journal receipt, separate from allocation authority. Format 1
// receipts from the former service copier remain readable historical evidence;
// they cannot authorize bound exposure/seal. A live authenticated kernel receipt
// transport is still required; no V19 ACK or V27 metadata page is that transport.
public sealed record StagedSeedCompletion(StagedVersionIdentity Allocation, long Length)
{
    public int FormatVersion { get; init; } = 1;
    public Guid ReceiptId { get; init; }
    public Guid DriverInstanceId { get; init; }
    public StagedAllocationSecurityReference? Metadata { get; init; }
    public StagedAllocationBindingV23? Binding { get; init; }
    public StagedSeedOrigin Origin { get; init; }
    public StagedVersionIdentity? Predecessor { get; init; }
    public bool EofSet { get; init; }
    public bool Flushed { get; init; }
    public bool Revalidated { get; init; }

    internal static void Require(TransferJournalEntry entry)
    {
        if (entry.BoundAllocation is null) return;
        var receipt = entry.SeedCompletion;
        var provenance = entry.SeedProvenance;
        if (receipt is null || provenance is null || receipt.FormatVersion != 2 || receipt.ReceiptId == Guid.Empty ||
            receipt.Allocation != provenance.Allocation || receipt.Allocation != StagedTransferJournal.VersionIdentity(entry) ||
            receipt.DriverInstanceId != entry.DriverInstanceId || receipt.Binding != entry.BoundAllocation ||
            receipt.Metadata is null || receipt.Metadata != entry.AllocationSecurity ||
            receipt.Origin != provenance.Origin || receipt.Predecessor != provenance.Predecessor ||
            !Enum.IsDefined(receipt.Origin) || receipt.Length < 0 ||
            !receipt.EofSet || !receipt.Flushed || !receipt.Revalidated)
            throw new IOException("seed_completion_unproved");
        // No qualified public-source interval producer exists. This also refuses
        // a claimed zero-byte public copy: a concurrent writer can grow it.
        if (receipt.Origin == StagedSeedOrigin.ExistingPublic)
            throw new IOException("seed_coherence_unproved");
        if (receipt.Origin == StagedSeedOrigin.None && receipt.Length != 0)
            throw new IOException("seed_completion_unproved");
        if (receipt.Origin == StagedSeedOrigin.PrivatePredecessor)
            throw new IOException("seed_coherence_unproved"); // Exact private interval integration is pending too.
    }
}

internal static class StagedSeedExport
{
    internal const string Denied = "seed_export_denied";
    internal const string Unproven = "seed_export_unproven";
    internal const string RecipientUnproven = "seed_export_recipient_unproven";
    internal static bool IsFailure(string? reason) => reason is Denied or Unproven or RecipientUnproven;

    internal static string? Failure(TransferJournalEntry entry, string? recipientSid = null)
    {
        var seed = entry.SeedProvenance;
        if (entry.BoundAllocation is null && entry.UnboundSeedExport is { } unbound)
        {
            try { unbound.Validate(entry.Transfer); }
            catch (InvalidDataException) { return Unproven; }
            if (unbound.ReadAuthority == StagedSeedAuthority.Denied) return Denied;
            if (unbound.ReadAuthority != StagedSeedAuthority.Allowed) return Unproven;
            if (recipientSid is not null && !string.Equals(unbound.RequestorSid, recipientSid, StringComparison.OrdinalIgnoreCase))
                return RecipientUnproven;
        }
        if (seed is null) return entry.BoundAllocation is not null ? Unproven :
            IsFailure(entry.HandbackFailureReason) ? entry.HandbackFailureReason : null;
        try { StagedSeedCompletion.Require(entry); }
        catch (IOException) { return Unproven; }
        // This guard also serves callers holding an in-memory entry. Never let
        // a contradictory/missing bound intent reach the no-prior-bytes fast path.
        if (entry.BoundAllocation is not null)
        {
            try { seed.Validate(entry); }
            catch (InvalidDataException) { return Unproven; }
        }
        if (seed.InheritedRestriction is { } restriction) return restriction;
        if (!seed.ContainsPriorBytes) return null;
        if (seed.Allocation != StagedTransferJournal.VersionIdentity(entry)) return Unproven;
        var proof = seed.ExportEvidence;
        if (proof is null || proof.FormatVersion != 1 || proof.EvidenceId == Guid.Empty ||
            proof.EffectiveSubjectId == Guid.Empty || string.IsNullOrWhiteSpace(proof.EffectiveSubjectSid) ||
            proof.EffectiveSubjectSid.Length > 184 || !proof.EffectiveSubjectSid.StartsWith("S-", StringComparison.Ordinal) ||
            proof.EffectiveSubjectSid.Any(char.IsWhiteSpace) ||
            seed.SourceBinding is null || seed.PublicSource is null || seed.SourceSecurity is null ||
            proof.SourceBinding != seed.SourceBinding || proof.PublicSource != seed.PublicSource ||
            proof.Security != seed.SourceSecurity || proof.ProcessId != entry.Transfer.ProcessId ||
            proof.ProcessCreationTime != entry.Transfer.RequestorProcessCreationTime ||
            (entry.BoundAllocation is not null && seed.AllocationBinding != entry.BoundAllocation)) return Unproven;
        if (proof.ReadAuthority == StagedSeedAuthority.Denied) return Denied;
        if (proof.ReadAuthority != StagedSeedAuthority.Allowed) return Unproven;
        // A thread grant and the process-primary SID are never interchangeable.
        if (proof.RecipientAuthority != StagedSeedAuthority.Allowed ||
            !string.Equals(proof.RecipientSid, recipientSid ?? entry.Transfer.RequestorSid, StringComparison.OrdinalIgnoreCase) ||
            proof.RecipientSessionId != entry.Transfer.SessionId) return RecipientUnproven;
        return null;
    }

    internal static TransferJournalEntry PrivateBlocked(TransferJournalEntry entry, string reason) => entry with
    {
        HandbackState = StagedHandbackState.Failed, HandbackFailureReason = reason,
        HandbackPath = null, HandbackLength = null, JustificationWindowClosed = true,
        JustificationExpiresAtUtc = null, StageCleanupStarted = false
    };
}
