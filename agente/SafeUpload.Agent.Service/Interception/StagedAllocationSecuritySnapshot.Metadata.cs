using System.Buffers.Binary;
using System.Security.Principal;
using System.Text;
using SafeUpload.Agent.Minifilter;

namespace SafeUpload.Agent.Service.Interception;

public sealed partial record StagedAllocationSecuritySnapshot
{
    internal static StagedAllocationSecuritySnapshot FromWriterMetadata(WriterMetadataSnapshot metadata)
    {
        // Re-parse rather than trusting externally constructed record properties.
        var checkedMetadata = WriterMetadataV27.DecodeEnvelope(Convert.FromHexString(metadata.EnvelopeHex));
        if (metadata != checkedMetadata) throw new InvalidDataException("writer_metadata_binding_mismatch");
        byte[] blob = metadata.Blob();
        var binding = CapturedBinding(metadata, blob);
        int construction = checked((int)U32(blob, 904)), stored = checked((int)U32(blob, 908));
        var result = Create(metadata.SnapshotId, binding, U32(blob, 896), U32(blob, 900),
            blob.AsSpan(1024, construction), blob.AsSpan(1024 + construction, stored)) with
            { WriterMetadataEnvelopeHex = metadata.EnvelopeHex };
        result.Validate();
        return result;
    }

    private WriterMetadataSnapshot ValidateWriterMetadata()
    {
        if (WriterMetadataEnvelopeHex is not { } hex || hex.Length > 2 * WriterMetadataV27.MaximumEnvelopeBytes ||
            (hex.Length & 1) != 0) throw new InvalidDataException("writer_metadata_incomplete");
        byte[] bytes;
        try { bytes = Convert.FromHexString(hex); }
        catch (FormatException error) { throw new InvalidDataException("writer_metadata_encoding", error); }
        var metadata = WriterMetadataV27.DecodeEnvelope(bytes);
        if (metadata.EnvelopeHex != hex || metadata.DriverInstanceId != DriverInstanceId ||
            metadata.ReservationId != ReservationId || metadata.SnapshotId != SnapshotId)
            throw new InvalidDataException("writer_metadata_binding_mismatch");
        byte[] blob = metadata.Blob();
        var binding = CapturedBinding(metadata, blob);
        int construction = checked((int)U32(blob, 904)), stored = checked((int)U32(blob, 908));
        if (BindingDigest(binding) != BindingSha256Hex || AssignmentRevision != U32(blob, 896) ||
            SecurityInformation != U32(blob, 900) ||
            ConstructionHex != Convert.ToHexString(StagedSecurityDescriptor.Canonicalize(blob.AsSpan(1024, construction))) ||
            ExpectedStoredHex != Convert.ToHexString(StagedSecurityDescriptor.Canonicalize(blob.AsSpan(1024 + construction, stored))))
            throw new InvalidDataException("writer_metadata_security_mismatch");
        return metadata;
    }

    internal void RequireWriterMetadata(StagedAllocationBindingV23 binding, StagedTransfer transfer)
    {
        RequireBinding(binding);
        var metadata = ValidateWriterMetadata();
        byte[] blob = metadata.Blob();
        if (CapturedBinding(metadata, blob) != binding || transfer.TransferId != binding.ReservationId ||
            transfer.ProcessId != U32(blob, 644) || transfer.SessionId != U32(blob, 648) ||
            transfer.RequestorProcessCreationTime != BinaryPrimitives.ReadInt64LittleEndian(blob.AsSpan(652)) ||
            transfer.RequestorSid != new SecurityIdentifier(blob, 664).Value)
            throw new InvalidDataException("writer_metadata_caller_mismatch");
    }

    internal StagedSeedExportEvidence? CapturedSeedEvidence(StagedAllocationBindingV23 binding, StagedTransfer transfer)
    {
        RequireWriterMetadata(binding, transfer);
        return CapturedSeedEvidence();
    }

    internal void RequireCapturedSeedProvenance(TransferJournalEntry entry)
    {
        var metadata = ValidateWriterMetadata();
        byte[] blob = metadata.Blob();
        var binding = CapturedBinding(metadata, blob);
        var seed = entry.SeedProvenance ?? throw new InvalidDataException("writer_metadata_seed_provenance_missing");
        seed.Validate(entry);
        if (seed.AllocationBinding != binding || seed.Origin != (StagedSeedOrigin)U32(blob, 912))
            throw new InvalidDataException("writer_metadata_seed_intent_mismatch");
        if (seed.Origin == StagedSeedOrigin.PrivatePredecessor)
        {
            if (seed.Predecessor is not { } parent || parent.TransferId != binding.ParentTransferId ||
                parent.DestinationGeneration >= seed.Allocation.DestinationGeneration)
                throw new InvalidDataException("writer_metadata_seed_lineage_mismatch");
            // Source fields are checked against the exact predecessor by the journal.
            return;
        }
        // Use the captured allocation identity, which survives namespace changes.
        var original = entry with { BoundAllocation = binding,
            DestinationGeneration = seed.Allocation.DestinationGeneration };
        if (seed != StagedSeedProvenance.ForBound(original, null, CapturedSeedEvidence()))
            throw new InvalidDataException("writer_metadata_seed_intent_mismatch");
    }

    // An inherited source keeps its original captured writer/recipient. A child
    // is not substituted here; the export gate independently checks that child.
    internal StagedSeedExportEvidence? CapturedSeedEvidence()
    {
        Validate();
        var metadata = ValidateWriterMetadata();
        byte[] blob = metadata.Blob();
        var binding = CapturedBinding(metadata, blob);
        if (U32(blob, 912) != 1) return null;
        return new(1, SnapshotId, binding, binding.PublicTarget!, Reference(), new Guid(blob.AsSpan(932, 16)),
            new SecurityIdentifier(blob, 736).Value, checked((int)U32(blob, 644)),
            BinaryPrimitives.ReadInt64LittleEndian(blob.AsSpan(652)),
            new SecurityIdentifier(blob, 664).Value, U32(blob, 648),
            StagedSeedAuthority.Unproven, StagedSeedAuthority.Unproven)
        {
            ReadStatus = BinaryPrimitives.ReadInt32LittleEndian(blob.AsSpan(924)),
            RecipientStatus = BinaryPrimitives.ReadInt32LittleEndian(blob.AsSpan(928))
        };
    }

    private static StagedAllocationBindingV23 CapturedBinding(WriterMetadataSnapshot metadata, byte[] blob)
    {
        ulong serial = BinaryPrimitives.ReadUInt64LittleEndian(blob.AsSpan(104));
        var parent = new StagedStageIdentity(serial, BinaryPrimitives.ReadUInt64LittleEndian(blob.AsSpan(120)),
            BinaryPrimitives.ReadUInt64LittleEndian(blob.AsSpan(112)));
        ushort sensitive = BinaryPrimitives.ReadUInt16LittleEndian(blob.AsSpan(128));
        if (sensitive > 1) throw new InvalidDataException("writer_metadata_case_mismatch");
        string leaf;
        try { leaf = new UnicodeEncoding(false, false, true).GetString(blob, 132,
            BinaryPrimitives.ReadUInt16LittleEndian(blob.AsSpan(130))); }
        catch (DecoderFallbackException error) { throw new InvalidDataException("writer_metadata_leaf_invalid", error); }
        var result = new StagedAllocationBindingV23(metadata.ReservationId, metadata.DriverInstanceId,
            new Guid(blob.AsSpan(32, 16)), U32(blob, 48), U32(blob, 52), new Guid(blob.AsSpan(72, 16)),
            new(serial, BinaryPrimitives.ReadUInt64LittleEndian(blob.AsSpan(96)),
                BinaryPrimitives.ReadUInt64LittleEndian(blob.AsSpan(88))), parent, sensitive == 1, leaf,
            blob.AsSpan(56, 16).IndexOfAnyExcept((byte)0) < 0 ? null : new(serial,
                BinaryPrimitives.ReadUInt64LittleEndian(blob.AsSpan(64)), BinaryPrimitives.ReadUInt64LittleEndian(blob.AsSpan(56))));
        result.Validate();
        return result;
    }

    private static uint U32(ReadOnlySpan<byte> bytes, int offset) => BinaryPrimitives.ReadUInt32LittleEndian(bytes[offset..]);
}
