#if SAFEUPLOAD_ADMISSION_EVIDENCE
using System.Collections.Immutable;
using System.Security.Cryptography;
using System.Text;

namespace SafeUpload.Agent.Service.Interception;

internal sealed record EvidencePackPlanV1(EvidenceOwnerV1 Owner, int Alignment, byte[] Payload, int EntryBytes,
    int MetadataBytes, int FindingCount, int NameCount, long SuffixUnits, int ChunkCount, int FileBytes);
internal sealed record EvidencePackImageV1(EvidenceReferenceV1 Reference, byte[] Bytes);
internal sealed record EvidencePackContentV1(TransferJournalEntry Entry, PublicationApprovalV1? Approval);
internal sealed record EvidenceObservationV1(StagedStageIdentity Identity, bool SecurityMatches, bool SingleLink, bool ReparsePoint);

// Pure stored-format codec. Observed identity/security must later come from the
// same held native object; this class creates no handles or storage authority.
internal static class EvidencePackCodecV1
{
    internal const int MaximumFindings = 16384, MaximumMemberUnits = 1179634, MaximumSuffixUnits = 8699904;
    internal const int MaximumLogicalBytes = 18972672, MaximumFileBytes = 19202048;
    internal const int ChunkBytes = 131072, HeaderBytes = 256, ChunkPayloadBytes = 130816, MaximumChunks = 146;
    private static readonly UnicodeEncoding Utf16 = new(false, false, true);

    internal static EvidencePackPlanV1 Preflight(EvidenceOwnerV1 owner, int alignment, TransferJournalEntry entry,
        PublicationApprovalV1? approval)
    {
        EvidenceReferenceCodecV1.ValidateOwner(owner); EvidenceBinaryV1.Alignment(alignment);
        byte[] source = StagedEntryCoreCodecV1.Serialize(entry);
        ValidateAuthority(owner, entry, approval);
        byte[] metadata = approval is null ? [] : PublicationApprovalMetadataCodecV1.Serialize(approval);
        var findings = approval?.Inspection.Findings ?? [];
        EvidenceBinaryV1.Need(findings.Length <= MaximumFindings, "Finding count exceeds the producer bound.");
        foreach (var finding in findings)
        {
            Text(finding.MaskedSnippet, 32);
            if (finding.MemberName is { } name) Text(name, MaximumMemberUnits);
        }
        string[] names = findings.Select(f => f.MemberName).OfType<string>().Distinct(StringComparer.Ordinal)
            .Order(StringComparer.Ordinal).ToArray();
        var indices = names.Select((name, index) => (name, index)).ToDictionary(x => x.name, x => x.index, StringComparer.Ordinal);
        // Check all dimensions before retaining the payload or issuing a child.
        long suffixUnits = 0, logical = checked(source.Length + metadata.Length); string previous = "";
        foreach (var finding in findings) logical = checked(logical + 12 + 2 * finding.MaskedSnippet.Length);
        foreach (string name in names)
        {
            int suffix = name.Length - CommonPrefix(previous, name); suffixUnits = checked(suffixUnits + suffix);
            logical = checked(logical + 8 + 2L * suffix); previous = name;
        }
        ValidateShape(source.Length, metadata.Length, findings.Length, names.Length, suffixUnits, logical, owner.Kind);
        using var stream = new MemoryStream(checked((int)logical)); using var writer = new BinaryWriter(stream, Utf16, leaveOpen: true);
        writer.Write(source); writer.Write(metadata);
        foreach (var finding in findings)
        {
            writer.Write((uint)finding.Category); writer.Write(finding.MemberName is null ? -1 : indices[finding.MemberName]);
            writer.Write((uint)finding.MaskedSnippet.Length); writer.Write(Utf16.GetBytes(finding.MaskedSnippet));
        }
        previous = "";
        foreach (string name in names)
        {
            int prefix = CommonPrefix(previous, name);
            writer.Write((uint)prefix); writer.Write((uint)(name.Length - prefix)); writer.Write(Utf16.GetBytes(name[prefix..])); previous = name;
        }
        int chunks = checked(((int)logical + ChunkPayloadBytes - 1) / ChunkPayloadBytes);
        int fileBytes = checked(alignment + chunks * ChunkBytes);
        EvidenceBinaryV1.Need(chunks <= MaximumChunks && fileBytes <= MaximumFileBytes, "Evidence container exceeds its bound.");
        return new(owner, alignment, stream.ToArray(), source.Length, metadata.Length, findings.Length, names.Length, suffixUnits, chunks, fileBytes);
    }

    internal static EvidencePackImageV1 Serialize(EvidencePackPlanV1 plan, StagedStageIdentity capturedIdentity)
    {
        ResourceJsonV3.Identity(capturedIdentity);
        // Plans are caller-owned data too. Re-read/rebuild before publishing any
        // bytes, so mutating a plan cannot bypass shape/authority validation.
        var content = DecodePayload(plan.Payload, plan.EntryBytes, plan.MetadataBytes, plan.FindingCount, plan.NameCount,
            plan.SuffixUnits, plan.Owner);
        var verified = Preflight(plan.Owner, plan.Alignment, content.Entry, content.Approval);
        EvidenceBinaryV1.Need(plan.ChunkCount == verified.ChunkCount && plan.FileBytes == verified.FileBytes &&
            plan.Payload.AsSpan().SequenceEqual(verified.Payload), "Changed evidence plan.");
        var bytes = new byte[plan.FileBytes];
        "SAFEVP01"u8.CopyTo(bytes); EvidenceBinaryV1.U32(bytes, 8, 1); EvidenceBinaryV1.U32(bytes, 12, HeaderBytes);
        EvidenceBinaryV1.Owner(bytes, plan.Owner); EvidenceBinaryV1.Identity(bytes, 88, capturedIdentity);
        EvidenceBinaryV1.U32(bytes, 112, (uint)plan.Owner.Kind); EvidenceBinaryV1.U32(bytes, 116, plan.EntryBytes);
        EvidenceBinaryV1.U32(bytes, 120, plan.MetadataBytes); EvidenceBinaryV1.U32(bytes, 124, plan.FindingCount);
        EvidenceBinaryV1.U32(bytes, 128, plan.NameCount); EvidenceBinaryV1.U32(bytes, 132, plan.ChunkCount);
        EvidenceBinaryV1.U64(bytes, 136, checked((ulong)plan.SuffixUnits)); EvidenceBinaryV1.U64(bytes, 144, checked((ulong)plan.Payload.Length));
        EvidenceBinaryV1.U64(bytes, 152, checked((ulong)plan.FileBytes));
        byte[] previousHash = new byte[32];
        for (int index = 0, logicalOffset = 0; index < plan.ChunkCount; index++)
        {
            Span<byte> chunk = bytes.AsSpan(plan.Alignment + index * ChunkBytes, ChunkBytes);
            int length = Math.Min(ChunkPayloadBytes, plan.Payload.Length - logicalOffset);
            "SAFEVC01"u8.CopyTo(chunk); EvidenceBinaryV1.U32(chunk, 8, 1); EvidenceBinaryV1.U32(chunk, 12, HeaderBytes);
            EvidenceBinaryV1.Id(chunk, 16, plan.Owner.RecordId); EvidenceBinaryV1.I64(chunk, 32, plan.Owner.Generation);
            EvidenceBinaryV1.U64(chunk, 40, (ulong)index); EvidenceBinaryV1.U64(chunk, 48, (ulong)plan.ChunkCount);
            EvidenceBinaryV1.U64(chunk, 56, (ulong)logicalOffset); EvidenceBinaryV1.U32(chunk, 64, length); EvidenceBinaryV1.U32(chunk, 68, ChunkBytes);
            plan.Payload.AsSpan(logicalOffset, length).CopyTo(chunk[HeaderBytes..]);
            SHA256.HashData(chunk.Slice(HeaderBytes, length)).CopyTo(chunk[72..]); previousHash.CopyTo(chunk[104..]);
            previousHash = SHA256.HashData(chunk); logicalOffset += length;
        }
        return new(new(plan.Owner, capturedIdentity, bytes.Length, Convert.ToHexString(SHA256.HashData(bytes))), bytes);
    }

    internal static EvidencePackContentV1 Deserialize(EvidenceReferenceV1 reference, EvidenceOwnerV1 expectedOwner,
        EvidenceObservationV1 observed, int alignment, ReadOnlySpan<byte> bytes)
    {
        EvidenceReferenceCodecV1.Validate(reference); EvidenceReferenceCodecV1.ValidateOwner(expectedOwner); EvidenceBinaryV1.Alignment(alignment);
        EvidenceBinaryV1.Need(reference.Owner == expectedOwner && observed.Identity == reference.Identity && observed.SecurityMatches &&
            observed.SingleLink && !observed.ReparsePoint && bytes.Length == reference.Length, "Evidence owner/held object differs.");
        EvidenceBinaryV1.Hash(bytes, Convert.FromHexString(reference.Sha256));
        EvidenceBinaryV1.Need(bytes[..8].SequenceEqual("SAFEVP01"u8) && EvidenceBinaryV1.U32(bytes, 8) == 1 &&
            EvidenceBinaryV1.U32(bytes, 12) == HeaderBytes && EvidenceBinaryV1.Owner(bytes, 112) == reference.Owner &&
            EvidenceBinaryV1.Identity(bytes, 88) == reference.Identity && EvidenceBinaryV1.U64(bytes, 152) == (ulong)bytes.Length,
            "Evidence file header differs.");
        EvidenceBinaryV1.Zero(bytes[192..alignment]);
        uint entryBytes = EvidenceBinaryV1.U32(bytes, 116), metadataBytes = EvidenceBinaryV1.U32(bytes, 120);
        uint findings = EvidenceBinaryV1.U32(bytes, 124), names = EvidenceBinaryV1.U32(bytes, 128), chunks = EvidenceBinaryV1.U32(bytes, 132);
        ulong suffix = EvidenceBinaryV1.U64(bytes, 136), logical = EvidenceBinaryV1.U64(bytes, 144);
        EvidenceBinaryV1.Need(entryBytes <= 131072 && metadataBytes <= 65536 && findings <= MaximumFindings && names <= findings &&
            suffix <= MaximumSuffixUnits && logical is > 0 and <= MaximumLogicalBytes && chunks is > 0 and <= MaximumChunks &&
            chunks == (logical + ChunkPayloadBytes - 1) / ChunkPayloadBytes && (long)alignment + chunks * (long)ChunkBytes == bytes.Length,
            "Evidence file dimensions differ.");
        ValidateShape((int)entryBytes, (int)metadataBytes, (int)findings, (int)names, (long)suffix, (long)logical, expectedOwner.Kind);
        var payload = new byte[(int)logical]; byte[] previousHash = new byte[32]; int offset = 0;
        for (int index = 0; index < (int)chunks; index++)
        {
            var chunk = bytes.Slice(alignment + index * ChunkBytes, ChunkBytes);
            int length = Math.Min(ChunkPayloadBytes, payload.Length - offset);
            EvidenceBinaryV1.Need(chunk[..8].SequenceEqual("SAFEVC01"u8) && EvidenceBinaryV1.U32(chunk, 8) == 1 &&
                EvidenceBinaryV1.U32(chunk, 12) == HeaderBytes && EvidenceBinaryV1.Id(chunk, 16) == expectedOwner.RecordId &&
                EvidenceBinaryV1.I64(chunk, 32) == expectedOwner.Generation && EvidenceBinaryV1.U64(chunk, 40) == (ulong)index &&
                EvidenceBinaryV1.U64(chunk, 48) == chunks && EvidenceBinaryV1.U64(chunk, 56) == (ulong)offset &&
                EvidenceBinaryV1.U32(chunk, 64) == length && EvidenceBinaryV1.U32(chunk, 68) == ChunkBytes &&
                chunk.Slice(104, 32).SequenceEqual(previousHash), "Evidence chunk header/order/chain differs.");
            EvidenceBinaryV1.Zero(chunk[136..HeaderBytes]); EvidenceBinaryV1.Hash(chunk.Slice(HeaderBytes, length), chunk.Slice(72, 32));
            EvidenceBinaryV1.Zero(chunk[(HeaderBytes + length)..]); chunk.Slice(HeaderBytes, length).CopyTo(payload.AsSpan(offset));
            previousHash = SHA256.HashData(chunk); offset += length;
        }
        return DecodePayload(payload, (int)entryBytes, (int)metadataBytes, (int)findings, (int)names, (long)suffix, expectedOwner);
    }

    internal static EvidencePackContentV1 DecodePayload(ReadOnlySpan<byte> payload, int entryBytes, int metadataBytes,
        int findingCount, int nameCount, long suffixUnits, EvidenceOwnerV1 owner)
    {
        try { return DecodePayloadCore(payload, entryBytes, metadataBytes, findingCount, nameCount, suffixUnits, owner); }
        catch (Exception error) when (error is ArgumentException or OverflowException or System.Text.Json.JsonException)
        { throw new InvalidDataException("Invalid evidence payload.", error); }
    }
    private static EvidencePackContentV1 DecodePayloadCore(ReadOnlySpan<byte> payload, int entryBytes, int metadataBytes,
        int findingCount, int nameCount, long suffixUnits, EvidenceOwnerV1 owner)
    {
        ValidateShape(entryBytes, metadataBytes, findingCount, nameCount, suffixUnits, payload.Length, owner.Kind);
        EvidenceBinaryV1.Need(entryBytes + metadataBytes <= payload.Length, "Truncated evidence sections.");
        var entry = StagedEntryCoreCodecV1.Deserialize(payload[..entryBytes]);
        var approval = metadataBytes == 0 ? null : PublicationApprovalMetadataCodecV1.Deserialize(payload.Slice(entryBytes, metadataBytes));
        int position = entryBytes + metadataBytes;
        var findings = new (int Category, int Member, string Snippet)[findingCount];
        for (int index = 0; index < findingCount; index++)
        {
            EvidenceBinaryV1.Need(payload.Length - position >= 12, "Truncated finding header.");
            uint category = EvidenceBinaryV1.U32(payload, position), member = EvidenceBinaryV1.U32(payload, position + 4), units = EvidenceBinaryV1.U32(payload, position + 8);
            EvidenceBinaryV1.Need(category <= 4 && (member == uint.MaxValue || member < nameCount) && units <= 32, "Invalid finding dimensions.");
            position += 12;
            findings[index] = ((int)category, unchecked((int)member), ReadText(payload, ref position, (int)units));
        }
        string[] names = new string[nameCount]; long suffixSum = 0; string previous = "";
        for (int index = 0; index < nameCount; index++)
        {
            EvidenceBinaryV1.Need(payload.Length - position >= 8, "Truncated member header.");
            uint prefix = EvidenceBinaryV1.U32(payload, position), suffix = EvidenceBinaryV1.U32(payload, position + 4); position += 8;
            EvidenceBinaryV1.Need(prefix <= previous.Length && suffix <= MaximumMemberUnits && (long)prefix + suffix <= MaximumMemberUnits &&
                (prefix == 0 || !char.IsHighSurrogate(previous[(int)prefix - 1])), "Invalid member prefix/surrogate.");
            suffixSum = checked(suffixSum + suffix);
            EvidenceBinaryV1.Need(suffixSum <= MaximumSuffixUnits && suffixSum <= suffixUnits, "Member suffix total exceeds its bound.");
            string name = previous[..(int)prefix] + ReadText(payload, ref position, (int)suffix);
            EvidenceBinaryV1.Need((index == 0 || string.CompareOrdinal(previous, name) < 0) && CommonPrefix(previous, name) == prefix,
                "Member names/prefixes are not canonical ordinal front coding.");
            names[index] = name; previous = name;
        }
        EvidenceBinaryV1.Need(position == payload.Length && suffixSum == suffixUnits, "Extra/truncated evidence payload.");
        var used = new bool[nameCount];
        var reconstructed = findings.Select(f =>
        {
            if (f.Member >= 0) used[f.Member] = true;
            return new PublicationApprovalFindingV1(f.Category, f.Snippet, f.Member < 0 ? null : names[f.Member]);
        }).ToImmutableArray();
        EvidenceBinaryV1.Need(used.All(x => x), "Unreferenced member table entries.");
        if (approval is not null) approval = approval with { Inspection = approval.Inspection with { Findings = reconstructed } };
        else EvidenceBinaryV1.Need(findingCount == 0 && nameCount == 0, "Missing approval for findings.");
        ValidateAuthority(owner, entry, approval);
        return new(entry, approval);
    }

    private static void ValidateAuthority(EvidenceOwnerV1 owner, TransferJournalEntry entry, PublicationApprovalV1? approval)
    {
        EvidenceReferenceCodecV1.ValidateOwner(owner);
        EvidenceBinaryV1.Need(entry.Transfer.TransferId == owner.TransferId && entry.DestinationGeneration == owner.DestinationGeneration &&
            (entry.DriverInstanceId is not { } driver || driver != Guid.Empty), "Source Entry binding differs.");
        if (owner.Kind == EvidenceKindV1.EntryCore)
        { EvidenceBinaryV1.Need(approval is null, "EntryCore cannot carry an approval."); return; }
        if (approval is null)
        {
            EvidenceBinaryV1.Need(entry.State == TransferJournalState.Blocked && entry.HandbackState == StagedHandbackState.Copying,
                "Hand-back authorization requires the complete Blocked/Copying source."); return;
        }
        PublicationApprovalCodecV1.Validate(approval);
        var binding = approval.Binding; var operation = approval.Operation;
        EvidenceBinaryV1.Need(entry.State == TransferJournalState.Publishing && binding.TransferId == owner.TransferId &&
            binding.OperationId == owner.OperationId && binding.AllocationGeneration == owner.AllocationGeneration &&
            binding.DestinationGeneration == owner.DestinationGeneration && binding.StageIdentity == entry.StageIdentity &&
            binding.Length == entry.SealedLength && binding.Sha256 == entry.Sha256Hex && binding.RequestorSid == entry.Transfer.RequestorSid &&
            binding.SessionId == entry.Transfer.SessionId && operation.ProcessId == entry.Transfer.ProcessId &&
            operation.ProcessName == entry.Transfer.ProcessName && operation.DestinationPath == entry.Transfer.DestinationPath &&
            operation.Destination == (int)entry.Transfer.Destination && approval.Inspection.Reason is null &&
            (!approval.Justified || entry.BlockedPolicyVersion == approval.Inspection.PolicyVersion &&
                entry.BlockedPolicyFingerprint == approval.Inspection.PolicyContentFingerprint), "Approval/source authority differs.");
    }
    private static void ValidateShape(int entry, int metadata, int findings, int names, long suffix, long logical, EvidenceKindV1 kind)
    {
        EvidenceBinaryV1.Need(entry is > 0 and <= 131072 && metadata is >= 0 and <= 65536 && findings is >= 0 and <= MaximumFindings &&
            names >= 0 && names <= findings && suffix is >= 0 and <= MaximumSuffixUnits && logical is > 0 and <= MaximumLogicalBytes &&
            (kind == EvidenceKindV1.Authorization || kind == EvidenceKindV1.EntryCore && metadata == 0 && findings == 0 && names == 0 && suffix == 0) &&
            (metadata != 0 || findings == 0 && names == 0 && suffix == 0), "Evidence dimensions exceed the selected format.");
    }
    internal static int CommonPrefix(string left, string right)
    {
        int prefix = 0;
        while (prefix < Math.Min(left.Length, right.Length) && left[prefix] == right[prefix]) prefix++;
        if (prefix > 0 && char.IsHighSurrogate(left[prefix - 1])) prefix--;
        return prefix;
    }
    private static string ReadText(ReadOnlySpan<byte> payload, ref int position, int units)
    {
        int bytes = checked(units * 2); EvidenceBinaryV1.Need(bytes <= payload.Length - position, "Truncated evidence text.");
        string value = Utf16.GetString(payload.Slice(position, bytes)); position += bytes; return value;
    }
    private static void Text(string value, int maximum)
    {
        EvidenceBinaryV1.Need(value is not null && value.Length <= maximum, "Evidence text exceeds its producer bound.");
        try { Utf16.GetByteCount(value); }
        catch (EncoderFallbackException error) { throw new InvalidDataException("Unpaired evidence surrogate.", error); }
    }
}
#endif
