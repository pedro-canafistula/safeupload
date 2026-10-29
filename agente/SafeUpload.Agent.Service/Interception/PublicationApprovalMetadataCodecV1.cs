#if SAFEUPLOAD_ADMISSION_EVIDENCE
namespace SafeUpload.Agent.Service.Interception;

// A storage projection is never an independent publication approval. Only the
// pack reader, after lossless finding reconstruction, validates the full DTO.
internal static class PublicationApprovalMetadataCodecV1
{
    internal const int MaximumBytes = 65536;
    internal static byte[] Serialize(PublicationApprovalV1 approval)
    {
        PublicationApprovalCodecV1.Validate(approval);
        EvidenceBinaryV1.Need(approval.Inspection.Reason is null, "Incomplete inspection cannot supply authorization evidence.");
        return ResourceJsonV3.Serialize(approval with { Inspection = approval.Inspection with { Findings = [] } }, MaximumBytes);
    }
    internal static PublicationApprovalV1 Deserialize(ReadOnlySpan<byte> bytes)
    {
        var value = ResourceJsonV4.Deserialize<PublicationApprovalV1>(bytes, MaximumBytes);
        PublicationApprovalCodecV1.Validate(value);
        EvidenceBinaryV1.Need(value.Inspection.Findings.IsEmpty && value.Inspection.Reason is null, "Noncanonical approval projection.");
        EvidenceBinaryV1.Need(bytes.SequenceEqual(Serialize(value)), "Noncanonical approval metadata bytes.");
        return value;
    }
}
#endif
