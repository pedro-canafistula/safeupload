#if SAFEUPLOAD_ADMISSION_EVIDENCE
namespace SafeUpload.Agent.Service.Interception;

internal sealed record EvidenceHeldImageV1(EvidenceReferenceV1 Reference, EvidenceObservationV1 Observed, int Alignment, byte[] Bytes);

// Snapshot of independently supplied held-object observations. Never performs a
// path/digest lookup or opens an object; callers must supply the expected tuple.
internal sealed class EvidenceCatalogV1(IEnumerable<EvidenceHeldImageV1> images)
{
    private readonly EvidenceHeldImageV1[] held = images.ToArray();
    internal EvidencePackContentV1 Resolve(EvidenceReferenceV1 expected)
    {
        var matches = held.Where(x => x.Reference.Owner.RecordId == expected.Owner.RecordId).ToArray();
        EvidenceBinaryV1.Need(matches.Length == 1 && matches[0].Reference == expected, "Missing/duplicate/changed referenced object.");
        var image = matches[0];
        return EvidencePackCodecV1.Deserialize(expected, expected.Owner, image.Observed, image.Alignment, image.Bytes);
    }
    internal EvidencePackContentV1 Resolve(string encoded) => Resolve(EvidenceReferenceCodecV1.Deserialize(ResourceJsonV3.Base64(encoded, 192)));
    internal static EvidenceCatalogV1 Empty => new([]);
}
#endif
