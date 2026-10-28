#if SAFEUPLOAD_ADMISSION_EVIDENCE
namespace SafeUpload.Agent.Service.Interception;

// Storage preflight for the complete typed schema. This is deliberately NOT an
// accepting ledger codec: semantic validation/strict readers and consumers must
// remain gated until the format's supported-shape fit blocker is resolved.
// The same compact default-escaped writer composes every retained source Entry,
// approval, claim and fixed receipt; no surrogate payload or field-size sum.
internal static class ResourceSerializationPreflightV3
{
    internal const int LedgerMaximumBytes = 65536;
    internal static byte[] Serialize(ResourceStateV3 value) => ResourceJsonV3.Serialize(value, LedgerMaximumBytes);
}
#endif
