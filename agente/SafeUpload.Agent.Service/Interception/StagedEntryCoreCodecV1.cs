#if SAFEUPLOAD_ADMISSION_EVIDENCE
namespace SafeUpload.Agent.Service.Interception;

// Passive access to the unchanged journal's semantic validator. No journal,
// store, namespace or publication operation is invoked by this codec.
public sealed partial class StagedTransferJournal
{
    internal static void ValidateEvidenceEntryCore(TransferJournalEntry entry) => ValidateEntry(entry, entry.Transfer.TransferId);
}
internal static class StagedEntryCoreCodecV1
{
    internal const int MaximumBytes = 131072;
    internal static byte[] Serialize(TransferJournalEntry entry)
    {
        StagedTransferJournal.ValidateEvidenceEntryCore(entry);
        return ResourceJsonV3.Serialize(entry, MaximumBytes);
    }
    internal static TransferJournalEntry Deserialize(ReadOnlySpan<byte> bytes)
    {
        var value = ResourceJsonV4.Deserialize<TransferJournalEntry>(bytes, MaximumBytes);
        StagedTransferJournal.ValidateEvidenceEntryCore(value);
        EvidenceBinaryV1.Need(bytes.SequenceEqual(Serialize(value)), "Noncanonical source Entry bytes.");
        return value;
    }
}
#endif
