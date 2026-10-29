#if SAFEUPLOAD_ADMISSION_EVIDENCE
namespace SafeUpload.Agent.Service.Interception;

// Passive seam for a future adapter. No product caller is connected. The child
// cannot be requested until every payload dimension and stored section fits.
internal static class EvidencePackAdmissionV1
{
    internal static void PreflightThenIssue(EvidenceOwnerV1 owner, int alignment, TransferJournalEntry entry,
        PublicationApprovalV1? approval, Action<EvidencePackPlanV1> issue)
    {
        var plan = EvidencePackCodecV1.Preflight(owner, alignment, entry, approval);
        issue(plan);
    }
}
#endif
