#if SAFEUPLOAD_ADMISSION_EVIDENCE
using System.Collections.Immutable;
using SafeUpload.Agent.Core.Domain;

namespace SafeUpload.Agent.Service.Interception;

// Explicit durable DTO: InspectionResult itself intentionally JsonIgnores the
// fingerprint. No approval reader/serializer is a live publication permit.
internal sealed record PublicationApprovalV1(int Version, PublicationApprovalBindingV1 Binding,
    PublicationApprovalOperationV1 Operation, PublicationApprovalInspectionV1 Inspection,
    PublicationApprovalPolicyV1 PolicyCheck, bool Justified, PublicationApprovalJustificationV1? Justification);
internal sealed record PublicationApprovalBindingV1(Guid OperationId, Guid TransferId, long AllocationGeneration,
    long DestinationGeneration, StagedStageIdentity StageIdentity, StagedStageIdentity SnapshotIdentity,
    long Length, string Sha256, string RequestorSid, uint SessionId);
internal sealed record PublicationApprovalOperationV1(string FilePath, string FileName, string Extension,
    long SizeBytes, long LastWriteUtcTicks, string ProcessName, int ProcessId, string DestinationPath, int Destination);
internal sealed record PublicationApprovalInspectionV1(int Verdict, ImmutableArray<PublicationApprovalFindingV1> Findings,
    string? Reason, long ElapsedMs, bool FromCache, int PolicyVersion, bool InScope, string PolicyContentFingerprint)
{
    internal static PublicationApprovalInspectionV1 Capture(InspectionResult result) => new((int)result.Verdict,
        result.Findings.Select(f => new PublicationApprovalFindingV1((int)f.Category, f.MaskedSnippet, f.MemberName)).ToImmutableArray(),
        result.Reason, result.ElapsedMs, result.FromCache, result.PolicyVersion, result.InScope,
        result.PolicyContentFingerprint ?? throw new InvalidDataException("Inspection fingerprint is missing."));
}
internal sealed record PublicationApprovalFindingV1(int Category, string MaskedSnippet, string? MemberName);
internal sealed record PublicationApprovalPolicyV1(PublicationApprovalOperationV1 Operation, int PolicyVersion,
    string PolicyContentFingerprint, bool ProcessExcluded, bool DestinationMonitored, bool ExtensionMonitored, bool OverrideAllowed);
internal sealed record PublicationApprovalJustificationV1(Guid ReceiptId, PublicationApprovalBindingV1 Binding,
    int PolicyVersion, string PolicyContentFingerprint, int BlockedPolicyVersion, string BlockedPolicyFingerprint,
    long ConsumedAtUtcTicks, long ExpiresAtUtcTicks);

internal static class PublicationApprovalCodecV1
{
    // A leaf has no extra allowance beyond the enclosing 64/128 KiB record.
    internal static byte[] Serialize(PublicationApprovalV1 value)
    {
        Validate(value);
        return ResourceJsonV3.Serialize(value, StagedJournalFile.MaximumManifestBytes);
    }
    internal static PublicationApprovalV1 Deserialize(ReadOnlySpan<byte> bytes)
    {
        var value = ResourceJsonV3.Deserialize<PublicationApprovalV1>(bytes, StagedJournalFile.MaximumManifestBytes);
        Validate(value); return value;
    }
    internal static void Validate(PublicationApprovalV1 value)
    {
        Require(value is { Version: 1, Binding: not null, Operation: not null, Inspection: not null, PolicyCheck: not null },
            "Incomplete approval.");
        var binding = value.Binding; var operation = value.Operation; var inspection = value.Inspection; var policy = value.PolicyCheck;
        ResourceJsonV3.Id(binding.OperationId); ResourceJsonV3.Id(binding.TransferId);
        ResourceJsonV3.Identity(binding.StageIdentity); ResourceJsonV3.Identity(binding.SnapshotIdentity);
        Require(binding.AllocationGeneration > 0 && binding.DestinationGeneration > 0 && binding.Length >= 0,
            "Invalid approval binding.");
        ResourceJsonV3.Hex(binding.Sha256); ValidateSid(binding.RequestorSid);
        ResourceJsonV3.Text(operation.FilePath, 1, 512); ResourceJsonV3.Text(operation.FileName, 1, 255);
        ResourceJsonV3.Text(operation.Extension, 0, 255); ResourceJsonV3.Text(operation.ProcessName, 1, 512);
        ResourceJsonV3.Text(operation.DestinationPath, 1, 512);
        Require(operation.SizeBytes == binding.Length && operation.ProcessId > 0 && operation.Destination is >= 0 and <= 4 &&
            Ticks(operation.LastWriteUtcTicks), "Invalid approval operation.");
        ResourceJsonV3.Hex(inspection.PolicyContentFingerprint);
        Require(inspection.PolicyVersion > 0 && inspection.InScope && inspection.ElapsedMs >= 0 && !inspection.Findings.IsDefault,
            "Invalid inspection.");
        if (inspection.Reason is not null) ResourceJsonV3.Text(inspection.Reason, 0, int.MaxValue);
        foreach (var finding in inspection.Findings)
        {
            Require(finding is not null && finding.Category is >= 0 and <= 4, "Invalid finding.");
            ResourceJsonV3.Text(finding.MaskedSnippet, 0, int.MaxValue);
            if (finding.MemberName is not null) ResourceJsonV3.Text(finding.MemberName, 0, int.MaxValue);
        }
        Require(policy.Operation == operation && policy.PolicyVersion == inspection.PolicyVersion &&
            policy.PolicyContentFingerprint == inspection.PolicyContentFingerprint && !policy.ProcessExcluded && policy.DestinationMonitored &&
            (policy.ExtensionMonitored || binding.Length == 0 && inspection.Verdict == 0 && !value.Justified),
            "Approval policy recheck differs.");
        if (!value.Justified)
        {
            Require(inspection.Verdict == 0 && value.Justification is null, "Clean approval has justification/incorrect verdict.");
            return;
        }
        Require(inspection.Verdict == 1 && policy.OverrideAllowed && value.Justification is not null &&
            inspection.Reason != "not_enough_staging_space", "Invalid justified approval.");
        var receipt = value.Justification!;
        ResourceJsonV3.Id(receipt.ReceiptId);
        Require(receipt.Binding == binding && receipt.PolicyVersion == inspection.PolicyVersion &&
            receipt.BlockedPolicyVersion == inspection.PolicyVersion && receipt.PolicyContentFingerprint == inspection.PolicyContentFingerprint &&
            receipt.BlockedPolicyFingerprint == inspection.PolicyContentFingerprint && Ticks(receipt.ConsumedAtUtcTicks) &&
            Ticks(receipt.ExpiresAtUtcTicks) && receipt.ConsumedAtUtcTicks < receipt.ExpiresAtUtcTicks,
            "Consumed justification binding/policy/time differs.");
    }
    internal static void ValidateSid(string value)
    {
        ResourceJsonV3.Text(value, 1, 184);
        string[] parts = value.Split('-');
        Require(parts.Length is >= 4 and <= 18 && parts[0] == "S" && parts[1] == "1" &&
            ulong.TryParse(parts[2], out var authority) && authority <= 0xffffffffffff && authority.ToString(System.Globalization.CultureInfo.InvariantCulture) == parts[2],
            "SID authority/revision is invalid.");
        foreach (var part in parts.Skip(3)) Require(uint.TryParse(part, out var sub) &&
            sub.ToString(System.Globalization.CultureInfo.InvariantCulture) == part, "SID subauthority is invalid.");
    }
    private static bool Ticks(long ticks) => ticks >= 0 && ticks <= DateTime.MaxValue.Ticks;
    private static void Require([System.Diagnostics.CodeAnalysis.DoesNotReturnIf(false)] bool condition, string message) => ResourceJsonV3.Require(condition, message);
}
#endif
