using SafeUpload.Agent.Core.Application;
using SafeUpload.Agent.Core.Domain;

namespace SafeUpload.Agent.Service.Drive;

/// <summary>Audit mode may release a completed finding, never incomplete or stale inspection authority.</summary>
internal static class DriveAuditRelease
{
    internal static async Task<bool> TryApproveAsync(IPolicyStore policies, FileOperation operation,
        InspectionResult result, Func<bool> approve, CancellationToken token)
    {
        if (!result.InScope || !result.IsBlocked || result.Reason is not null ||
            result.Findings.Count == 0 || result.PolicyContentFingerprint is null) return false;
        var current = await policies.LoadCurrentAsync(token).ConfigureAwait(false);
        if (!current.AuditOnly || !string.Equals(result.PolicyContentFingerprint,
                PolicyContentFingerprint.Compute(current), StringComparison.Ordinal) ||
            current.IsExcludedProcess(operation.ProcessName) || !current.IsMonitoredDestination(operation) ||
            !current.IsMonitoredExtension(operation.Extension)) return false;
        token.ThrowIfCancellationRequested();
        return approve();
    }
}
