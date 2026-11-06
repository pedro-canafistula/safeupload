using SafeUpload.Agent.Core.Contracts;
using SafeUpload.Agent.Core.Domain;
using SafeUpload.Agent.Service.Gate;

namespace SafeUpload.Agent.Service.Drive;

internal static class DriveProtectionSnapshot
{
    internal static StatusNotification Create(Policy policy, GateApplyResult gate,
        IEnumerable<string> wanted, IEnumerable<string> mounted)
    {
        var expected = wanted.ToHashSet(StringComparer.OrdinalIgnoreCase);
        var actual = mounted.ToHashSet(StringComparer.OrdinalIgnoreCase);
        var issue = expected.Count == 0 ? DriveProtectionIssue.NoDestinations
            : gate == GateApplyResult.Rejected ? DriveProtectionIssue.GateRejected
            : gate != GateApplyResult.Applied ? DriveProtectionIssue.GateUnavailable
            : !expected.SetEquals(actual) ? DriveProtectionIssue.MountsIncomplete
            : DriveProtectionIssue.None;
        var snapshot = new DriveProtectionStatus(gate == GateApplyResult.Applied, expected.Count,
            expected.Count(actual.Contains), issue);
        return new StatusNotification(policy.Version, policy.ActiveCategories.Count, snapshot.Ready,
            policy.AuditOnly, DriveProtection: snapshot);
    }
}
