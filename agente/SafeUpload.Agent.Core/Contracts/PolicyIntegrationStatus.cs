namespace SafeUpload.Agent.Core.Contracts;

/// <summary>Non-authoritative summary for the local tray. No policy contents or diagnostic hashes.</summary>
public sealed record PolicyIntegrationStatus(
    int? SnapshotVersion,
    string SnapshotSource,
    int? StrictVersion,
    int? LastAcceptedVersion,
    bool DriverScopeRecorded,
    bool CurrentReadFailed,
    bool DriverApplyFailed,
    bool? CurrentContentMatchesAccepted);
