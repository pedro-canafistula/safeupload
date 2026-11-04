using SafeUpload.Agent.Core.Domain;

namespace SafeUpload.Agent.Drive;

/// <summary>Who wrote a version: captured when the file was opened for writing, because the process may be gone later.</summary>
public sealed record DriveWriter(int ProcessId, string ProcessName, uint? SessionId, string? UserSid, string? UserName);

public enum DriveApprovalKind { Inspection, Audit, Justification }

/// <summary>The decision about one inspected version of a file on a SafeUpload drive.</summary>
/// <param name="VersionId">Identifies this exact version and its blocked audit event/justification, when present.</param>
/// <param name="Approved">Inspection permits publication; does not mean the destination was written.</param>
/// <param name="Snapshot">Private copy of the exact bytes that were inspected (kept while a blocked version may be justified).</param>
public sealed record DriveDecision(
    Guid VersionId,
    string DrivePath,
    string FileName,
    DriveWriter? Writer,
    FileOperation? Operation,
    InspectionResult? Result,
    bool Approved,
    string Summary,
    string Snapshot,
    DriveApprovalKind ApprovalKind = DriveApprovalKind.Inspection);

/// <summary>An actual publication attempt. Its event id is separate from the blocked version/justification id.</summary>
public sealed record DrivePublication(Guid EventId, DriveDecision Decision, string DestinationPath, bool Succeeded,
    bool AuditJournaled = false);

/// <summary>Connects a drive to the rest of the agent (sessions, notifications, audit).</summary>
public interface IDriveObserver
{
    DriveWriter? IdentifyWriter(int processId);
    void OnDecision(DriveDecision decision);
    void OnPublication(DrivePublication publication);
}
