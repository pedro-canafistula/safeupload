using SafeUpload.Agent.Core.Domain;

namespace SafeUpload.Agent.Drive;

/// <summary>Who wrote a version: captured when the file was opened for writing, because the process may be gone later.</summary>
public sealed record DriveWriter(int ProcessId, string ProcessName, uint? SessionId, string? UserSid, string? UserName);

/// <summary>The decision about one inspected version of a file on a SafeUpload drive.</summary>
/// <param name="VersionId">Identifies this exact version; also the audit event and justification id.</param>
/// <param name="Published">True when the version may reach the destination.</param>
public sealed record DriveDecision(
    Guid VersionId,
    string DrivePath,
    string FileName,
    DriveWriter? Writer,
    FileOperation? Operation,
    InspectionResult? Result,
    bool Published,
    string Summary);

/// <summary>Connects a drive to the rest of the agent (sessions, notifications, audit).</summary>
public interface IDriveObserver
{
    DriveWriter? IdentifyWriter(int processId);
    void OnDecision(DriveDecision decision);
}
