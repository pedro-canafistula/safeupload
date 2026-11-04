using System.Text.Json.Serialization;

namespace SafeUpload.Agent.Core.Contracts;

public enum DriveProtectionIssue
{
    None,
    Starting,
    NoDestinations,
    GateUnavailable,
    GateRejected,
    MountsIncomplete,
    PolicyUnavailable,
    ScopeInvalid,
    ScopeUnavailable,
    Stopped
}

/// <summary>Last drive synchronization observation; contains no destinations or native error text.</summary>
public sealed record DriveProtectionStatus(bool GatePolicyApplied, int RequiredDrives, int MountedDrives, DriveProtectionIssue Issue)
{
    [JsonIgnore]
    public bool Ready => Issue == DriveProtectionIssue.None && GatePolicyApplied && RequiredDrives > 0 && MountedDrives == RequiredDrives;
}
