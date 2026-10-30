namespace SafeUpload.Agent.Core.Contracts;

/// <summary>Last observed attempt, not a connectivity or protection guarantee.</summary>
public enum AdministrationOperationState
{
    NotConfigured, NotAttempted, InProgress, Success, Failure, Cancelled, Unknown
}

/// <summary>Only closed states and timestamps may reach ordinary interactive users.</summary>
public sealed record AdministrationOperationStatus(
    AdministrationOperationState State, DateTimeOffset? LastAttemptUtc, DateTimeOffset? LastSuccessUtc);

public sealed record AdministrationCommunicationStatus(
    AdministrationOperationStatus Heartbeat,
    AdministrationOperationStatus Audit,
    AdministrationOperationStatus Policy);
