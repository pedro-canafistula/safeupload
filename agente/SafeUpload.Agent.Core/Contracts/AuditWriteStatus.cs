namespace SafeUpload.Agent.Core.Contracts;

/// <summary>Historical local write failures since service startup; not audit completeness or server delivery.</summary>
public sealed record AuditWriteStatus(long FailureCount, string? LastRecordKind, string? LastErrorClass);
