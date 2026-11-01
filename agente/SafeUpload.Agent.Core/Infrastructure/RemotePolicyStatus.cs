namespace SafeUpload.Agent.Core.Infrastructure;

/// <summary>Last observed milestones in this process, not a disk inventory or application acknowledgement.</summary>
public sealed record RemotePolicyStatus(int? LastValidatedRemoteVersion = null,
    int? LastWrittenCacheVersion = null, int? LastReadCacheVersion = null);
