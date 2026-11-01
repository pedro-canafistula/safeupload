namespace SafeUpload.Agent.Core.Infrastructure;

/// <summary>Occurrence-age statistics only, never deletion eligibility or a retention policy.</summary>
public sealed record AuditQueueRetentionPreview(DateTimeOffset OccurredBeforeUtc,
    AuditQueueIntegritySnapshot Integrity, long ConfirmedEventsBeforeCutoff,
    long ConfirmedOverridesBeforeCutoff, long ConfirmedWithoutTimestamp)
{
    public bool PreviewOnly => true;
    public bool DeletionSupported => false;
    public string TimestampBasis => "record-occurrence-time";
}

public sealed partial class LocalQueueAuditSink
{
    /// <summary>
    /// Reuses the explicit integrity scan and its lock/deadline semantics, retaining only scalar counters.
    /// Counts valid confirmed lines strictly before an explicit occurrence cutoff. No confirmation timestamp
    /// is stored, no relationships or unknown metadata are evaluated, and no record is eligible for removal
    /// merely because it is counted here. Never creates, rewrites, truncates or removes a file.
    /// </summary>
    public async Task<AuditQueueRetentionPreview> PreviewRetentionAsync(DateTimeOffset occurredBeforeUtc,
        CancellationToken cancellationToken)
    {
        if (occurredBeforeUtc == default) throw new ArgumentOutOfRangeException(nameof(occurredBeforeUtc));
        var cutoff = occurredBeforeUtc.ToUniversalTime();
        var snapshot = await InspectIntegrityAsync(cutoff, cancellationToken).ConfigureAwait(false);
        return new(cutoff, snapshot, snapshot.ConfirmedEventsBeforeCutoff,
            snapshot.ConfirmedOverridesBeforeCutoff, snapshot.ConfirmedWithoutTimestamp);
    }
}
