using SafeUpload.Agent.Core.Domain;

namespace SafeUpload.Agent.Core.Application;

public interface IOverrideQueue
{
    Task<IReadOnlyList<AuditOverride>> ReadPendingOverridesAsync(int maxEvents, CancellationToken cancellationToken);
    Task MarkOverridesDispatchedAsync(IReadOnlyCollection<AuditOverride> records, CancellationToken cancellationToken);
}
