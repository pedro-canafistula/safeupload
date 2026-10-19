using SafeUpload.Agent.Core.Application;
using SafeUpload.Agent.Core.Domain;
using SafeUpload.Agent.Minifilter;
using SafeUpload.Agent.Service.Interception;

namespace SafeUpload.Agent.Service.Policies;

internal sealed record LoadedDriverPolicy(Policy Policy, SafeUploadPolicyMessage Message);

/// <summary>One strict read supplies the same candidate to boot seeding and live policy push.</summary>
internal static class DriverPolicyLoader
{
    internal static async Task<LoadedDriverPolicy> LoadAsync(IPolicyStore store, CancellationToken token)
    {
        ArgumentNullException.ThrowIfNull(store);
        var policy = await store.LoadCurrentAsync(token).ConfigureAwait(false);
        token.ThrowIfCancellationRequested();
        policy.EnsureValid();
        return new LoadedDriverPolicy(policy, MinifilterPolicyFactory.Build(policy));
    }
}
