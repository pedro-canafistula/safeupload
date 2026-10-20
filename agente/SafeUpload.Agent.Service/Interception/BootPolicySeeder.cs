using SafeUpload.Agent.Core.Application;
using SafeUpload.Agent.Service.Policies;

namespace SafeUpload.Agent.Service.Interception;

/// <summary>Loads the current configured policy and commits its driver scope before boot.</summary>
internal static class BootPolicySeeder
{
    internal static async Task SeedAsync(IPolicyStore policyStore,
        BootPolicyRegistryWriter registryWriter, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(policyStore);
        ArgumentNullException.ThrowIfNull(registryWriter);

        var loaded = await DriverPolicyLoader.LoadAsync(policyStore, cancellationToken).ConfigureAwait(false);
        cancellationToken.ThrowIfCancellationRequested();
        registryWriter.Seed(loaded.Message);
    }
}
