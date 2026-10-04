using SafeUpload.Agent.Core.Application;

namespace SafeUpload.Agent.Service.Interception;

/// <summary>Loads the protected local policy and commits its driver scope before boot.</summary>
internal static class BootPolicySeeder
{
    internal static async Task SeedAsync(IPolicyStore policyStore,
        BootPolicyRegistryWriter registryWriter, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(policyStore);
        ArgumentNullException.ThrowIfNull(registryWriter);

        var policy = await policyStore.LoadAsync(cancellationToken).ConfigureAwait(false);
        registryWriter.Seed(MinifilterPolicyFactory.Build(policy));
    }
}
