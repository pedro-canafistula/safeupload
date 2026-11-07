using SafeUpload.Agent.Core.Application;
using SafeUpload.Agent.Core.Domain;
using SafeUpload.Agent.Core.Infrastructure;

namespace SafeUpload.Agent.Tests;

/// <summary>Política fixa e identidade em memória para os testes de comunicação.</summary>
internal static class TestPolicies
{
    /// <summary>Semente do vetor compartilhado com o backend (bytes 0x00..0x1f).</summary>
    public static readonly byte[] Seed = Enumerable.Range(0, 32).Select(i => (byte)i).ToArray();

    public static IPolicyStore Local { get; } = new StaticPolicyStore(LocalPolicyStore.CreateDefault());

    public static SignedAgentIdentity Identity(Uri server, int hostId = 7) => new(server, hostId, Seed);

    private sealed class StaticPolicyStore(Policy policy) : IPolicyStore
    {
        public Task<Policy> LoadAsync(CancellationToken cancellationToken) => Task.FromResult(policy);
    }
}
