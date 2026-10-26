using SafeUpload.Agent.Core.Domain;
using SafeUpload.Agent.Core.Infrastructure;
using SafeUpload.Agent.Minifilter;
using SafeUpload.Agent.Service.Interception;

namespace SafeUpload.Agent.Tests;

/// <summary>Contrato do lado C#; não abre FilterCommunicationPort nem carrega driver.</summary>
public sealed class MinifilterPolicyBridgeTests
{
    [Theory]
    [InlineData(false, false)] [InlineData(false, true)]
    [InlineData(true, false)] [InlineData(true, true)]
    public void Audit_and_override_flags_reach_kernel_message(bool auditOnly, bool allowOverride)
    {
        var policy = PolicyForBridge() with { AuditOnly = auditOnly, OverrideAllowed = allowOverride };
        var message = MinifilterPolicyFactory.Build(policy);
        var flags = (PolicyFlags)message.Flags;
        Assert.Equal(auditOnly, flags.HasFlag(PolicyFlags.AuditOnly));
        Assert.Equal(allowOverride, flags.HasFlag(PolicyFlags.AllowOverride));
    }

    [Theory]
    [InlineData(false, false)] [InlineData(false, true)]
    [InlineData(true, false)] [InlineData(true, true)]
    public void Volume_scope_flags_match_loaded_policy(bool removable, bool network)
    {
        var policy = PolicyForBridge();
        policy = policy with { MonitoredScopes = policy.MonitoredScopes with { RemovableDrives = removable, NetworkPaths = network } };
        var flags = (PolicyFlags)MinifilterPolicyFactory.Build(policy).Flags;
        Assert.Equal(removable, flags.HasFlag(PolicyFlags.Removable));
        Assert.Equal(network, flags.HasFlag(PolicyFlags.Network));
    }

    [Fact]
    public void Standard_inspection_budget_leaves_reply_margin_and_preserves_scope_counts()
    {
        var policy = PolicyForBridge();
        var message = MinifilterPolicyFactory.Build(policy);
        Assert.Equal(5500u, message.VerdictTimeoutMs);
        Assert.Equal(2u, message.ExtensionCount);
        Assert.Equal(1u, message.PrefixCount);
        Assert.Equal(1u, message.ImageCount);
        // Versão de domínio não é ACK de aplicação no kernel: mensagem não testa porta real.
    }

    private static Policy PolicyForBridge()
    {
        var policy = LocalPolicyStore.CreateDefault() with
        {
            Version = 7,
            InspectionTimeoutSeconds = 5,
            MonitoredScopes = new MonitoredScopes(
                new HashSet<string>(StringComparer.OrdinalIgnoreCase) { ".txt", ".pdf" },
                new[] { @"\Device\HarddiskVolume7\Synthetic" }, true, true),
            ExcludedProcesses = new HashSet<string>(StringComparer.OrdinalIgnoreCase) { "SafeUpload.Agent.Service" }
        };
        policy.EnsureValid();
        return policy;
    }
}
