using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using SafeUpload.Agent.Core.Application;
using SafeUpload.Agent.Core.Domain;
using SafeUpload.Agent.Core.Infrastructure;
using SafeUpload.Agent.Core.Infrastructure.Extraction;

namespace SafeUpload.Agent.Tests;

public sealed class PolicyContentBindingTests : IDisposable
{
    private readonly TestWorkspace _workspace = new();
    public void Dispose() => _workspace.Dispose();

    [Theory]
    [InlineData("version")]
    [InlineData("categories")]
    [InlineData("extensions")]
    [InlineData("paths")]
    [InlineData("removable")]
    [InlineData("network")]
    [InlineData("size")]
    [InlineData("timeout")]
    [InlineData("fail-open")]
    [InlineData("excluded")]
    [InlineData("audit")]
    [InlineData("override")]
    [InlineData("clipboard-mode")]
    [InlineData("clipboard-egress")]
    [InlineData("clipboard-excluded")]
    [InlineData("clipboard-size")]
    [InlineData("clipboard-oversized")]
    public void Every_policy_field_changes_the_content_binding(string field)
    {
        var original = LocalPolicyStore.CreateDefault(); var scope = original.MonitoredScopes; var clip = original.EffectiveClipboard;
        var changed = field switch
        {
            "version" => original with { Version = original.Version + 1 },
            "categories" => original with { ActiveCategories = new HashSet<Category> { Category.Secret } },
            "extensions" => original with { MonitoredScopes = scope with { Extensions = new HashSet<string> { ".different" } } },
            "paths" => original with { MonitoredScopes = scope with { DestinationPaths = [@"C:\different"] } },
            "removable" => original with { MonitoredScopes = scope with { RemovableDrives = !scope.RemovableDrives } },
            "network" => original with { MonitoredScopes = scope with { NetworkPaths = !scope.NetworkPaths } },
            "size" => original with { MaxFileSizeMb = original.MaxFileSizeMb + 1 },
            "timeout" => original with { InspectionTimeoutSeconds = original.InspectionTimeoutSeconds + 1 },
            "fail-open" => original with { FailOpen = !original.FailOpen },
            "excluded" => original with { ExcludedProcesses = new HashSet<string> { "different" } },
            "audit" => original with { AuditOnly = !original.AuditOnly },
            "override" => original with { OverrideAllowed = !original.OverrideAllowed },
            "clipboard-mode" => original with { Clipboard = clip with { Mode = ClipboardMode.Audit } },
            "clipboard-egress" => original with { Clipboard = clip with { EgressDestinations = new HashSet<string> { "different" } } },
            "clipboard-excluded" => original with { Clipboard = clip with { ExcludedSources = new HashSet<string> { "different" } } },
            "clipboard-size" => original with { Clipboard = clip with { MaxTextLength = clip.MaxTextLength + 1 } },
            "clipboard-oversized" => original with { Clipboard = clip with { OversizedTextIsDirty = !clip.OversizedTextIsDirty } },
            _ => throw new ArgumentOutOfRangeException(nameof(field))
        };
        Assert.NotEqual(PolicyContentFingerprint.Compute(original), PolicyContentFingerprint.Compute(changed));
    }

    [Fact]
    public void Collection_order_and_implicit_clipboard_defaults_do_not_change_the_binding()
    {
        var policy = LocalPolicyStore.CreateDefault() with
        {
            Clipboard = null,
            MonitoredScopes = LocalPolicyStore.CreateDefault().MonitoredScopes with { DestinationPaths = [@"C:\a", @"C:\b"] }
        };
        var reordered = policy with
        {
            ActiveCategories = policy.ActiveCategories.Reverse().ToHashSet(),
            ExcludedProcesses = policy.ExcludedProcesses.Reverse().ToHashSet(),
            MonitoredScopes = policy.MonitoredScopes with
            {
                Extensions = policy.MonitoredScopes.Extensions.Reverse().ToHashSet(), DestinationPaths = [@"C:\b", @"C:\a", @"C:\a"]
            },
            Clipboard = ClipboardPolicy.Disabled
        };
        Assert.Equal(PolicyContentFingerprint.Compute(policy), PolicyContentFingerprint.Compute(reordered));
        Assert.NotEqual(PolicyContentFingerprint.Compute(policy with { ExcludedProcesses = new HashSet<string> { "a", "bc" } }),
            PolicyContentFingerprint.Compute(policy with { ExcludedProcesses = new HashSet<string> { "ab", "c" } }));
    }

    [Fact]
    public void Invalid_utf16_cannot_be_silently_replaced_in_a_policy_binding()
    {
        var policy = LocalPolicyStore.CreateDefault() with { ExcludedProcesses = new HashSet<string> { "\ud800" } };
        Assert.Throws<EncoderFallbackException>(() => PolicyContentFingerprint.Compute(policy));
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task Same_version_semantic_edit_revokes_a_staged_decision_until_the_exact_policy_returns(bool blocked)
    {
        var store = new LocalPolicyStore(_workspace.PolicyFile); await store.LoadAsync(CancellationToken.None);
        var document = JsonNode.Parse(await File.ReadAllTextAsync(_workspace.PolicyFile))!; document["overrideAllowed"] = true;
        await File.WriteAllTextAsync(_workspace.PolicyFile, document.ToJsonString());
        string original = await File.ReadAllTextAsync(_workspace.PolicyFile);
        var service = new InspectionService(store, new LocalQueueAuditSink(_workspace.QueueFile), ExtractorRegistry.CreateDefault(), new VerdictCache());
        var operation = TestWorkspace.Operation(_workspace.WriteText("bound.txt", blocked ? "CPF: 529.982.247-25" : "Clean bytes."));
        var result = await service.InspectStagedAsync(operation, CancellationToken.None);
        Assert.NotNull(result.PolicyContentFingerprint);
        async Task<bool> Allowed(InspectionResult current) => blocked
            ? await service.IsCurrentStagedJustificationAllowedAsync(operation, current, CancellationToken.None)
            : await service.IsCurrentStagedApprovalAsync(operation, current, CancellationToken.None);
        Assert.True(await Allowed(result));
        Assert.False(await Allowed(result with { PolicyContentFingerprint = null }));
        Assert.DoesNotContain(result.PolicyContentFingerprint!, JsonSerializer.Serialize(result));
        // The default document omits mode-specific limits. Change the effective
        // staged limit, preserving the same-version policy-revocation control.
        document["maxFileSizeMb"] = (await store.LoadCurrentAsync(CancellationToken.None)).MaxFileSizeMb + 1;
        await File.WriteAllTextAsync(_workspace.PolicyFile, document.ToJsonString());
        Assert.Equal(result.PolicyVersion, (await store.LoadCurrentAsync(CancellationToken.None)).Version);
        Assert.False(await Allowed(result));
        await File.WriteAllTextAsync(_workspace.PolicyFile, original);
        Assert.True(await Allowed(result));
    }
}
