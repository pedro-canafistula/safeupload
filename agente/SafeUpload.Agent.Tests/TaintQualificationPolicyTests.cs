using System.Reflection;
using SafeUpload.Agent.Core.Domain;
using SafeUpload.Agent.Minifilter;
using SafeUpload.Agent.Service.Interception;

namespace SafeUpload.Agent.Tests;

public sealed class TaintQualificationPolicyTests
{
    [Fact]
    public void Service_test_switch_exists_and_is_sent_only_in_feature_builds()
    {
        var policy = new Policy(1, new HashSet<Category> { Category.Cpf },
            new MonitoredScopes(new HashSet<string> { ".txt" }, [], false, false),
            50, 2, false, new HashSet<string>());
        SafeUploadPolicyMessage message = MinifilterPolicyFactory.Build(policy);
        MethodInfo? method = typeof(PolicyBuilder).GetMethod("WithTestDisableTaint");
#if SAFEUPLOAD_ADMISSION_EVIDENCE
        Assert.NotNull(method);
        Assert.NotEqual(0u, message.Flags & (uint)PolicyFlags.TestDisableTaint);
#else
        Assert.Null(method);
        Assert.Equal(0u, message.Flags & (uint)PolicyFlags.TestDisableTaint);
#endif
        // The durable boot record remains a scope-only v1 record. The
        // feature kernel's bootstrap supplies its own diagnostic test bit.
        Assert.Equal(0u, BootPolicyCodec.DecodeKnown(BootPolicyCodec.Encode(message)).Flags);
        // Read classification only feeds taint: requested exactly when taint is on.
#if SAFEUPLOAD_ADMISSION_EVIDENCE
        Assert.Equal(0u, message.Flags & ~(uint)PolicyFlags.TestDisableTaint);
#else
        Assert.Equal((uint)PolicyFlags.ClassifyAllSources, message.Flags);
#endif
    }
}
