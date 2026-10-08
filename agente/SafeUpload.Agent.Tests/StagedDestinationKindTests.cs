using SafeUpload.Agent.Core.Domain;
using SafeUpload.Agent.Minifilter;
using SafeUpload.Agent.Service.Interception;

namespace SafeUpload.Agent.Tests;

public sealed class StagedDestinationKindTests
{
    [Theory]
    [InlineData(RequestFlags.None, DestinationKind.Cloud)]
    [InlineData(RequestFlags.StageRemovable, DestinationKind.RemovableDrive)]
    [InlineData(RequestFlags.StageNetwork, DestinationKind.NetworkShare)]
    public void Volume_flags_classify_staged_destinations(RequestFlags flags, DestinationKind expected)
    {
        Assert.Equal(expected, MinifilterInterceptor.ClassifyStagedDestination(flags));
    }

    [Theory]
    [InlineData(@"S:\SafeUpload\Escopo Monitorado\document.txt")]
    [InlineData(@"C:\SafeUpload\Escopo Monitorado\document.txt")]
    public void Fixed_local_folder_uses_path_policy_with_removable_and_network_disabled(string path)
    {
        var policy = new Policy(1, new HashSet<Category>(),
            new MonitoredScopes(new HashSet<string> { ".txt" },
                new[] { path[..path.LastIndexOf('\\')] }, false, false),
            20, 5, true, new HashSet<string>());
        var operation = new FileOperation(path, "document.txt", ".txt", 0,
            DateTimeOffset.UtcNow, "writer.exe", 1234, path,
            MinifilterInterceptor.ClassifyStagedDestination(RequestFlags.None));
        Assert.True(policy.IsMonitoredDestination(operation));
        Assert.False(policy.IsMonitoredDestination(operation with { Destination = DestinationKind.RemovableDrive }));
        Assert.False(policy.IsMonitoredDestination(operation with { Destination = DestinationKind.NetworkShare }));
    }
}
