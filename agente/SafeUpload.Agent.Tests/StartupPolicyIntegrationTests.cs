using System.Reflection;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Hosting;
using SafeUpload.Agent.Core.Application;
using SafeUpload.Agent.Core.Infrastructure;
using SafeUpload.Agent.Service;
using SafeUpload.Agent.Service.Dispatch;
using SafeUpload.Agent.Service.Diagnostics;
using SafeUpload.Agent.Service.Interception;
using SafeUpload.Agent.Service.Policies;

namespace SafeUpload.Agent.Tests;

public sealed class StartupPolicyIntegrationTests : IDisposable
{
    private readonly TestWorkspace _workspace = new();
    public void Dispose() => _workspace.Dispose();

    [Theory]
    [InlineData(false, false, false)]
    [InlineData(false, true, false)]
    [InlineData(true, false, false)]
    [InlineData(true, true, false)]
    [InlineData(false, false, true)]
    [InlineData(true, false, true)]
    public void Actual_service_graph_preserves_parser_configuration_and_policy_order_without_starting(
        bool remote, bool parserEnabled, bool floorOnly)
    {
        string origin = remote ? "http://policy.invalid/agent/" : "";
        var builder = Program.CreateConfiguredServiceBuilder([
            "--CentroAdministracao:BaseUrl=" + origin,
            "--Interception:Mode=Minifilter",
            "--Interception:StageSpace:Enabled=" + (parserEnabled ? "true" : "false"),
            // The shipped appsettings selects the MVP floor-only mode; state it explicitly per case.
            "--Interception:StageSpace:FloorOnly=" + (floorOnly ? "true" : "false"),
            "--InspecaoTls:Habilitada=false"]);
        builder.Services.Replace(ServiceDescriptor.Singleton<IAuditSink>(new LocalQueueAuditSink(_workspace.QueueFile)));
        var workers = builder.Services.Where(d => d.ServiceType == typeof(IHostedService)).ToArray();
        Assert.Contains(workers, d => d.ImplementationType == typeof(MinifilterInterceptor));
        Assert.Contains(workers, d => d.ImplementationType == typeof(DiagnosticsPipeServer));
        Assert.DoesNotContain(workers, d => d.ImplementationType == typeof(FileSystemInterceptor));
        using var provider = builder.Services.BuildServiceProvider();
        var store = provider.GetRequiredService<IPolicyStore>();
        if (remote)
        {
            Assert.IsType<RefreshingPolicyStore>(store);
            Assert.NotNull(workers[0].ImplementationFactory);
            Assert.NotNull(workers[1].ImplementationFactory);
            Assert.Same(store, workers[0].ImplementationFactory!(provider));
            using var dispatcher = Assert.IsType<HttpAgentDispatcher>(workers[1].ImplementationFactory!(provider));
            Assert.True(Array.FindIndex(workers, d => d.ImplementationType == typeof(MinifilterInterceptor)) > 1);
        }
        else
        {
            Assert.IsType<LocalPolicyStore>(store);
            Assert.DoesNotContain(builder.Services, d => d.ServiceType == typeof(RefreshingPolicyStore));
        }
        // Resolve only the engine, never the interceptor or any hosted server.
        // The parser constructor holds a budget; InspectAsync starts the worker.
        var engine = provider.GetRequiredService<InspectionService>();
        var parser = typeof(InspectionService).GetField("_stagedParser", BindingFlags.NonPublic | BindingFlags.Instance);
        Assert.NotNull(parser);
        // The isolated parser follows the reservation budget or the MVP floor-only mode.
        if (parserEnabled || floorOnly) Assert.IsType<StagedParserProcess>(parser.GetValue(engine));
        else Assert.Null(parser.GetValue(engine));
        Assert.Equal(origin, builder.Configuration["CentroAdministracao:BaseUrl"]);
    }

    [Theory]
    [InlineData("")]
    [InlineData("http://policy.invalid/agent/")]
    public void Actual_seed_graph_has_no_hosted_workers_or_inspection_engine(string origin)
    {
        string[] args = ["--seed-boot-policy", "--CentroAdministracao:BaseUrl=" + origin];
        Assert.True(Program.TryGetBootPolicyConfigurationArguments(args, out var configuration));
        var builder = Program.CreateBootPolicyBuilder(configuration);
        Assert.DoesNotContain(builder.Services, d => d.ServiceType == typeof(IHostedService));
        Assert.DoesNotContain(builder.Services, d => d.ServiceType == typeof(InspectionService));
        using var provider = builder.Services.BuildServiceProvider();
        var store = provider.GetRequiredService<IPolicyStore>();
        if (origin.Length == 0) Assert.IsType<LocalPolicyStore>(store);
        else Assert.IsType<RefreshingPolicyStore>(store);
        Assert.Equal(origin, builder.Configuration["CentroAdministracao:BaseUrl"]);
    }
}
