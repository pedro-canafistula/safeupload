using System.Reflection;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Hosting;
using SafeUpload.Agent.Core.Application;
using SafeUpload.Agent.Core.Infrastructure;
using SafeUpload.Agent.Service;
using SafeUpload.Agent.Service.Dispatch;
using SafeUpload.Agent.Service.Drive;
using SafeUpload.Agent.Service.Interception;
using SafeUpload.Agent.Service.Policies;

namespace SafeUpload.Agent.Tests;

public sealed class StartupPolicyIntegrationTests : IDisposable
{
    private readonly TestWorkspace _workspace = new();
    public void Dispose() => _workspace.Dispose();

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void Actual_service_graph_uses_the_drive_and_keeps_policy_order_without_starting(bool remote)
    {
        string origin = remote ? "http://policy.invalid/agent/" : "";
        var builder = Program.CreateConfiguredServiceBuilder([
            "--CentroAdministracao:BaseUrl=" + origin,
            "--InspecaoTls:Habilitada=false"]);
        builder.Services.Replace(ServiceDescriptor.Singleton<IAuditSink>(new LocalQueueAuditSink(_workspace.QueueFile)));
        var workers = builder.Services.Where(d => d.ServiceType == typeof(IHostedService)).ToArray();
        Assert.Contains(builder.Services, d => d.ServiceType == typeof(DriveService));
        Assert.DoesNotContain(workers, d => d.ImplementationType == typeof(FileSystemInterceptor));
        using var provider = builder.Services.BuildServiceProvider();
        var store = provider.GetRequiredService<IPolicyStore>();
        if (remote)
        {
            Assert.IsType<RefreshingPolicyStore>(store);
            Assert.Same(store, workers[0].ImplementationFactory!(provider));
            using var dispatcher = Assert.IsType<HttpAgentDispatcher>(workers[1].ImplementationFactory!(provider));
        }
        else
        {
            Assert.IsType<LocalPolicyStore>(store);
            Assert.DoesNotContain(builder.Services, d => d.ServiceType == typeof(RefreshingPolicyStore));
        }
        Assert.NotNull(provider.GetRequiredService<InspectionService>());
        Assert.Equal(origin, builder.Configuration["CentroAdministracao:BaseUrl"]);
    }

    [Fact]
    public void File_watcher_mode_replaces_the_drive()
    {
        var builder = Program.CreateConfiguredServiceBuilder([
            "--CentroAdministracao:BaseUrl=", "--Interception:Mode=FileSystemWatcher", "--InspecaoTls:Habilitada=false"]);
        var workers = builder.Services.Where(d => d.ServiceType == typeof(IHostedService)).ToArray();
        Assert.Contains(workers, d => d.ImplementationType == typeof(FileSystemInterceptor));
        Assert.DoesNotContain(builder.Services, d => d.ServiceType == typeof(DriveService));
    }
}
