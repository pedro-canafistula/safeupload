using SafeUpload.Agent.Core.Application;
using SafeUpload.Agent.Core.Infrastructure;
using SafeUpload.Agent.Service.Dispatch;

namespace SafeUpload.Agent.Service.Policies;

/// <summary>Shares policy origin selection between the service and the pre-boot command.</summary>
internal static class PolicyServiceRegistration
{
    internal const string HttpClientName = "CentroAdministracao";

    internal static void AddAgentPolicies(this IServiceCollection services, IConfiguration configuration,
        string endpointId, bool includeHostedServices = true)
    {
        services.AddSingleton<PolicyIntegrationDiagnostics>();
        string baseUrl = configuration["CentroAdministracao:BaseUrl"] ?? string.Empty;
        if (string.IsNullOrWhiteSpace(baseUrl))
        {
            services.AddSingleton<IPolicyStore, LocalPolicyStore>();
            return;
        }

        var baseUri = new Uri(baseUrl.EndsWith('/') ? baseUrl : baseUrl + "/", UriKind.Absolute);
        if (baseUri.Scheme != Uri.UriSchemeHttp && baseUri.Scheme != Uri.UriSchemeHttps)
            throw new InvalidOperationException("CentroAdministracao:BaseUrl precisa usar HTTP ou HTTPS.");
        int timeoutSeconds = PositiveSeconds(configuration, "TimeoutSeconds", 5);
        int dispatchSeconds = PositiveSeconds(configuration, "DispatchIntervalSeconds", 30);

        services.AddHttpClient(HttpClientName, client =>
        {
            client.BaseAddress = baseUri;
            client.Timeout = TimeSpan.FromSeconds(timeoutSeconds);
        });
        services.AddSingleton(provider => new DurableHttpPolicyStore(
            provider.GetRequiredService<IHttpClientFactory>().CreateClient(HttpClientName), endpointId,
            Path.Combine(AgentPaths.RootDirectory, "server-policy-cache.json")));
        services.AddSingleton(provider => new RefreshingPolicyStore(
            provider.GetRequiredService<DurableHttpPolicyStore>(), TimeSpan.FromSeconds(30),
            provider.GetRequiredService<ILogger<RefreshingPolicyStore>>(),
            provider.GetRequiredService<PolicyIntegrationDiagnostics>()));
        services.AddSingleton<IPolicyStore>(provider => provider.GetRequiredService<RefreshingPolicyStore>());

        if (!includeHostedServices) return;
        // Registered before dispatch and interceptors: StartAsync completes the
        // initial bounded remote attempt before later consumers configure scope.
        services.AddHostedService(provider => provider.GetRequiredService<RefreshingPolicyStore>());
        services.AddHostedService(provider => new HttpAgentDispatcher(
            provider.GetRequiredService<IAuditSink>(), provider.GetRequiredService<IPolicyStore>(),
            provider.GetRequiredService<IHttpClientFactory>().CreateClient(HttpClientName), endpointId,
            TimeSpan.FromSeconds(dispatchSeconds), provider.GetRequiredService<ILogger<HttpAgentDispatcher>>()));
    }

    private static int PositiveSeconds(IConfiguration configuration, string name, int fallback)
    {
        string? value = configuration["CentroAdministracao:" + name];
        if (value is null) return fallback;
        if (!int.TryParse(value, out int seconds) || seconds <= 0)
            throw new InvalidOperationException($"CentroAdministracao:{name} precisa ser um inteiro positivo.");
        return seconds;
    }
}
