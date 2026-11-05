using System.Globalization;
using SafeUpload.Agent.Core.Infrastructure;

namespace SafeUpload.Agent.Service.Dispatch;

/// <summary>Validate the service configuration before creating clients or starting network work.</summary>
internal sealed record AdministrationConfiguration(
    Uri? BaseUri, TimeSpan Timeout, TimeSpan DispatchInterval, AgentHeartbeatConfiguration Heartbeat,
    ConsolePolicyOptions? ConsolePolicy = null)
{
    internal static AdministrationConfiguration Parse(IConfiguration configuration, RegisteredHostIdentityStore? identities = null,
        SignedHostIdentityStore? signedIdentities = null)
    {
        string? address = configuration["CentroAdministracao:BaseUrl"];
        if (string.IsNullOrWhiteSpace(address))
        {
            var heartbeat = ReadHeartbeat(configuration, null, identities, signedIdentities);
            ReadConsolePolicy(configuration, null, heartbeat);
            if (heartbeat.RegisteredHostId is not null)
                throw new InvalidOperationException("Heartbeat AgentApi exige CentroAdministracao:BaseUrl.");
            return new(null, TimeSpan.FromSeconds(5), TimeSpan.FromSeconds(30), heartbeat);
        }

        // Error messages never include the URL, its credentials, or parser exception text.
        if (!Uri.TryCreate(address.Trim(), UriKind.Absolute, out var uri) ||
            (uri.Scheme != Uri.UriSchemeHttp && uri.Scheme != Uri.UriSchemeHttps) ||
            string.IsNullOrEmpty(uri.Host) || uri.UserInfo.Length != 0 ||
            uri.Query.Length != 0 || uri.Fragment.Length != 0 ||
            !(uri.AbsolutePath.EndsWith("/agent/", StringComparison.Ordinal) ||
              uri.AbsolutePath.EndsWith("/agent", StringComparison.Ordinal)))
            throw new InvalidOperationException("CentroAdministracao:BaseUrl exige URL HTTP(S) terminada em /agent/, sem credenciais, query ou fragmento.");

        if (!uri.AbsolutePath.EndsWith('/')) uri = new Uri(uri.AbsoluteUri + "/");
        var timeout = ReadPositiveSeconds(configuration, "TimeoutSeconds", 5);
        var interval = ReadPositiveSeconds(configuration, "DispatchIntervalSeconds", 30);
        if (timeout.TotalMilliseconds > int.MaxValue)
            throw new InvalidOperationException("CentroAdministracao:TimeoutSeconds excede o limite do cliente HTTP.");
        if (interval.TotalMilliseconds > uint.MaxValue - 1)
            throw new InvalidOperationException("CentroAdministracao:DispatchIntervalSeconds excede o limite do temporizador.");
        var configuredHeartbeat = ReadHeartbeat(configuration, uri, identities, signedIdentities);
        var consolePolicy = ReadConsolePolicy(configuration, uri, configuredHeartbeat);
        // Reject the entire configuration before committing the initial host binding.
        // Otherwise an invalid policy option can pin an ID from a failed service start.
        if (configuredHeartbeat.SigningIdentity is null && configuredHeartbeat.RegisteredHostId is { } hostId && identities is not null)
            identities.Resolve(uri, hostId);
        return new(uri, timeout, interval, configuredHeartbeat, consolePolicy);
    }

    private static ConsolePolicyOptions? ReadConsolePolicy(IConfiguration configuration, Uri? server,
        AgentHeartbeatConfiguration heartbeat)
    {
        string? protocol = configuration["CentroAdministracao:PolicyProtocol"];
        string? ip = configuration["CentroAdministracao:PolicyHostIp"];
        if (string.IsNullOrWhiteSpace(protocol) || protocol == "Legacy")
        {
            if (!string.IsNullOrWhiteSpace(ip))
                throw new InvalidOperationException("PolicyHostIp exige PolicyProtocol=ConsoleByIp.");
            return null;
        }
        if (protocol != "ConsoleByIp")
            throw new InvalidOperationException("PolicyProtocol deve ser Legacy ou ConsoleByIp.");
        if (server is null || heartbeat.RegisteredHostId is not { } hostId)
            throw new InvalidOperationException("ConsoleByIp exige BaseUrl e identidade HeartbeatProtocol=AgentApi.");
        try { return new ConsolePolicyOptions(hostId, ip ?? ""); }
        catch (ArgumentException)
        {
            throw new InvalidOperationException("PolicyHostIp exige IPv4 canônico do host provisionado.");
        }
    }

    private static AgentHeartbeatConfiguration ReadHeartbeat(IConfiguration configuration, Uri? server,
        RegisteredHostIdentityStore? identities, SignedHostIdentityStore? signedIdentities)
    {
        string? protocol = configuration["CentroAdministracao:HeartbeatProtocol"];
        string? host = configuration["CentroAdministracao:RegisteredHostId"];
        string? legacyUser = configuration["CentroAdministracao:RegisteredUserId"];
        if (protocol == "AgentApiEd25519")
        {
            if (server is null || signedIdentities is null)
                throw new InvalidOperationException("AgentApiEd25519 exige BaseUrl e identidade protegida provisionada.");
            string? ip = configuration["CentroAdministracao:HostIp"];
            if (!int.TryParse(configuration["CentroAdministracao:HostMask"], NumberStyles.None,
                    CultureInfo.InvariantCulture, out int mask) || string.IsNullOrWhiteSpace(ip))
                throw new InvalidOperationException("AgentApiEd25519 exige HostIp e HostMask explícitos.");
            string? policyIp = configuration["CentroAdministracao:PolicyHostIp"];
            if (!string.IsNullOrWhiteSpace(policyIp) && policyIp != ip)
                throw new InvalidOperationException("HostIp e PolicyHostIp devem identificar o mesmo host.");
            return AgentHeartbeatConfiguration.Parse(protocol, host, legacyUser, signedIdentities.Load(server),
                AgentHeartbeatHost.ForMachine(ip, mask));
        }
        if (protocol == "AgentApi" && string.IsNullOrWhiteSpace(host) && string.IsNullOrWhiteSpace(legacyUser) &&
            identities is not null && server is not null)
            return new(identities.Resolve(server, null));

        return AgentHeartbeatConfiguration.Parse(protocol, host, legacyUser);
    }

    private static TimeSpan ReadPositiveSeconds(IConfiguration configuration, string name, int fallback)
    {
        string? value = configuration["CentroAdministracao:" + name];
        if (string.IsNullOrWhiteSpace(value)) return TimeSpan.FromSeconds(fallback);
        if (!int.TryParse(value, NumberStyles.Integer, CultureInfo.InvariantCulture, out int seconds) || seconds <= 0)
            throw new InvalidOperationException("CentroAdministracao:" + name + " precisa ser um número inteiro positivo.");
        return TimeSpan.FromSeconds(seconds);
    }
}
