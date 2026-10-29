using System.Globalization;
using SafeUpload.Agent.Core.Infrastructure;

namespace SafeUpload.Agent.Service.Dispatch;

/// <summary>Validate the service configuration before creating clients or starting network work.</summary>
internal sealed record AdministrationConfiguration(
    Uri? BaseUri, TimeSpan Timeout, TimeSpan DispatchInterval, AgentHeartbeatConfiguration Heartbeat)
{
    internal static AdministrationConfiguration Parse(IConfiguration configuration, RegisteredHostIdentityStore? identities = null)
    {
        string? address = configuration["CentroAdministracao:BaseUrl"];
        if (string.IsNullOrWhiteSpace(address))
        {
            var heartbeat = ReadHeartbeat(configuration, null, identities);
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
        return new(uri, timeout, interval, ReadHeartbeat(configuration, uri, identities));
    }

    private static AgentHeartbeatConfiguration ReadHeartbeat(IConfiguration configuration, Uri? server,
        RegisteredHostIdentityStore? identities)
    {
        string? protocol = configuration["CentroAdministracao:HeartbeatProtocol"];
        string? host = configuration["CentroAdministracao:RegisteredHostId"];
        string? legacyUser = configuration["CentroAdministracao:RegisteredUserId"];
        if (protocol == "AgentApi" && string.IsNullOrWhiteSpace(host) && string.IsNullOrWhiteSpace(legacyUser) &&
            identities is not null && server is not null)
            return new(identities.Resolve(server, null));

        var heartbeat = AgentHeartbeatConfiguration.Parse(protocol, host, legacyUser);
        if (heartbeat.RegisteredHostId is { } id && server is not null && identities is not null)
            identities.Resolve(server, id);
        return heartbeat;
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
