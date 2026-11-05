using System.Globalization;
using SafeUpload.Agent.Core.Application;

namespace SafeUpload.Agent.Core.Infrastructure;

/// <summary>Opt-in explícito; não detecta protocolo por tentativa e erro e nunca cadastra a máquina.</summary>
public sealed record AgentHeartbeatConfiguration(int? RegisteredHostId)
{
    public SignedAgentIdentity? SigningIdentity { get; init; }
    public AgentHeartbeatHost? Host { get; init; }

    public static AgentHeartbeatConfiguration Parse(string? protocol, string? hostId, string? legacyUserId = null,
        SignedAgentIdentity? signingIdentity = null, AgentHeartbeatHost? host = null)
    {
        if (!string.IsNullOrWhiteSpace(legacyUserId))
            throw new InvalidOperationException("RegisteredUserId foi removido: configure RegisteredHostId com id_host; os identificadores não são intercambiáveis.");
        if (protocol == "AgentApiEd25519")
        {
            if (signingIdentity is null || host is null)
                throw new InvalidOperationException("AgentApiEd25519 exige identidade provisionada e dados do host.");
            host.EnsureValid();
            if (!string.IsNullOrWhiteSpace(hostId) && hostId != signingIdentity.HostId.ToString(CultureInfo.InvariantCulture))
                throw new InvalidOperationException("RegisteredHostId conflita com a identidade Ed25519; nenhum vínculo foi alterado.");
            return new(signingIdentity.HostId) { SigningIdentity = signingIdentity, Host = host };
        }
        if (string.IsNullOrWhiteSpace(protocol) || protocol == "Legacy")
        {
            if (!string.IsNullOrWhiteSpace(hostId))
                throw new InvalidOperationException("RegisteredHostId exige HeartbeatProtocol=AgentApi.");
            return new((int?)null);
        }
        if (protocol != "AgentApi")
            throw new InvalidOperationException("HeartbeatProtocol deve ser Legacy, AgentApi ou AgentApiEd25519.");
        if (!int.TryParse(hostId, NumberStyles.None, CultureInfo.InvariantCulture, out int id) || id <= 0)
            throw new InvalidOperationException("Heartbeat AgentApi exige RegisteredHostId inteiro positivo do cadastro existente.");
        return new(id);
    }

    public IAgentHeartbeat? CreateSender(HttpClient client, ICommunicationObserver? observer = null) =>
        SigningIdentity is { } identity && Host is { } host
            ? new SignedAgentHeartbeat(new AgentApiClient(client, observer), identity, host)
            : RegisteredHostId is { } id ? new RegisteredAgentHeartbeat(new AgentApiClient(client, observer), id) : null;
}

internal sealed class SignedAgentHeartbeat(AgentApiClient client, SignedAgentIdentity identity, AgentHeartbeatHost host) : IAgentHeartbeat
{
    public Task SendAsync(CancellationToken token)
    {
        token.ThrowIfCancellationRequested();
        return client.HeartbeatAuthenticatedAsync(identity.HostId, identity.SignHost(), host, token);
    }
}
