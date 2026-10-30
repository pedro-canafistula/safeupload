using System.Globalization;
using SafeUpload.Agent.Core.Application;

namespace SafeUpload.Agent.Core.Infrastructure;

/// <summary>Opt-in explícito; não detecta protocolo por tentativa e erro e nunca cadastra a máquina.</summary>
public sealed record AgentHeartbeatConfiguration(int? RegisteredHostId)
{
    public static AgentHeartbeatConfiguration Parse(string? protocol, string? hostId, string? legacyUserId = null)
    {
        if (!string.IsNullOrWhiteSpace(legacyUserId))
            throw new InvalidOperationException("RegisteredUserId foi removido: configure RegisteredHostId com id_host; os identificadores não são intercambiáveis.");
        if (string.IsNullOrWhiteSpace(protocol) || protocol == "Legacy")
        {
            if (!string.IsNullOrWhiteSpace(hostId))
                throw new InvalidOperationException("RegisteredHostId exige HeartbeatProtocol=AgentApi.");
            return new((int?)null);
        }
        if (protocol != "AgentApi")
            throw new InvalidOperationException("HeartbeatProtocol deve ser Legacy ou AgentApi.");
        if (!int.TryParse(hostId, NumberStyles.None, CultureInfo.InvariantCulture, out int id) || id <= 0)
            throw new InvalidOperationException("Heartbeat AgentApi exige RegisteredHostId inteiro positivo do cadastro existente.");
        return new(id);
    }

    public IAgentHeartbeat? CreateSender(HttpClient client, ICommunicationObserver? observer = null) => RegisteredHostId is {} id
        ? new RegisteredAgentHeartbeat(new AgentApiClient(client, observer), id)
        : null;
}
