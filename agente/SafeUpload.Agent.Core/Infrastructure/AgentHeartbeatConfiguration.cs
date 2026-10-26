using System.Globalization;
using SafeUpload.Agent.Core.Application;

namespace SafeUpload.Agent.Core.Infrastructure;

/// <summary>Opt-in explícito; não detecta protocolo por tentativa e erro e nunca cadastra a máquina.</summary>
public sealed record AgentHeartbeatConfiguration(int? RegisteredUserId)
{
    public static AgentHeartbeatConfiguration Parse(string? protocol, string? userId)
    {
        if (string.IsNullOrWhiteSpace(protocol) || protocol == "Legacy")
        {
            if (!string.IsNullOrWhiteSpace(userId))
                throw new InvalidOperationException("RegisteredUserId exige HeartbeatProtocol=AgentApi.");
            return new((int?)null);
        }
        if (protocol != "AgentApi")
            throw new InvalidOperationException("HeartbeatProtocol deve ser Legacy ou AgentApi.");
        if (!int.TryParse(userId, NumberStyles.None, CultureInfo.InvariantCulture, out int id) || id <= 0)
            throw new InvalidOperationException("Heartbeat AgentApi exige RegisteredUserId inteiro positivo do cadastro existente.");
        return new(id);
    }

    public IAgentHeartbeat? CreateSender(HttpClient client) => RegisteredUserId is {} id
        ? new RegisteredAgentHeartbeat(new AgentApiClient(client), id)
        : null;
}
