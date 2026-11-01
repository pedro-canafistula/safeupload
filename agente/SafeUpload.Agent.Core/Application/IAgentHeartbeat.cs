namespace SafeUpload.Agent.Core.Application;

/// <summary>Heartbeat explícito de um cadastro existente; independente de política e auditoria.</summary>
public interface IAgentHeartbeat
{
    Task SendAsync(CancellationToken cancellationToken);
}
