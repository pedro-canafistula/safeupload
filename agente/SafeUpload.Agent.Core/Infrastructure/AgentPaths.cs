namespace SafeUpload.Agent.Core.Infrastructure;

/// <summary>
/// Onde vive o estado local do agente.
///
/// A pasta fica em %ProgramData%\SafeUpload, e não no perfil do usuário, pelo
/// mesmo motivo do produto real: política e trilha de auditoria pertencem à
/// máquina e ao administrador, não a quem está logado. No agente real a pasta
/// seria protegida por ACL para que o usuário comum não pudesse editar a
/// política nem apagar a fila; aqui, sem elevação nem serviço, ela é apenas
/// gravável — o que é uma das limitações declaradas do mock.
/// </summary>
public static class AgentPaths
{
    /// <summary>Nome do arquivo de política.</summary>
    public const string PolicyFileName = "policy.json";

    /// <summary>Nome da fila de auditoria.</summary>
    public const string QueueFileName = "queue.jsonl";

    /// <summary>%ProgramData%\SafeUpload</summary>
    public static string RootDirectory { get; } = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
        "SafeUpload");

    /// <summary>Caminho completo do policy.json.</summary>
    public static string PolicyFile => Path.Combine(RootDirectory, PolicyFileName);

    /// <summary>Caminho completo do queue.jsonl.</summary>
    public static string QueueFile => Path.Combine(RootDirectory, QueueFileName);

    /// <summary>Cria a pasta se ainda não existir.</summary>
    public static void EnsureRootDirectory() => Directory.CreateDirectory(RootDirectory);
}
