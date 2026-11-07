namespace SafeUpload.Agent.Core.Domain;

/// <summary>
/// Inspeção dos envios pelo navegador (proxy TLS), ligada pela política. Desligada quando a política não diz nada.
/// </summary>
/// <param name="Enabled">Liga a CA local, o proxy e o desvio dos navegadores.</param>
/// <param name="ExceptionDomains">
/// Domínios que nunca são descriptografados (cada um cobre os subdomínios), além das listas fixas de bancos, saúde e
/// governo. Entradas que não são domínio são ignoradas pelo proxy.
/// </param>
public sealed record WebInspectionPolicy(bool Enabled, IReadOnlyList<string> ExceptionDomains)
{
    /// <summary>No máximo quantos domínios de exceção a política pode trazer.</summary>
    public const int MaxExceptionDomains = 200;

    public static WebInspectionPolicy Off { get; } = new(false, []);

    /// <summary>Chave estável das exceções, para saber se o proxy precisa recarregá-las.</summary>
    public string ExceptionsKey => string.Join("\n",
        ExceptionDomains.Select(static d => d.Trim().ToLowerInvariant()).Distinct().Order(StringComparer.Ordinal));
}
