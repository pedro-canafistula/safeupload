using System.Text.Json;
using System.Text.Json.Serialization;
using SafeUpload.Agent.Core.Application;
using SafeUpload.Agent.Core.Domain;

namespace SafeUpload.Agent.Core.Infrastructure;

/// <summary>
/// Lê a política de %ProgramData%\SafeUpload\policy.json.
///
/// É a implementação local da IPolicyStore. Se o arquivo não existir, grava um
/// padrão e segue com ele: um agente que não sobe porque nunca foi configurado
/// é um agente que não protege ninguém na primeira execução.
///
/// O formato em disco é descrito por DTOs próprios desta camada. O domínio não
/// conhece JSON, e manter a tradução aqui deixa o arquivo livre para evoluir
/// (renomear chave, aceitar formato antigo) sem mexer em Policy.
/// </summary>
public sealed class LocalPolicyStore : IPolicyStore
{
    private static readonly JsonSerializerOptions ReadOptions = new()
    {
        PropertyNameCaseInsensitive = true,
        ReadCommentHandling = JsonCommentHandling.Skip,
        AllowTrailingCommas = true,
        Converters = { new JsonStringEnumConverter() }
    };

    private static readonly JsonSerializerOptions WriteOptions = new()
    {
        WriteIndented = true,
        Converters = { new JsonStringEnumConverter() }
    };

    private readonly string _policyFile;

    /// <summary>Usa o caminho padrão do agente.</summary>
    public LocalPolicyStore() : this(AgentPaths.PolicyFile)
    {
    }

    /// <summary>Usa um caminho específico. Serve aos testes.</summary>
    public LocalPolicyStore(string policyFile)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(policyFile);
        _policyFile = policyFile;
    }

    /// <summary>Caminho do arquivo lido, para exibição na interface.</summary>
    public string PolicyFilePath => _policyFile;

    /// <inheritdoc />
    public async Task<Policy> LoadAsync(CancellationToken cancellationToken)
    {
        if (!File.Exists(_policyFile))
        {
            await WriteDefaultAsync(cancellationToken).ConfigureAwait(false);
        }

        PolicyDocument? document;

        await using (var stream = File.OpenRead(_policyFile))
        {
            document = await JsonSerializer
                .DeserializeAsync<PolicyDocument>(stream, ReadOptions, cancellationToken)
                .ConfigureAwait(false);
        }

        if (document is null)
        {
            throw new InvalidPolicyException($"O arquivo {_policyFile} não contém uma política.");
        }

        var policy = document.ToPolicy();

        // RN-009: a validação acontece no carregamento, e não no uso. Uma
        // política inválida precisa falhar alto e cedo, no lugar de ser
        // descoberta no meio de uma inspeção que deveria ter bloqueado.
        policy.EnsureValid();

        return policy;
    }

    /// <summary>
    /// A política que o agente assume quando nunca foi configurado: as quatro
    /// categorias ligadas, os formatos que sabemos ler, 20 MB de limite, 5 s de
    /// timeout e fail-open.
    /// </summary>
    public static Policy CreateDefault() => PolicyDocument.Default.ToPolicy();

    private async Task WriteDefaultAsync(CancellationToken cancellationToken)
    {
        var directory = Path.GetDirectoryName(_policyFile);
        if (!string.IsNullOrEmpty(directory))
        {
            Directory.CreateDirectory(directory);
        }

        await using var stream = File.Create(_policyFile);
        await JsonSerializer
            .SerializeAsync(stream, PolicyDocument.Default, WriteOptions, cancellationToken)
            .ConfigureAwait(false);
    }
}
