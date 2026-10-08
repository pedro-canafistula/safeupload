using System.Text.Json;
using System.Text.Json.Serialization;
using System.Security.AccessControl;
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
    private readonly bool _enforceProtectedAcl;
    private readonly Func<string, bool>? _aclVerifier;
    private readonly SemaphoreSlim _loadGate = new(1, 1);
    private Policy? _lastGoodPolicy;

    /// <summary>Usa o caminho padrão do agente.</summary>
    public LocalPolicyStore() : this(AgentPaths.PolicyFile, enforceProtectedAcl: true, aclVerifier: null)
    {
    }

    /// <summary>Usa um caminho específico. Serve aos testes isolados.</summary>
    public LocalPolicyStore(string policyFile) : this(policyFile, enforceProtectedAcl: false, aclVerifier: null)
    {
    }

    internal LocalPolicyStore(string policyFile, Func<string, bool> aclVerifier)
        : this(policyFile, enforceProtectedAcl: true,
            aclVerifier ?? throw new ArgumentNullException(nameof(aclVerifier)))
    {
    }

    private LocalPolicyStore(string policyFile, bool enforceProtectedAcl, Func<string, bool>? aclVerifier)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(policyFile);
        _policyFile = policyFile;
        _enforceProtectedAcl = enforceProtectedAcl;
        _aclVerifier = aclVerifier;
    }

    /// <summary>Caminho do arquivo lido, para exibição na interface.</summary>
    public string PolicyFilePath => _policyFile;

    /// <inheritdoc />
    public async Task<Policy> LoadAsync(CancellationToken cancellationToken)
    {
        await _loadGate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            try
            {
                if (_enforceProtectedAcl && _aclVerifier is not null)
                {
                    VerifyInjectedAcl();
                }
                else if (_enforceProtectedAcl && OperatingSystem.IsWindows())
                {
                    ProtectedPolicyAcl.EnsureDirectory(_policyFile);
                }

                if (!File.Exists(_policyFile))
                {
                    await WriteDefaultAsync(cancellationToken).ConfigureAwait(false);
                }

                if (_enforceProtectedAcl && OperatingSystem.IsWindows() && _aclVerifier is null)
                {
                    ProtectedPolicyAcl.VerifyPolicyFile(_policyFile);
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

                // RN-009: the validation happens at load time. Cache only a
                // policy whose protected ACL and contents both passed checks.
                policy.EnsureValid();
                _lastGoodPolicy = policy;
                return policy;
            }
            catch (PolicyFileAclRejectedException) when (_lastGoodPolicy is not null)
            {
                // Do not read or adopt a policy whose ACL is weaker. Existing
                // service users keep the prior in-memory policy; first start
                // without a valid policy fails instead of selecting a default.
                return _lastGoodPolicy;
            }
        }
        finally
        {
            _loadGate.Release();
        }
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
            if (!_enforceProtectedAcl || !OperatingSystem.IsWindows())
            {
                Directory.CreateDirectory(directory);
            }
        }

        await using var stream = _enforceProtectedAcl && OperatingSystem.IsWindows()
            ? new FileInfo(_policyFile).Create(FileMode.CreateNew, FileSystemRights.FullControl,
                FileShare.None, 4096, FileOptions.Asynchronous | FileOptions.WriteThrough,
                ProtectedPolicyAcl.CreatePolicyFileSecurity())
            : File.Create(_policyFile);
        await JsonSerializer
            .SerializeAsync(stream, PolicyDocument.Default, WriteOptions, cancellationToken)
            .ConfigureAwait(false);
        await stream.FlushAsync(cancellationToken).ConfigureAwait(false);
    }

    private void VerifyInjectedAcl()
    {
        if (!_aclVerifier!(_policyFile))
        {
            throw new PolicyFileAclRejectedException(
                $"SafeUpload policy directory or {_policyFile} ACL does not match the protected SYSTEM/Administrators DACL.");
        }
    }
}
