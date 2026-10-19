using System.Diagnostics;
using System.Security.AccessControl;
using System.Text.Json;
using System.Text.Json.Serialization;
using SafeUpload.Agent.Core.Application;
using SafeUpload.Agent.Core.Domain;

namespace SafeUpload.Agent.Core.Infrastructure;

/// <summary>
/// Política remota com cópia durável da última versão válida para uso offline (HU-12).
/// O fallback atende consumidores legados. Decisões staged exigem a origem
/// atual por LoadCurrentAsync e falham sem substituir a política pelo cache.
/// </summary>
public sealed class DurableHttpPolicyStore : IPolicyStore
{
    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        PropertyNameCaseInsensitive = true,
        Converters = { new JsonStringEnumConverter() }
    };

    private readonly HttpClient _http;
    private readonly string _endpointId;
    private readonly string _cacheFile;
    private readonly bool _enforceProtectedAcl;
    private readonly SemaphoreSlim _gate = new(1, 1);
    private Policy? _lastGood;

    /// <summary>Origem da última carga concluída, para diagnóstico operacional.</summary>
    public string? LastSource { get; private set; }

    public DurableHttpPolicyStore(HttpClient http, string endpointId, string cacheFile)
        : this(http, endpointId, cacheFile, enforceProtectedAcl: true) { }

    // Suíte isolada usa diretórios temporários sem privilégios administrativos.
    internal DurableHttpPolicyStore(HttpClient http, string endpointId, string cacheFile,
        bool enforceProtectedAcl)
    {
        _http = http ?? throw new ArgumentNullException(nameof(http));
        ArgumentException.ThrowIfNullOrWhiteSpace(endpointId);
        ArgumentException.ThrowIfNullOrWhiteSpace(cacheFile);
        _endpointId = endpointId;
        _cacheFile = cacheFile;
        _enforceProtectedAcl = enforceProtectedAcl;
    }

    public Task<Policy> LoadAsync(CancellationToken cancellationToken) =>
        LoadCoreAsync(allowFallback: true, cancellationToken);

    /// <summary>Reads and validates the remote policy without memory/disk/default fallback.</summary>
    public Task<Policy> LoadCurrentAsync(CancellationToken cancellationToken) =>
        LoadCoreAsync(allowFallback: false, cancellationToken);

    private async Task<Policy> LoadCoreAsync(bool allowFallback, CancellationToken cancellationToken)
    {
        await _gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            try
            {
                using var response = await _http.GetAsync(
                    $"policy?endpointId={Uri.EscapeDataString(_endpointId)}", cancellationToken)
                    .ConfigureAwait(false);
                response.EnsureSuccessStatusCode();

                await using var content = await response.Content
                    .ReadAsStreamAsync(cancellationToken).ConfigureAwait(false);
                var document = await JsonSerializer.DeserializeAsync<PolicyDocument>(
                    content, JsonOptions, cancellationToken).ConfigureAwait(false)
                    ?? throw new InvalidPolicyException("O servidor respondeu sem uma política atual.");

                var policy = document.ToPolicy(staged: !allowFallback);
                policy.EnsureValid();

                // A política publicada pode ser usada nesta execução mesmo quando
                // o disco não permite atualizar o cache; a falha fica diagnosticada.
                // A strict staged read may use larger defaults for omitted limits.
                // Keep the document's legacy projection for fallback/refresh so
                // staged authority cannot enlarge an offline legacy decision.
                _lastGood = allowFallback ? policy : document.ToPolicy();
                try
                {
                    await SaveAsync(document, cancellationToken).ConfigureAwait(false);
                }
                catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
                {
                    throw;
                }
                catch (Exception ex)
                {
                    Trace.TraceWarning("SafeUpload: não foi possível persistir a política: {0}",
                        ex.GetType().Name);
                }
                LastSource = "remote";
                return policy;
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
            {
                throw;
            }
            catch (Exception ex) when (allowFallback)
            {
                Trace.TraceWarning("SafeUpload: política remota indisponível/inválida: {0}",
                    ex.GetType().Name);
            }

            return await RestoreUnsynchronizedAsync(cancellationToken).ConfigureAwait(false);
        }
        finally
        {
            _gate.Release();
        }
    }

    /// <summary>Inicializa a proteção pelo disco ou padrão existente, sem esperar uma conexão HTTP.</summary>
    public async Task<Policy> LoadCachedOrDefaultAsync(CancellationToken cancellationToken)
    {
        await _gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try { return await RestoreUnsynchronizedAsync(cancellationToken).ConfigureAwait(false); }
        finally { _gate.Release(); }
    }

    private async Task<Policy> RestoreUnsynchronizedAsync(CancellationToken cancellationToken)
    {
        // Durante a execução, a última política conhecida tem precedência.
        if (_lastGood is not null)
        {
            LastSource = "memory";
            return _lastGood;
        }

        // Após reiniciar o serviço offline, recupera a última versão persistida.
        try
        {
            var cached = await ReadCacheAsync(cancellationToken).ConfigureAwait(false);
            _lastGood = cached;
            LastSource = "disk";
            return cached;
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception ex)
        {
            Trace.TraceWarning("SafeUpload: cache remoto indisponível/inválido: {0}",
                ex.GetType().Name);
        }

        // Somente no primeiro uso sem política remota recuperável.
        var fallback = LocalPolicyStore.CreateDefault();
        fallback.EnsureValid();
        LastSource = "default";
        return fallback;
    }

    private async Task<Policy> ReadCacheAsync(CancellationToken cancellationToken)
    {
        if (_enforceProtectedAcl && OperatingSystem.IsWindows())
        {
            ProtectedPolicyAcl.EnsureDirectory(_cacheFile);
            ProtectedPolicyAcl.VerifyPolicyFile(_cacheFile);
        }

        await using var stream = File.OpenRead(_cacheFile);
        var document = await JsonSerializer.DeserializeAsync<PolicyDocument>(
            stream, JsonOptions, cancellationToken).ConfigureAwait(false)
            ?? throw new JsonException("Cache de política vazio.");

        var policy = document.ToPolicy();
        policy.EnsureValid();
        return policy;
    }

    private async Task SaveAsync(PolicyDocument document, CancellationToken cancellationToken)
    {
        string fullPath = Path.GetFullPath(_cacheFile);
        string directory = Path.GetDirectoryName(fullPath)
            ?? throw new IOException("Cache de política sem diretório.");

        if (_enforceProtectedAcl && OperatingSystem.IsWindows())
        {
            ProtectedPolicyAcl.EnsureDirectory(fullPath);
            if (File.Exists(fullPath))
                ProtectedPolicyAcl.VerifyPolicyFile(fullPath);
        }
        else
        {
            Directory.CreateDirectory(directory);
        }

        // Temporário no mesmo diretório => rename atômico no mesmo volume.
        // Nome aleatório impede que um temp antigo seja substituído por engano.
        string temporary = Path.Combine(directory, ".policy-" + Guid.NewGuid().ToString("N") + ".tmp");
        try
        {
            await using (var stream = OperatingSystem.IsWindows() && _enforceProtectedAcl
                ? new FileInfo(temporary).Create(FileMode.CreateNew, FileSystemRights.FullControl,
                    FileShare.None, 4096, FileOptions.Asynchronous | FileOptions.WriteThrough,
                    ProtectedPolicyAcl.CreatePolicyFileSecurity())
                : new FileStream(temporary, FileMode.CreateNew, FileAccess.Write, FileShare.None,
                    4096, FileOptions.Asynchronous | FileOptions.WriteThrough))
            {
                await JsonSerializer.SerializeAsync(stream, document, JsonOptions, cancellationToken)
                    .ConfigureAwait(false);
                await stream.FlushAsync(cancellationToken).ConfigureAwait(false);
            }

            File.Move(temporary, fullPath, overwrite: true);
        }
        finally
        {
            if (File.Exists(temporary)) File.Delete(temporary);
        }
    }
}
