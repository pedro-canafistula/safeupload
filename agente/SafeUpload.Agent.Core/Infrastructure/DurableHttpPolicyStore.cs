using System.Diagnostics;
using System.Security.AccessControl;
using System.Text.Json;
using System.Text.Json.Serialization;
using SafeUpload.Agent.Core.Application;
using SafeUpload.Agent.Core.Domain;

namespace SafeUpload.Agent.Core.Infrastructure;

/// <summary>
/// Política remota com cópia durável da última versão válida para uso offline (HU-12).
/// A decisão de inspeção nunca depende de o servidor estar acessível.
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
    private readonly ICommunicationObserver? _observer;

    /// <summary>Origem da última carga concluída, para diagnóstico operacional.</summary>
    public string? LastSource { get; private set; }

    public DurableHttpPolicyStore(HttpClient http, string endpointId, string cacheFile)
        : this(http, endpointId, cacheFile, enforceProtectedAcl: true) { }

    public DurableHttpPolicyStore(HttpClient http, string endpointId, string cacheFile, ICommunicationObserver observer)
        : this(http, endpointId, cacheFile, enforceProtectedAcl: true, observer) { }

    // Suíte isolada usa diretórios temporários sem privilégios administrativos.
    internal DurableHttpPolicyStore(HttpClient http, string endpointId, string cacheFile,
        bool enforceProtectedAcl, ICommunicationObserver? observer = null)
    {
        _http = http ?? throw new ArgumentNullException(nameof(http));
        ArgumentException.ThrowIfNullOrWhiteSpace(endpointId);
        ArgumentException.ThrowIfNullOrWhiteSpace(cacheFile);
        _endpointId = endpointId;
        _cacheFile = cacheFile;
        _enforceProtectedAcl = enforceProtectedAcl;
        _observer = observer;
    }

    public async Task<Policy> LoadAsync(CancellationToken cancellationToken)
    {
        await _gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        using var observation = new CommunicationObservation(_observer, CommunicationOperation.Policy);
        try
        {
            CommunicationFailure? failure = null;
            int? failedStatus = null;
            try
            {
                using var response = await _http.GetAsync(
                    $"policy?endpointId={Uri.EscapeDataString(_endpointId)}", cancellationToken)
                    .ConfigureAwait(false);
                failedStatus = (int)response.StatusCode;
                response.EnsureSuccessStatusCode();

                await using var content = await response.Content
                    .ReadAsStreamAsync(cancellationToken).ConfigureAwait(false);
                var document = await JsonSerializer.DeserializeAsync<PolicyDocument>(
                    content, JsonOptions, cancellationToken).ConfigureAwait(false)
                    ?? throw new JsonException("O servidor respondeu com política vazia.");

                var policy = document.ToPolicy();
                policy.EnsureValid();

                // A política publicada pode ser usada nesta execução mesmo quando
                // o disco não permite atualizar o cache; a falha fica diagnosticada.
                _lastGood = policy;
                bool persisted = false;
                try
                {
                    await SaveAsync(document, cancellationToken).ConfigureAwait(false);
                    persisted = true;
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
                observation.Success((int)response.StatusCode, PolicyLoadSource.Remote, persisted);
                return policy;
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
            {
                observation.Exception(new OperationCanceledException(), cancellationToken);
                throw;
            }
            catch (Exception ex)
            {
                failure = CommunicationObservation.Classify(ex);
                if (ex is HttpRequestException request && request.StatusCode is { } status) failedStatus = (int)status;
                Trace.TraceWarning("SafeUpload: política remota indisponível/inválida: {0}",
                    ex.GetType().Name);
            }

            try
            {
                var restored = await RestoreUnsynchronizedAsync(cancellationToken).ConfigureAwait(false);
                PolicyLoadSource? source = LastSource switch
                {
                    "memory" => PolicyLoadSource.Memory, "disk" => PolicyLoadSource.Disk,
                    "default" => PolicyLoadSource.Default, _ => null
                };
                observation.Failure(failure ?? CommunicationFailure.UnexpectedError, failedStatus, source);
                return restored;
            }
            catch (Exception exception)
            {
                observation.Exception(exception, cancellationToken);
                throw;
            }
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
