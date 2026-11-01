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
        AllowDuplicateProperties = false,
        Converters = { new JsonStringEnumConverter() }
    };

    private readonly HttpClient _http;
    private readonly string _endpointId;
    private readonly string _cacheFile;
    private readonly bool _enforceProtectedAcl;
    private readonly SemaphoreSlim _gate = new(1, 1);
    private Policy? _lastGood;
    private readonly ICommunicationObserver? _observer;
    private readonly ConsolePolicyOptions? _consolePolicy;
    private readonly IPolicyStore? _operationalPolicy;
    private PolicyDocument? _lastConsoleDocument;
    private RemotePolicyStatus _status = new();

    public RemotePolicyStatus ReadStatus() => Volatile.Read(ref _status);

    /// <summary>Origem da última carga concluída, para diagnóstico operacional.</summary>
    public string? LastSource { get; private set; }

    public DurableHttpPolicyStore(HttpClient http, string endpointId, string cacheFile)
        : this(http, endpointId, cacheFile, enforceProtectedAcl: true) { }

    public DurableHttpPolicyStore(HttpClient http, string endpointId, string cacheFile, ICommunicationObserver observer)
        : this(http, endpointId, cacheFile, enforceProtectedAcl: true, observer) { }

    public DurableHttpPolicyStore(HttpClient http, string endpointId, string cacheFile,
        ICommunicationObserver observer, ConsolePolicyOptions consolePolicy, IPolicyStore operationalPolicy)
        : this(http, endpointId, cacheFile, true, observer, consolePolicy, operationalPolicy) { }

    // Suíte isolada usa diretórios temporários sem privilégios administrativos.
    internal DurableHttpPolicyStore(HttpClient http, string endpointId, string cacheFile,
        bool enforceProtectedAcl, ICommunicationObserver? observer = null,
        ConsolePolicyOptions? consolePolicy = null, IPolicyStore? operationalPolicy = null)
    {
        _http = http ?? throw new ArgumentNullException(nameof(http));
        ArgumentException.ThrowIfNullOrWhiteSpace(endpointId);
        ArgumentException.ThrowIfNullOrWhiteSpace(cacheFile);
        _endpointId = endpointId;
        _cacheFile = cacheFile;
        _enforceProtectedAcl = enforceProtectedAcl;
        _observer = observer;
        if (consolePolicy is not null)
        {
            _ = new AgentApiClient(http); // Mesma base /agent/, sem query/credenciais.
            ArgumentNullException.ThrowIfNull(operationalPolicy);
        }
        _consolePolicy = consolePolicy;
        _operationalPolicy = operationalPolicy;
    }

    public Task<Policy> LoadAsync(CancellationToken cancellationToken) => LoadCoreAsync(true, cancellationToken);

    /// <summary>Fresh origin read; never returns memory, disk or default policy on failure.</summary>
    public Task<Policy> LoadCurrentAsync(CancellationToken cancellationToken) => LoadCoreAsync(false, cancellationToken);

    private async Task<Policy> LoadCoreAsync(bool allowFallback, CancellationToken cancellationToken)
    {
        await _gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        using var observation = new CommunicationObservation(_observer, CommunicationOperation.Policy);
        try
        {
            CommunicationFailure? failure = null;
            int? failedStatus = null;
            try
            {
                // Recupera a revisão persistida antes de aceitar outra, inclusive após reinício.
                if (_consolePolicy is not null)
                {
                    if (allowFallback) await RestoreUnsynchronizedAsync(cancellationToken).ConfigureAwait(false);
                    else if (_lastConsoleDocument is null && File.Exists(_cacheFile))
                    {
                        // A trusted previous revision is only a rollback baseline, never current authority.
                        try { await ReadCacheAsync(cancellationToken).ConfigureAwait(false); }
                        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) { throw; }
                        catch (Exception error) { Trace.TraceWarning("SafeUpload: revision baseline unavailable: {0}", error.GetType().Name); }
                    }
                }
                using var deadline = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
                if (_consolePolicy is not null && _http.Timeout != Timeout.InfiniteTimeSpan)
                    deadline.CancelAfter(_http.Timeout);
                var networkToken = _consolePolicy is null ? cancellationToken : deadline.Token;
                using var response = await _http.GetAsync(
                    _consolePolicy?.RequestPath ?? $"policy?endpointId={Uri.EscapeDataString(_endpointId)}",
                    _consolePolicy is null ? HttpCompletionOption.ResponseContentRead : HttpCompletionOption.ResponseHeadersRead,
                    networkToken)
                    .ConfigureAwait(false);
                failedStatus = (int)response.StatusCode;
                response.EnsureSuccessStatusCode();

                await using var content = await response.Content
                    .ReadAsStreamAsync(networkToken).ConfigureAwait(false);
                PolicyDocument document;
                PolicyDocument? cacheDocument;
                if (_consolePolicy is null)
                {
                    document = await JsonSerializer.DeserializeAsync<PolicyDocument>(
                        content, JsonOptions, networkToken).ConfigureAwait(false)
                        ?? throw new JsonException("O servidor respondeu com política vazia.");
                    cacheDocument = document;
                }
                else
                {
                    using var json = await ReadConsoleJsonAsync(content, networkToken).ConfigureAwait(false);
                    var operational = allowFallback
                        ? await _operationalPolicy!.LoadAsync(cancellationToken).ConfigureAwait(false)
                        : await _operationalPolicy!.LoadCurrentAsync(networkToken).ConfigureAwait(false);
                    operational.EnsureValid();
                    document = _consolePolicy.Translate(json.RootElement, operational);
                    if (_lastConsoleDocument is { } previous &&
                        (document.Version < previous.Version ||
                         document.Version == previous.Version && !SameConsolePublication(document, previous)))
                        throw new InvalidPolicyException("Revisão da console regressiva ou alterada sem nova publicação.");
                    cacheDocument = allowFallback ? document : null;
                    if (!allowFallback)
                    {
                        // The current result has already been read from the live operational origin.
                        // This second projection is only for legacy caching, never authority to return.
                        try
                        {
                            var legacy = _consolePolicy.Translate(json.RootElement,
                                await _operationalPolicy!.LoadAsync(networkToken).ConfigureAwait(false));
                            legacy.ToPolicy().EnsureValid();
                            cacheDocument = legacy;
                        }
                        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) { throw; }
                        catch (Exception error) { Trace.TraceWarning("SafeUpload: legacy cache projection unavailable: {0}", error.GetType().Name); }
                    }
                }

                var policy = document.ToPolicy(staged: !allowFallback);
                policy.EnsureValid();
                var cachedPolicy = cacheDocument?.ToPolicy();
                cachedPolicy?.EnsureValid();
                Volatile.Write(ref _status, _status with { LastValidatedRemoteVersion = policy.Version });

                // A política publicada pode ser usada nesta execução mesmo quando
                // o disco não permite atualizar o cache; a falha fica diagnosticada.
                if (cachedPolicy is not null) _lastGood = allowFallback ? policy : cachedPolicy;
                if (_consolePolicy is not null) _lastConsoleDocument = cacheDocument ?? document;
                bool persisted = false;
                try
                {
                    if (cacheDocument is not null)
                    {
                        await SaveAsync(cacheDocument, cancellationToken).ConfigureAwait(false);
                        Volatile.Write(ref _status, _status with { LastWrittenCacheVersion = cacheDocument.Version });
                        persisted = true;
                    }
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
                if (!allowFallback)
                {
                    observation.Exception(ex, cancellationToken, failedStatus);
                    throw;
                }
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

    // The console owns these fields. Local operational limits/scopes differ by consumer mode and are not
    // a mutation of the central publication. Destination/format/rules are checked during translation.
    private static bool SameConsolePublication(PolicyDocument left, PolicyDocument right) =>
        left.Version == right.Version && left.AuditOnly == right.AuditOnly &&
        left.OverrideAllowed == right.OverrideAllowed &&
        (left.ActiveCategories ?? []).SequenceEqual(right.ActiveCategories ?? [], StringComparer.Ordinal);

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
        var fallback = _consolePolicy is null
            ? LocalPolicyStore.CreateDefault()
            : await _operationalPolicy!.LoadAsync(cancellationToken).ConfigureAwait(false);
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
        PolicyDocument document;
        if (_consolePolicy is null)
            document = await JsonSerializer.DeserializeAsync<PolicyDocument>(
                stream, JsonOptions, cancellationToken).ConfigureAwait(false)
                ?? throw new JsonException("Cache de política vazio.");
        else
        {
            using var json = await ReadConsoleJsonAsync(stream, cancellationToken).ConfigureAwait(false);
            ConsolePolicyOptions.RejectDuplicates(json.RootElement);
            var cache = json.RootElement.Deserialize<ConsolePolicyCache>(JsonOptions)
                ?? throw new JsonException("Cache de política vazio.");
            document = _consolePolicy.ReadCache(cache, _http.BaseAddress!);
        }

        var policy = document.ToPolicy();
        policy.EnsureValid();
        if (_consolePolicy is not null) _lastConsoleDocument = document;
        Volatile.Write(ref _status, _status with { LastReadCacheVersion = policy.Version });
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
                if (_consolePolicy is null)
                    await JsonSerializer.SerializeAsync(stream, document, JsonOptions, cancellationToken).ConfigureAwait(false);
                else
                    await JsonSerializer.SerializeAsync(stream, _consolePolicy.Wrap(_http.BaseAddress!, document),
                        JsonOptions, cancellationToken).ConfigureAwait(false);
                await stream.FlushAsync(cancellationToken).ConfigureAwait(false);
            }

            File.Move(temporary, fullPath, overwrite: true);
        }
        finally
        {
            if (File.Exists(temporary)) File.Delete(temporary);
        }
    }

    private static async Task<JsonDocument> ReadConsoleJsonAsync(Stream stream, CancellationToken token)
    {
        using var buffer = new MemoryStream();
        byte[] chunk = new byte[4096];
        int count;
        while ((count = await stream.ReadAsync(chunk, token).ConfigureAwait(false)) != 0)
        {
            if (buffer.Length + count > 64 * 1024)
                throw new JsonException("Política da console excede o limite de leitura.");
            buffer.Write(chunk, 0, count);
        }
        return JsonDocument.Parse(buffer.ToArray(), new JsonDocumentOptions { MaxDepth = 16 });
    }
}
