using System.Diagnostics;
using System.Net;
using System.Security.AccessControl;
using System.Text.Json;
using System.Text.Json.Serialization;
using SafeUpload.Agent.Core.Application;
using SafeUpload.Agent.Core.Domain;

namespace SafeUpload.Agent.Core.Infrastructure;

/// <summary>
/// Política do console (GET policy, assinado) com cópia em disco para uso offline (docs/console-agente.md).
/// 200 = documento do console (mesmo formato do policy.json); 404 = nenhuma atribuída, vale o policy.json local;
/// falha = última política do console conhecida (memória, depois disco), senão o policy.json local.
/// A inspeção nunca espera a rede: o RefreshingPolicyStore chama isto em segundo plano.
/// </summary>
public sealed class DurableHttpPolicyStore : IPolicyStore
{
    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        PropertyNameCaseInsensitive = true,
        AllowDuplicateProperties = false,
        Converters = { new JsonStringEnumConverter() }
    };
    private const int MaxDocumentBytes = 64 * 1024;
    // O envelope e a serialização local (campos padrão e escapes) podem ser maiores que a resposta HTTP.
    private const int MaxCacheBytes = 1024 * 1024;
    private const int CacheFormat = 3;

    private readonly HttpClient _http;
    private readonly SignedAgentIdentity _identity;
    private readonly string _cacheFile;
    private readonly IPolicyStore _local;
    private readonly bool _enforceProtectedAcl;
    private readonly ICommunicationObserver? _observer;
    private readonly SemaphoreSlim _gate = new(1, 1);
    private Policy? _lastConsole;

    /// <summary>Origem da última carga: remote, local, memory, disk.</summary>
    public string? LastSource { get; private set; }

    /// <summary>Versão do console em uso, relatada no heartbeat; null quando vale o policy.json local.</summary>
    public int? ConsoleVersion { get; private set; }

    public DurableHttpPolicyStore(HttpClient http, SignedAgentIdentity identity, string cacheFile, IPolicyStore local,
        ICommunicationObserver? observer = null)
        : this(http, identity, cacheFile, local, enforceProtectedAcl: true, observer) { }

    // Testes isolados usam diretórios temporários sem privilégios administrativos.
    internal DurableHttpPolicyStore(HttpClient http, SignedAgentIdentity identity, string cacheFile, IPolicyStore local,
        bool enforceProtectedAcl, ICommunicationObserver? observer = null)
    {
        _http = http ?? throw new ArgumentNullException(nameof(http));
        _identity = identity ?? throw new ArgumentNullException(nameof(identity));
        if (_http.BaseAddress != _identity.Server)
            throw new ArgumentException("O cliente de política deve usar o servidor da identidade.", nameof(http));
        ArgumentException.ThrowIfNullOrWhiteSpace(cacheFile);
        _cacheFile = cacheFile;
        _local = local ?? throw new ArgumentNullException(nameof(local));
        _enforceProtectedAcl = enforceProtectedAcl;
        _observer = observer;
    }

    public async Task<Policy> LoadAsync(CancellationToken cancellationToken)
    {
        await _gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        using var observation = new CommunicationObservation(_observer, CommunicationOperation.Policy);
        try
        {
            int? status = null;
            CommunicationFailure failure;
            try
            {
                using var deadline = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
                if (_http.Timeout != Timeout.InfiniteTimeSpan) deadline.CancelAfter(_http.Timeout);
                using var response = await _http.GetAsync("policy", HttpCompletionOption.ResponseHeadersRead, deadline.Token)
                    .ConfigureAwait(false);
                status = (int)response.StatusCode;
                if (response.StatusCode == HttpStatusCode.NotFound)
                {
                    // Nenhuma política atribuída a esta máquina: volta ao policy.json local.
                    var local = await _local.LoadAsync(cancellationToken).ConfigureAwait(false);
                    local.EnsureValid();
                    _lastConsole = null;
                    ConsoleVersion = null;
                    TryDeleteCache();
                    LastSource = "local";
                    observation.Success(status, PolicyLoadSource.Default, cachePersisted: false);
                    return local;
                }
                response.EnsureSuccessStatusCode();
                await using var content = await response.Content.ReadAsStreamAsync(deadline.Token).ConfigureAwait(false);
                var document = JsonSerializer.Deserialize<PolicyDocument>(await ReadBoundedAsync(content, MaxDocumentBytes, deadline.Token)
                    .ConfigureAwait(false), JsonOptions) ?? throw new JsonException("Política vazia.");
                var policy = document.ToPolicy();
                policy.EnsureValid();
                _lastConsole = policy;
                ConsoleVersion = policy.Version;
                bool persisted = await TrySaveAsync(document, cancellationToken).ConfigureAwait(false);
                LastSource = "remote";
                observation.Success(status, PolicyLoadSource.Remote, persisted);
                return policy;
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
            {
                observation.Exception(new OperationCanceledException(), cancellationToken);
                throw;
            }
            catch (Exception error)
            {
                failure = CommunicationObservation.Classify(error);
                if (error is HttpRequestException { StatusCode: { } code }) status = (int)code;
                Trace.TraceWarning("SafeUpload: política do console indisponível/inválida: {0}", error.GetType().Name);
            }

            var restored = await RestoreUnsynchronizedAsync(cancellationToken).ConfigureAwait(false);
            observation.Failure(failure, status, LastSource switch
            {
                "memory" => PolicyLoadSource.Memory, "disk" => PolicyLoadSource.Disk, _ => PolicyLoadSource.Default
            });
            return restored;
        }
        finally
        {
            _gate.Release();
        }
    }

    /// <summary>Política inicial sem esperar a rede: cache do console, senão policy.json local.</summary>
    public async Task<Policy> LoadCachedOrDefaultAsync(CancellationToken cancellationToken)
    {
        await _gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try { return await RestoreUnsynchronizedAsync(cancellationToken).ConfigureAwait(false); }
        finally { _gate.Release(); }
    }

    private async Task<Policy> RestoreUnsynchronizedAsync(CancellationToken cancellationToken)
    {
        if (_lastConsole is not null)
        {
            LastSource = "memory";
            return _lastConsole;
        }
        try
        {
            var cached = await ReadCacheAsync(cancellationToken).ConfigureAwait(false);
            _lastConsole = cached;
            ConsoleVersion = cached.Version;
            LastSource = "disk";
            return cached;
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) { throw; }
        catch (Exception error) when (error is not FileNotFoundException)
        {
            Trace.TraceWarning("SafeUpload: cache da política do console inválido: {0}", error.GetType().Name);
        }
        catch (FileNotFoundException) { }

        var local = await _local.LoadAsync(cancellationToken).ConfigureAwait(false);
        local.EnsureValid();
        ConsoleVersion = null;
        LastSource = "local";
        return local;
    }

    private async Task<Policy> ReadCacheAsync(CancellationToken cancellationToken)
    {
        if (!File.Exists(_cacheFile)) throw new FileNotFoundException("Sem cache.", _cacheFile);
        if (_enforceProtectedAcl && OperatingSystem.IsWindows())
        {
            ProtectedPolicyAcl.EnsureDirectory(_cacheFile);
            ProtectedPolicyAcl.VerifyPolicyFile(_cacheFile);
        }
        await using var stream = File.OpenRead(_cacheFile);
        var cache = JsonSerializer.Deserialize<CacheFile>(await ReadBoundedAsync(stream, MaxCacheBytes, cancellationToken)
            .ConfigureAwait(false), JsonOptions) ?? throw new JsonException("Cache vazio.");
        // O mesmo servidor e id numérico podem ser reutilizados depois de um novo cadastro.
        if (cache.Format != CacheFormat || cache.Server != _identity.Server.AbsoluteUri ||
            cache.HostId != _identity.HostId || cache.PublicKey != _identity.PublicKey || cache.Policy is null)
            throw new InvalidPolicyException("Cache da política pertence a outro cadastro ou formato.");
        var policy = cache.Policy.ToPolicy();
        policy.EnsureValid();
        return policy;
    }

    private async Task<bool> TrySaveAsync(PolicyDocument document, CancellationToken cancellationToken)
    {
        try
        {
            string fullPath = Path.GetFullPath(_cacheFile);
            string directory = Path.GetDirectoryName(fullPath) ?? throw new IOException("Cache sem diretório.");
            if (_enforceProtectedAcl && OperatingSystem.IsWindows())
            {
                ProtectedPolicyAcl.EnsureDirectory(fullPath);
                if (File.Exists(fullPath)) ProtectedPolicyAcl.VerifyPolicyFile(fullPath);
            }
            else Directory.CreateDirectory(directory);

            // Temporário no mesmo diretório => troca atômica no mesmo volume.
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
                    var cache = new CacheFile(CacheFormat, _identity.Server.AbsoluteUri, _identity.HostId, _identity.PublicKey, document);
                    await JsonSerializer.SerializeAsync(stream, cache,
                        JsonOptions, cancellationToken).ConfigureAwait(false);
                    await stream.FlushAsync(cancellationToken).ConfigureAwait(false);
                    if (stream.Length > MaxCacheBytes) throw new JsonException("Cache da política excede o limite.");
                }
                cancellationToken.ThrowIfCancellationRequested();
                File.Move(temporary, fullPath, overwrite: true);
                return true;
            }
            finally
            {
                if (File.Exists(temporary)) File.Delete(temporary);
            }
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) { throw; }
        catch (Exception error)
        {
            // A política recebida vale nesta execução mesmo sem cache; a falha fica diagnosticada.
            Trace.TraceWarning("SafeUpload: não foi possível gravar o cache da política: {0}", error.GetType().Name);
            return false;
        }
    }

    private void TryDeleteCache()
    {
        try { File.Delete(_cacheFile); }
        catch (Exception error) when (error is IOException or UnauthorizedAccessException)
        {
            Trace.TraceWarning("SafeUpload: cache da política não removido: {0}", error.GetType().Name);
        }
    }

    private static async Task<byte[]> ReadBoundedAsync(Stream stream, int maxBytes, CancellationToken token)
    {
        using var buffer = new MemoryStream();
        byte[] chunk = new byte[4096];
        int count;
        while ((count = await stream.ReadAsync(chunk, token).ConfigureAwait(false)) != 0)
        {
            if (buffer.Length + count > maxBytes) throw new JsonException("Política excede o limite de leitura.");
            buffer.Write(chunk, 0, count);
        }
        return buffer.ToArray();
    }

    private sealed record CacheFile(int Format, string Server, int HostId, string PublicKey, PolicyDocument Policy);
}
