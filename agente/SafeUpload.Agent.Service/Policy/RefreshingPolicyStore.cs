using SafeUpload.Agent.Core.Application;
using DomainPolicy = SafeUpload.Agent.Core.Domain.Policy;
using SafeUpload.Agent.Core.Infrastructure;

namespace SafeUpload.Agent.Service.Policies;

/// <summary>
/// Publica um snapshot validado para as inspeções. Somente o serviço de fundo
/// acessa a rede; inicialização lê o cache protegido antes de tentar HTTP.
/// </summary>
public sealed class RefreshingPolicyStore : BackgroundService, IPolicyStore
{
    private readonly IPolicyStore _remote;
    private readonly Func<CancellationToken, Task<DomainPolicy>> _restore;
    private readonly TimeSpan _interval;
    private readonly ILogger<RefreshingPolicyStore> _logger;
    private readonly SemaphoreSlim _initializeGate = new(1, 1);
    private readonly SemaphoreSlim _refreshGate = new(1, 1);
    private DomainPolicy? _current;

    public RefreshingPolicyStore(DurableHttpPolicyStore remote, TimeSpan interval,
        ILogger<RefreshingPolicyStore> logger)
        : this(remote, remote.LoadCachedOrDefaultAsync, interval, logger) { }

    internal RefreshingPolicyStore(IPolicyStore remote,
        Func<CancellationToken, Task<DomainPolicy>> restore, TimeSpan interval,
        ILogger<RefreshingPolicyStore> logger)
    {
        ArgumentNullException.ThrowIfNull(remote);
        ArgumentNullException.ThrowIfNull(restore);
        ArgumentNullException.ThrowIfNull(logger);
        ArgumentOutOfRangeException.ThrowIfLessThanOrEqual(interval, TimeSpan.Zero);
        _remote = remote;
        _restore = restore;
        _interval = interval;
        _logger = logger;
    }

    public Task<DomainPolicy> LoadAsync(CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        return Volatile.Read(ref _current) is { } current
            ? Task.FromResult(current)
            : InitializeAsync(cancellationToken);
    }

    private async Task<DomainPolicy> InitializeAsync(CancellationToken token)
    {
        await _initializeGate.WaitAsync(token).ConfigureAwait(false);
        try
        {
            if (Volatile.Read(ref _current) is { } current) return current;
            var restored = await _restore(token).ConfigureAwait(false);
            restored.EnsureValid();
            Volatile.Write(ref _current, restored);
            var source = _remote is DurableHttpPolicyStore durable ? durable.LastSource : "local";
            _logger.LogInformation("Política inicial v{Version} disponível sem consulta de rede. Origem={Source}.",
                restored.Version, source);
            return restored;
        }
        finally { _initializeGate.Release(); }
    }

    public override async Task StartAsync(CancellationToken cancellationToken)
    {
        await LoadAsync(cancellationToken).ConfigureAwait(false);
        // Interceptores configuram seus escopos na inicialização. Conclui uma
        // carga remota limitada pelo timeout HTTP antes de iniciá-los, como
        // no fluxo anterior; todas as renovações posteriores ficam em fundo.
        try { await RefreshAsync(cancellationToken).ConfigureAwait(false); }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) { throw; }
        catch (Exception exception)
        {
            _logger.LogWarning(exception, "Carga remota inicial falhou; política recuperada mantida.");
        }
        await base.StartAsync(cancellationToken).ConfigureAwait(false);
    }

    internal async Task RefreshAsync(CancellationToken token)
    {
        await LoadAsync(token).ConfigureAwait(false);
        await _refreshGate.WaitAsync(token).ConfigureAwait(false);
        try
        {
            var refreshed = await _remote.LoadAsync(token).ConfigureAwait(false);
            refreshed.EnsureValid();
            Volatile.Write(ref _current, refreshed);
            _logger.LogInformation("Política v{Version} disponível após atualização.", refreshed.Version);
        }
        finally { _refreshGate.Release(); }
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        while (!stoppingToken.IsCancellationRequested)
        {
            try { await Task.Delay(_interval, stoppingToken).ConfigureAwait(false); }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested) { break; }
            try { await RefreshAsync(stoppingToken).ConfigureAwait(false); }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested) { break; }
            catch (Exception exception)
            {
                _logger.LogWarning(exception, "Falha na atualização de política; último snapshot mantido.");
            }
        }
    }
}
