using System.Diagnostics;
using System.Security.Cryptography;
using SafeUpload.Agent.Core.Domain;
using SafeUpload.Agent.Core.Infrastructure.Extraction;

namespace SafeUpload.Agent.Core.Application;

/// <summary>
/// O motor de decisão do agente: recebe uma operação de arquivo, decide se ela
/// passa e registra o que decidiu.
///
/// A ordem das etapas é parte da regra, e não uma escolha de implementação. As
/// verificações baratas e as que dispensam ler o arquivo vêm antes das caras,
/// de modo que o caminho comum termine sem nunca abrir o conteúdo:
///
///   1. processo excluído                    RN-014
///   2. destino ou extensão fora do escopo   RN-011
///   3. arquivo grande demais                RN-013
///   4. formato não suportado                RN-013
///   5. leitura e hash, acerto de cache
///   6. extração e varredura com prazo       RN-012
///   7. veredito                             RN-005
///   8. cache e auditoria
///
/// A inspeção legada libera erros com AllowedWithoutInspection (RN-012/013).
/// Uma transferência staged em escopo exige inspeção completa: tamanho acima
/// do limite, formato não suportado, timeout e falhas de leitura ou parsing
/// produzem Blocked. O publicador devolve os bytes ao usuário e só aceita uma
/// justificativa vinculada à versão e à política atuais quando ela é permitida.
/// </summary>
public sealed class InspectionService
{
    private readonly IPolicyStore _policyStore;
    private readonly IAuditSink _auditSink;
    private readonly ExtractorRegistry _extractors;
    private readonly VerdictCache _cache;
    private readonly string _endpointId;
    private readonly string _userName;
    // A timeout must not admit unbounded background parsing work. A parser
    // that ignores cancellation keeps its slot until it actually finishes.
    // This is a concurrency budget, independent of the file-size policy.
    private const int MaximumConcurrentInspections = 2;
    private readonly SemaphoreSlim _inspectionSlots = new(MaximumConcurrentInspections, MaximumConcurrentInspections);
    internal int ActiveInspectionWorkers => MaximumConcurrentInspections - _inspectionSlots.CurrentCount;

    /// <summary>Compõe o motor com suas dependências.</summary>
    public InspectionService(
        IPolicyStore policyStore,
        IAuditSink auditSink,
        ExtractorRegistry extractors,
        VerdictCache cache,
        string? endpointId = null,
        string? userName = null)
    {
        _policyStore = policyStore ?? throw new ArgumentNullException(nameof(policyStore));
        _auditSink = auditSink ?? throw new ArgumentNullException(nameof(auditSink));
        _extractors = extractors ?? throw new ArgumentNullException(nameof(extractors));
        _cache = cache ?? throw new ArgumentNullException(nameof(cache));
        _endpointId = endpointId ?? Environment.MachineName;
        _userName = userName ?? Environment.UserName;
    }

    /// <summary>Julga uma operação de arquivo.</summary>
    public async Task<InspectionResult> InspectAsync(FileOperation operation, CancellationToken cancellationToken)
        => await InspectCoreAsync(operation, staged: false, cancellationToken).ConfigureAwait(false);

    /// <summary>
    /// Classifies a sealed staging file. Its verdict is not an operation
    /// outcome: the caller records the outcome after publication or retention.
    /// Never reuse a cached decision for a staged file.
    /// An in-scope file that cannot be fully inspected is Blocked.
    /// </summary>
    public Task<InspectionResult> InspectStagedAsync(FileOperation operation, CancellationToken cancellationToken)
        => InspectCoreAsync(operation, staged: true, cancellationToken);

    /// <summary>
    /// A staged approval may only be published under the same policy that
    /// inspected it. Reload just before publication; a changed or unreadable
    /// policy keeps the file local for a new inspection.
    /// </summary>
    public async Task<bool> IsCurrentStagedApprovalAsync(
        FileOperation operation,
        InspectionResult result,
        CancellationToken cancellationToken)
    {
        if (!result.InScope || result.Verdict != Verdict.Approved)
        {
            return false;
        }

        var current = await _policyStore.LoadAsync(cancellationToken).ConfigureAwait(false);
        return current.Version == result.PolicyVersion &&
            !current.IsExcludedProcess(operation.ProcessName) &&
            current.IsMonitoredDestination(operation) &&
            current.IsMonitoredExtension(operation.Extension);
    }

    public async Task<bool> IsCurrentStagedJustificationAllowedAsync(
        FileOperation operation, InspectionResult result, CancellationToken cancellationToken)
    {
        if (!result.InScope || !result.IsBlocked) return false;
        var current = await _policyStore.LoadAsync(cancellationToken).ConfigureAwait(false);
        return current.OverrideAllowed && current.Version == result.PolicyVersion &&
            !current.IsExcludedProcess(operation.ProcessName) &&
            current.IsMonitoredDestination(operation) &&
            current.IsMonitoredExtension(operation.Extension);
    }

    public Task RecordTransferOutcomeAsync(
        FileOperation operation,
        InspectionResult inspection,
        Verdict outcome,
        string? reason,
        CancellationToken cancellationToken,
        Guid? eventId = null,
        string? publishedSha256Hex = null)
        => AuditAsync(operation, inspection with { Verdict = outcome, Reason = reason },
            cancellationToken, eventId, publishedSha256Hex);

    private async Task<InspectionResult> InspectCoreAsync(
        FileOperation operation, bool staged, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(operation);

        var stopwatch = Stopwatch.StartNew();
        var policy = await _policyStore.LoadAsync(cancellationToken).ConfigureAwait(false);
        bool auditAndCache = !staged;
        var inspectionFailure = staged ? Verdict.Blocked : Verdict.AllowedWithoutInspection;

        // 1. RN-014 — o próprio agente e os processos de sistema jamais são
        // interceptados. Além do ruído, deixar o agente se interceptar criaria
        // recursão: ler o arquivo dispararia outra inspeção, que leria de novo.
        if (policy.IsExcludedProcess(operation.ProcessName))
        {
            return OutOfScope(stopwatch, policy, "excluded_process");
        }

        // 2. RN-011 — fora do escopo declarado não se inspeciona nada.
        if (!policy.IsInScope(operation) || !policy.IsMonitoredExtension(operation.Extension))
        {
            return OutOfScope(stopwatch, policy, "out_of_scope");
        }

        // RN-013 applies to legacy operations; staged failures require a blocked hand-back.
        if (operation.SizeBytes > policy.MaxFileSizeBytes)
        {
            return await CompleteAsync(
                    operation, policy, stopwatch, inspectionFailure, [], "file_too_large", auditAndCache, cancellationToken)
                .ConfigureAwait(false);
        }

        // 5. RN-013 — sem extrator para a extensão, não há o que varrer.
        var extractor = _extractors.Resolve(operation.Extension);
        if (extractor is null)
        {
            return await CompleteAsync(
                    operation, policy, stopwatch, inspectionFailure, [], "unsupported_format", auditAndCache, cancellationToken)
                .ConfigureAwait(false);
        }

        // 6. Extração e varredura com prazo (RN-012).
        IReadOnlyList<Finding> findings;
        string? fingerprint = null;

        try
        {
            var inspected = await InspectWithBudgetAsync(extractor, operation, policy, auditAndCache, cancellationToken)
                .ConfigureAwait(false);
            fingerprint = inspected.Fingerprint;
            findings = inspected.Findings;
            if (inspected.Cached is not null)
            {
                stopwatch.Stop();
                var fromCache = inspected.Cached with
                {
                    ElapsedMs = stopwatch.ElapsedMilliseconds,
                    FromCache = true
                };
                await AuditAsync(operation, fromCache, cancellationToken).ConfigureAwait(false);
                return fromCache;
            }
        }
        catch (TimeoutException)
        {
            // The caller's mode determines the failure verdict; the reason is retained.
            return await CompleteAsync(
                    operation, policy, stopwatch, inspectionFailure, [], "inspection_timeout", auditAndCache, cancellationToken)
                .ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            // Cancelamento pedido por quem chamou não é falha de inspeção:
            // propaga em vez de virar veredito.
            throw;
        }
        catch (Exception ex)
        {
            // RN-012 — arquivo corrompido, extensão que mente sobre o formato,
            // falha de leitura. O tipo da exceção entra no motivo para permitir
            // diagnóstico depois; a mensagem não entra, porque pode conter
            // trecho do conteúdo do arquivo.
            return await CompleteAsync(
                    operation, policy, stopwatch, inspectionFailure, [],
                    $"parse_error:{ex.GetType().Name}", auditAndCache, cancellationToken)
                .ConfigureAwait(false);
        }

        // 7. RN-005 — um achado válido basta para negar.
        var verdict = findings.Count > 0 ? Verdict.Blocked : Verdict.Approved;

        // 8. Cache e auditoria.
        return await CompleteAsync(operation, policy, stopwatch, verdict, findings, null, auditAndCache, cancellationToken, fingerprint)
            .ConfigureAwait(false);
    }

    private async Task<(IReadOnlyList<Finding> Findings, string? Fingerprint, InspectionResult? Cached)> InspectWithBudgetAsync(
        ITextExtractor extractor, FileOperation operation, Policy policy, bool useCache, CancellationToken cancellationToken)
    {
        var budget = Stopwatch.StartNew();
        if (!await _inspectionSlots.WaitAsync(policy.InspectionTimeout, cancellationToken).ConfigureAwait(false))
            throw new TimeoutException("No inspection worker became available within the policy budget.");
        bool workerOwnsSlot = false;
        CancellationTokenSource? deadline = null;
        try
        {
            TimeSpan remaining = policy.InspectionTimeout - budget.Elapsed;
            if (remaining <= TimeSpan.Zero) throw new TimeoutException("The inspection budget was exhausted while waiting.");
            deadline = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            deadline.CancelAfter(remaining);
            var workerDeadline = deadline;
            var workerToken = workerDeadline.Token;
            // The delegate must run even if the caller cancels before it is
            // scheduled: its finally owns the slot and cancellation source.
            var inspection = Task.Run(async () =>
            {
                try
                {
                    return await ExtractAndScanAsync(extractor, operation, policy, useCache, workerToken)
                        .ConfigureAwait(false);
                }
                finally
                {
                    workerDeadline.Dispose();
                    _inspectionSlots.Release();
                }
            }, CancellationToken.None);
            workerOwnsSlot = true;
            // A caller can leave before a noncooperative parser faults. Observe
            // that fault without allowing its late result to reach cache/audit.
            _ = inspection.ContinueWith(static task => { _ = task.Exception; }, CancellationToken.None,
                TaskContinuationOptions.OnlyOnFaulted | TaskContinuationOptions.ExecuteSynchronously, TaskScheduler.Default);
            try
            {
                return await inspection.WaitAsync(remaining, cancellationToken).ConfigureAwait(false);
            }
            catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested && workerToken.IsCancellationRequested)
            {
                throw new TimeoutException("The inspection exceeded the policy budget.");
            }
        }
        finally
        {
            if (!workerOwnsSlot)
            {
                deadline?.Dispose();
                _inspectionSlots.Release();
            }
        }
    }

    /// <summary>
    /// RN-006 — o conteúdo é lido para memória, extraído, varrido e descartado
    /// no mesmo escopo. Não há arquivo temporário em nenhum caminho, nem no de
    /// erro: se a extração lançar, os bytes e o texto saem de escopo junto com
    /// a pilha e nada chegou a ser gravado.
    /// </summary>
    private async Task<(IReadOnlyList<Finding> Findings, string? Fingerprint, InspectionResult? Cached)> ExtractAndScanAsync(
        ITextExtractor extractor,
        FileOperation operation,
        Policy policy,
        bool useCache,
        CancellationToken cancellationToken)
    {
        byte[] bytes;
        // Keep the opened file's bytes stable while allowing an approved save
        // to replace its directory entry. A source classification triggered by
        // a reader must not transiently veto the publisher's final rename.
        await using (var input = new FileStream(operation.FilePath, FileMode.Open,
            FileAccess.Read, FileShare.Read | FileShare.Delete, 64 * 1024,
            FileOptions.Asynchronous | FileOptions.SequentialScan))
        {
            bytes = new byte[checked((int)input.Length)];
            await input.ReadExactlyAsync(bytes, cancellationToken).ConfigureAwait(false);
        }

        // Hash and scan the same in-memory bytes. Size and timestamps alone
        // can collide (or be restored), so they cannot authorize cache reuse.
        string? fingerprint = useCache ? Convert.ToHexString(SHA256.HashData(bytes)) : null;
        if (useCache && _cache.TryGet(operation, policy.Version, out var cached, fingerprint) && cached is not null)
            return (cached.Findings, fingerprint, cached);
        using var content = new MemoryStream(bytes, writable: false);
        var text = await extractor.ExtractAsync(content, cancellationToken).ConfigureAwait(false);

        // O que sai daqui já é só achado mascarado. O texto em claro não
        // atravessa esta fronteira.
        return (ContentScanner.Scan(text, policy.ActiveCategories), fingerprint, null);
    }

    private async Task<InspectionResult> CompleteAsync(
        FileOperation operation,
        Policy policy,
        Stopwatch stopwatch,
        Verdict verdict,
        IReadOnlyList<Finding> findings,
        string? reason,
        bool auditAndCache,
        CancellationToken cancellationToken,
        string? fingerprint = null)
    {
        stopwatch.Stop();

        var result = new InspectionResult(
            verdict,
            findings,
            reason,
            stopwatch.ElapsedMilliseconds,
            FromCache: false,
            policy.Version,
            InScope: true);

        if (auditAndCache)
        {
            if (fingerprint is not null && verdict is Verdict.Approved or Verdict.Blocked)
                _cache.Set(operation, result, fingerprint);
            await AuditAsync(operation, result, cancellationToken).ConfigureAwait(false);
        }

        return result;
    }

    /// <summary>
    /// Operação que a política não acompanha. Não gera evento de auditoria: a
    /// trilha registra o que o agente julgou, e anotar cada arquivo que ele
    /// deliberadamente ignora encheria a fila de ruído e afogaria os eventos
    /// que importam.
    /// </summary>
    private static InspectionResult OutOfScope(Stopwatch stopwatch, Policy policy, string reason)
    {
        stopwatch.Stop();

        return new InspectionResult(
            Verdict.AllowedWithoutInspection,
            [],
            reason,
            stopwatch.ElapsedMilliseconds,
            FromCache: false,
            policy.Version,
            InScope: false);
    }

    private async Task AuditAsync(
        FileOperation operation,
        InspectionResult result,
        CancellationToken cancellationToken,
        Guid? eventId = null,
        string? publishedSha256Hex = null)
    {
        var auditEvent = new AuditEvent(
            eventId ?? Guid.NewGuid(),
            DateTimeOffset.UtcNow,
            _endpointId,
            _userName,
            operation.FileName,
            operation.Extension,
            operation.SizeBytes,
            result.Verdict,
            result.Categories,
            result.Findings.Select(static f => f.MaskedSnippet).Distinct().ToList(),
            operation.ProcessName,
            operation.ProcessId,
            operation.DestinationPath,
            result.Reason,
            result.PolicyVersion,
            result.ElapsedMs,
            Dispatched: false,
            PublishedSha256Hex: publishedSha256Hex);

        try
        {
            await _auditSink.WriteAsync(auditEvent, cancellationToken).ConfigureAwait(false);
        }
        catch (Exception) when (!cancellationToken.IsCancellationRequested)
        {
            // Falha ao registrar não pode mudar o veredito nem derrubar a
            // operação do usuário. O evento se perde; a decisão vale.
        }
    }
}
