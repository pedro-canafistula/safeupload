using System.Diagnostics;
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
///   3. acerto de cache
///   4. arquivo grande demais                RN-013
///   5. formato não suportado                RN-013
///   6. extração e varredura com prazo       RN-012
///   7. veredito                             RN-005
///   8. cache e auditoria
///
/// Fail-open é a propriedade central: nenhum caminho de erro deste tipo produz
/// bloqueio. Timeout, arquivo corrompido, formato inesperado, falha de leitura
/// — todos terminam em AllowedWithoutInspection com o motivo registrado. Um DLP
/// que bloqueia quando quebra impede o usuário de trabalhar e é desligado na
/// primeira semana.
/// </summary>
public sealed class InspectionService
{
    private readonly IPolicyStore _policyStore;
    private readonly IAuditSink _auditSink;
    private readonly ExtractorRegistry _extractors;
    private readonly VerdictCache _cache;
    private readonly string _endpointId;
    private readonly string _userName;

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
    {
        ArgumentNullException.ThrowIfNull(operation);

        var stopwatch = Stopwatch.StartNew();
        var policy = await _policyStore.LoadAsync(cancellationToken).ConfigureAwait(false);

        // 1. RN-014 — o próprio agente e os processos de sistema jamais são
        // interceptados. Além do ruído, deixar o agente se interceptar criaria
        // recursão: ler o arquivo dispararia outra inspeção, que leria de novo.
        if (policy.IsExcludedProcess(operation.ProcessName))
        {
            return OutOfScope(stopwatch, policy, "excluded_process");
        }

        // 2. RN-011 — fora do escopo declarado não se inspeciona nada.
        if (!policy.IsMonitoredDestination(operation) || !policy.IsMonitoredExtension(operation.Extension))
        {
            return OutOfScope(stopwatch, policy, "out_of_scope");
        }

        // 3. Cache. A versão da política faz parte da validade da entrada.
        if (_cache.TryGet(operation, policy.Version, out var cached) && cached is not null)
        {
            stopwatch.Stop();

            var fromCache = cached with
            {
                ElapsedMs = stopwatch.ElapsedMilliseconds,
                FromCache = true
            };

            await AuditAsync(operation, fromCache, cancellationToken).ConfigureAwait(false);
            return fromCache;
        }

        // 4. RN-013 — acima do limite, libera sem inspecionar. Nunca bloqueia.
        if (operation.SizeBytes > policy.MaxFileSizeBytes)
        {
            return await CompleteAsync(
                    operation, policy, stopwatch, Verdict.AllowedWithoutInspection, [], "file_too_large", cancellationToken)
                .ConfigureAwait(false);
        }

        // 5. RN-013 — sem extrator para a extensão, não há o que varrer.
        var extractor = _extractors.Resolve(operation.Extension);
        if (extractor is null)
        {
            return await CompleteAsync(
                    operation, policy, stopwatch, Verdict.AllowedWithoutInspection, [], "unsupported_format", cancellationToken)
                .ConfigureAwait(false);
        }

        // 6. Extração e varredura com prazo (RN-012).
        IReadOnlyList<Finding> findings;

        try
        {
            // A leitura e o parsing são síncronos por natureza; jogá-los numa
            // tarefa de fundo é o que permite ao WaitAsync devolver o controle
            // no prazo mesmo que a análise continue presa. O trabalho abandonado
            // morre sozinho, porque não escreve nada em lugar nenhum.
            var inspection = Task.Run(
                () => ExtractAndScanAsync(extractor, operation, policy, cancellationToken),
                cancellationToken);

            findings = await inspection.WaitAsync(policy.InspectionTimeout, cancellationToken).ConfigureAwait(false);
        }
        catch (TimeoutException)
        {
            // RN-012 — estourou o prazo. Libera e audita o motivo.
            return await CompleteAsync(
                    operation, policy, stopwatch, Verdict.AllowedWithoutInspection, [], "inspection_timeout", cancellationToken)
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
                    operation, policy, stopwatch, Verdict.AllowedWithoutInspection, [],
                    $"parse_error:{ex.GetType().Name}", cancellationToken)
                .ConfigureAwait(false);
        }

        // 7. RN-005 — um achado válido basta para negar.
        var verdict = findings.Count > 0 ? Verdict.Blocked : Verdict.Approved;

        // 8. Cache e auditoria.
        return await CompleteAsync(operation, policy, stopwatch, verdict, findings, null, cancellationToken)
            .ConfigureAwait(false);
    }

    /// <summary>
    /// RN-006 — o conteúdo é lido para memória, extraído, varrido e descartado
    /// no mesmo escopo. Não há arquivo temporário em nenhum caminho, nem no de
    /// erro: se a extração lançar, os bytes e o texto saem de escopo junto com
    /// a pilha e nada chegou a ser gravado.
    /// </summary>
    private static async Task<IReadOnlyList<Finding>> ExtractAndScanAsync(
        ITextExtractor extractor,
        FileOperation operation,
        Policy policy,
        CancellationToken cancellationToken)
    {
        var bytes = await File.ReadAllBytesAsync(operation.FilePath, cancellationToken).ConfigureAwait(false);

        using var content = new MemoryStream(bytes, writable: false);
        var text = await extractor.ExtractAsync(content, cancellationToken).ConfigureAwait(false);

        // O que sai daqui já é só achado mascarado. O texto em claro não
        // atravessa esta fronteira.
        return ContentScanner.Scan(text, policy.ActiveCategories);
    }

    private async Task<InspectionResult> CompleteAsync(
        FileOperation operation,
        Policy policy,
        Stopwatch stopwatch,
        Verdict verdict,
        IReadOnlyList<Finding> findings,
        string? reason,
        CancellationToken cancellationToken)
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

        _cache.Set(operation, result);
        await AuditAsync(operation, result, cancellationToken).ConfigureAwait(false);

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
        CancellationToken cancellationToken)
    {
        var auditEvent = new AuditEvent(
            Guid.NewGuid(),
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
            Dispatched: false);

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
