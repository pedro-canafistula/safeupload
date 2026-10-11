using System.Diagnostics;
using System.Text;
using SafeUpload.Agent.Core.Domain;
using SafeUpload.Agent.Core.Infrastructure.Extraction;

namespace SafeUpload.Agent.Core.Application;

/// <summary>Uma parte do que o navegador está enviando.</summary>
/// <param name="FileName">Nome do arquivo, quando o site informou.</param>
/// <param name="Content">Os bytes, já sem codificação de transporte.</param>
/// <param name="IsFile">Arquivo (verdadeiro) ou texto digitado (falso).</param>
public sealed record WebUploadPart(string? FileName, ReadOnlyMemory<byte> Content, bool IsFile);

/// <summary>Um envio pela web, visto pelo proxy de inspeção.</summary>
/// <param name="Destination">Para onde vai: esquema, site e caminho, sem a query string.</param>
/// <param name="ProcessName">Programa que enviou (o navegador).</param>
/// <param name="ProcessId">PID desse programa.</param>
/// <param name="Parts">O que está sendo enviado.</param>
/// <param name="UserName">
/// Dono do programa que enviou. O serviço roda como SYSTEM, então sem isto o
/// evento sairia em nome da conta do serviço. Nulo quando não foi possível
/// descobrir.
/// </param>
public sealed record WebUpload(
    string Destination,
    string ProcessName,
    int ProcessId,
    IReadOnlyList<WebUploadPart> Parts,
    string? UserName = null);

/// <summary>Um evento de auditoria gravado para o envio, com os achados dele.</summary>
/// <param name="Event">O evento, como foi para a fila.</param>
/// <param name="Findings">Achados mascarados que o motivaram; vazio quando não há.</param>
public sealed record WebAuditRecord(AuditEvent Event, IReadOnlyList<Finding> Findings);

/// <summary>O que o motor concluiu sobre um envio pela web.</summary>
/// <param name="Findings">Achados mascarados de todas as partes.</param>
/// <param name="AuditOnly">A política está em modo de auditoria: registra, mas não nega.</param>
/// <param name="PolicyVersion">Versão da política aplicada.</param>
/// <param name="Records">
/// Eventos de auditoria gravados para este envio. É o que o serviço anuncia ao
/// aplicativo de bandeja. Pode estar vazio mesmo com achados: bloqueio
/// repetido não gera evento novo.
/// </param>
public sealed record WebInspectionResult(
    IReadOnlyList<Finding> Findings,
    bool AuditOnly,
    int PolicyVersion,
    IReadOnlyList<WebAuditRecord> Records)
{
    /// <summary>Categorias distintas encontradas, na ordem em que apareceram.</summary>
    public IReadOnlyList<Category> Categories => Findings.Select(static f => f.Category).Distinct().ToList();

    /// <summary>Verdadeiro quando o envio deve ser negado (RN-005).</summary>
    public bool IsBlocked => Findings.Count > 0 && !AuditOnly;
}

/// <summary>
/// O motor de inspeção para o canal web (Fase 5 da inspeção TLS).
///
/// É o mesmo trabalho do <see cref="InspectionService"/>, com a mesma
/// política, os mesmos extratores e a mesma varredura, mas com outra entrada:
/// lá o conteúdo é um arquivo no disco; aqui são bytes que o proxy segurou em
/// memória, e uma requisição pode trazer várias partes (três arquivos e dois
/// campos de texto no mesmo formulário).
///
/// Para cada envio:
///
///   1. processo excluído                              RN-014
///   2. texto digitado: todas as partes de texto juntas, direto na varredura
///   3. cada arquivo: formato pelos bytes, extensão em escopo (RN-011),
///      tamanho (RN-013), extração e varredura com prazo (RN-012)
///   4. veredito: qualquer achado bloqueia o envio inteiro (RN-005)
///
/// O que vira evento de auditoria: todo arquivo julgado, como no canal de
/// arquivo, e o texto <b>só quando tem achado</b>. Uma página comum faz
/// dezenas de POST pequenos por minuto; registrar cada um afogaria a trilha.
/// Pelo mesmo motivo, o mesmo achado em texto, do mesmo programa para o mesmo
/// site, vira um evento só dentro de <see cref="RepeatWindow"/>: há sites que
/// enviam o texto a cada tecla, e cada envio é bloqueado.
///
/// Fail-open como o resto do agente: tamanho, formato, prazo e erro de
/// leitura liberam com o motivo registrado, nunca bloqueiam. E o conteúdo não
/// é gravado em lugar nenhum (RN-006): daqui só saem achados mascarados.
/// </summary>
public sealed class WebInspectionService
{
    private readonly IPolicyStore _policyStore;
    private readonly IAuditSink _auditSink;
    private readonly ExtractorRegistry _extractors;
    private readonly string _endpointId;
    private readonly string _userName;
    private readonly TimeProvider _clock;
    private readonly Dictionary<string, DateTimeOffset> _recentTextBlocks = new(StringComparer.Ordinal);
    private readonly Lock _repeatGate = new();
    private CachedPolicy? _policy;

    /// <summary>Compõe o motor com suas dependências.</summary>
    public WebInspectionService(
        IPolicyStore policyStore,
        IAuditSink auditSink,
        ExtractorRegistry extractors,
        string? endpointId = null,
        string? userName = null,
        TimeProvider? clock = null)
    {
        _clock = clock ?? TimeProvider.System;
        _policyStore = policyStore ?? throw new ArgumentNullException(nameof(policyStore));
        _auditSink = auditSink ?? throw new ArgumentNullException(nameof(auditSink));
        _extractors = extractors ?? throw new ArgumentNullException(nameof(extractors));
        _endpointId = endpointId ?? Environment.MachineName;
        _userName = userName ?? Environment.UserName;
    }

    /// <summary>Julga um envio.</summary>
    public async Task<WebInspectionResult> InspectAsync(WebUpload upload, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(upload);

        var stopwatch = Stopwatch.StartNew();
        var policy = await LoadPolicyAsync(cancellationToken).ConfigureAwait(false);
        var findings = new List<Finding>();
        var records = new List<WebAuditRecord>();

        // 1. RN-014 — processo excluído nunca é julgado.
        if (policy.IsExcludedProcess(upload.ProcessName))
        {
            return new WebInspectionResult(findings, policy.AuditOnly, policy.Version, records);
        }

        // 2. Texto digitado. Vai direto para a varredura: não há formato a extrair.
        var text = new StringBuilder();
        long textBytes = 0;

        foreach (var part in upload.Parts)
        {
            if (!part.IsFile && textBytes + part.Content.Length <= policy.MaxFileSizeBytes)
            {
                text.Append(Encoding.UTF8.GetString(part.Content.Span)).Append('\n');
                textBytes += part.Content.Length;
            }
        }

        if (text.Length > 0)
        {
            var found = ContentScanner.Scan(text.ToString(), policy.ActiveCategories);

            if (found.Count > 0)
            {
                findings.AddRange(found);

                // O envio é barrado de qualquer jeito; só o registro é que não
                // se repete.
                if (!IsRepeatedTextBlock(upload, found))
                {
                    records.Add(await AuditAsync(
                            upload, policy, stopwatch, string.Empty, string.Empty, textBytes, Verdict.Blocked, found, null, cancellationToken)
                        .ConfigureAwait(false));
                }
            }
        }

        // 3. Arquivos, um a um.
        foreach (var part in upload.Parts)
        {
            if (!part.IsFile)
            {
                continue;
            }

            string extension = ResolveExtension(part);

            // RN-011 — só o que a política manda vigiar. Uma foto enviada a uma
            // rede social não é julgada nem registrada.
            if (!policy.IsMonitoredExtension(extension))
            {
                continue;
            }

            var (verdict, found, reason) = await InspectFileAsync(part, extension, policy, cancellationToken).ConfigureAwait(false);

            findings.AddRange(found);
            records.Add(await AuditAsync(
                    upload, policy, stopwatch, FileNameOnly(part.FileName), extension, part.Content.Length, verdict, found, reason, cancellationToken)
                .ConfigureAwait(false));
        }

        return new WebInspectionResult(findings, policy.AuditOnly, policy.Version, records);
    }

    /// <summary>
    /// Intervalo em que o mesmo achado em texto, do mesmo programa para o
    /// mesmo site, não gera evento novo.
    /// </summary>
    public TimeSpan RepeatWindow { get; init; } = TimeSpan.FromSeconds(60);

    /// <summary>
    /// Se este bloqueio de texto repete um já registrado há pouco. A chave é
    /// programa, site (sem o caminho: o texto digitado sai por endereços
    /// diferentes do mesmo site) e os trechos mascarados encontrados.
    /// </summary>
    private bool IsRepeatedTextBlock(WebUpload upload, IReadOnlyList<Finding> found)
    {
        string site = Uri.TryCreate(upload.Destination, UriKind.Absolute, out Uri? uri) ? uri.Host : upload.Destination;
        string key = string.Join(
            '|',
            upload.ProcessId.ToString(System.Globalization.CultureInfo.InvariantCulture),
            site,
            string.Join(',', found.Select(static f => $"{f.Category}:{f.MaskedSnippet}").Distinct().Order(StringComparer.Ordinal)));

        var now = _clock.GetUtcNow();

        lock (_repeatGate)
        {
            if (_recentTextBlocks.TryGetValue(key, out var last) && now - last < RepeatWindow)
            {
                return true;
            }

            if (_recentTextBlocks.Count >= 1024)
            {
                _recentTextBlocks.Clear();
            }

            _recentTextBlocks[key] = now;
            return false;
        }
    }

    /// <summary>
    /// Por quanto tempo a política carregada é reaproveitada.
    ///
    /// Carregar a política é ler um arquivo ou, com o painel configurado, uma
    /// chamada HTTP que pode levar segundos quando o painel está fora do ar. No
    /// canal de arquivo isso acontece uma vez por arquivo copiado. Aqui
    /// aconteceria a cada POST de cada página, e o navegador ficaria esperando.
    /// O preço é uma política nova demorar até este intervalo para valer na web.
    /// </summary>
    public TimeSpan PolicyLifetime { get; init; } = TimeSpan.FromSeconds(30);

    private async Task<Policy> LoadPolicyAsync(CancellationToken cancellationToken)
    {
        var now = _clock.GetUtcNow();

        if (_policy is { } cached && cached.ExpiresAt > now)
        {
            return cached.Policy;
        }

        // Duas requisições simultâneas podem carregar duas vezes; não faz mal.
        var policy = await _policyStore.LoadAsync(cancellationToken).ConfigureAwait(false);
        _policy = new CachedPolicy(policy, now + PolicyLifetime);
        return policy;
    }

    /// <summary>
    /// O formato do arquivo. Os bytes mandam; o nome só vale quando eles não
    /// dizem nada (texto e csv não têm assinatura).
    /// </summary>
    private string ResolveExtension(WebUploadPart part)
    {
        if (ContentTypeSniffer.Sniff(part.Content) is { } sniffed)
        {
            return sniffed;
        }

        string named = Path.GetExtension(FileNameOnly(part.FileName)).ToLowerInvariant();
        bool text = ContentTypeSniffer.LooksLikeText(part.Content.Span);

        // Nome de formato com assinatura (.pdf, .docx) sem a assinatura nos
        // bytes: o nome está errado, e o conteúdo é julgado pelo que parece.
        if (text && !(_extractors.Resolve(named) is PlainTextExtractor))
        {
            return ".txt";
        }

        return named;
    }

    private async Task<(Verdict Verdict, IReadOnlyList<Finding> Findings, string? Reason)> InspectFileAsync(
        WebUploadPart part, string extension, Policy policy, CancellationToken cancellationToken)
    {
        // RN-013 — acima do limite, libera sem inspecionar.
        if (part.Content.Length > policy.MaxFileSizeBytes)
        {
            return (Verdict.AllowedWithoutInspection, [], "file_too_large");
        }

        // RN-013 — formato sem extrator, idem.
        var extractor = _extractors.Resolve(extension);

        if (extractor is null)
        {
            return (Verdict.AllowedWithoutInspection, [], "unsupported_format");
        }

        try
        {
            // Como no canal de arquivo: a análise roda numa tarefa e o prazo é
            // contado por fora, porque um extrator preso não devolve o controle.
            var inspection = Task.Run(
                async () =>
                {
                    using var content = ContentTypeSniffer.AsStream(part.Content);
                    string extracted = await extractor.ExtractAsync(content, cancellationToken).ConfigureAwait(false);
                    return ContentScanner.Scan(extracted, policy.ActiveCategories);
                },
                cancellationToken);

            var found = await inspection.WaitAsync(policy.InspectionTimeout, cancellationToken).ConfigureAwait(false);
            return (found.Count > 0 ? Verdict.Blocked : Verdict.Approved, found, null);
        }
        catch (TimeoutException)
        {
            return (Verdict.AllowedWithoutInspection, [], "inspection_timeout");
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception ex)
        {
            // Só o tipo da exceção: a mensagem pode trazer trecho do conteúdo.
            return (Verdict.AllowedWithoutInspection, [], $"parse_error:{ex.GetType().Name}");
        }
    }

    private async Task<WebAuditRecord> AuditAsync(
        WebUpload upload,
        Policy policy,
        Stopwatch stopwatch,
        string fileName,
        string extension,
        long sizeBytes,
        Verdict verdict,
        IReadOnlyList<Finding> findings,
        string? reason,
        CancellationToken cancellationToken)
    {
        var auditEvent = new AuditEvent(
            Guid.NewGuid(),
            DateTimeOffset.UtcNow,
            _endpointId,
            string.IsNullOrWhiteSpace(upload.UserName) ? _userName : upload.UserName,
            fileName,
            extension,
            sizeBytes,
            verdict,
            findings.Select(static f => f.Category).Distinct().ToList(),
            findings.Select(static f => f.MaskedSnippet).Distinct().ToList(),
            upload.ProcessName,
            upload.ProcessId,
            upload.Destination,
            reason,
            policy.Version,
            stopwatch.ElapsedMilliseconds,
            Dispatched: false,
            Channel: AuditChannel.Web);

        try
        {
            await _auditSink.WriteAsync(auditEvent, cancellationToken).ConfigureAwait(false);
        }
        catch (Exception) when (!cancellationToken.IsCancellationRequested)
        {
            // Falha ao registrar não muda o veredito nem derruba o envio.
        }

        return new WebAuditRecord(auditEvent, findings);
    }

    /// <summary>Só o nome: o site pode mandar um caminho inteiro em "filename".</summary>
    private static string FileNameOnly(string? fileName)
    {
        if (string.IsNullOrWhiteSpace(fileName))
        {
            return string.Empty;
        }

        int slash = fileName.LastIndexOfAny(['/', '\\']);
        return slash < 0 ? fileName : fileName[(slash + 1)..];
    }

    private sealed record CachedPolicy(Policy Policy, DateTimeOffset ExpiresAt);
}
