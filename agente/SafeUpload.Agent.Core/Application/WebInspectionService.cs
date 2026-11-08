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
    string? UserName = null,
    string? OwnerSid = null);

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
/// <param name="InspectionFailed">
/// Um arquivo de tipo vigiado não pôde ser inspecionado (não abriu, passou do tamanho ou do prazo). Bloqueia sempre,
/// como no canal de arquivo, inclusive em modo de auditoria.
/// </param>
public sealed record WebInspectionResult(
    IReadOnlyList<Finding> Findings,
    bool AuditOnly,
    int PolicyVersion,
    IReadOnlyList<WebAuditRecord> Records,
    bool InspectionFailed = false)
{
    /// <summary>Categorias distintas encontradas, na ordem em que apareceram.</summary>
    public IReadOnlyList<Category> Categories => Findings.Select(static f => f.Category).Distinct().ToList();

    /// <summary>Verdadeiro quando o envio deve ser negado (RN-005).</summary>
    public bool IsBlocked => InspectionFailed || (Findings.Count > 0 && !AuditOnly);
}

/// <summary>Um envio maior que o proxy consegue segurar: só o começo do corpo chega ao motor.</summary>
/// <param name="Upload">Destino, programa e dono; sem partes.</param>
/// <param name="FileNames">Nomes de arquivo declarados no cabeçalho ou nas partes do formulário que já chegaram.</param>
/// <param name="ContentType">Tipo declarado da requisição.</param>
/// <param name="Prefix">O começo do corpo.</param>
/// <param name="TotalBytes">Tamanho declarado; nulo quando o corpo vem em pedaços.</param>
public sealed record WebOversizedUpload(
    WebUpload Upload,
    IReadOnlyList<string> FileNames,
    string? ContentType,
    ReadOnlyMemory<byte> Prefix,
    long? TotalBytes);

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
///   2. texto digitado: todas as partes de texto juntas, na varredura de
///      texto escrito (<see cref="TypedTextScanner"/>)
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
/// Arquivos vigiados que não podem ser inspecionados são bloqueados com o
/// motivo registrado. O conteúdo não é gravado (RN-006): daqui só saem
/// achados mascarados.
/// </summary>
public sealed class WebInspectionService
{
    private readonly IPolicyStore _policyStore;
    private readonly IAuditSink _auditSink;
    private readonly ExtractorRegistry _extractors;
    private readonly string _endpointId;
    private readonly string _userName;
    private readonly TimeProvider _clock;
    private readonly Dictionary<string, long> _recentTextBlocks = new(StringComparer.Ordinal);
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

        // 2. Texto digitado. Não há formato a extrair, e a régua é a de
        // texto escrito por gente, mais estrita que a de documento: o tráfego
        // de uma página é cheio de telemetria (ver TypedTextScanner).
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
            var typed = text.ToString();
            IReadOnlyList<Finding> found = TypedTextScanner.Scan(typed, policy.ActiveCategories);
            if (policy.Rules.Rules.Count > 0) found = [.. found, .. policy.Rules.Scan(typed)];

            if (found.Count > 0)
            {
                findings.AddRange(found);

                // A decisão é preservada; só o registro repetido é agrupado.
                if (!IsRepeatedTextBlock(upload, found, policy))
                {
                    records.Add(await AuditAsync(
                            upload, policy, stopwatch, string.Empty, string.Empty, textBytes, Verdict.Blocked, found, null, cancellationToken)
                        .ConfigureAwait(false));
                }
            }
        }

        // 3. Arquivos, um a um.
        bool failed = false;

        foreach (var part in upload.Parts)
        {
            if (!part.IsFile)
            {
                continue;
            }

            string fileName = FileNameOnly(part.FileName);
            string? extension = ResolveMonitoredExtension(part, fileName, policy);

            // RN-011 — só o que a política manda vigiar. Uma foto enviada a uma
            // rede social não é julgada nem registrada.
            if (extension is null)
            {
                continue;
            }

            var (verdict, found, reason) = await InspectFileAsync(part, extension, policy, cancellationToken).ConfigureAwait(false);

            findings.AddRange(found);
            failed |= reason is not null;
            records.Add(await AuditAsync(
                    upload, policy, stopwatch, fileName, extension, part.Content.Length, verdict, found, reason, cancellationToken)
                .ConfigureAwait(false));
        }

        return new WebInspectionResult(findings,
            findings.Count == 0 ? policy.AuditOnly : policy.ReleasesWithAlert(findings.Select(static f => f.Category)),
            policy.Version, records, failed);
    }

    /// <summary>
    /// Julga um envio grande demais para o proxy segurar, pelo começo dele. Como no canal de arquivo: se é de um tipo
    /// que a política vigia (pelo nome do arquivo, pelo tipo declarado ou pelos primeiros bytes), bloqueia e registra
    /// (RN-013); se é de um tipo conhecido que a política não vigia, segue sem registro (RN-011); se não dá para saber o
    /// tipo, segue e fica registrado.
    /// </summary>
    public async Task<WebInspectionResult> InspectOversizedAsync(WebOversizedUpload oversized, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(oversized);

        var stopwatch = Stopwatch.StartNew();
        var policy = await LoadPolicyAsync(cancellationToken).ConfigureAwait(false);
        WebUpload upload = oversized.Upload;

        if (policy.IsExcludedProcess(upload.ProcessName))
        {
            return new WebInspectionResult([], policy.AuditOnly, policy.Version, []);
        }

        var extensions = oversized.FileNames.Select(static name => Path.GetExtension(name).ToLowerInvariant())
            .Where(static extension => extension.Length > 1).ToList();
        if (ExtensionOfMediaType(oversized.ContentType) is { } declared) extensions.Add(declared);
        if (ContentTypeSniffer.Sniff(oversized.Prefix) is { } sniffed) extensions.Add(sniffed);
        else if (oversized.Prefix.Span.StartsWith("PK\u0003\u0004"u8)) extensions.Add(".zip");

        string? monitored = extensions.FirstOrDefault(policy.IsMonitoredExtension);

        if (monitored is null && extensions.Count > 0)
        {
            return new WebInspectionResult([], policy.AuditOnly, policy.Version, []);
        }

        string fileName = oversized.FileNames.FirstOrDefault(name => policy.IsMonitoredExtension(Path.GetExtension(name)))
            ?? oversized.FileNames.FirstOrDefault() ?? string.Empty;
        var record = await AuditAsync(
                upload, policy, stopwatch, FileNameOnly(fileName), monitored ?? string.Empty,
                oversized.TotalBytes ?? oversized.Prefix.Length,
                monitored is null ? Verdict.AllowedWithoutInspection : Verdict.Blocked, [], "file_too_large", cancellationToken)
            .ConfigureAwait(false);

        return new WebInspectionResult([], policy.AuditOnly, policy.Version, [record], InspectionFailed: monitored is not null);
    }

    /// <summary>
    /// Registra um envio que seguiu sem inspeção por um erro interno (corpo que não foi possível separar, falha do
    /// motor). O envio não é barrado, mas fica na auditoria com o tipo do erro.
    /// </summary>
    public async Task<WebInspectionResult> RecordErrorAsync(WebUpload upload, long sizeBytes, string reason, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(upload);

        var stopwatch = Stopwatch.StartNew();
        var policy = await LoadPolicyAsync(cancellationToken).ConfigureAwait(false);
        var record = await AuditAsync(
                upload, policy, stopwatch, string.Empty, string.Empty, sizeBytes, Verdict.AllowedWithoutInspection, [], reason,
                cancellationToken)
            .ConfigureAwait(false);

        return new WebInspectionResult([], policy.AuditOnly, policy.Version, [record]);
    }

    /// <summary>Extensão dos tipos declarados mais comuns de documento; nulo para os demais.</summary>
    private static string? ExtensionOfMediaType(string? contentType)
    {
        string type = (contentType ?? string.Empty).Split(';')[0].Trim().ToLowerInvariant();

        return type switch
        {
            "application/pdf" => ".pdf",
            "application/zip" or "application/x-zip-compressed" => ".zip",
            "text/csv" => ".csv",
            "text/plain" => ".txt",
            "application/msword" => ".doc",
            "application/vnd.ms-excel" => ".xls",
            "application/vnd.openxmlformats-officedocument.wordprocessingml.document" => ".docx",
            "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet" => ".xlsx",
            "application/vnd.openxmlformats-officedocument.presentationml.presentation" => ".pptx",
            _ => null,
        };
    }

    /// <summary>
    /// Intervalo em que o mesmo achado em texto, do mesmo programa para o
    /// mesmo site, não gera evento novo.
    /// </summary>
    public TimeSpan RepeatWindow { get; init; } = TimeSpan.FromSeconds(60);

    /// <summary>
    /// Se este bloqueio de texto repete um já registrado há pouco. A chave é
    /// programa, site (sem o caminho: o texto digitado sai por endereços
    /// diferentes do mesmo site), política efetiva e trechos mascarados encontrados.
    /// </summary>
    private bool IsRepeatedTextBlock(WebUpload upload, IReadOnlyList<Finding> found, Policy policy)
    {
        string site = Uri.TryCreate(upload.Destination, UriKind.Absolute, out Uri? uri) ? uri.Host : upload.Destination;
        string key = string.Join(
            '|',
            policy.EvaluationKey,
            upload.ProcessId.ToString(System.Globalization.CultureInfo.InvariantCulture),
            site,
            string.Join(',', found.Select(static f => $"{f.Category}:{f.MaskedSnippet}").Distinct().Order(StringComparer.Ordinal)));

        long now = _clock.GetTimestamp();

        lock (_repeatGate)
        {
            if (_recentTextBlocks.TryGetValue(key, out var last) && _clock.GetElapsedTime(last, now) < RepeatWindow)
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
        long now = _clock.GetTimestamp();

        if (_policy is { } cached && _clock.GetElapsedTime(cached.LoadedAt, now) < PolicyLifetime)
        {
            return cached.Policy;
        }

        // Duas requisições simultâneas podem carregar duas vezes; não faz mal.
        var policy = await _policyStore.LoadAsync(cancellationToken).ConfigureAwait(false);
        _policy = new CachedPolicy(policy, now);
        return policy;
    }

    /// <summary>
    /// Extensão usada para inspecionar o arquivo, ou nulo se estiver fora do escopo.
    /// Uma assinatura reconhecida tem prioridade. A heurística de texto pode
    /// mudar o extrator sem retirar do escopo um nome de arquivo vigiado.
    /// </summary>
    private string? ResolveMonitoredExtension(WebUploadPart part, string fileName, Policy policy)
    {
        if (ContentTypeSniffer.Sniff(part.Content) is { } sniffed)
        {
            return policy.IsMonitoredExtension(sniffed) ? sniffed : null;
        }

        string named = Path.GetExtension(fileName).ToLowerInvariant();
        bool nameInScope = policy.IsMonitoredExtension(named);
        if (ContentTypeSniffer.LooksLikeText(part.Content.Span) && _extractors.Resolve(named) is not PlainTextExtractor)
        {
            return nameInScope || policy.IsMonitoredExtension(".txt") ? ".txt" : null;
        }

        return nameInScope ? named : null;
    }

    private async Task<(Verdict Verdict, IReadOnlyList<Finding> Findings, string? Reason)> InspectFileAsync(
        WebUploadPart part, string extension, Policy policy, CancellationToken cancellationToken)
    {
        // RN-013 — como no canal de arquivo, o que não pode ser inspecionado não sai: acima do limite da política,
        // formato sem extrator, prazo esgotado ou arquivo que não abre bloqueiam, com o motivo registrado.
        if (part.Content.Length > policy.MaxFileSizeBytes)
        {
            return (Verdict.Blocked, [], "file_too_large");
        }

        var extractor = _extractors.Resolve(extension);

        if (extractor is null)
        {
            return (Verdict.Blocked, [], "unsupported_format");
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
                    return ContentScanner.Scan(extracted, policy.ActiveCategories, policy.Rules);
                },
                cancellationToken);

            var found = await inspection.WaitAsync(policy.InspectionTimeout, cancellationToken).ConfigureAwait(false);
            return (found.Count > 0 ? Verdict.Blocked : Verdict.Approved, found, null);
        }
        catch (TimeoutException)
        {
            return (Verdict.Blocked, [], "inspection_timeout");
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception ex)
        {
            // Só o tipo da exceção: a mensagem pode trazer trecho do conteúdo.
            return (Verdict.Blocked, [], $"parse_error:{ex.GetType().Name}");
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
        // The queue describes the operation that happened, while findings retain
        // what enforcement would have blocked. This also keeps the tray and panel
        // from showing an audit-only release as a real block.
        // An inspection failure has no findings and blocks even in audit mode, as on the file channel.
        if (verdict == Verdict.Blocked && findings.Count > 0 &&
            (policy.AuditOnly || policy.ReleasesWithAlert(findings.Select(static f => f.Category))))
            verdict = Verdict.Approved;
        var auditEvent = new AuditEvent(
            Guid.NewGuid(),
            DateTimeOffset.UtcNow,
            _endpointId,
            string.IsNullOrWhiteSpace(upload.UserName) ? _userName : upload.UserName,
            AuditTextPrivacy.Sanitize(fileName),
            AuditTextPrivacy.Sanitize(extension),
            sizeBytes,
            verdict,
            findings.Select(static f => f.Category).Distinct().ToList(),
            findings.Select(static f => f.MaskedSnippet).Distinct().ToList(),
            AuditTextPrivacy.Sanitize(upload.ProcessName),
            upload.ProcessId,
            AuditTextPrivacy.Sanitize(AuditMetadata.WebOrigin(upload.Destination)),
            reason,
            policy.Version,
            stopwatch.ElapsedMilliseconds,
            Dispatched: false,
            Channel: AuditChannel.Web) { OwnerSid = upload.OwnerSid, CustomRules = AuditEvent.RuleNames(findings) };

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
        => AuditMetadata.FileNameOnly(fileName);

    private sealed record CachedPolicy(Policy Policy, long LoadedAt);
}
