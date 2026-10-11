using System.Diagnostics;
using SafeUpload.Agent.Core.Application;
using SafeUpload.Agent.Network.Inspection;
using SafeUpload.Agent.Network.Proxy;

namespace SafeUpload.Agent.Service.Network;

/// <summary>
/// Liga o proxy ao motor de inspeção (Fase 5 do plano).
///
/// O proxy entrega a requisição com o corpo inteiro e espera "pode sair?".
/// Aqui o corpo é desmontado em partes (<see cref="UploadBodyParser"/>), as
/// partes vão para o <see cref="WebInspectionService"/> e o resultado vira a
/// resposta ao proxy: libera, ou barra com as categorias encontradas.
///
/// O proxy não conhece o Core e o Core não conhece HTTP; esta classe é o único
/// ponto que conhece os dois. Nada do conteúdo é registrado (RN-006): o log
/// tem site, caminho sem query string, tamanhos, categorias e processo.
/// </summary>
public sealed class WebUploadInspector(WebInspectionService inspection, ILogger<WebUploadInspector> logger) : IUploadInspector
{
    /// <inheritdoc />
    public async ValueTask<UploadDecision> InspectAsync(UploadRequest request, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(request);

        IReadOnlyList<UploadPart> parts = UploadBodyParser.Parse(request.Head, request.Body);

        if (parts.Count == 0)
        {
            return UploadDecision.Allow;
        }

        string destination = Destination(request);
        string processName = ProcessName(request.ProcessId);

        WebInspectionResult result = await inspection
            .InspectAsync(
                new WebUpload(
                    destination,
                    processName,
                    request.ProcessId ?? 0,
                    [.. parts.Select(part => new WebUploadPart(part.FileName, part.Content, part.Kind == UploadPartKind.File))]),
                cancellationToken)
            .ConfigureAwait(false);

        if (result.Findings.Count == 0)
        {
            logger.LogDebug(
                "Envio liberado: {Method} {Destination} ({Bytes} bytes, {Parts} partes) por {Process}.",
                request.Head.Method, destination, request.Body.Length, parts.Count, processName);

            return UploadDecision.Allow;
        }

        string categories = string.Join(", ", result.Categories);

        if (!result.IsBlocked)
        {
            logger.LogInformation(
                "Envio com dado sensível liberado pelo modo de auditoria: {Method} {Destination}, categorias [{Categories}], por {Process}.",
                request.Head.Method, destination, categories, processName);

            return UploadDecision.Allow;
        }

        logger.LogInformation(
            "Envio bloqueado: {Method} {Destination}, categorias [{Categories}], por {Process}.",
            request.Head.Method, destination, categories, processName);

        return UploadDecision.Block($"Dados sensíveis encontrados: {categories}.");
    }

    /// <summary>
    /// Esquema, site e caminho. Sem a query string, que pode carregar tokens
    /// de sessão e dados do usuário.
    /// </summary>
    private static string Destination(UploadRequest request)
    {
        string target = request.Head.Target;
        int query = target.IndexOf('?');
        string path = query < 0 ? target : target[..query];
        string scheme = request.Encrypted ? "https" : "http";
        bool defaultPort = request.Port == (request.Encrypted ? 443 : 80);

        return defaultPort ? $"{scheme}://{request.Host}{path}" : $"{scheme}://{request.Host}:{request.Port}{path}";
    }

    private static string ProcessName(int? processId)
    {
        if (processId is not { } pid)
        {
            return "desconhecido";
        }

        try
        {
            using var process = Process.GetProcessById(pid);
            return process.ProcessName;
        }
        catch (Exception ex) when (ex is ArgumentException or InvalidOperationException)
        {
            return "desconhecido";
        }
    }
}
