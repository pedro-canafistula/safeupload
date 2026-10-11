using System.Diagnostics;
using System.Security.Principal;
using SafeUpload.Agent.Core.Application;
using SafeUpload.Agent.Core.Contracts;
using SafeUpload.Agent.Network.Inspection;
using SafeUpload.Agent.Network.Proxy;
using SafeUpload.Agent.Service.Notifications;

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
///
/// Também é daqui que sai o aviso ao usuário (Fase 6). O proxy só enxerga um
/// PID; pelo token desse processo o serviço descobre de quem é o navegador e
/// em que sessão do Windows ele está. O nome vai para o evento de auditoria, e
/// a notificação é entregue só ao aplicativo de bandeja daquele usuário,
/// naquela sessão.
/// </summary>
public sealed class WebUploadInspector(
    WebInspectionService inspection,
    ILogger<WebUploadInspector> logger,
    NotificationHub? hub = null) : IUploadInspector
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
        SessionResolver.ProcessIdentity? owner = OwnerOf(request.ProcessId);

        WebInspectionResult result = await inspection
            .InspectAsync(
                new WebUpload(
                    destination,
                    processName,
                    request.ProcessId ?? 0,
                    [.. parts.Select(part => new WebUploadPart(part.FileName, part.Content, part.Kind == UploadPartKind.File))],
                    UserNameOf(owner)),
                cancellationToken)
            .ConfigureAwait(false);

        Announce(result, owner);

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

    /// <summary>
    /// Anuncia os eventos ao aplicativo de bandeja do dono do navegador. Sem
    /// saber quem é o dono, não anuncia a ninguém: difundir para todas as
    /// sessões mostraria a um usuário o que outro tentou enviar.
    /// </summary>
    private void Announce(WebInspectionResult result, SessionResolver.ProcessIdentity? owner)
    {
        if (hub is null || owner is null)
        {
            return;
        }

        foreach (WebAuditRecord record in result.Records)
        {
            try
            {
                hub.Publish(new EventNotification(record.Event, record.Findings), owner.SessionId, owner.UserSid.Value);
            }
            catch (Exception ex)
            {
                // Falhar em avisar não muda o veredito.
                logger.LogWarning(ex, "Falha ao publicar a notificação do envio para {Destination}.", record.Event.DestinationPath);
            }
        }
    }

    /// <summary>Sessão e usuário do processo, pelo token dele.</summary>
    private static SessionResolver.ProcessIdentity? OwnerOf(int? processId)
    {
        if (processId is not { } pid || pid <= 0)
        {
            return null;
        }

        try
        {
            return SessionResolver.GetRequiredProcessIdentity(pid);
        }
        catch (Exception ex) when (ex is IOException or ArgumentException or InvalidOperationException)
        {
            return null;
        }
    }

    /// <summary>Nome de usuário, sem o domínio, como no canal de arquivo.</summary>
    private static string? UserNameOf(SessionResolver.ProcessIdentity? owner)
    {
        if (owner is null)
        {
            return null;
        }

        try
        {
            string account = owner.UserSid.Translate(typeof(NTAccount)).Value;
            int separator = account.LastIndexOf('\\');
            return separator < 0 ? account : account[(separator + 1)..];
        }
        catch (SystemException)
        {
            // SID sem conta correspondente (perfil removido, domínio fora do ar).
            return null;
        }
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
