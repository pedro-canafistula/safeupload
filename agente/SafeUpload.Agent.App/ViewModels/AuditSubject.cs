using SafeUpload.Agent.Core.Domain;

namespace SafeUpload.Agent.App.ViewModels;

/// <summary>
/// O "o quê" de um evento, para exibir.
///
/// No canal de arquivo é sempre o nome do arquivo. No canal web pode não haver
/// arquivo nenhum: o achado estava num texto digitado (um prompt, um campo de
/// formulário), e aí o que identifica o envio é o site de destino.
/// </summary>
public static class AuditSubject
{
    /// <summary>Nome do arquivo ou, para texto enviado pela web, o site.</summary>
    public static string Describe(AuditEvent auditEvent)
    {
        ArgumentNullException.ThrowIfNull(auditEvent);

        if (auditEvent.Channel != AuditChannel.Web)
        {
            return auditEvent.FileName;
        }

        string site = Site(auditEvent.DestinationPath);

        return string.IsNullOrEmpty(auditEvent.FileName)
            ? $"texto destinado a {site}"
            : $"{auditEvent.FileName} para {site}";
    }

    private static string Site(string destination) =>
        Uri.TryCreate(destination, UriKind.Absolute, out Uri? uri) ? uri.Host : destination;
}
