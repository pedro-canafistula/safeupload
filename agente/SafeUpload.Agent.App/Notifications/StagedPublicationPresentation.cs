namespace SafeUpload.Agent.App.Notifications;

internal static class StagedPublicationPresentation
{
    internal static string Busy(string fileName) =>
        $"{fileName}: o arquivo está aguardando envio porque outro programa está usando o destino. " +
        "Feche o programa e salve novamente. Esta versão continua guardada localmente.";
}
