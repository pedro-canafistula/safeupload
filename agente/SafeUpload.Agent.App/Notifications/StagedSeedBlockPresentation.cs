using SafeUpload.Agent.Core.Contracts;

namespace SafeUpload.Agent.App.Notifications;

internal static class StagedSeedBlockPresentation
{
    internal const string Explanation = "As permissões disponíveis não permitem devolver o conteúdo anterior deste arquivo. " +
        "Esta versão permanece privada no SafeUpload e não foi enviada ao destino. Não é possível justificar o envio desta versão.";

    internal static TransferNotification ForDisplay(TransferNotification notice) =>
        notice.BlockReason == StagedBlockReason.SeedExportRestricted
            ? notice with { OverrideAllowed = false, HandbackPath = null, HandbackVerified = false }
            : notice;
}
