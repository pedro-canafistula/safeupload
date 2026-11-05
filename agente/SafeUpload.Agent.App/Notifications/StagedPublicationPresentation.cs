using SafeUpload.Agent.Core.Contracts;
using SafeUpload.Agent.Core.Domain;

namespace SafeUpload.Agent.App.Notifications;

internal static class StagedPublicationPresentation
{
    internal static (string Title, string Message) Released(string fileName, TransferNotification notice)
    {
        fileName = AuditTextPrivacy.Sanitize(fileName);
        if (notice.Event?.NotInspectedReason is "publication_outcome_unknown" or "publication_failed" ||
            notice.Event?.Verdict is Verdict.Blocked or Verdict.Retained ||
            notice.PublishedSha256Hex is not { Length: 64 } hash || !hash.All(Uri.IsHexDigit))
            return ("SafeUpload: publicação não confirmada", $"{fileName}: a conclusão do envio não foi confirmada. Consulte o histórico ou o administrador.");
        bool findings = notice.Event?.Categories.Count > 0 || notice.Findings?.Count > 0;
        bool incomplete = notice.Event?.NotInspectedReason is not null;
        return (findings || incomplete ? "SafeUpload: envio concluído com alerta" : "SafeUpload: envio concluído",
            $"{fileName} foi enviado ao destino. " +
            (incomplete ? "A inspeção não foi concluída; o envio foi autorizado. " :
             findings ? "Foram detectados dados sensíveis; o envio foi autorizado. " : "Análise concluída. ") +
            $"SHA-256: {notice.PublishedSha256Hex ?? "indisponível"}");
    }

    internal static InspectionFailureKind? FailureFor(string? reason) => reason switch
    {
        "file_too_large" => InspectionFailureKind.TooLarge,
        "unsupported_format" or "archive_encrypted" or "archive_unsupported_member" or "archive_unsupported_structure" or "archive_7z_unavailable" => InspectionFailureKind.UnsupportedFormat,
        "inspection_timeout" => InspectionFailureKind.Timeout,
        "inspection_limit" => InspectionFailureKind.Limit,
        "not_enough_staging_space" => InspectionFailureKind.NotEnoughStagingSpace,
        _ when reason?.StartsWith("parse_error:", StringComparison.Ordinal) == true => InspectionFailureKind.ReadOrParse,
        _ => null
    };

    internal static string Busy(string fileName) =>
        $"{fileName}: o arquivo está aguardando envio porque outro programa está usando o destino. " +
        "Feche o programa e salve novamente. Esta versão continua guardada localmente.";

    internal static string Metadata(string fileName, string? reason) =>
        $"{fileName}: o envio está aguardando porque " + (reason switch
        {
            "metadata_zone_transaction_unavailable" => "a marca de origem da Internet ainda não pode ser inspecionada e publicada com o arquivo",
            "metadata_ads_unsupported" => "o arquivo contém um fluxo de dados adicional não suportado",
            "metadata_ea_unsupported" => "o arquivo contém atributos estendidos não suportados",
            "metadata_efs_unsupported" => "o arquivo usa criptografia EFS não suportada",
            "metadata_offline_unsupported" => "o arquivo está offline",
            "metadata_compression_unsupported" => "o arquivo usa compressão NTFS não suportada",
            "metadata_sparse_unsupported" => "o arquivo é esparso",
            "metadata_readonly_destination" => "o destino é somente leitura",
            "metadata_single_link_regular_file_required" => "o arquivo não é um arquivo comum com um único vínculo",
            _ => "os metadados do arquivo não puderam ser preservados com segurança"
        }) + ". Esta versão continua guardada localmente; o destino não foi substituído.";
}
