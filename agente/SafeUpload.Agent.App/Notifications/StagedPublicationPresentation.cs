using SafeUpload.Agent.Core.Contracts;

namespace SafeUpload.Agent.App.Notifications;

internal static class StagedPublicationPresentation
{
    internal static (string Title, string Message) Released(string fileName, TransferNotification notice)
    {
        bool findings = notice.Event?.Categories.Count > 0 || notice.Findings?.Count > 0;
        bool incomplete = notice.Event?.NotInspectedReason is not null;
        return (findings || incomplete ? "SafeUpload: envio concluído com alerta" : "SafeUpload: envio concluído",
            $"{fileName} foi enviado ao destino. " +
            (incomplete ? "A inspeção não foi concluída; o envio foi autorizado. " :
             findings ? "Foram detectados dados sensíveis; o envio foi autorizado. " : "Análise concluída. ") +
            $"SHA-256: {notice.PublishedSha256Hex ?? "indisponível"}");
    }

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
