using System.IO.Compression;
using System.Runtime.InteropServices;

namespace SafeUpload.Agent.Core.Infrastructure.Extraction;

/// <summary>
/// Descobre o formato de um conteúdo pelos bytes, e não pelo nome.
///
/// No canal de arquivo a extensão vem do sistema de arquivos e basta. Na web
/// ela não é confiável: o site pode não mandar nome nenhum, mandar um tipo
/// declarado errado (o Drive envia arquivo como <c>x-www-form-urlencoded</c>)
/// ou o usuário pode renomear <c>folha.xlsx</c> para <c>foto.jpg</c> antes de
/// enviar. Os primeiros bytes do arquivo não mentem: todo PDF começa com
/// <c>%PDF-</c>, e todo docx e xlsx é um ZIP com arquivos de nome fixo dentro.
/// </summary>
public static class ContentTypeSniffer
{
    /// <summary>
    /// Extensão do formato reconhecido (<c>.pdf</c>, <c>.docx</c>,
    /// <c>.xlsx</c>), ou nulo se os bytes não são de um formato conhecido.
    /// </summary>
    public static string? Sniff(ReadOnlyMemory<byte> content)
    {
        ReadOnlySpan<byte> span = content.Span;

        if (span.StartsWith("%PDF-"u8))
        {
            return ".pdf";
        }

        if (!span.StartsWith("PK\u0003\u0004"u8))
        {
            return null;
        }

        try
        {
            using Stream stream = AsStream(content);
            using var archive = new ZipArchive(stream, ZipArchiveMode.Read);

            foreach (ZipArchiveEntry entry in archive.Entries)
            {
                if (entry.FullName.Equals("word/document.xml", StringComparison.OrdinalIgnoreCase))
                {
                    return ".docx";
                }

                if (entry.FullName.Equals("xl/workbook.xml", StringComparison.OrdinalIgnoreCase))
                {
                    return ".xlsx";
                }
            }
        }
        catch (InvalidDataException)
        {
            // ZIP truncado ou corrompido: formato desconhecido.
        }

        return null;
    }

    /// <summary>
    /// Se o conteúdo parece texto: sem byte nulo e quase sem caracteres de
    /// controle no começo. Imagem, vídeo e executável falham logo aqui.
    /// </summary>
    public static bool LooksLikeText(ReadOnlySpan<byte> content)
    {
        ReadOnlySpan<byte> sample = content[..Math.Min(content.Length, 4096)];

        if (sample.IsEmpty)
        {
            return false;
        }

        int control = 0;

        foreach (byte value in sample)
        {
            if (value == 0)
            {
                return false;
            }

            if (value < 0x20 && value is not ((byte)'\t' or (byte)'\r' or (byte)'\n'))
            {
                control++;
            }
        }

        return control * 20 < sample.Length;
    }

    internal static MemoryStream AsStream(ReadOnlyMemory<byte> content) =>
        MemoryMarshal.TryGetArray(content, out ArraySegment<byte> segment)
            ? new MemoryStream(segment.Array!, segment.Offset, segment.Count, writable: false)
            : new MemoryStream(content.ToArray(), writable: false);
}
