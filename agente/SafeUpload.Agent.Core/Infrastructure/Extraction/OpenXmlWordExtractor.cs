using System.Text;
using DocumentFormat.OpenXml;
using DocumentFormat.OpenXml.Packaging;
using DocumentFormat.OpenXml.Wordprocessing;

namespace SafeUpload.Agent.Core.Infrastructure.Extraction;

/// <summary>
/// Extrator de documentos do Word (<c>.docx</c>), via Open XML.
///
/// Cobre o corpo do documento mais cabeçalhos e rodapés, que é onde costuma
/// aparecer o dado que interessa. Fora do alcance desta entrega, e por isso
/// declarado: comentários, controle de alterações, texto dentro de imagens
/// (não há OCR) e objetos incorporados. O formato antigo <c>.doc</c>, binário,
/// também não é lido.
/// </summary>
public sealed class OpenXmlWordExtractor : ITextExtractor
{
    /// <inheritdoc />
    public IReadOnlySet<string> SupportedExtensions { get; } =
        new HashSet<string>(StringComparer.OrdinalIgnoreCase) { ".docx" };

    /// <inheritdoc />
    public Task<string> ExtractAsync(Stream content, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(content);
        cancellationToken.ThrowIfCancellationRequested();

        using var document = WordprocessingDocument.Open(content, isEditable: false);
        var mainPart = document.MainDocumentPart;

        if (mainPart is null)
        {
            return Task.FromResult(string.Empty);
        }

        var builder = new StringBuilder();

        foreach (var header in mainPart.HeaderParts)
        {
            AppendParagraphs(builder, header.Header, cancellationToken);
        }

        AppendParagraphs(builder, mainPart.Document?.Body, cancellationToken);

        foreach (var footer in mainPart.FooterParts)
        {
            AppendParagraphs(builder, footer.Footer, cancellationToken);
        }

        return Task.FromResult(builder.ToString());
    }

    /// <summary>
    /// Percorre parágrafo a parágrafo — inclusive os que estão dentro de
    /// tabelas — em vez de pegar o <c>InnerText</c> do bloco inteiro.
    ///
    /// A diferença importa: <c>InnerText</c> emenda os parágrafos sem nenhum
    /// caractere entre eles, e um parágrafo terminado em dígito seguido de
    /// outro começado em dígito viraria uma única sequência numérica que não
    /// existe no documento. Cada parágrafo sai numa linha própria, e quebra de
    /// linha não é separador válido dentro de um número para a varredura.
    /// </summary>
    private static void AppendParagraphs(
        StringBuilder builder,
        OpenXmlElement? root,
        CancellationToken cancellationToken)
    {
        if (root is null)
        {
            return;
        }

        foreach (var paragraph in root.Descendants<Paragraph>())
        {
            cancellationToken.ThrowIfCancellationRequested();

            var text = paragraph.InnerText;
            if (!string.IsNullOrEmpty(text))
            {
                builder.Append(text).Append('\n');
            }
        }
    }
}
