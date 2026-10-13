using System.Text;
using DocumentFormat.OpenXml;
using DocumentFormat.OpenXml.Packaging;
using DocumentFormat.OpenXml.Spreadsheet;

namespace SafeUpload.Agent.Core.Infrastructure.Extraction;

/// <summary>
/// Extrator de planilhas do Excel (<c>.xlsx</c>), via Open XML.
///
/// Percorre todas as planilhas do arquivo e resolve a tabela de strings
/// compartilhadas — sem isso a maior parte do texto de um <c>.xlsx</c> real
/// apareceria como número de índice e a varredura não veria nada.
///
/// Inspeciona a expressão das fórmulas e seus resultados em cache. Uma fórmula
/// sem resultado em cache é recusada: o agente não executa a planilha.
/// Gráficos, caixas de texto e o formato antigo <c>.xls</c> permanecem fora do alcance.
/// Imagens, miniaturas e objetos/pacotes/controles incorporados são recusados
/// explicitamente em vez de aprovar apenas a camada de texto.
/// </summary>
public sealed class OpenXmlSheetExtractor : IStreamingTextExtractor
{
    /// <inheritdoc />
    public IReadOnlySet<string> SupportedExtensions { get; } =
        new HashSet<string>(StringComparer.OrdinalIgnoreCase) { ".xlsx" };

    /// <inheritdoc />
    public Task<TextReader> OpenReaderAsync(Stream content, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(content);
        cancellationToken.ThrowIfCancellationRequested();
        return Task.FromResult<TextReader>(new SpreadsheetTextReader(content, cancellationToken));
    }

    /// <inheritdoc />
    public Task<string> ExtractAsync(Stream content, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(content);
        cancellationToken.ThrowIfCancellationRequested();

        using var document = SpreadsheetDocument.Open(content, isEditable: false);
        OpenXmlInspectionGuard.RejectUnsupportedPayloads(document, cancellationToken);
        var workbookPart = document.WorkbookPart
            ?? throw new InvalidDataException("The spreadsheet package has no workbook part.");

        var sharedStrings = LoadSharedStrings(workbookPart);
        var builder = new StringBuilder();

        foreach (var worksheetPart in workbookPart.WorksheetParts)
        {
            cancellationToken.ThrowIfCancellationRequested();

            foreach (var row in worksheetPart.Worksheet.Descendants<Row>())
            {
                foreach (var cell in row.Elements<Cell>())
                {
                    cancellationToken.ThrowIfCancellationRequested();
                    if (cell.CellFormula is { } formula)
                    {
                        // Cached display text does not cover literals inside
                        // a formula. Inspect both without evaluating workbook
                        // code, links or external data. A missing result cannot
                        // stand for a completely inspected calculation.
                        if (cell.CellValue is null) throw new UnsupportedContentException();
                        builder.Append(formula.InnerText).Append('\n');
                    }
                    var value = ReadCell(cell, sharedStrings);
                    if (!string.IsNullOrEmpty(value))
                    {
                        // Uma célula por linha. Unir células com espaço faria a
                        // varredura colar "11222333" e "000181" num CNPJ que
                        // não está na planilha — espaço é separador válido
                        // dentro de um número.
                        builder.Append(value).Append('\n');
                    }
                }
            }
            if (worksheetPart.WorksheetCommentsPart is { } commentsPart)
            {
                var comments = commentsPart.Comments
                    ?? throw new InvalidDataException("The worksheet comments have no root.");
                foreach (var author in comments.Descendants<Author>())
                {
                    cancellationToken.ThrowIfCancellationRequested();
                    builder.Append(author.InnerText).Append('\n');
                }
                foreach (var comment in comments.Descendants<Comment>())
                {
                    cancellationToken.ThrowIfCancellationRequested();
                    // Comment text is optional; an empty note remains valid.
                    builder.Append(comment.CommentText?.InnerText).Append('\n');
                }
            }
        }

        return Task.FromResult(builder.ToString());
    }

    private static string[] LoadSharedStrings(WorkbookPart workbookPart)
    {
        var table = workbookPart.SharedStringTablePart?.SharedStringTable;
        if (table is null)
        {
            return [];
        }

        var items = table.Elements<SharedStringItem>().ToArray();
        var values = new string[items.Length];

        for (var i = 0; i < items.Length; i++)
        {
            values[i] = items[i].InnerText;
        }

        return values;
    }

    private static string? ReadCell(Cell cell, string[] sharedStrings)
    {
        var raw = cell.CellValue?.InnerText;

        if (cell.DataType?.Value == CellValues.SharedString)
        {
            if (raw is not null
                && int.TryParse(raw, out var index)
                && index >= 0
                && index < sharedStrings.Length)
            {
                return sharedStrings[index];
            }

            throw new InvalidDataException("The cell has an invalid shared-string reference.");
        }

        if (cell.DataType?.Value == CellValues.InlineString)
        {
            return cell.InlineString?.InnerText
                ?? throw new InvalidDataException("The inline-string cell has no string value.");
        }

        return raw;
    }
}
