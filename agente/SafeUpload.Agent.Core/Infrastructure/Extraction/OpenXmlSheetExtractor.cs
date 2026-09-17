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
/// Fora do alcance: resultado de fórmula que o Excel não tenha gravado em
/// cache, gráficos, caixas de texto e o formato antigo <c>.xls</c>.
/// </summary>
public sealed class OpenXmlSheetExtractor : ITextExtractor
{
    /// <inheritdoc />
    public IReadOnlySet<string> SupportedExtensions { get; } =
        new HashSet<string>(StringComparer.OrdinalIgnoreCase) { ".xlsx" };

    /// <inheritdoc />
    public Task<string> ExtractAsync(Stream content, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(content);
        cancellationToken.ThrowIfCancellationRequested();

        using var document = SpreadsheetDocument.Open(content, isEditable: false);
        var workbookPart = document.WorkbookPart;

        if (workbookPart is null)
        {
            return Task.FromResult(string.Empty);
        }

        var sharedStrings = LoadSharedStrings(workbookPart);
        var builder = new StringBuilder();

        foreach (var worksheetPart in workbookPart.WorksheetParts)
        {
            cancellationToken.ThrowIfCancellationRequested();

            foreach (var row in worksheetPart.Worksheet.Descendants<Row>())
            {
                foreach (var cell in row.Elements<Cell>())
                {
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

            return null;
        }

        if (cell.DataType?.Value == CellValues.InlineString)
        {
            return cell.InlineString?.InnerText;
        }

        return raw;
    }
}
