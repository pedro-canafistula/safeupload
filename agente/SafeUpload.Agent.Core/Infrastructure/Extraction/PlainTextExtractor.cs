using System.Text;

namespace SafeUpload.Agent.Core.Infrastructure.Extraction;

/// <summary>
/// Extrator de arquivos de texto puro: <c>.txt</c> e <c>.csv</c>.
///
/// O CSV é lido literalmente, sem interpretar delimitadores. Para a varredura
/// isso é o que se quer: vírgula e ponto-e-vírgula não são separadores válidos
/// dentro de um número, então células vizinhas não se colam por acidente.
/// </summary>
public sealed class PlainTextExtractor : ITextExtractor
{
    /// <inheritdoc />
    public IReadOnlySet<string> SupportedExtensions { get; } =
        new HashSet<string>(StringComparer.OrdinalIgnoreCase) { ".txt", ".csv" };

    /// <inheritdoc />
    public async Task<string> ExtractAsync(Stream content, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(content);

        // detectEncodingFromByteOrderMarks respeita a BOM quando existe e cai
        // em UTF-8 quando não existe, que é o caso mais comum em exportações.
        using var reader = new StreamReader(
            content,
            Encoding.UTF8,
            detectEncodingFromByteOrderMarks: true,
            leaveOpen: true);

        return await reader.ReadToEndAsync(cancellationToken).ConfigureAwait(false);
    }
}
