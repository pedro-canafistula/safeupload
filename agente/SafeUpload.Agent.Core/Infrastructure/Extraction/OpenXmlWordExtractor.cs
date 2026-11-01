namespace SafeUpload.Agent.Core.Infrastructure.Extraction;

/// <summary>
/// Extrator de documentos do Word (<c>.docx</c>), via Open XML.
///
/// Cobre corpo, cabeçalhos, rodapés, notas de rodapé/finais e comentários.
/// Imagens, miniaturas, objetos/pacotes/controles incorporados e importações
/// alternativas causam recusa explícita: não há OCR nem inspeção desses payloads.
/// O formato antigo <c>.doc</c>, binário, também não é lido.
/// </summary>
public sealed class OpenXmlWordExtractor : IStreamingTextExtractor
{
    /// <inheritdoc />
    public IReadOnlySet<string> SupportedExtensions { get; } =
        new HashSet<string>(StringComparer.OrdinalIgnoreCase) { ".docx" };

    /// <inheritdoc />
    public Task<TextReader> OpenReaderAsync(Stream content, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(content);
        cancellationToken.ThrowIfCancellationRequested();
        return Task.FromResult<TextReader>(new WordParagraphTextReader(content, cancellationToken));
    }

    /// <inheritdoc />
    public async Task<string> ExtractAsync(Stream content, CancellationToken cancellationToken)
    {
        using var reader = await OpenReaderAsync(content, cancellationToken).ConfigureAwait(false);
        var text = new System.Text.StringBuilder();
        var buffer = new char[8192];
        int count;
        while ((count = await reader.ReadAsync(buffer.AsMemory(), cancellationToken).ConfigureAwait(false)) != 0)
            text.Append(buffer, 0, count);
        return text.ToString();
    }
}
