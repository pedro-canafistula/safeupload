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
/// Desenhos, gráficos, comentários e propriedades também são inspecionados.
/// O formato antigo <c>.xls</c> permanece fora do alcance.
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
