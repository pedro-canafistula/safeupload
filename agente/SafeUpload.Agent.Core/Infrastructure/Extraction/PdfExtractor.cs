namespace SafeUpload.Agent.Core.Infrastructure.Extraction;

/// <summary>
/// Extrator de PDF.
///
/// É o formato em que contrato circula de verdade: assinado, exportado do
/// Word, mandado por e-mail. Sem ele o produto inspeciona o rascunho e deixa
/// passar a versão final — e o pior é que passa em silêncio, porque a porta
/// barata do driver rejeita a extensão antes de qualquer coisa e nada é
/// registrado.
///
/// <para><b>O que este extrator não faz.</b> PDF de digitalização é imagem:
/// não há texto para extrair e nenhum achado sai dele. Reconhecimento óptico
/// resolveria e não está aqui — é outro projeto, com outro custo de tempo por
/// arquivo. Qualquer página com imagem precisa dessa capacidade, mesmo que
/// também tenha texto: texto limpo não prova que a imagem é inspecionável.
/// O arquivo inteiro recebe <c>unsupported_format</c>; staged bloqueia e
/// devolve a versão. Uma página realmente vazia continua válida.</para>
/// </summary>
public sealed class PdfExtractor : IStreamingTextExtractor
{
    /// <inheritdoc />
    public IReadOnlySet<string> SupportedExtensions { get; } =
        new HashSet<string>(StringComparer.OrdinalIgnoreCase) { ".pdf" };

    /// <inheritdoc />
    public Task<TextReader> OpenReaderAsync(Stream content, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(content);
        cancellationToken.ThrowIfCancellationRequested();
        return Task.FromResult<TextReader>(new PdfTextReader(content));
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
