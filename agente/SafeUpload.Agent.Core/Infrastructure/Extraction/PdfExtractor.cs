using UglyToad.PdfPig;
using UglyToad.PdfPig.Content;

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
/// arquivo. Um PDF sem texto extraível cai como <c>unsupported_format</c> na
/// prática, e desde a mudança de "não consegui inspecionar marca o processo"
/// isso deixou de significar passagem livre.</para>
/// </summary>
public sealed class PdfExtractor : ITextExtractor
{
    /// <inheritdoc />
    public IReadOnlySet<string> SupportedExtensions { get; } =
        new HashSet<string>(StringComparer.OrdinalIgnoreCase) { ".pdf" };

    /// <inheritdoc />
    public Task<string> ExtractAsync(Stream content, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(content);

        // PdfPig é síncrono e trabalha sobre um stream posicionável. Quem
        // chama entrega um FileStream, então não há cópia extra aqui.
        using PdfDocument document = PdfDocument.Open(content);

        var text = new System.Text.StringBuilder();

        foreach (Page page in document.GetPages())
        {
            cancellationToken.ThrowIfCancellationRequested();

            // ContentOrderTextExtractor respeita a ordem em que o texto foi
            // desenhado, e não a posição na página. Para varredura é o que se
            // quer: um CPF quebrado entre dois blocos posicionados lado a
            // lado continua contíguo na ordem de desenho, enquanto ordenar
            // por coordenada poderia intercalar uma coluna vizinha no meio
            // dos dígitos e destruir o número.
            text.AppendLine(page.Text);
        }

        return Task.FromResult(text.ToString());
    }
}
