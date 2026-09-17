namespace SafeUpload.Agent.Core.Infrastructure.Extraction;

/// <summary>
/// Extrai texto plano de um formato de arquivo, para que o
/// <see cref="Domain.ContentScanner"/> possa varrê-lo.
///
/// RN-006 — descarte. A assinatura recebe um <see cref="Stream"/> já aberto e
/// nunca um caminho: o extrator não abre, não copia e não grava arquivo. O
/// conteúdo vive no fluxo que o chamador controla e é descartado no mesmo
/// escopo, inclusive quando a extração falha. Nenhuma implementação pode
/// escrever arquivo temporário, nem em caminho de erro.
/// </summary>
public interface ITextExtractor
{
    /// <summary>
    /// Extensões que este extrator entende, em minúsculas e com ponto
    /// (<c>.txt</c>, <c>.docx</c>, ...).
    /// </summary>
    IReadOnlySet<string> SupportedExtensions { get; }

    /// <summary>
    /// Lê o fluxo do começo ao fim e devolve o texto encontrado.
    /// Erros de parsing sobem como exceção: quem orquestra decide o que fazer
    /// com eles, e pela RN-012 a decisão é liberar a operação, nunca bloquear.
    /// </summary>
    Task<string> ExtractAsync(Stream content, CancellationToken cancellationToken);
}
