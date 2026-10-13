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
    /// Erros de parsing sobem como exceção: quem orquestra decide o veredito.
    /// A inspeção legada libera sem inspecionar (RN-012); staged bloqueia
    /// quando o conteúdo em escopo não pode ser inspecionado integralmente.
    /// </summary>
    Task<string> ExtractAsync(Stream content, CancellationToken cancellationToken);
}

/// <summary>Opens a bounded text reader; disposing it must leave the caller's stream open.</summary>
public interface IStreamingTextExtractor : ITextExtractor
{
    /// <summary>No source reopen, whole-file capture or temporary file is permitted.</summary>
    Task<TextReader> OpenReaderAsync(Stream content, CancellationToken cancellationToken);
}

/// <summary>Content requires an inspection capability this extractor does not provide.</summary>
public sealed class UnsupportedContentException : NotSupportedException
{
    /// <summary>Creates a failure without carrying source content or parser diagnostics.</summary>
    public UnsupportedContentException() : base("The file contains unsupported inspection content.") { }
}
