namespace SafeUpload.Agent.Core.Infrastructure.Extraction;

/// <summary>
/// Resolve qual <see cref="ITextExtractor"/> atende cada extensão.
///
/// É também a definição operacional de "formato suportado" da RN-013: se
/// nenhum extrator reivindica a extensão, a operação é liberada sem inspeção
/// com o motivo <c>unsupported_format</c>, nunca bloqueada.
///
/// PDF está fora desta entrega por decisão de escopo. Adicioná-lo depois é
/// escrever um <see cref="ITextExtractor"/> e registrá-lo aqui; nada mais no
/// agente precisa mudar.
/// </summary>
public sealed class ExtractorRegistry
{
    private readonly Dictionary<string, ITextExtractor> _byExtension;

    /// <summary>
    /// Monta o registro a partir dos extratores informados. Extensão declarada
    /// por dois extratores é erro de configuração, e falha aqui em vez de
    /// escolher um deles em silêncio.
    /// </summary>
    public ExtractorRegistry(IEnumerable<ITextExtractor> extractors)
    {
        ArgumentNullException.ThrowIfNull(extractors);

        _byExtension = new Dictionary<string, ITextExtractor>(StringComparer.OrdinalIgnoreCase);

        foreach (var extractor in extractors)
        {
            foreach (var extension in extractor.SupportedExtensions)
            {
                if (!_byExtension.TryAdd(extension, extractor))
                {
                    throw new InvalidOperationException(
                        $"A extensão '{extension}' foi declarada por mais de um extrator.");
                }
            }
        }

        SupportedExtensions = _byExtension.Keys.ToHashSet(StringComparer.OrdinalIgnoreCase);
    }

    /// <summary>Conjunto de extensões que o agente sabe ler.</summary>
    public IReadOnlySet<string> SupportedExtensions { get; }

    /// <summary>
    /// Composição padrão do mock: texto puro, Word e Excel.
    /// </summary>
    public static ExtractorRegistry CreateDefault() => new(
    [
        new PlainTextExtractor(),
        new OpenXmlWordExtractor(),
        new OpenXmlSheetExtractor()
    ]);

    /// <summary>
    /// Devolve o extrator da extensão, ou <c>null</c> se o formato não for
    /// suportado.
    /// </summary>
    public ITextExtractor? Resolve(string? extension)
    {
        if (string.IsNullOrWhiteSpace(extension))
        {
            return null;
        }

        return _byExtension.GetValueOrDefault(extension);
    }

    /// <summary>Verdadeiro quando existe extrator para a extensão.</summary>
    public bool IsSupported(string? extension) => Resolve(extension) is not null;
}
