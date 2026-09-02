using System.IO;
using SafeUpload.Agent.Core.Infrastructure.Extraction;

namespace SafeUpload.Agent.App.Simulation;

/// <summary>
/// Extrator que trava por oito segundos antes de fazer o trabalho de verdade.
///
/// É como o simulador demonstra a RN-012 sem código de mentira dentro do motor.
/// O InspectionService não sabe que está sendo simulado: ele chama um
/// ITextExtractor comum, esse extrator demora mais do que o prazo da política,
/// e o caminho do timeout é exercitado exatamente como seria com um arquivo
/// grande num compartilhamento de rede lento.
///
/// A alternativa — um parâmetro "simular travamento" no motor — colocaria uma
/// preocupação de demonstração dentro da regra de negócio, e o que a
/// demonstração provaria seria o próprio parâmetro, não o comportamento.
/// </summary>
/// <param name="inner">Extrator real, chamado depois do atraso.</param>
/// <param name="delay">Duração do travamento simulado.</param>
public sealed class StalledTextExtractor(ITextExtractor inner, TimeSpan delay) : ITextExtractor
{
    /// <summary>Atraso injetado, maior que o prazo padrão de cinco segundos.</summary>
    public static readonly TimeSpan DefaultDelay = TimeSpan.FromSeconds(8);

    /// <inheritdoc />
    public IReadOnlySet<string> SupportedExtensions => inner.SupportedExtensions;

    /// <inheritdoc />
    public async Task<string> ExtractAsync(Stream content, CancellationToken cancellationToken)
    {
        // O atraso não observa o cancelamento de propósito: um serviço travado
        // de verdade não responde a pedido de parada, e é justamente por isso
        // que existe um prazo do lado de fora.
        await Task.Delay(delay, CancellationToken.None).ConfigureAwait(false);

        return await inner.ExtractAsync(content, cancellationToken).ConfigureAwait(false);
    }

    /// <summary>
    /// Envolve todos os extratores de um registro, preservando as extensões
    /// atendidas.
    /// </summary>
    public static ExtractorRegistry Wrap(ExtractorRegistry registry, TimeSpan delay)
    {
        ArgumentNullException.ThrowIfNull(registry);

        var stalled = registry.SupportedExtensions
            .Select(registry.Resolve)
            .OfType<ITextExtractor>()
            .Distinct()
            .Select(ITextExtractor (extractor) => new StalledTextExtractor(extractor, delay));

        return new ExtractorRegistry(stalled);
    }
}
