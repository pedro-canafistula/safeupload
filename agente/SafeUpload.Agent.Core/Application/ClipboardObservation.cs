using SafeUpload.Agent.Core.Contracts;
using SafeUpload.Agent.Core.Domain;

namespace SafeUpload.Agent.Core.Application;

/// <summary>O que aconteceu no canal de clipboard e vale registrar.</summary>
public enum ClipboardObservationKind
{
    /// <summary>A política não carregou; o canal liberou (RN-013).</summary>
    PolicyUnavailable,

    /// <summary>Uma cópia sujou o clipboard.</summary>
    DirtyCopy,

    /// <summary>O foco foi para um destino de saída com o clipboard sujo.</summary>
    EgressFocusWhileDirty
}

/// <summary>
/// Um fato do canal de clipboard, para quem registra.
///
/// <para>O Core não registra nada: devolve isto, e quem está no serviço
/// escreve o log. É a mesma divisão do canal web, em que o Core decide e o
/// serviço registra e avisa.</para>
///
/// <para><b>Não há campo de texto aqui, e é de propósito.</b> Categorias,
/// nomes de processo, veredito e contagens; nunca o texto copiado nem o trecho
/// achado (RN-006). Como o tipo não tem onde guardar texto, um log escrito a
/// partir dele também não tem.</para>
/// </summary>
/// <param name="Kind">O que aconteceu.</param>
/// <param name="Metrics">Os contadores logo depois.</param>
/// <param name="SourceProcess">Quem copiou, se conhecido.</param>
/// <param name="DestinationProcess">Para onde o foco foi, se for o caso.</param>
/// <param name="Reason">Por que a cópia ficou suja, se for o caso.</param>
/// <param name="Categories">Categorias achadas, se for o caso.</param>
/// <param name="Verdict">Veredito da colagem, se for o caso.</param>
/// <param name="FailureType">Tipo da exceção, quando a política não carregou. Só o tipo: a mensagem pode citar caminhos.</param>
public sealed record ClipboardObservation(
    ClipboardObservationKind Kind,
    ClipboardMetricsSnapshot Metrics,
    string? SourceProcess = null,
    string? DestinationProcess = null,
    ClipboardCopyReason? Reason = null,
    IReadOnlyList<Category>? Categories = null,
    ClipboardPasteVerdict? Verdict = null,
    string? FailureType = null,
    long SizeBytes = 0,
    int PolicyVersion = 1);

/// <summary>A resposta a devolver pelo pipe e, se houver, o fato a registrar.</summary>
/// <param name="Response">O que volta para o aplicativo.</param>
/// <param name="Observation">O que vale registrar, ou <c>null</c> se nada.</param>
public sealed record ClipboardOutcome(ClipboardResponse Response, ClipboardObservation? Observation = null);
