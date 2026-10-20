using SafeUpload.Agent.Core.Application;

namespace SafeUpload.Agent.Service.Clipboard;

/// <summary>
/// Escreve no log o que o motor do canal de clipboard observou.
///
/// <para>O Core não registra nada; o motor devolve uma
/// <see cref="ClipboardObservation"/>, e a ponte no serviço a escreve aqui. As
/// mensagens são as mesmas da Fase 1. O que entra no log vem só da observação,
/// que não tem campo de texto: categorias, processos, veredito e contagens
/// (RN-006).</para>
/// </summary>
public static class ClipboardLog
{
    /// <summary>Registra a observação, se houver uma.</summary>
    public static void Write(ILogger logger, ClipboardObservation? observation)
    {
        ArgumentNullException.ThrowIfNull(logger);

        if (observation is null)
        {
            return;
        }

        switch (observation.Kind)
        {
            case ClipboardObservationKind.PolicyUnavailable:
                logger.LogWarning(
                    "Politica indisponivel no canal de clipboard ({Tipo}). Liberando.",
                    observation.FailureType);
                break;

            case ClipboardObservationKind.DirtyCopy:
                logger.LogInformation(
                    "Clipboard sujo: motivo {Motivo}, categorias [{Categorias}], origem {Origem}. " +
                    "Copias {Copias}, sujas {Sujas}.",
                    observation.Reason,
                    string.Join(", ", observation.Categories ?? []),
                    observation.SourceProcess ?? "(desconhecida)",
                    observation.Metrics.Copies,
                    observation.Metrics.DirtyCopies);
                break;

            case ClipboardObservationKind.EgressFocusWhileDirty:
                logger.LogInformation(
                    "Foco em destino de saida com o clipboard sujo: {Destino} (origem {Origem}, veredito {Veredito}). " +
                    "Total {Total} de {Trocas} trocas de foco.",
                    observation.DestinationProcess ?? "(desconhecido)",
                    observation.SourceProcess ?? "(desconhecida)",
                    observation.Verdict,
                    observation.Metrics.FocusOnEgressWhileDirty,
                    observation.Metrics.FocusChangesWhileDirty);
                break;

            case ClipboardObservationKind.EgressPasteWhileDirty:
                logger.LogInformation(
                    "Colagem em destino de saida com o clipboard sujo: {Destino} (origem {Origem}, veredito {Veredito}). " +
                    "Bloqueadas {Bloqueadas} de {Tentativas} colagens.",
                    observation.DestinationProcess ?? "(desconhecido)",
                    observation.SourceProcess ?? "(desconhecida)",
                    observation.Verdict,
                    observation.Metrics.PastesBlocked,
                    observation.Metrics.PasteAttemptsWhileDirty);
                break;
        }
    }
}
