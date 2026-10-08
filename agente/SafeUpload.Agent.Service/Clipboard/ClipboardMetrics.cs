using SafeUpload.Agent.Core.Domain;

namespace SafeUpload.Agent.Service.Clipboard;

/// <summary>Os contadores num instante, para log e para teste.</summary>
/// <param name="Copies">Cópias classificadas com o canal ligado.</param>
/// <param name="DirtyCopies">Dessas, quantas sujaram o clipboard.</param>
/// <param name="FocusChangesWhileDirty">Trocas de foco vistas com o clipboard sujo.</param>
/// <param name="FocusOnEgressWhileDirty">
/// Dessas, quantas foram para um destino de saída. É a estimativa de quantos
/// bloqueios a Fase 3 faria.
/// </param>
public readonly record struct ClipboardMetricsSnapshot(
    long Copies,
    long DirtyCopies,
    long FocusChangesWhileDirty,
    long FocusOnEgressWhileDirty);

/// <summary>
/// As duas medidas da Fase 1: quantas cópias ficam sujas e quantas vezes o foco
/// vai para um destino de saída com o clipboard sujo.
///
/// Só números. Nenhum texto, nenhum achado e nenhum nome de arquivo passa por
/// aqui, de modo que o que for registrado a partir destes contadores não tem
/// como carregar o que o usuário copiou.
///
/// Vivem na memória do serviço e zeram quando ele reinicia: servem para
/// estimar o volume de bloqueios antes de ligar o modo Block, não para
/// auditoria. A trilha de auditoria é a fila de eventos, e a Fase 1 não grava
/// nela de propósito.
/// </summary>
public sealed class ClipboardMetrics
{
    private long _copies;
    private long _dirtyCopies;
    private long _focusChangesWhileDirty;
    private long _focusOnEgressWhileDirty;

    /// <summary>Uma cópia foi classificada com o canal ligado.</summary>
    public void RecordCopy(bool dirty)
    {
        Interlocked.Increment(ref _copies);

        if (dirty)
        {
            Interlocked.Increment(ref _dirtyCopies);
        }
    }

    /// <summary>
    /// O foco mudou com o clipboard sujo. O veredito diz se o destino é uma
    /// saída: qualquer coisa diferente de <see cref="ClipboardPasteVerdict.Allow"/>
    /// é uma colagem que a política barraria ou registraria.
    /// </summary>
    public void RecordFocusWhileDirty(ClipboardPasteVerdict verdict)
    {
        Interlocked.Increment(ref _focusChangesWhileDirty);

        if (verdict != ClipboardPasteVerdict.Allow)
        {
            Interlocked.Increment(ref _focusOnEgressWhileDirty);
        }
    }

    /// <summary>Lê os contadores.</summary>
    public ClipboardMetricsSnapshot Snapshot() => new(
        Interlocked.Read(ref _copies),
        Interlocked.Read(ref _dirtyCopies),
        Interlocked.Read(ref _focusChangesWhileDirty),
        Interlocked.Read(ref _focusOnEgressWhileDirty));
}
