using SafeUpload.Agent.Core.Domain;

namespace SafeUpload.Agent.Core.Application;

/// <summary>O que o proxy do clipboard faz com uma leitura.</summary>
public enum ClipboardReadAction
{
    /// <summary>
    /// Entrega o original sem perguntar nada. É o próprio agente lendo: o OLE
    /// consulta o proxy ao instalá-lo, e negar isso quebraria a instalação.
    /// </summary>
    DeliverOriginal,

    /// <summary>
    /// Nega. É o serviço de clipboard do Windows (histórico Win+V): se ele
    /// recebesse o conteúdo, o sistema guardaria a entrega e as colagens
    /// seguintes nem passariam pelo proxy.
    /// </summary>
    Deny,

    /// <summary>Uma colagem: pergunta ao serviço se este destino pode receber o conteúdo.</summary>
    AskForDestination
}

/// <summary>A decisão sobre uma leitura do clipboard.</summary>
/// <param name="Action">O que fazer.</param>
/// <param name="Destination">Para onde o conteúdo iria, quando é uma colagem.</param>
/// <param name="ReinstallAfter">
/// Se o proxy deve se reinstalar depois. Só leitura de fora reinstala: as do
/// próprio agente e as do histórico do Windows acontecem a cada reinstalação, e
/// reinstalar por causa delas vira um laço.
/// </param>
public sealed record ClipboardReadDecision(ClipboardReadAction Action, string? Destination, bool ReinstallAfter);

/// <summary>
/// As regras do proxy que decide a colagem na hora (Fase 3), medidas na Fase 2
/// (<c>docs/clipboard/FASE-2-TESTES.md</c>).
///
/// <para><b>Quem lê não diz para onde vai.</b> Durante o pedido ao proxy,
/// <c>GetOpenClipboardWindow</c> aponta ninguém para o Edge, o Chrome, o Teams e o
/// WhatsApp, e a janela OLE do próprio agente quando é ele quem lê. O destino é a
/// janela em primeiro plano; quem lê vale só quando aponta outro processo.</para>
///
/// <para>Funções puras, sem Windows: o proxy no aplicativo consulta estas regras,
/// e os testes as cobrem sem precisar de clipboard.</para>
/// </summary>
public static class ClipboardPasteGuardRules
{
    /// <summary>Nome do processo do serviço de clipboard do Windows (histórico Win+V).</summary>
    public const string WindowsClipboardService = "svchost";

    /// <summary>
    /// Decide uma leitura.
    /// </summary>
    /// <param name="readerProcess">Dono da janela que abriu o clipboard, se houver.</param>
    /// <param name="foregroundProcess">Processo da janela em primeiro plano.</param>
    /// <param name="ownProcess">O processo do próprio agente.</param>
    public static ClipboardReadDecision DecideRead(string? readerProcess, string? foregroundProcess, string ownProcess)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(ownProcess);

        var reader = ClipboardPolicy.NormalizeProcessName(readerProcess);
        var own = ClipboardPolicy.NormalizeProcessName(ownProcess);

        if (Same(reader, own))
        {
            return new ClipboardReadDecision(ClipboardReadAction.DeliverOriginal, null, ReinstallAfter: false);
        }

        if (Same(reader, WindowsClipboardService))
        {
            return new ClipboardReadDecision(ClipboardReadAction.Deny, null, ReinstallAfter: false);
        }

        // Ninguém abriu o clipboard com janela: quem cola é a janela da frente.
        var destination = reader ?? ClipboardPolicy.NormalizeProcessName(foregroundProcess);
        return new ClipboardReadDecision(ClipboardReadAction.AskForDestination, destination, ReinstallAfter: true);
    }

    private static bool Same(string? a, string? b) =>
        a is not null && b is not null && string.Equals(a, b, StringComparison.OrdinalIgnoreCase);
}

/// <summary>
/// Lembra a decisão de uma colagem por um instante.
///
/// <para>Um Ctrl+V vira vários pedidos ao proxy em poucos milissegundos (texto,
/// HTML, imagem, descritores). Perguntar ao serviço a cada um multiplicaria a
/// espera do aplicativo e os eventos de auditoria; a decisão vale para o mesmo
/// par cópia e destino durante <see cref="Window"/>.</para>
/// </summary>
public sealed class ClipboardPasteMemo
{
    /// <summary>Quanto tempo uma decisão vale para pedidos da mesma colagem.</summary>
    public static readonly TimeSpan Window = TimeSpan.FromSeconds(1);

    private readonly TimeProvider _time;
    private (string CopyId, string? Destination, ClipboardPasteVerdict Verdict, DateTimeOffset At)? _last;

    /// <summary>Cria a memória, com o relógio injetável para teste.</summary>
    public ClipboardPasteMemo(TimeProvider? time = null)
    {
        _time = time ?? TimeProvider.System;
    }

    /// <summary>A decisão recente para esta cópia e este destino, se ainda vale.</summary>
    public ClipboardPasteVerdict? TryGet(string copyId, string? destination)
    {
        if (_last is not { } last ||
            !string.Equals(last.CopyId, copyId, StringComparison.Ordinal) ||
            !string.Equals(last.Destination, destination, StringComparison.OrdinalIgnoreCase) ||
            _time.GetUtcNow() - last.At > Window)
        {
            return null;
        }

        return last.Verdict;
    }

    /// <summary>Guarda a decisão desta colagem.</summary>
    public void Remember(string copyId, string? destination, ClipboardPasteVerdict verdict) =>
        _last = (copyId, destination, verdict, _time.GetUtcNow());

    /// <summary>Esquece: a cópia mudou ou o proxy saiu.</summary>
    public void Clear() => _last = null;
}
