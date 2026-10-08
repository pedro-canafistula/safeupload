using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Windows;
using System.Windows.Interop;
using SafeUpload.Agent.Core.Contracts;

namespace SafeUpload.Agent.App.ClipboardWatch;

/// <summary>
/// Observa o clipboard e o foco, e pergunta ao serviço. Na Fase 1 não muda
/// nada para o usuário.
///
/// <para><b>Ctrl+C.</b> Uma janela só de mensagens escuta
/// <c>WM_CLIPBOARDUPDATE</c> (<c>AddClipboardFormatListener</c>). A cada
/// mudança, o texto vai ao serviço, que devolve "sujo" ou "limpo". É a única
/// vez que o texto sai deste processo, e ele não é guardado: a variável sai de
/// escopo no fim do método, e não há log, fila ou campo que o retenha.</para>
///
/// <para><b>Foco.</b> Com o clipboard sujo, cada troca de janela em primeiro
/// plano é uma sonda: "o usuário foi para este processo". O serviço só conta
/// (<c>ClipboardMetrics</c>). O pedido é o <c>paste</c> do protocolo, que na
/// Fase 3 passa a ser feito no Ctrl+V.</para>
///
/// <para>O aplicativo continua sendo um visor: quem classifica e decide é o
/// serviço, e este código não tem como alterar o clipboard. A decisão de não
/// escrever nele é a mesma que mantém o canal de notificação só de leitura.</para>
///
/// <para><b>Tudo roda na thread da interface.</b> O clipboard do WPF exige
/// uma thread STA, e o gancho de foco (<c>WINEVENT_OUTOFCONTEXT</c>) entrega na
/// thread que o instalou. As perguntas ao serviço são assíncronas e não
/// bloqueiam essa thread.</para>
/// </summary>
public sealed class ClipboardMonitor : IDisposable
{
    private const int WmClipboardUpdate = 0x031D;
    private const uint EventSystemForeground = 0x0003;
    private const uint WinEventOutOfContext = 0x0000;

    /// <summary>Janela só de mensagens: não aparece, não recebe foco, não tem tela.</summary>
    private static readonly IntPtr HwndMessage = new(-3);

    /// <summary>Quantas vezes tentar ler o clipboard quando outro processo o mantém aberto.</summary>
    private const int ReadAttempts = 5;

    private static readonly TimeSpan ReadRetryDelay = TimeSpan.FromMilliseconds(40);

    /// <summary>
    /// Quanto esperar por mais avisos antes de tratar uma cópia como concluída.
    /// Curto o bastante para a classificação estar pronta muito antes de o
    /// usuário trocar de janela e colar.
    /// </summary>
    private static readonly TimeSpan CoalesceDelay = TimeSpan.FromMilliseconds(120);

    private readonly ClipboardPipeClient _client;
    private readonly int _ownProcessId = Environment.ProcessId;

    private HwndSource? _sink;
    private IntPtr _foregroundHook;

    /// <summary>
    /// O delegate precisa ficar em campo: o Windows guarda só o ponteiro, e o
    /// coletor de lixo recolheria um delegate local, derrubando o processo na
    /// próxima troca de foco.
    /// </summary>
    private WinEventProc? _foregroundProc;

    private long _sequence;
    private CurrentCopy? _current;
    private (string CopyId, string Destination)? _lastProbe;

    /// <summary>A cópia em vigor, como o serviço a classificou.</summary>
    private sealed record CurrentCopy(string CopyId, bool Dirty);

    /// <summary>Compõe o monitor.</summary>
    public ClipboardMonitor(ClipboardPipeClient client)
    {
        _client = client ?? throw new ArgumentNullException(nameof(client));
    }

    /// <summary>Começa a observar. Chamar na thread da interface.</summary>
    public void Start()
    {
        if (_sink is not null)
        {
            return;
        }

        _sink = new HwndSource(new HwndSourceParameters("SafeUploadClipboardSink")
        {
            ParentWindow = HwndMessage,
            WindowStyle = 0,
        });

        _sink.AddHook(WndProc);

        if (!AddClipboardFormatListener(_sink.Handle))
        {
            // Sem o listener o canal fica cego, mas o aplicativo segue de pé:
            // proteger não depende desta janela (RN-013).
            return;
        }

        _foregroundProc = OnForegroundChanged;
        _foregroundHook = SetWinEventHook(
            EventSystemForeground,
            EventSystemForeground,
            IntPtr.Zero,
            _foregroundProc,
            0,
            0,
            WinEventOutOfContext);
    }

    /// <inheritdoc />
    public void Dispose()
    {
        if (_foregroundHook != IntPtr.Zero)
        {
            UnhookWinEvent(_foregroundHook);
            _foregroundHook = IntPtr.Zero;
        }

        if (_sink is not null)
        {
            RemoveClipboardFormatListener(_sink.Handle);
            _sink.RemoveHook(WndProc);
            _sink.Dispose();
            _sink = null;
        }
    }

    private IntPtr WndProc(IntPtr hwnd, int msg, IntPtr wParam, IntPtr lParam, ref bool handled)
    {
        if (msg == WmClipboardUpdate)
        {
            _ = OnClipboardChangedAsync();
            handled = true;
        }

        return IntPtr.Zero;
    }

    private async Task OnClipboardChangedAsync()
    {
        long sequence = Interlocked.Increment(ref _sequence);

        // Quem copiou, lido já: o dono do clipboard muda na cópia seguinte, e
        // depois do await esta informação seria de outra pessoa.
        string? source = ProcessNameFromWindow(GetClipboardOwner());

        // Uma cópia costuma disparar mais de um aviso: muitos aplicativos
        // limpam o clipboard e escrevem em seguida, ou entregam um formato por
        // vez. Sem esperar, cada aviso viraria uma "cópia" no serviço e a
        // medida da fase, quantas cópias ficam sujas, sairia inflada. Quem
        // espera sem ser superado é o último aviso da rajada.
        await Task.Delay(CoalesceDelay);

        if (sequence != Interlocked.Read(ref _sequence))
        {
            return;
        }

        string? text = await ReadTextAsync();

        // Outra cópia começou enquanto esta esperava. A mais nova vale.
        if (sequence != Interlocked.Read(ref _sequence))
        {
            return;
        }

        if (text is null)
        {
            // Não deu para ler. Não se sabe o que há no clipboard, então não se
            // afirma que está sujo: o estado anterior seria de outra cópia.
            _current = null;
            return;
        }

        ClipboardResponse? response = await _client.SendAsync(
            ClipboardRequest.Classify(text, source),
            ClipboardProtocol.ClassifyTimeout);

        if (sequence != Interlocked.Read(ref _sequence))
        {
            return;
        }

        // Sem resposta = limpo (RN-013).
        _current = response is { CopyId: not null } answered
            ? new CurrentCopy(answered.CopyId, answered.Dirty)
            : null;

        _lastProbe = null;
    }

    /// <summary>
    /// Lê o texto do clipboard.
    /// </summary>
    /// <returns>
    /// O texto; vazio se a cópia não é texto (imagem, arquivos), o que também
    /// precisa limpar o estado; e <c>null</c> se o clipboard não abriu.
    /// </returns>
    private static async Task<string?> ReadTextAsync()
    {
        for (int attempt = 0; attempt < ReadAttempts; attempt++)
        {
            try
            {
                return System.Windows.Clipboard.ContainsText(TextDataFormat.UnicodeText)
                    ? System.Windows.Clipboard.GetText(TextDataFormat.UnicodeText)
                    : string.Empty;
            }
            catch (ExternalException)
            {
                // CLIPBRD_E_CANT_OPEN: quem copiou ainda está com o clipboard
                // aberto. É normal logo depois do Ctrl+C; espera um pouco.
                await Task.Delay(ReadRetryDelay);
            }
        }

        return null;
    }

    private void OnForegroundChanged(
        IntPtr hook,
        uint eventType,
        IntPtr hwnd,
        int idObject,
        int idChild,
        uint eventThread,
        uint eventTime)
    {
        if (_current is not { Dirty: true } copy)
        {
            return;
        }

        string? destination = ProcessNameFromWindow(hwnd, skipOwnProcess: true);

        if (destination is null)
        {
            return;
        }

        // Alt+Tab para a mesma janela, ou o Windows reanunciando o foco, não
        // são duas trocas: o que se mede é "foi para lá", uma vez por cópia.
        if (_lastProbe is { } last &&
            last.CopyId == copy.CopyId &&
            string.Equals(last.Destination, destination, StringComparison.OrdinalIgnoreCase))
        {
            return;
        }

        _lastProbe = (copy.CopyId, destination);

        // Sem await e sem uso da resposta: na Fase 1 quem conta é o serviço.
        _ = _client.SendAsync(
            ClipboardRequest.Paste(copy.CopyId, destination),
            ClipboardProtocol.PasteTimeout);
    }

    private string? ProcessNameFromWindow(IntPtr hwnd, bool skipOwnProcess = false)
    {
        if (hwnd == IntPtr.Zero || GetWindowThreadProcessId(hwnd, out uint pid) == 0 || pid == 0)
        {
            return null;
        }

        // O próprio aplicativo é o visor do agente: dar foco a ele não é ir para
        // uma saída, e a política o exclui de qualquer forma (RN-014).
        if (skipOwnProcess && pid == _ownProcessId)
        {
            return null;
        }

        try
        {
            using Process process = Process.GetProcessById((int)pid);
            return process.ProcessName;
        }
        catch (Exception)
        {
            // O processo já saiu, ou é protegido. Sem nome, sem sonda.
            return null;
        }
    }

    private delegate void WinEventProc(
        IntPtr hook,
        uint eventType,
        IntPtr hwnd,
        int idObject,
        int idChild,
        uint eventThread,
        uint eventTime);

    [DllImport("user32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool AddClipboardFormatListener(IntPtr hwnd);

    [DllImport("user32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool RemoveClipboardFormatListener(IntPtr hwnd);

    [DllImport("user32.dll")]
    private static extern IntPtr GetClipboardOwner();

    [DllImport("user32.dll")]
    private static extern uint GetWindowThreadProcessId(IntPtr hwnd, out uint processId);

    [DllImport("user32.dll")]
    private static extern IntPtr SetWinEventHook(
        uint eventMin,
        uint eventMax,
        IntPtr hmodWinEventProc,
        WinEventProc proc,
        uint processId,
        uint threadId,
        uint flags);

    [DllImport("user32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool UnhookWinEvent(IntPtr hook);
}
