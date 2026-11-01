using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Runtime.InteropServices.ComTypes;
using System.Text;
using System.Windows.Forms;
using SafeUpload.Agent.Core.Application;
using SafeUpload.Agent.Core.Domain;

namespace SafeUpload.Agent.App.ClipboardWatch;

/// <summary>
/// O proxy OLE que decide a colagem na hora, no modo Block (Fase 3). É a técnica
/// escolhida e medida na Fase 2 (<c>docs/clipboard/FASE-2-TESTES.md</c>).
///
/// <para><b>Como funciona.</b> Quando uma cópia suja o clipboard, o agente toma a
/// posse com um <see cref="IDataObject"/> próprio que embrulha o original. A cada
/// leitura (um Ctrl+V vira várias), as regras puras do Core
/// (<see cref="ClipboardPasteGuardRules"/>) dizem o que fazer: entregar o original
/// a quem é o próprio agente, negar o histórico do Windows, ou — para quem cola —
/// perguntar ao serviço pelo destino. Em <c>Block</c>, o texto é trocado por um
/// aviso; caso contrário, o original (ou a cópia guardada) é entregue. Depois de
/// cada leitura de fora o proxy se reinstala, para o Windows não guardar a entrega
/// e a decisão não "grudar" na colagem seguinte.</para>
///
/// <para><b>Thread própria.</b> O OLE entrega as leituras na STA que chamou
/// <c>OleSetClipboard</c> e exige que ela bombeie mensagens. Para não travar a
/// interface do WPF durante uma colagem, o proxy vive numa STA dedicada com seu
/// próprio laço de mensagens.</para>
///
/// <para><b>A falha sempre libera (RN-013).</b> Sem resposta do serviço, a decisão
/// é liberar. <b>E o texto não é persistido (RN-006):</b> a cópia guardada fica só
/// em memória, enquanto o proxy está instalado, e some quando a cópia muda.</para>
/// </summary>
public sealed class ClipboardPasteGuard : IDisposable
{
    /// <summary>O que aparece no lugar do conteúdo bloqueado (RN-005).</summary>
    public const string WarningText = "[SafeUpload] conteúdo bloqueado — a cópia contém dado sensível.";

    private const int DV_E_FORMATETC = unchecked((int)0x80040064);
    private const int E_NOTIMPL = unchecked((int)0x80004001);
    private const int OLE_E_ADVISENOTSUPPORTED = unchecked((int)0x80040003);
    private const int DATA_S_SAMEFORMATETC = 0x00040130;

    private const ushort CF_TEXT = 1;
    private const ushort CF_OEMTEXT = 7;
    private const ushort CF_UNICODETEXT = 13;

    /// <summary>Espera antes de reinstalar, para agrupar as leituras de uma mesma colagem.</summary>
    private static readonly TimeSpan ReinstallDelay = TimeSpan.FromMilliseconds(250);

    private readonly string _ownProcess = Process.GetCurrentProcess().ProcessName;
    private readonly ushort _htmlFormat;
    private readonly ushort _rtfFormat;

    private Thread? _thread;
    private HiddenWindow? _window;

    private PasteProxy? _proxy;
    private IDataObjectWithHResult? _original;
    private Func<string?, ClipboardPasteVerdict>? _decide;

    /// <summary>Compõe o guarda. Chamar <see cref="Start"/> antes de instalar.</summary>
    public ClipboardPasteGuard()
    {
        _htmlFormat = (ushort)RegisterClipboardFormat("HTML Format");
        _rtfFormat = (ushort)RegisterClipboardFormat("Rich Text Format");
    }

    /// <summary>
    /// Verdadeiro quando o clipboard pertence ao próprio agente: ou porque o proxy
    /// está instalado, ou por uma reinstalação em curso. O monitor usa isto para
    /// ignorar os avisos de mudança que o próprio guarda provoca.
    /// </summary>
    public bool OwnsClipboard()
    {
        IntPtr owner = GetClipboardOwner();
        return owner != IntPtr.Zero &&
            GetWindowThreadProcessId(owner, out uint pid) != 0 &&
            pid == (uint)Environment.ProcessId;
    }

    /// <summary>Sobe a STA dedicada e seu laço de mensagens.</summary>
    public void Start()
    {
        if (_thread is not null)
        {
            return;
        }

        using var ready = new ManualResetEventSlim();

        _thread = new Thread(() =>
        {
            OleInitialize(IntPtr.Zero);
            _window = new HiddenWindow();
            _ = _window.Handle;
            ready.Set();
            Application.Run(_window);
            OleUninitialize();
        })
        {
            Name = "SafeUpload.ClipboardPasteGuard",
            IsBackground = true,
        };

        _thread.SetApartmentState(ApartmentState.STA);
        _thread.Start();
        ready.Wait();
    }

    /// <summary>
    /// Toma a posse do clipboard para esta cópia suja.
    /// </summary>
    /// <param name="decide">
    /// Decide um destino de colagem. Roda na STA do guarda e deve ser rápido:
    /// é o ponto onde o App pergunta ao serviço e mostra o aviso. Devolver
    /// <see cref="ClipboardPasteVerdict.Allow"/> entrega o conteúdo original.
    /// </param>
    public void Install(Func<string?, ClipboardPasteVerdict> decide)
    {
        ArgumentNullException.ThrowIfNull(decide);

        OnSta(() =>
        {
            _decide = decide;

            if (OleGetClipboard(out var current) != 0 || current is null)
            {
                return;
            }

            _original = current;
            _proxy = new PasteProxy(this, current);
            _proxy.FillCache(new[] { CF_UNICODETEXT, CF_TEXT, _htmlFormat, _rtfFormat });

            if (OleSetClipboard(_proxy) != 0)
            {
                _proxy = null;
                _original = null;
            }
        });
    }

    /// <summary>
    /// Larga a posse sem mexer no clipboard. Usado quando uma cópia nova (limpa,
    /// ou com o canal desligado) já substituiu o nosso proxy: o novo dono é o
    /// aplicativo que copiou, e não há o que desinstalar.
    /// </summary>
    public void Clear() => OnSta(() =>
    {
        _proxy = null;
        _original = null;
        _decide = null;
    });

    /// <summary>
    /// Devolve o conteúdo original ao clipboard, numa saída limpa do agente, para
    /// o usuário não perder o que copiou. Só age se ainda formos o dono: numa
    /// queda não há como, e aí a cópia suja se perde sem vazar (decisão 18).
    /// </summary>
    public void HandBack() => OnSta(() =>
    {
        if (_proxy is not null && _original is not null && OwnsClipboard())
        {
            if (OleSetClipboard(_original) == 0)
            {
                OleFlushClipboard();
            }
        }

        _proxy = null;
        _original = null;
        _decide = null;
    });

    /// <inheritdoc />
    public void Dispose()
    {
        if (_window is not null)
        {
            _window.BeginInvoke(new Action(() =>
            {
                HandBack();
                _window.Close();
            }));
        }

        _thread?.Join(TimeSpan.FromSeconds(2));
        _thread = null;
        _window = null;
    }

    private void OnSta(Action action)
    {
        HiddenWindow? window = _window;
        if (window is null || window.IsDisposed)
        {
            return;
        }

        if (window.InvokeRequired)
        {
            window.Invoke(action);
        }
        else
        {
            action();
        }
    }

    private void ScheduleReinstall(PasteProxy proxy)
    {
        HiddenWindow? window = _window;
        window?.ScheduleReinstall(() =>
        {
            if (ReferenceEquals(_proxy, proxy))
            {
                OleSetClipboard(proxy);
            }
        }, ReinstallDelay);
    }

    private string? ProcessNameFromWindow(IntPtr hwnd)
    {
        if (hwnd == IntPtr.Zero || GetWindowThreadProcessId(hwnd, out uint pid) == 0 || pid == 0)
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
            return null;
        }
    }

    // --------------------------------------------------------------- o proxy

    /// <summary>
    /// O <see cref="IDataObject"/> que embrulha o original. Devolve HRESULT em vez
    /// de lançar: negar por exceção num objeto gerenciado derrubou o processo na
    /// Fase 2 (P1/P2), e <c>[PreserveSig]</c> resolveu.
    /// </summary>
    [ComVisible(true)]
    private sealed class PasteProxy : IDataObjectWithHResult
    {
        [ThreadStatic] private static int _depth;

        private readonly ClipboardPasteGuard _guard;
        private readonly IDataObjectWithHResult _original;
        private Dictionary<ushort, byte[]>? _cache;

        public PasteProxy(ClipboardPasteGuard guard, IDataObjectWithHResult original)
        {
            _guard = guard;
            _original = original;
        }

        /// <summary>Guarda uma cópia dos formatos de texto: a reserva para quem lê por Win32.</summary>
        public void FillCache(IEnumerable<ushort> formats)
        {
            _cache = new Dictionary<ushort, byte[]>();

            foreach (ushort id in formats)
            {
                var format = new FORMATETC
                {
                    cfFormat = (short)id,
                    dwAspect = DVASPECT.DVASPECT_CONTENT,
                    lindex = -1,
                    tymed = TYMED.TYMED_HGLOBAL,
                };

                if (_original.GetData(ref format, out var medium) != 0)
                {
                    continue;
                }

                try
                {
                    byte[]? bytes = ReadHGlobal(medium.unionmember);
                    if (bytes is not null)
                    {
                        _cache[id] = bytes;
                    }
                }
                finally
                {
                    ReleaseStgMedium(ref medium);
                }
            }
        }

        public int GetData(ref FORMATETC format, out STGMEDIUM medium)
        {
            medium = default;

            // Reentrância: ao ler o original, o OLE pode chamar o proxy de novo.
            if (_depth > 0)
            {
                return DV_E_FORMATETC;
            }

            _depth++;

            string? reader = _guard.ProcessNameFromWindow(GetOpenClipboardWindow());
            string? foreground = _guard.ProcessNameFromWindow(GetForegroundWindow());
            ClipboardReadDecision decision = ClipboardPasteGuardRules.DecideRead(reader, foreground, _guard._ownProcess);

            try
            {
                switch (decision.Action)
                {
                    case ClipboardReadAction.Deny:
                        return DV_E_FORMATETC;

                    case ClipboardReadAction.DeliverOriginal:
                        return Forward(ref format, out medium);

                    default:
                        return Resolve(ref format, out medium, decision.Destination);
                }
            }
            finally
            {
                _depth--;

                if (decision.ReinstallAfter)
                {
                    _guard.ScheduleReinstall(this);
                }
            }
        }

        private int Resolve(ref FORMATETC format, out STGMEDIUM medium, string? destination)
        {
            medium = default;

            ClipboardPasteVerdict verdict = _guard._decide?.Invoke(destination) ?? ClipboardPasteVerdict.Allow;

            if (verdict != ClipboardPasteVerdict.Block)
            {
                return Forward(ref format, out medium);
            }

            ushort id = (ushort)format.cfFormat;

            if (id is CF_UNICODETEXT or CF_TEXT or CF_OEMTEXT && MediumAccepted(format.tymed))
            {
                byte[] bytes = id == CF_UNICODETEXT
                    ? Encoding.Unicode.GetBytes(WarningText + "\0")
                    : Encoding.ASCII.GetBytes(WarningText + "\0");
                medium = FromBytes(bytes, format.tymed);
                return 0;
            }

            // Em Block, nenhum outro formato (HTML, RTF, imagem) é entregue.
            return DV_E_FORMATETC;
        }

        private int Forward(ref FORMATETC format, out STGMEDIUM medium)
        {
            int hr = _original.GetData(ref format, out medium);

            // O repasse ao original falha para quem lê por Win32 (0x800401D0 na
            // Fase 2). A cópia guardada é a reserva.
            if (hr < 0 && _cache is not null && _cache.TryGetValue((ushort)format.cfFormat, out byte[]? bytes)
                && MediumAccepted(format.tymed))
            {
                medium = FromBytes(bytes, format.tymed);
                return 0;
            }

            return hr;
        }

        public int EnumFormatEtc(DATADIR direction, out IEnumFORMATETC? enumFormatEtc)
        {
            enumFormatEtc = null;

            if (_depth > 0)
            {
                return DV_E_FORMATETC;
            }

            _depth++;

            try
            {
                int hr = _original.EnumFormatEtc(direction, out var original);
                if (hr != 0 || original is null)
                {
                    return hr;
                }

                // Anuncia os formatos de texto como HGLOBAL: é o meio que os
                // leitores Win32 recebem prontos. Sem isto, um leitor Win32
                // pedia o fluxo e recebia nada (Fase 2, caso do Teams).
                var all = new List<FORMATETC>();
                var buffer = new FORMATETC[1];
                var fetched = new int[1];

                while (original.Next(1, buffer, fetched) == 0 && fetched[0] == 1)
                {
                    FORMATETC entry = buffer[0];
                    if (_cache is not null && _cache.ContainsKey((ushort)entry.cfFormat))
                    {
                        entry.tymed = TYMED.TYMED_HGLOBAL;
                    }

                    all.Add(entry);
                }

                enumFormatEtc = new FormatEnumerator(all.ToArray());
                return 0;
            }
            finally
            {
                _depth--;
            }
        }

        public int QueryGetData(ref FORMATETC format)
        {
            if (_depth > 0)
            {
                return DV_E_FORMATETC;
            }

            _depth++;
            try
            {
                return _original.QueryGetData(ref format);
            }
            finally
            {
                _depth--;
            }
        }

        public int GetCanonicalFormatEtc(ref FORMATETC formatIn, out FORMATETC formatOut)
        {
            formatOut = formatIn;
            return DATA_S_SAMEFORMATETC;
        }

        public int GetDataHere(ref FORMATETC format, ref STGMEDIUM medium) => E_NOTIMPL;
        public int SetData(ref FORMATETC format, ref STGMEDIUM medium, bool release) => E_NOTIMPL;
        public int DAdvise(ref FORMATETC format, ADVF advf, IAdviseSink sink, out int connection)
        {
            connection = 0;
            return OLE_E_ADVISENOTSUPPORTED;
        }

        public int DUnadvise(int connection) => OLE_E_ADVISENOTSUPPORTED;
        public int EnumDAdvise(out IEnumSTATDATA? enumAdvise)
        {
            enumAdvise = null;
            return OLE_E_ADVISENOTSUPPORTED;
        }

        private static bool MediumAccepted(TYMED tymed) =>
            (tymed & (TYMED.TYMED_HGLOBAL | TYMED.TYMED_ISTREAM)) != 0;

        private static STGMEDIUM FromBytes(byte[] bytes, TYMED requested)
        {
            IntPtr handle = GlobalAlloc(0x0002 /* GMEM_MOVEABLE */, (UIntPtr)(uint)bytes.Length);
            IntPtr pointer = GlobalLock(handle);
            Marshal.Copy(bytes, 0, pointer, bytes.Length);
            GlobalUnlock(handle);

            if ((requested & TYMED.TYMED_HGLOBAL) == 0 && (requested & TYMED.TYMED_ISTREAM) != 0)
            {
                CreateStreamOnHGlobal(handle, fDeleteOnRelease: true, out IntPtr stream);
                return new STGMEDIUM { tymed = TYMED.TYMED_ISTREAM, unionmember = stream, pUnkForRelease = null };
            }

            return new STGMEDIUM { tymed = TYMED.TYMED_HGLOBAL, unionmember = handle, pUnkForRelease = null };
        }

        private static byte[]? ReadHGlobal(IntPtr handle)
        {
            if (handle == IntPtr.Zero)
            {
                return null;
            }

            int size = (int)(ulong)GlobalSize(handle);
            if (size <= 0)
            {
                return null;
            }

            IntPtr pointer = GlobalLock(handle);
            if (pointer == IntPtr.Zero)
            {
                return null;
            }

            try
            {
                var bytes = new byte[size];
                Marshal.Copy(pointer, bytes, 0, size);
                return bytes;
            }
            finally
            {
                GlobalUnlock(handle);
            }
        }
    }

    /// <summary>Um enumerador de formatos próprio, para anunciar a lista que o proxy decide.</summary>
    [ComVisible(true)]
    private sealed class FormatEnumerator : IEnumFORMATETC
    {
        private readonly FORMATETC[] _items;
        private int _position;

        public FormatEnumerator(FORMATETC[] items, int position = 0)
        {
            _items = items;
            _position = position;
        }

        public int Next(int celt, FORMATETC[] rgelt, int[]? pceltFetched)
        {
            int taken = 0;
            while (taken < celt && _position < _items.Length)
            {
                rgelt[taken++] = _items[_position++];
            }

            if (pceltFetched is { Length: > 0 })
            {
                pceltFetched[0] = taken;
            }

            return taken == celt ? 0 : 1;
        }

        public int Skip(int celt)
        {
            _position = Math.Min(_items.Length, _position + celt);
            return _position < _items.Length ? 0 : 1;
        }

        public int Reset()
        {
            _position = 0;
            return 0;
        }

        public void Clone(out IEnumFORMATETC newEnum) => newEnum = new FormatEnumerator(_items, _position);
    }

    /// <summary>A janela só de mensagens da STA do guarda, com o timer de reinstalação.</summary>
    private sealed class HiddenWindow : Form
    {
        private System.Windows.Forms.Timer? _reinstallTimer;
        private Action? _pending;

        public HiddenWindow()
        {
            ShowInTaskbar = false;
            FormBorderStyle = FormBorderStyle.None;
            Opacity = 0;
            Load += (_, _) => Visible = false;
        }

        protected override void SetVisibleCore(bool value) => base.SetVisibleCore(false);

        public void ScheduleReinstall(Action reinstall, TimeSpan delay)
        {
            BeginInvoke(new Action(() =>
            {
                _pending = reinstall;
                _reinstallTimer?.Dispose();
                _reinstallTimer = new System.Windows.Forms.Timer { Interval = (int)delay.TotalMilliseconds };
                _reinstallTimer.Tick += (_, _) =>
                {
                    _reinstallTimer?.Dispose();
                    _reinstallTimer = null;
                    _pending?.Invoke();
                    _pending = null;
                };
                _reinstallTimer.Start();
            }));
        }
    }

    // --------------------------------------------------------- interop

    [ComImport]
    [Guid("0000010e-0000-0000-C000-000000000046")]
    [InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
    private interface IDataObjectWithHResult
    {
        [PreserveSig] int GetData(ref FORMATETC format, out STGMEDIUM medium);
        [PreserveSig] int GetDataHere(ref FORMATETC format, ref STGMEDIUM medium);
        [PreserveSig] int QueryGetData(ref FORMATETC format);
        [PreserveSig] int GetCanonicalFormatEtc(ref FORMATETC formatIn, out FORMATETC formatOut);
        [PreserveSig] int SetData(ref FORMATETC formatIn, ref STGMEDIUM medium, [MarshalAs(UnmanagedType.Bool)] bool release);
        [PreserveSig] int EnumFormatEtc(DATADIR direction, out IEnumFORMATETC? enumFormatEtc);
        [PreserveSig] int DAdvise(ref FORMATETC format, ADVF advf, IAdviseSink sink, out int connection);
        [PreserveSig] int DUnadvise(int connection);
        [PreserveSig] int EnumDAdvise(out IEnumSTATDATA? enumAdvise);
    }

    [DllImport("ole32.dll")]
    private static extern int OleInitialize(IntPtr reserved);

    [DllImport("ole32.dll")]
    private static extern void OleUninitialize();

    [DllImport("ole32.dll")]
    private static extern int OleGetClipboard(out IDataObjectWithHResult dataObject);

    [DllImport("ole32.dll")]
    private static extern int OleSetClipboard(IDataObjectWithHResult? dataObject);

    [DllImport("ole32.dll")]
    private static extern int OleFlushClipboard();

    [DllImport("ole32.dll")]
    private static extern void ReleaseStgMedium(ref STGMEDIUM medium);

    [DllImport("ole32.dll")]
    private static extern int CreateStreamOnHGlobal(IntPtr hGlobal, bool fDeleteOnRelease, out IntPtr stream);

    [DllImport("user32.dll")]
    private static extern IntPtr GetOpenClipboardWindow();

    [DllImport("user32.dll")]
    private static extern IntPtr GetForegroundWindow();

    [DllImport("user32.dll")]
    private static extern IntPtr GetClipboardOwner();

    [DllImport("user32.dll")]
    private static extern uint GetWindowThreadProcessId(IntPtr hwnd, out uint processId);

    [DllImport("user32.dll", CharSet = CharSet.Unicode)]
    private static extern uint RegisterClipboardFormat(string format);

    [DllImport("kernel32.dll")]
    private static extern IntPtr GlobalAlloc(uint flags, UIntPtr bytes);

    [DllImport("kernel32.dll")]
    private static extern IntPtr GlobalLock(IntPtr handle);

    [DllImport("kernel32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GlobalUnlock(IntPtr handle);

    [DllImport("kernel32.dll")]
    private static extern UIntPtr GlobalSize(IntPtr handle);
}
