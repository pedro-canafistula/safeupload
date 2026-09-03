using System.Drawing;
using System.Drawing.Drawing2D;
using WinForms = System.Windows.Forms;

namespace SafeUpload.Agent.App;

/// <summary>
/// O ícone de bandeja do agente.
///
/// Usa o <c>NotifyIcon</c> do Windows Forms, que é a API do próprio sistema
/// para isso; o WPF não tem equivalente. Trazer uma biblioteca só para
/// embrulhar essa classe acrescentaria uma dependência sem acrescentar
/// capacidade.
///
/// A bandeja é onde o agente vive: não há janela principal, e fechar o painel
/// não encerra a proteção.
/// </summary>
public sealed class TrayIconHost : IDisposable
{
    private readonly WinForms.NotifyIcon _notifyIcon;
    private readonly Icon _icon;

    /// <summary>
    /// Cria o ícone e o menu de contexto.
    /// </summary>
    /// <param name="openPanel">Ação do item "Abrir painel".</param>
    /// <param name="exit">Ação do item "Sair".</param>
    /// <param name="openSimulator">
    /// Ação do item "Simular operação...". Só é usada em builds de depuração;
    /// em Release o item não existe, ainda que a ação seja informada.
    /// </param>
    public TrayIconHost(Action openPanel, Action exit, Action? openSimulator = null)
    {
        ArgumentNullException.ThrowIfNull(openPanel);
        ArgumentNullException.ThrowIfNull(exit);

        _icon = CreateShieldIcon();

        var menu = new WinForms.ContextMenuStrip();
        menu.Items.Add("Abrir painel", null, (_, _) => openPanel());

#if DEBUG
        // O simulador é ferramenta de desenvolvimento, não recurso do produto.
        // O agente informa e não dá controle ao usuário final: uma tela onde se
        // escolhe o destino e o processo de origem à mão daria a ele exatamente
        // o controle que a decisão de projeto retirou. Fica disponível apenas em
        // depuração, para exercitar caminhos difíceis de reproduzir por cópia de
        // arquivo — o timeout da RN-012 acima de todos.
        if (openSimulator is not null)
        {
            menu.Items.Add("Simular operação...", null, (_, _) => openSimulator());
        }
#endif

        menu.Items.Add(new WinForms.ToolStripSeparator());
        menu.Items.Add("Sair", null, (_, _) => exit());

        _notifyIcon = new WinForms.NotifyIcon
        {
            Icon = _icon,
            Text = "SafeUpload — proteção ativa",
            Visible = true,
            ContextMenuStrip = menu
        };

        // Clique simples e duplo com o botão esquerdo abrem o painel. Abrir é
        // idempotente: se a janela já estiver visível, ela apenas vem à frente.
        _notifyIcon.MouseClick += (_, args) =>
        {
            if (args.Button == WinForms.MouseButtons.Left)
            {
                openPanel();
            }
        };

        _notifyIcon.DoubleClick += (_, _) => openPanel();
    }

    /// <summary>
    /// Mostra um balão da própria bandeja. Serve para avisos secundários; o
    /// bloqueio tem janela própria, porque precisa listar as categorias.
    /// </summary>
    public void ShowBalloon(string title, string message) =>
        _notifyIcon.ShowBalloonTip(5000, title, message, WinForms.ToolTipIcon.Info);

    /// <inheritdoc />
    public void Dispose()
    {
        // Sem o Visible = false o ícone fica como fantasma na bandeja até o
        // usuário passar o mouse por cima.
        _notifyIcon.Visible = false;
        _notifyIcon.Dispose();
        _icon.Dispose();
    }

    /// <summary>
    /// Desenha o ícone em memória, em vez de carregar um .ico do disco.
    ///
    /// Um binário a mais no repositório seria um arquivo que ninguém revisa e
    /// que precisa ser regerado sempre que a paleta mudar. Aqui o escudo é
    /// desenhado com a cor Primary da própria paleta, e muda junto com ela.
    /// </summary>
    private static Icon CreateShieldIcon()
    {
        const int size = 32;

        using var bitmap = new Bitmap(size, size);
        using (var graphics = Graphics.FromImage(bitmap))
        {
            graphics.SmoothingMode = SmoothingMode.AntiAlias;
            graphics.Clear(Color.Transparent);

            // Primary #1E3A5F, o mesmo token do painel web.
            using var shieldBrush = new SolidBrush(Color.FromArgb(0x1E, 0x3A, 0x5F));
            using var markPen = new Pen(Color.White, 3f)
            {
                StartCap = LineCap.Round,
                EndCap = LineCap.Round
            };

            using var shield = new GraphicsPath();
            shield.AddLines(
            [
                new PointF(16, 2),
                new PointF(29, 7),
                new PointF(29, 17),
                new PointF(16, 30),
                new PointF(3, 17),
                new PointF(3, 7)
            ]);
            shield.CloseFigure();

            graphics.FillPath(shieldBrush, shield);

            // Marca de verificação: o agente está de guarda.
            graphics.DrawLines(markPen,
            [
                new PointF(10, 16),
                new PointF(14.5f, 21),
                new PointF(23, 11)
            ]);
        }

        // Icon.FromHandle não é dono do handle, então o ícone é clonado e o
        // handle original é devolvido ao sistema na mesma hora.
        var handle = bitmap.GetHicon();

        try
        {
            using var temporary = Icon.FromHandle(handle);
            return (Icon)temporary.Clone();
        }
        finally
        {
            DestroyIcon(handle);
        }
    }

    // DllImport, e nao LibraryImport: o gerador do LibraryImport exige
    // AllowUnsafeBlocks no projeto inteiro, e ligar codigo inseguro numa
    // aplicacao de prevencao de vazamento so para liberar um handle de icone
    // seria um preco alto pago no lugar errado.
    [System.Runtime.InteropServices.DllImport("user32.dll", SetLastError = true)]
    [return: System.Runtime.InteropServices.MarshalAs(System.Runtime.InteropServices.UnmanagedType.Bool)]
    private static extern bool DestroyIcon(IntPtr handle);
}
