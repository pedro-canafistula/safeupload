using System.Reflection;
using SafeUpload.Agent.App.Mvvm;

namespace SafeUpload.Agent.App.ViewModels;

/// <summary>
/// O modelo de visão do painel do agente.
///
/// O painel informa; ele não dá controle ao usuário final. Não há botão de
/// liberar, de reinspecionar nem de desligar a proteção, porque a decisão é da
/// política e não de quem está na máquina. O que o usuário pode fazer aqui é
/// olhar: ver que está protegido, sob qual política, e o que aconteceu com
/// seus arquivos.
/// </summary>
public sealed class AgentViewModel : ObservableObject
{
    private NavigationSection _selectedSection = null!;

    /// <summary>Compõe o painel sobre as duas telas.</summary>
    public AgentViewModel(StatusViewModel status, HistoryViewModel history)
    {
        ArgumentNullException.ThrowIfNull(status);
        ArgumentNullException.ThrowIfNull(history);

        Status = status;
        History = history;

        Sections =
        [
            new NavigationSection("Status", "IconShield", status),
            new NavigationSection("Histórico", "IconClock", history)
        ];

        SelectedSection = Sections[0];
    }

    /// <summary>A tela de status.</summary>
    public StatusViewModel Status { get; }

    /// <summary>A tela de histórico.</summary>
    public HistoryViewModel History { get; }

    /// <summary>
    /// Carrega as duas telas.
    ///
    /// Chamado no arranque, com o painel ainda oculto, para que o agente já
    /// tenha o estado em mãos quando o usuário abrir a janela pela primeira
    /// vez — e para que o histórico esteja pronto para receber interceptações
    /// antes de qualquer tela ter sido exibida.
    /// </summary>
    public async Task LoadAsync()
    {
        await Status.LoadAsync().ConfigureAwait(true);
        await History.LoadAsync().ConfigureAwait(true);
    }

    /// <summary>Os dois itens de navegação da barra lateral.</summary>
    public IReadOnlyList<NavigationSection> Sections { get; }

    /// <summary>Item selecionado; determina o conteúdo exibido à direita.</summary>
    public NavigationSection SelectedSection
    {
        get => _selectedSection;
        set
        {
            // A lista nunca deve ficar sem seleção: clicar fora de um item num
            // ListBox pode limpar a seleção e deixar a área de conteúdo vazia.
            if (value is not null)
            {
                SetProperty(ref _selectedSection, value);
            }
        }
    }

    /// <summary>
    /// Versão real do assembly, mostrada sob a marca. Vem do metadado do
    /// binário, e não de uma constante escrita à mão que envelheceria em
    /// silêncio a cada publicação.
    /// </summary>
    public string VersionLabel
    {
        get
        {
            var version = Assembly.GetExecutingAssembly().GetName().Version;

            return version is null
                ? "Endpoint Utility"
                : $"Endpoint Utility v{version.Major}.{version.Minor}";
        }
    }

    /// <summary>Nome da conta do Windows em uso.</summary>
    public string UserName => Environment.UserName;

    /// <summary>
    /// Iniciais para o círculo do rodapé. Não há foto: o agente não conhece o
    /// diretório da organização, e inventar um avatar sugeriria uma integração
    /// que não existe.
    /// </summary>
    public string UserInitials
    {
        get
        {
            var name = Environment.UserName;

            if (string.IsNullOrWhiteSpace(name))
            {
                return "?";
            }

            var parts = name.Split(['.', '_', '-', ' '], StringSplitOptions.RemoveEmptyEntries);

            if (parts.Length >= 2)
            {
                return string.Concat(char.ToUpperInvariant(parts[0][0]), char.ToUpperInvariant(parts[1][0]));
            }

            // Nome de uma palavra só: as duas primeiras letras dele.
            return name.Length >= 2
                ? name[..2].ToUpperInvariant()
                : name.ToUpperInvariant();
        }
    }
}

/// <summary>
/// Um item da navegação lateral.
/// </summary>
/// <param name="Label">Texto do item.</param>
/// <param name="IconKey">Chave do ícone em Resources/Icons.xaml.</param>
/// <param name="Content">Modelo de visão exibido quando o item está selecionado.</param>
public sealed record NavigationSection(string Label, string IconKey, ObservableObject Content);
