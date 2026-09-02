using System.Windows.Input;

namespace SafeUpload.Agent.App.Mvvm;

/// <summary>
/// Comando de interface, síncrono ou assíncrono.
///
/// A parte que importa é a trava de reentrada: enquanto a inspeção corre — e
/// ela pode levar os cinco segundos do timeout —, o comando fica indisponível.
/// Sem isso, o usuário clica de novo no botão que parece travado e dispara uma
/// segunda inspeção por cima da primeira.
/// </summary>
public sealed class RelayCommand : ICommand
{
    private readonly Func<Task> _execute;
    private readonly Func<bool>? _canExecute;
    private bool _running;

    /// <summary>Comando síncrono.</summary>
    public RelayCommand(Action execute, Func<bool>? canExecute = null)
        : this(() => { execute(); return Task.CompletedTask; }, canExecute)
    {
    }

    /// <summary>Comando assíncrono.</summary>
    public RelayCommand(Func<Task> execute, Func<bool>? canExecute = null)
    {
        _execute = execute ?? throw new ArgumentNullException(nameof(execute));
        _canExecute = canExecute;
    }

    /// <inheritdoc />
    public event EventHandler? CanExecuteChanged;

    /// <inheritdoc />
    public bool CanExecute(object? parameter) => !_running && (_canExecute?.Invoke() ?? true);

    /// <inheritdoc />
    public async void Execute(object? parameter)
    {
        if (!CanExecute(parameter))
        {
            return;
        }

        _running = true;
        RaiseCanExecuteChanged();

        try
        {
            await _execute().ConfigureAwait(true);
        }
        finally
        {
            // Sempre libera o comando, inclusive quando a execução falha: um
            // botão que fica morto depois de um erro obriga a reiniciar o
            // agente para tentar de novo.
            _running = false;
            RaiseCanExecuteChanged();
        }
    }

    /// <summary>Pede à interface que reavalie a disponibilidade do comando.</summary>
    public void RaiseCanExecuteChanged() => CanExecuteChanged?.Invoke(this, EventArgs.Empty);
}
