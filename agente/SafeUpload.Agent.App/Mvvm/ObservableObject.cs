using System.ComponentModel;
using System.Runtime.CompilerServices;

namespace SafeUpload.Agent.App.Mvvm;

/// <summary>
/// Base de notificação para os modelos de visão.
///
/// Escrita à mão, e não trazida de uma biblioteca de MVVM, porque o agente usa
/// exatamente isto: notificar mudança de propriedade. Um pacote inteiro para
/// vinte linhas seria mais dependência a auditar do que código a manter, e
/// este é um projeto em que a lista de dependências é parte do que se avalia.
/// </summary>
public abstract class ObservableObject : INotifyPropertyChanged
{
    /// <inheritdoc />
    public event PropertyChangedEventHandler? PropertyChanged;

    /// <summary>Anuncia que uma propriedade mudou.</summary>
    protected void OnPropertyChanged([CallerMemberName] string? propertyName = null) =>
        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propertyName));

    /// <summary>
    /// Atribui o valor e notifica, se ele tiver mudado de fato.
    /// </summary>
    /// <returns>Verdadeiro quando houve mudança.</returns>
    protected bool SetProperty<T>(ref T field, T value, [CallerMemberName] string? propertyName = null)
    {
        if (EqualityComparer<T>.Default.Equals(field, value))
        {
            return false;
        }

        field = value;
        OnPropertyChanged(propertyName);
        return true;
    }
}
