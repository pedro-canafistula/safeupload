using System.Globalization;
using System.Windows;
using System.Windows.Data;

namespace SafeUpload.Agent.App.Mvvm;

/// <summary>
/// Mostra o elemento quando o valor é verdadeiro e o remove do layout quando é
/// falso. <c>Collapsed</c>, e não <c>Hidden</c>, para que o cartão de resultado
/// não deixe um buraco na tela antes da primeira inspeção.
/// </summary>
public sealed class BooleanToVisibilityConverter : IValueConverter
{
    /// <inheritdoc />
    public object Convert(object? value, Type targetType, object? parameter, CultureInfo culture) =>
        value is true ? Visibility.Visible : Visibility.Collapsed;

    /// <inheritdoc />
    public object ConvertBack(object? value, Type targetType, object? parameter, CultureInfo culture) =>
        value is Visibility.Visible;
}

/// <summary>
/// Mostra o elemento quando a contagem é zero. Serve para a frase que aparece
/// no lugar da lista de achados quando o arquivo está limpo.
/// </summary>
public sealed class ZeroCountToVisibilityConverter : IValueConverter
{
    /// <inheritdoc />
    public object Convert(object? value, Type targetType, object? parameter, CultureInfo culture) =>
        value is int count && count == 0 ? Visibility.Visible : Visibility.Collapsed;

    /// <inheritdoc />
    public object ConvertBack(object? value, Type targetType, object? parameter, CultureInfo culture) =>
        throw new NotSupportedException();
}
