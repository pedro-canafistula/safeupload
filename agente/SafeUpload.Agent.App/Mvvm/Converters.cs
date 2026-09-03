using System.Globalization;
using System.Windows;
using System.Windows.Data;
using System.Windows.Media;

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

/// <summary>
/// Resolve o nome de um ícone de <c>Resources/Icons.xaml</c> para a geometria
/// correspondente.
///
/// Serve ao template do item de navegação, que é um só e precisa desenhar um
/// ícone diferente por item. Sem isto, cada item exigiria o próprio template,
/// ou o modelo de visão teria de carregar um objeto <c>Geometry</c> — um tipo
/// de apresentação dentro de algo que só deveria saber o nome da tela.
/// </summary>
public sealed class IconLookupConverter : IValueConverter
{
    /// <inheritdoc />
    public object? Convert(object? value, Type targetType, object? parameter, CultureInfo culture)
    {
        if (value is not string key || string.IsNullOrEmpty(key))
        {
            return null;
        }

        return System.Windows.Application.Current?.TryFindResource(key) as Geometry;
    }

    /// <inheritdoc />
    public object ConvertBack(object? value, Type targetType, object? parameter, CultureInfo culture) =>
        throw new NotSupportedException();
}

/// <summary>
/// Resolve o nome de um pincel dos tokens da paleta para o pincel em si.
///
/// A pílula de status guarda nomes de token, e não cores: assim o modelo de
/// visão diz "isto é um bloqueio" em vez de "isto é #FEE2E2", e trocar a
/// paleta continua sendo mexer só em Tokens.xaml.
/// </summary>
public sealed class BrushLookupConverter : IValueConverter
{
    /// <inheritdoc />
    public object? Convert(object? value, Type targetType, object? parameter, CultureInfo culture)
    {
        if (value is not string key || string.IsNullOrEmpty(key))
        {
            return null;
        }

        return System.Windows.Application.Current?.TryFindResource(key) as Brush;
    }

    /// <inheritdoc />
    public object ConvertBack(object? value, Type targetType, object? parameter, CultureInfo culture) =>
        throw new NotSupportedException();
}

/// <summary>
/// Cor do indicador de monitoramento: verde quando o serviço confirma que
/// está vigiando, cinza quando não há confirmação.
///
/// A ausência de verde é deliberada e não é um detalhe estético. Enquanto o
/// aplicativo não tiver ouvido o serviço, ele não tem base para afirmar que a
/// máquina está protegida — e um indicador verde afirma exatamente isso.
/// </summary>
public sealed class MonitoringBrushConverter : IValueConverter
{
    /// <inheritdoc />
    public object? Convert(object? value, Type targetType, object? parameter, CultureInfo culture)
    {
        var key = value is true ? "PillApprovedText" : "TextMuted";

        return System.Windows.Application.Current?.TryFindResource(key) as Brush;
    }

    /// <inheritdoc />
    public object ConvertBack(object? value, Type targetType, object? parameter, CultureInfo culture) =>
        throw new NotSupportedException();
}
