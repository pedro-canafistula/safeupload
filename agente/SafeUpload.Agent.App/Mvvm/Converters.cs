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
/// Insere um espaço fino (U+2009) entre cada caractere, imitando o
/// espaçamento entre letras dos rótulos em maiúscula do design.
///
/// Existe porque o WPF não tem <c>CharacterSpacing</c>: essa propriedade é do
/// UWP/WinUI. Também não adianta recorrer a <c>Typography.*</c>, que expõe
/// recursos OpenType da fonte e não controla tracking. Sem uma caixa de texto
/// rica, a única saída no WPF é mexer no próprio texto.
///
/// O espaço fino é escolhido em vez do espaço comum porque não quebra a
/// palavra em duas ao final da linha e ocupa cerca de um sexto do quadratim,
/// que é a ordem de grandeza do tracking pedido. O texto exibido deixa de ser
/// idêntico ao texto do modelo, e por isso a conversão fica na apresentação: o
/// que vai para o log continua sendo o valor original.
/// </summary>
public sealed class LetterSpacingConverter : IValueConverter
{
    // Escrito como escape, e nao como o caractere literal: um espaco fino e
    // invisivel no editor e qualquer normalizacao de espacos em branco o
    // trocaria por um espaco comum sem ninguem notar.
    private const char ThinSpace = '\u2009';

    /// <inheritdoc />
    public object Convert(object? value, Type targetType, object? parameter, CultureInfo culture)
    {
        var text = value?.ToString();

        if (string.IsNullOrEmpty(text))
        {
            return string.Empty;
        }

        return string.Join(ThinSpace, text.ToCharArray());
    }

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
