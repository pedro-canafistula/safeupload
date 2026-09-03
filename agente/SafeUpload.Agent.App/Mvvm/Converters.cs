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
/// Insere um espaço estreito entre cada caractere, imitando o espaçamento
/// entre letras dos rótulos em maiúscula do design.
///
/// Existe porque o WPF não tem <c>CharacterSpacing</c>: essa propriedade é do
/// UWP/WinUI. Também não adianta recorrer a <c>Typography.*</c>, que expõe
/// recursos OpenType da fonte e não controla tracking. Sem uma caixa de texto
/// rica, a única saída no WPF é mexer no próprio texto.
///
/// O espaçamento entre letras usa o U+200A, espaço capilar, o mais estreito do
/// Unicode. As alternativas mais óbvias ficam largas demais: no corpo de 10px
/// desta legenda, o U+2009 (fino) e o U+202F (estreito) somam quase um terço da
/// largura do rótulo, e "OPERAÇÕES EM SEGUNDO PLANO" deixa de caber no cartão.
/// Tracking de rótulo é da ordem de um pixel, não de dois ou três.
///
/// Cada espaço capilar vem seguido de um U+2060, o "word joiner", que ocupa
/// largura zero e proíbe a quebra de linha naquele ponto. Sem ele o rótulo
/// quebraria no meio da palavra — "DISPOSITIVO SEG / URO" —, porque todo espaço
/// do Unicode é ponto de quebra válido. As palavras continuam separadas por um
/// espaço comum, que é o único lugar onde a linha pode virar e é visivelmente
/// mais largo que o espaçamento entre letras.
///
/// O texto exibido deixa de ser idêntico ao texto do modelo, e por isso a
/// conversão fica na apresentação: o que vai para o log continua sendo o valor
/// original.
/// </summary>
public sealed class LetterSpacingConverter : IValueConverter
{
    // Escritos como escape, e não como caracteres literais: espaços de largura
    // especial são invisíveis no editor e qualquer normalização de espaços em
    // branco os trocaria por espaços comuns sem ninguém notar.

    /// <summary>
    /// Espaçamento entre as letras de uma mesma palavra: espaço capilar
    /// (U+200A) seguido de word joiner (U+2060), que impede a quebra ali.
    /// </summary>
    private const string LetterGap = "\u200A\u2060";

    /// <summary>Separação entre palavras, e único ponto de quebra do rótulo.</summary>
    private const char WordGap = ' ';

    /// <inheritdoc />
    public object Convert(object? value, Type targetType, object? parameter, CultureInfo culture)
    {
        var text = value?.ToString();

        if (string.IsNullOrEmpty(text))
        {
            return string.Empty;
        }

        var words = text.Split(' ', StringSplitOptions.RemoveEmptyEntries);
        var spaced = words.Select(word => string.Join(LetterGap, word.ToCharArray()));

        return string.Join(WordGap, spaced);
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
