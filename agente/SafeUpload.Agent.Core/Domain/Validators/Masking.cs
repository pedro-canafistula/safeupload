using System.Text;

namespace SafeUpload.Agent.Core.Domain.Validators;

/// <summary>
/// RN-007 — mascaramento.
///
/// Nenhum valor sensível real pode aparecer na interface nem no log de
/// auditoria. O mascaramento mora no domínio, e não na camada de apresentação,
/// exatamente para que não exista um caminho no código em que o valor em claro
/// chegue à UI ou ao disco e só lá seja escondido: o que sai do
/// <see cref="ContentScanner"/> já sai mascarado.
/// </summary>
public static class Masking
{
    /// <summary>Caractere usado no lugar de cada dígito escondido.</summary>
    public const char MaskChar = '•';

    /// <summary>Quantos dígitos finais permanecem legíveis.</summary>
    public const int VisibleDigits = 2;

    /// <summary>
    /// Quantos marcadores representam uma senha. É um valor fixo, e não o
    /// comprimento real, para que o log não revele nem o tamanho do segredo.
    /// </summary>
    private const int SecretMaskLength = 8;

    /// <summary>
    /// Mascara um valor numérico preservando apenas os dois últimos dígitos.
    /// A pontuação é descartada, de modo que o resultado não denuncie o formato
    /// original: <c>529.982.247-25</c> vira <c>••••••••&#8226;25</c>.
    /// </summary>
    public static string Mask(string value)
    {
        ArgumentNullException.ThrowIfNull(value);

        var digits = new StringBuilder(value.Length);
        foreach (var c in value)
        {
            if (char.IsAsciiDigit(c))
            {
                digits.Append(c);
            }
        }

        if (digits.Length <= VisibleDigits)
        {
            // Curto demais para mostrar sufixo sem entregar o valor inteiro.
            return new string(MaskChar, Math.Max(digits.Length, VisibleDigits));
        }

        var masked = new StringBuilder(digits.Length);
        masked.Append(MaskChar, digits.Length - VisibleDigits);
        masked.Append(digits.ToString(), digits.Length - VisibleDigits, VisibleDigits);
        return masked.ToString();
    }

    /// <summary>
    /// Mascara uma senha. Ao contrário dos números, aqui nenhum caractere do
    /// valor é preservado: o sufixo de uma senha é tão sensível quanto o
    /// resto dela. Só o rótulo que disparou a regra (<c>senha</c>,
    /// <c>password</c>, ...) sobrevive, porque ele localiza o problema no
    /// arquivo sem revelar nada.
    /// </summary>
    public static string MaskSecret(string label)
    {
        ArgumentNullException.ThrowIfNull(label);
        return $"{label}: {new string(MaskChar, SecretMaskLength)}";
    }
}
