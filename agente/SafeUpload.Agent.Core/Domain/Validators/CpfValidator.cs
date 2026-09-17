namespace SafeUpload.Agent.Core.Domain.Validators;

/// <summary>
/// RN-001 — validação de CPF.
/// Onze dígitos, sem sequências de dígitos iguais, com os dois dígitos
/// verificadores conferidos por módulo 11 (pesos decrescentes a partir de 10
/// para o primeiro e de 11 para o segundo).
/// </summary>
public static class CpfValidator
{
    /// <summary>Quantidade de dígitos de um CPF.</summary>
    public const int DigitCount = 11;

    private static ReadOnlySpan<int> FirstWeights => [10, 9, 8, 7, 6, 5, 4, 3, 2];
    private static ReadOnlySpan<int> SecondWeights => [11, 10, 9, 8, 7, 6, 5, 4, 3, 2];

    /// <summary>
    /// Valida um CPF já normalizado — apenas os 11 dígitos, sem pontuação.
    /// A normalização é responsabilidade de quem varre o texto.
    /// </summary>
    public static bool IsValid(ReadOnlySpan<char> digits)
    {
        if (digits.Length != DigitCount || !DigitRules.IsAllDigits(digits))
        {
            return false;
        }

        if (DigitRules.IsAllSameDigit(digits))
        {
            return false;
        }

        var first = DigitRules.Modulo11(digits, FirstWeights);
        if (digits[9] - '0' != first)
        {
            return false;
        }

        var second = DigitRules.Modulo11(digits, SecondWeights);
        return digits[10] - '0' == second;
    }
}
