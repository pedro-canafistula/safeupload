namespace SafeUpload.Agent.Core.Domain.Validators;

/// <summary>
/// RN-002 — validação de CNPJ.
/// Quatorze dígitos e dois dígitos verificadores por módulo 11, com os pesos
/// cíclicos 5..2 / 9..2 no primeiro e 6..2 / 9..2 no segundo.
/// </summary>
public static class CnpjValidator
{
    /// <summary>Quantidade de dígitos de um CNPJ.</summary>
    public const int DigitCount = 14;

    private static ReadOnlySpan<int> FirstWeights => [5, 4, 3, 2, 9, 8, 7, 6, 5, 4, 3, 2];
    private static ReadOnlySpan<int> SecondWeights => [6, 5, 4, 3, 2, 9, 8, 7, 6, 5, 4, 3, 2];

    /// <summary>
    /// Valida um CNPJ já normalizado — apenas os 14 dígitos, sem pontuação.
    /// </summary>
    public static bool IsValid(ReadOnlySpan<char> digits)
    {
        if (digits.Length != DigitCount || !DigitRules.IsAllDigits(digits))
        {
            return false;
        }

        // 00000000000000 satisfaz os dois dígitos verificadores; descartamos
        // qualquer repetição pelo mesmo motivo que no CPF.
        if (DigitRules.IsAllSameDigit(digits))
        {
            return false;
        }

        var first = DigitRules.Modulo11(digits, FirstWeights);
        if (digits[12] - '0' != first)
        {
            return false;
        }

        var second = DigitRules.Modulo11(digits, SecondWeights);
        return digits[13] - '0' == second;
    }
}
