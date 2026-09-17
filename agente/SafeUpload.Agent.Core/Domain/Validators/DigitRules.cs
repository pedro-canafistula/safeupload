namespace SafeUpload.Agent.Core.Domain.Validators;

/// <summary>
/// Aritmética compartilhada por CPF e CNPJ. Ambos usam o mesmo dígito
/// verificador módulo 11, mudando apenas o vetor de pesos.
/// </summary>
internal static class DigitRules
{
    /// <summary>
    /// Calcula um dígito verificador módulo 11: soma os dígitos ponderados,
    /// tira o resto por 11 e converte — resto menor que 2 vira 0, senão 11 − resto.
    /// </summary>
    internal static int Modulo11(ReadOnlySpan<char> digits, ReadOnlySpan<int> weights)
    {
        var sum = 0;
        for (var i = 0; i < weights.Length; i++)
        {
            sum += (digits[i] - '0') * weights[i];
        }

        var remainder = sum % 11;
        return remainder < 2 ? 0 : 11 - remainder;
    }

    /// <summary>
    /// Sequências de dígitos repetidos (00000000000, 11111111111, ...) são
    /// rejeitadas antes da conta. Elas não são documentos reais e várias delas
    /// passariam no cálculo — 000.000.000-00 é o caso clássico —, o que geraria
    /// bloqueio em cima de dado de teste ou de preenchimento.
    /// </summary>
    internal static bool IsAllSameDigit(ReadOnlySpan<char> digits)
    {
        for (var i = 1; i < digits.Length; i++)
        {
            if (digits[i] != digits[0])
            {
                return false;
            }
        }

        return true;
    }

    /// <summary>Verdadeiro se todos os caracteres forem dígitos ASCII.</summary>
    internal static bool IsAllDigits(ReadOnlySpan<char> value)
    {
        foreach (var c in value)
        {
            if (c is < '0' or > '9')
            {
                return false;
            }
        }

        return true;
    }
}
