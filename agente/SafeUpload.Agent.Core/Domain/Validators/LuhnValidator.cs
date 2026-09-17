namespace SafeUpload.Agent.Core.Domain.Validators;

/// <summary>
/// RN-003 — validação de cartão de pagamento.
/// Exatamente 16 dígitos e soma de verificação de Luhn. O escopo desta entrega
/// é só o comprimento 16; bandeiras de 15 dígitos (Amex) ou 19 (alguns Maestro)
/// ficam de fora por decisão de projeto, não por limitação do algoritmo.
/// </summary>
public static class LuhnValidator
{
    /// <summary>Único comprimento aceito nesta entrega.</summary>
    public const int DigitCount = 16;

    /// <summary>
    /// Valida um número de cartão já normalizado — apenas os 16 dígitos.
    /// </summary>
    public static bool IsValid(ReadOnlySpan<char> digits)
    {
        if (digits.Length != DigitCount || !DigitRules.IsAllDigits(digits))
        {
            return false;
        }

        var sum = 0;
        var doubling = false;

        // Luhn percorre da direita para a esquerda dobrando um dígito sim,
        // outro não; dobra que passa de 9 tem 9 subtraído.
        for (var i = digits.Length - 1; i >= 0; i--)
        {
            var value = digits[i] - '0';

            if (doubling)
            {
                value *= 2;
                if (value > 9)
                {
                    value -= 9;
                }
            }

            sum += value;
            doubling = !doubling;
        }

        return sum % 10 == 0;
    }
}
