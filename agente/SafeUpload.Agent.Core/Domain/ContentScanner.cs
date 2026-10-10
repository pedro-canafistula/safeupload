using SafeUpload.Agent.Core.Domain.Validators;

namespace SafeUpload.Agent.Core.Domain;

/// <summary>
/// Varre um texto já extraído e devolve os achados mascarados.
///
/// O scanner é puro e sem estado: recebe o texto e o conjunto de categorias
/// ativas como parâmetro. O domínio não lê política de lugar nenhum — quem
/// carrega a política é a camada de aplicação.
/// </summary>
public static class ContentScanner
{
    /// <summary>
    /// Ordem de varredura: do padrão mais longo para o mais curto.
    ///
    /// Isto não é detalhe de otimização, é correção. Toda sequência de 14
    /// dígitos contém quatro sequências de 11, e toda sequência de 16 contém
    /// seis de 11 e três de 14. Se o CPF fosse testado primeiro, um CNPJ
    /// legítimo viraria um punhado de achados de CPF e o bloqueio apontaria a
    /// categoria errada. Varrendo do maior para o menor e anotando os
    /// intervalos já consumidos, o trecho mais específico vence e os menores
    /// que se sobrepõem a ele são descartados.
    /// </summary>
    private static readonly (Category Category, int DigitCount)[] NumericRules =
    [
        (Category.PaymentCard, LuhnValidator.DigitCount), // 16
        (Category.Cnpj, CnpjValidator.DigitCount),        // 14
        (Category.Cpf, CpfValidator.DigitCount)           // 11
    ];

    /// <summary>
    /// Varre <paramref name="text"/> procurando apenas as categorias em
    /// <paramref name="active"/>.
    /// </summary>
    /// <returns>
    /// Achados mascarados, na ordem em que aparecem no texto. Lista vazia
    /// quando não há nada — nunca <c>null</c>.
    /// </returns>
    public static IReadOnlyList<Finding> Scan(string text, IReadOnlySet<Category> active)
    {
        ArgumentNullException.ThrowIfNull(text);
        ArgumentNullException.ThrowIfNull(active);

        if (text.Length == 0 || active.Count == 0)
        {
            return [];
        }

        var consumed = new List<(int Start, int End)>();
        var found = new List<(int Start, Finding Finding)>();

        ScanNumbers(text, active, consumed, found);

        // Segredos antes de senhas, pela mesma razão que os números vêm do
        // mais longo para o mais curto: o padrão mais específico vence. Uma
        // linha "password = ghp_abc..." casa as duas regras, e reportar como
        // credencial do GitHub diz o que precisa ser rotacionado; reportar
        // como senha diz só que havia uma.
        ScanSecrets(text, active, consumed, found);
        ScanPasswords(text, active, consumed, found);

        if (found.Count == 0)
        {
            return [];
        }

        found.Sort(static (a, b) => a.Start.CompareTo(b.Start));
        return found.ConvertAll(static entry => entry.Finding);
    }

    private static void ScanNumbers(
        string text,
        IReadOnlySet<Category> active,
        List<(int Start, int End)> consumed,
        List<(int Start, Finding Finding)> found)
    {
        foreach (var (category, digitCount) in NumericRules)
        {
            if (active.Contains(category))
            {
                ScanNumericRule(text, category, digitCount, consumed, found);
            }
        }
    }

    private static void ScanNumericRule(
        string text,
        Category category,
        int digitCount,
        List<(int Start, int End)> consumed,
        List<(int Start, Finding Finding)> found)
    {
        // Each category still completes its full left-to-right pass before the
        // shorter rule starts. Only one candidate's digits/positions are kept;
        // a long digit run no longer needs a position list proportional to it.
        Span<int> positions = stackalloc int[digitCount];
        Span<char> digits = stackalloc char[digitCount];
        Span<char> candidate = stackalloc char[digitCount];
        var next = 0;
        var count = 0;
        for (var index = 0; index < text.Length; index++)
        {
            var value = text[index];
            if (!char.IsAsciiDigit(value))
            {
                if (count != 0 && IsSeparator(value)
                    && index + 1 < text.Length && char.IsAsciiDigit(text[index + 1]))
                {
                    continue;
                }

                next = 0;
                count = 0;
                continue;
            }

            positions[next] = index;
            digits[next] = value;
            next = (next + 1) % digitCount;
            if (count < digitCount)
            {
                count++;
            }

            if (count != digitCount || Overlaps(consumed, positions[next], index))
            {
                continue;
            }

            digits[next..].CopyTo(candidate);
            digits[..next].CopyTo(candidate[(digitCount - next)..]);
            if (!IsValid(category, candidate))
            {
                continue;
            }

            consumed.Add((positions[next], index));
            found.Add((positions[next], new Finding(category, Masking.Mask(new string(candidate)))));
        }
    }

    private static void ScanSecrets(
        string text,
        IReadOnlySet<Category> active,
        List<(int Start, int End)> consumed,
        List<(int Start, Finding Finding)> found)
    {
        if (!active.Contains(Category.Secret))
        {
            return;
        }

        foreach (var match in SecretDetector.Find(text))
        {
            var end = match.Start + match.Length - 1;

            if (Overlaps(consumed, match.Start, end))
            {
                continue;
            }

            consumed.Add((match.Start, end));

            // MaskSecret e não Mask: de uma credencial, nem o sufixo pode
            // sobreviver. O rótulo diz o que rotacionar sem revelar nada.
            found.Add((match.Start, new Finding(Category.Secret, Masking.MaskSecret(match.Kind))));
        }
    }

    private static void ScanPasswords(
        string text,
        IReadOnlySet<Category> active,
        List<(int Start, int End)> consumed,
        List<(int Start, Finding Finding)> found)
    {
        if (!active.Contains(Category.Password))
        {
            return;
        }

        foreach (var match in PasswordHeuristic.Find(text))
        {
            var secretEnd = match.SecretStart + match.SecretLength - 1;

            // "senha: 4111111111111111" já foi contabilizado como cartão; não
            // vale relatar o mesmo trecho duas vezes com categorias diferentes.
            if (Overlaps(consumed, match.SecretStart, secretEnd))
            {
                continue;
            }

            var label = ExtractLabel(text, match);
            consumed.Add((match.Start, match.Start + match.Length - 1));
            found.Add((match.Start, new Finding(Category.Password, Masking.MaskSecret(label))));
        }
    }

    /// <summary>
    /// Recorta só a palavra que disparou a regra (<c>senha</c>, <c>pwd</c>, ...),
    /// que é o que a UI mostra junto dos marcadores.
    /// </summary>
    private static string ExtractLabel(string text, PasswordHeuristic.PasswordMatch match)
    {
        var separator = text.IndexOfAny([':', '='], match.Start);
        var end = separator < 0 ? match.Start + match.Length : separator;
        return text[match.Start..end].Trim();
    }

    private static bool IsValid(Category category, ReadOnlySpan<char> digits) => category switch
    {
        Category.PaymentCard => LuhnValidator.IsValid(digits),
        Category.Cnpj => CnpjValidator.IsValid(digits),
        Category.Cpf => CpfValidator.IsValid(digits),
        _ => false
    };

    private static bool Overlaps(List<(int Start, int End)> consumed, int start, int end)
    {
        foreach (var (otherStart, otherEnd) in consumed)
        {
            if (start <= otherEnd && otherStart <= end)
            {
                return true;
            }
        }

        return false;
    }

    private static bool IsSeparator(char c) => c is '.' or '-' or '/' or ' ';
}
