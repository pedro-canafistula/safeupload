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
        var runs = BuildDigitRuns(text);
        if (runs.Count == 0)
        {
            return;
        }

        foreach (var (category, digitCount) in NumericRules)
        {
            if (!active.Contains(category))
            {
                continue;
            }

            foreach (var run in runs)
            {
                for (var start = 0; start + digitCount <= run.Count; start++)
                {
                    var from = run[start];
                    var to = run[start + digitCount - 1];

                    if (Overlaps(consumed, from, to))
                    {
                        continue;
                    }

                    var candidate = string.Create(digitCount, (text, run, start), static (span, state) =>
                    {
                        for (var i = 0; i < span.Length; i++)
                        {
                            span[i] = state.text[state.run[state.start + i]];
                        }
                    });

                    if (!IsValid(category, candidate))
                    {
                        continue;
                    }

                    consumed.Add((from, to));
                    found.Add((from, new Finding(category, Masking.Mask(candidate))));
                }
            }
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

    /// <summary>
    /// Agrupa os dígitos do texto em corridas, aceitando um único caractere de
    /// pontuação entre dois dígitos. É o que permite reconhecer
    /// <c>529.982.247-25</c> e <c>4111 1111 1111 1111</c> como um número só,
    /// sem colar números vizinhos separados por vírgula, quebra de linha ou
    /// qualquer outra coisa.
    ///
    /// Cada corrida guarda a posição de cada dígito no texto original, para que
    /// os intervalos consumidos sejam comparáveis mesmo entre padrões de
    /// comprimentos diferentes.
    /// </summary>
    private static List<List<int>> BuildDigitRuns(string text)
    {
        var runs = new List<List<int>>();
        var index = 0;

        while (index < text.Length)
        {
            if (!char.IsAsciiDigit(text[index]))
            {
                index++;
                continue;
            }

            var positions = new List<int>();
            var cursor = index;

            while (cursor < text.Length)
            {
                if (char.IsAsciiDigit(text[cursor]))
                {
                    positions.Add(cursor);
                    cursor++;
                    continue;
                }

                if (IsSeparator(text[cursor])
                    && cursor + 1 < text.Length
                    && char.IsAsciiDigit(text[cursor + 1]))
                {
                    cursor++;
                    continue;
                }

                break;
            }

            runs.Add(positions);
            index = cursor;
        }

        return runs;
    }

    private static bool IsSeparator(char c) => c is '.' or '-' or '/' or ' ';
}
