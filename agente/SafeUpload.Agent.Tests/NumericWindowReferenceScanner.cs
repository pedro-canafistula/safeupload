using SafeUpload.Agent.Core.Domain;
using SafeUpload.Agent.Core.Domain.Validators;

namespace SafeUpload.Agent.Tests;

// Numeric-only oracle captured from qualified 8619b690. Deliberately retains
// the old all-run algorithm so the new bounded-window implementation is checked
// against its previous precedence, separator, masking and ordering semantics.
internal static class NumericWindowReferenceScanner
{
    private static readonly (Category Category, int DigitCount)[] NumericRules =
    [(Category.PaymentCard, 16), (Category.Cnpj, 14), (Category.Cpf, 11)];

    internal static IReadOnlyList<Finding> Scan(string text, IReadOnlySet<Category> active)
    {
        var consumed = new List<(int Start, int End)>();
        var found = new List<(int Start, Finding Finding)>();
        ScanNumbers(text, active, consumed, found);
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
