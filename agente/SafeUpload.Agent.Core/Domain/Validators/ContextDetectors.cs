using System.Text.RegularExpressions;

namespace SafeUpload.Agent.Core.Domain.Validators;

/// <summary>
/// Detectores das regras da console web que não têm um número com dígito verificador próprio: RG, dados bancários,
/// dados de saúde, documentos confidenciais e dados pessoais.
///
/// Para não bloquear qualquer texto com números, cada achado precisa de um rótulo ("RG:", "agência ... conta ...",
/// "CID", "Diagnóstico:") ou de um formato distintivo que se pode validar (RG de SP, IBAN, Cartão Nacional de Saúde,
/// e-mail, telefone). Marcações de classificação contam uma vez por texto.
/// </summary>
public static partial class ContextDetectors
{
    public readonly record struct ContextMatch(int Start, int Length, Finding Finding);

    private const RegexOptions Options = RegexOptions.IgnoreCase | RegexOptions.CultureInvariant;
    private const string Number = @"(?:n[º°o.]?\s*)?[:\-]?\s*";

    // RG
    [GeneratedRegex(@"\b(?:RG|R\.G\.|registro\s+geral|(?:carteira|c[ée]dula)\s+de\s+identidade)\s*" + Number +
        @"(?<n>\d{1,2}\.?\d{3}\.?\d{3}(?:-?[\dX])?|\d{5,10}(?:-[\dX])?)(?![\w\-/]|\.\d)", Options)]
    private static partial Regex LabeledRg();

    [GeneratedRegex(@"(?<![\w.\-/])(?<n>\d{2}\.\d{3}\.\d{3}-[\dX])(?![\w\-/]|\.\d)", Options)]
    private static partial Regex SaoPauloRg();

    // Dados bancários
    [GeneratedRegex(@"\bag(?:[êe]ncia|\.)?\s*" + Number + @"(?<ag>\d{3,5}(?:-[\dX])?)[^\d\r\n]{0,40}?" +
        @"\b(?:conta(?:\s+corrente|\s+poupan[çc]a)?|c/c|c\.c\.|cc)\s*" + Number + @"(?<conta>\d{3,13}(?:-[\dX])?)(?![\w/])", Options)]
    private static partial Regex BranchAndAccount();

    [GeneratedRegex(@"(?<![A-Z0-9])(?<n>[A-Z]{2}\d{2}(?: ?[A-Z0-9]){11,30})(?![A-Z0-9])", RegexOptions.CultureInvariant)]
    private static partial Regex Iban();

    // Dados de saúde
    [GeneratedRegex(@"\bCID(?:[\s\-]?10)?\s*[:\-]?\s*(?<n>[A-TV-Z]\d{2}(?:\.\d{1,2})?)\b", Options)]
    private static partial Regex Cid();

    [GeneratedRegex(@"\b(?:CNS|cart[ãa]o\s+(?:do\s+)?SUS|cart[ãa]o\s+nacional\s+de\s+sa[úu]de)\s*" + Number +
        @"(?<n>\d{3} ?\d{4} ?\d{4} ?\d{4})(?![\w\-/])", Options)]
    private static partial Regex HealthCard();

    [GeneratedRegex(@"\b(?<label>diagn[óo]stico|prontu[áa]rio|laudo\s+m[ée]dico|atestado\s+m[ée]dico|hist[óo]rico\s+cl[íi]nico|" +
        @"tipo\s+sangu[íi]neo|alergias?|medicamentos?\s+em\s+uso|doen[çc]as?\s+pr[ée]-?existentes?)\s*:[ \t]*\S", Options)]
    private static partial Regex MedicalField();

    // Documentos confidenciais
    [GeneratedRegex(@"\b(?:estritamente\s+confidencial|confidencial|sigilos[oa]|strictly\s+confidential|confidential|" +
        @"uso\s+interno|internal\s+use\s+only|n[ãa]o\s+divulgar|proibida\s+a\s+divulga[çc][ãa]o|do\s+not\s+distribute)\b", Options)]
    private static partial Regex ConfidentialMarking();

    // Dados pessoais
    [GeneratedRegex(@"(?<![\w.%+\-])[A-Z0-9._%+\-]{1,64}@[A-Z0-9\-]+(?:\.[A-Z0-9\-]+)*\.[A-Z]{2,24}\b", Options)]
    private static partial Regex Email();

    [GeneratedRegex(@"(?<![\w+(])(?:\+55\s?)?(?:\([1-9]{2}\)|[1-9]{2})\s?9?\d{4}[\-\s]\d{4}(?![\w\-/]|\.\d)", Options)]
    private static partial Regex Phone();

    [GeneratedRegex(@"\b(?:data\s+de\s+nascimento|nascimento|nascid[oa]\s+em|date\s+of\s+birth|DOB)\s*[:\-]?\s*" +
        @"(?<n>\d{1,2}[/.\-]\d{1,2}[/.\-]\d{2,4})\b", Options)]
    private static partial Regex BirthDate();

    /// <summary>
    /// IBAN válido. Quem chama procura antes dos números: com 15 a 34 caracteres validados, é mais específico que as
    /// sequências de cartão ou CNPJ que podem aparecer dentro dele.
    /// </summary>
    public static IEnumerable<ContextMatch> FindIbans(string text, IReadOnlySet<Category> active)
    {
        ArgumentNullException.ThrowIfNull(text);
        ArgumentNullException.ThrowIfNull(active);
        if (!active.Contains(Category.BankData)) yield break;
        foreach (Match m in Iban().Matches(text))
            if (IsIban(m.Groups["n"].Value)) yield return new(m.Index, m.Length, new Finding(Category.BankData, Masking.MaskSecret("IBAN")));
    }

    /// <summary>Os demais achados das categorias ativas, na ordem das regras (quem chama ordena e descarta sobreposições).</summary>
    public static IEnumerable<ContextMatch> Find(string text, IReadOnlySet<Category> active)
    {
        ArgumentNullException.ThrowIfNull(text);
        ArgumentNullException.ThrowIfNull(active);

        if (active.Contains(Category.Rg))
        {
            foreach (Match m in LabeledRg().Matches(text)) yield return Masked(m, Category.Rg);
            foreach (Match m in SaoPauloRg().Matches(text))
                if (IsSaoPauloRg(m.Groups["n"].Value)) yield return Masked(m, Category.Rg);
        }

        if (active.Contains(Category.BankData))
        {
            foreach (Match m in BranchAndAccount().Matches(text))
                yield return new(m.Index, m.Length, new Finding(Category.BankData,
                    $"agência {Masking.Mask(m.Groups["ag"].Value)}, conta {Masking.Mask(m.Groups["conta"].Value)}"));
        }

        if (active.Contains(Category.HealthData))
        {
            foreach (Match m in Cid().Matches(text))
                yield return new(m.Index, m.Length, new Finding(Category.HealthData, Masking.MaskSecret("CID")));
            foreach (Match m in HealthCard().Matches(text))
                if (IsHealthCard(m.Groups["n"].Value)) yield return Masked(m, Category.HealthData);
            foreach (Match m in MedicalField().Matches(text))
                yield return new(m.Index, m.Length, new Finding(Category.HealthData, Masking.MaskSecret(Collapse(m.Groups["label"].Value))));
        }

        if (active.Contains(Category.ConfidentialDocument) && ConfidentialMarking().Match(text) is { Success: true } marking)
            yield return new(marking.Index, marking.Length, new Finding(Category.ConfidentialDocument, Collapse(marking.Value).ToUpperInvariant()));

        if (active.Contains(Category.PersonalData))
        {
            foreach (Match m in Email().Matches(text))
                yield return new(m.Index, m.Length, new Finding(Category.PersonalData, Masking.MaskSecret("e-mail")));
            foreach (Match m in Phone().Matches(text))
                yield return new(m.Index, m.Length, new Finding(Category.PersonalData, Masking.Mask(m.Value)));
            foreach (Match m in BirthDate().Matches(text))
                yield return new(m.Index, m.Length, new Finding(Category.PersonalData, Masking.MaskSecret("data de nascimento")));
        }
    }

    private static ContextMatch Masked(Match m, Category category) =>
        new(m.Index, m.Length, new Finding(category, Masking.Mask(m.Groups["n"].Value)));

    private static string Collapse(string value) => string.Join(' ', value.Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries));

    /// <summary>RG de SP: pesos 2..9 sobre os 8 dígitos; DV = 11 - soma % 11 (10 = X, 11 = 0).</summary>
    internal static bool IsSaoPauloRg(string value)
    {
        var digits = value.Where(char.IsAsciiDigit).ToArray();
        char last = char.ToUpperInvariant(value[^1]);
        if (last != 'X') digits = digits[..^1];
        if (digits.Length != 8 || digits.All(d => d == digits[0])) return false;
        int sum = 0;
        for (int i = 0; i < 8; i++) sum += (digits[i] - '0') * (i + 2);
        int dv = 11 - sum % 11;
        char expected = dv == 10 ? 'X' : dv == 11 ? '0' : (char)('0' + dv);
        return last == expected;
    }

    /// <summary>IBAN: país + 2 dígitos + conta; válido quando o número reordenado dá resto 1 na divisão por 97.</summary>
    internal static bool IsIban(string value)
    {
        string iban = value.Replace(" ", "", StringComparison.Ordinal).ToUpperInvariant();
        if (iban.Length is < 15 or > 34) return false;
        int remainder = 0;
        foreach (char c in iban[4..] + iban[..4])
        {
            if (char.IsAsciiDigit(c)) remainder = (remainder * 10 + (c - '0')) % 97;
            else if (c is >= 'A' and <= 'Z') remainder = (remainder * 100 + (c - 'A' + 10)) % 97;
            else return false;
        }
        return remainder == 1;
    }

    /// <summary>Cartão Nacional de Saúde: 15 dígitos começando por 1, 2, 7, 8 ou 9; soma(dígito × (15 - posição)) % 11 == 0.</summary>
    internal static bool IsHealthCard(string value)
    {
        var digits = value.Where(char.IsAsciiDigit).ToArray();
        if (digits.Length != 15 || digits[0] is not ('1' or '2' or '7' or '8' or '9')) return false;
        int sum = 0;
        for (int i = 0; i < 15; i++) sum += (digits[i] - '0') * (15 - i);
        return sum % 11 == 0;
    }
}
