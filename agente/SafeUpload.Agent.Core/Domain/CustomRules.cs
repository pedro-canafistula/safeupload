using System.Globalization;
using System.Text;
using System.Text.RegularExpressions;
using SafeUpload.Agent.Core.Domain.Validators;

namespace SafeUpload.Agent.Core.Domain;

/// <summary>
/// Regras personalizadas criadas no console (docs/console-agente.md, "Regras personalizadas"). O servidor valida
/// e normaliza tudo antes de publicar; aqui só se compila e avalia. Uma regra que não compila torna a política
/// inteira inválida, e o agente continua na versão anterior.
/// </summary>
public sealed record CustomRule(int Id, int Revision, string Name, bool Alert, CustomCondition When);

public abstract record CustomCondition;
public sealed record AllCondition(IReadOnlyList<CustomCondition> Children) : CustomCondition;
public sealed record AnyCondition(IReadOnlyList<CustomCondition> Children) : CustomCondition;
public sealed record NotCondition(CustomCondition Child) : CustomCondition;

/// <summary>Palavras ou frases inteiras, já normalizadas pelo servidor; qualquer uma conta.</summary>
public sealed record WordsCondition(IReadOnlyList<string> Terms, int Minimum) : CustomCondition;

/// <summary>Expressão já normalizada pelo servidor (subconjunto comum Java/.NET), com validador opcional.</summary>
public sealed record PatternCondition(string Pattern, bool IgnoreCase, int Minimum, CustomValidator Validator, int Group)
    : CustomCondition;

public enum CustomValidator { None, Cpf, Cnpj, Luhn, Mod11 }

/// <summary>Normalização usada pelas palavras: minúsculas, sem acento, espaços e hífens viram um espaço só.</summary>
public sealed class TextFolder
{
    private bool _lastWasSeparator;

    public static string Fold(string text)
    {
        var builder = new StringBuilder(text.Length);
        new TextFolder().Append(text, builder);
        return builder.ToString();
    }

    public void Append(ReadOnlySpan<char> input, StringBuilder output)
    {
        foreach (char c in input)
        {
            if (IsSeparator(c))
            {
                if (!_lastWasSeparator) output.Append(' ');
                _lastWasSeparator = true;
                continue;
            }
            _lastWasSeparator = false;
            if (c < 128 || char.IsSurrogate(c))
            {
                output.Append(char.ToLowerInvariant(c));
                continue;
            }
            foreach (char part in c.ToString().Normalize(NormalizationForm.FormD))
                if (CharUnicodeInfo.GetUnicodeCategory(part) != UnicodeCategory.NonSpacingMark)
                    output.Append(char.ToLowerInvariant(part));
        }
    }

    /// <summary>Mesma definição do backend (TextFold.java): espaços Unicode, quebras de linha, hífen e travessões.</summary>
    private static bool IsSeparator(char c) =>
        CharUnicodeInfo.GetUnicodeCategory(c) == UnicodeCategory.SpaceSeparator ||
        c is '\t' or '\n' or '\r' or '\f' or '\v' or '-' ||
        c == (char)0x85 || c == (char)0x2028 || c == (char)0x2029 ||
        c is >= (char)0x2010 and <= (char)0x2015;
}

public static class Mod11Validator
{
    /// <summary>Último dígito = verificador; pesos 2..9 da direita para a esquerda; resto &lt; 2 dá 0, senão 11 − resto.</summary>
    public static bool IsValid(ReadOnlySpan<char> digits)
    {
        if (digits.Length < 2 || !DigitRules.IsAllDigits(digits)) return false;
        int sum = 0, weight = 2;
        for (int i = digits.Length - 2; i >= 0; i--)
        {
            sum += (digits[i] - '0') * weight;
            weight = weight == 9 ? 2 : weight + 1;
        }
        int rest = sum % 11;
        return digits[^1] - '0' == (rest < 2 ? 0 : 11 - rest);
    }
}

/// <summary>Regras compiladas de uma política. Imutável; cada inspeção usa um <see cref="CustomRuleScan"/> próprio.</summary>
public sealed class CustomRuleSet
{
    public const int SupportedFormat = 1;
    internal const int MaximumLeaves = 400;
    private static readonly TimeSpan MatchTimeout = TimeSpan.FromSeconds(2);

    public IReadOnlyList<CustomRule> Rules { get; }

    /// <summary>Texto determinístico de todas as regras, para a impressão digital da política.</summary>
    public string Canonical { get; }

    internal IReadOnlyList<Leaf> Leaves { get; }
    private readonly Dictionary<CustomCondition, int> _leafIndex;

    internal sealed record Leaf(Regex Regex, bool Folded, CustomValidator Validator, int Group, int Minimum, bool Words);

    private CustomRuleSet(IReadOnlyList<CustomRule> rules, List<Leaf> leaves, Dictionary<CustomCondition, int> index, string canonical)
    {
        Rules = rules;
        Leaves = leaves;
        _leafIndex = index;
        Canonical = canonical;
    }

    public static CustomRuleSet Empty { get; } = new([], [], new(ReferenceEqualityComparer.Instance), "");

    /// <exception cref="InvalidPolicyException">Regra malformada ou expressão que este agente não compila.</exception>
    public static CustomRuleSet Compile(IReadOnlyList<CustomRule> rules)
    {
        var leaves = new List<Leaf>();
        var index = new Dictionary<CustomCondition, int>(ReferenceEqualityComparer.Instance);
        var canonical = new StringBuilder();
        var ids = new HashSet<int>();
        foreach (var rule in rules)
        {
            if (rule.Id <= 0 || rule.Revision <= 0 || string.IsNullOrWhiteSpace(rule.Name) || rule.Name.Length > 80 || !ids.Add(rule.Id))
                throw new InvalidPolicyException("Regra personalizada com identificação inválida.");
            canonical.Append(rule.Id).Append('#').Append(rule.Revision).Append('#').Append(rule.Alert ? 'A' : 'B').Append('#')
                .Append(rule.Name).Append('#');
            Visit(rule.When, depth: 0);
            canonical.Append('\n');
        }
        return new CustomRuleSet(rules, leaves, index, canonical.ToString());

        void Visit(CustomCondition condition, int depth)
        {
            if (depth > 4) throw new InvalidPolicyException("Regra personalizada aninhada demais.");
            switch (condition)
            {
                case AllCondition all when all.Children.Count > 0:
                    canonical.Append("all(");
                    foreach (var child in all.Children) Visit(child, depth + 1);
                    canonical.Append(')');
                    break;
                case AnyCondition any when any.Children.Count > 0:
                    canonical.Append("any(");
                    foreach (var child in any.Children) Visit(child, depth + 1);
                    canonical.Append(')');
                    break;
                case NotCondition not:
                    canonical.Append("not(");
                    Visit(not.Child, depth + 1);
                    canonical.Append(')');
                    break;
                case WordsCondition words when words.Terms.Count is > 0 and <= 50 && words.Minimum is >= 1 and <= 1000:
                    foreach (var term in words.Terms)
                        if (string.IsNullOrEmpty(term) || term.Length > 100 || term != TextFolder.Fold(term) ||
                            !char.IsLetterOrDigit(term[0]) || !char.IsLetterOrDigit(term[^1]))
                            throw new InvalidPolicyException("Palavra de regra personalizada fora da forma normalizada.");
                    canonical.Append("words(").Append(words.Minimum).Append(';').AppendJoin('|', words.Terms).Append(')');
                    AddLeaf(condition, @"\b(?:" + string.Join('|', words.Terms.Select(Regex.Escape)) + @")\b",
                        RegexOptions.None, folded: true, CustomValidator.None, 0, words.Minimum, isWords: true);
                    break;
                case PatternCondition pattern when pattern.Pattern.Length is > 0 and <= 1000 && pattern.Minimum is >= 1 and <= 1000
                                                   && pattern.Group >= 0 && Enum.IsDefined(pattern.Validator):
                    canonical.Append("pattern(").Append(pattern.Minimum).Append(';').Append(pattern.IgnoreCase ? 'i' : 'c')
                        .Append(';').Append(pattern.Validator).Append(';').Append(pattern.Group).Append(';').Append(pattern.Pattern).Append(')');
                    AddLeaf(condition, pattern.Pattern, pattern.IgnoreCase ? RegexOptions.IgnoreCase : RegexOptions.None,
                        folded: false, pattern.Validator, pattern.Group, pattern.Minimum, isWords: false);
                    break;
                default:
                    throw new InvalidPolicyException("Condição de regra personalizada inválida.");
            }
        }

        void AddLeaf(CustomCondition condition, string pattern, RegexOptions options, bool folded,
            CustomValidator validator, int group, int minimum, bool isWords)
        {
            if (leaves.Count >= MaximumLeaves) throw new InvalidPolicyException("Regras personalizadas demais.");
            Regex regex;
            try
            {
                // NonBacktracking: tempo linear no tamanho do texto, qualquer que seja a expressão.
                regex = new Regex(pattern, options | RegexOptions.NonBacktracking | RegexOptions.CultureInvariant, MatchTimeout);
            }
            catch (Exception error) when (error is ArgumentException or NotSupportedException)
            {
                // NotSupportedException: construção que o modo NonBacktracking não aceita (lookaround, referência...).
                throw new InvalidPolicyException("Expressão de regra personalizada que este agente não compila.");
            }
            if (group > regex.GetGroupNumbers().Max())
                throw new InvalidPolicyException("Grupo validado inexistente na expressão.");
            index[condition] = leaves.Count;
            leaves.Add(new Leaf(regex, folded, validator, group, minimum, isWords));
        }
    }

    public CustomRuleScan Start() => new(this);

    /// <summary>Avalia um texto inteiro (mesma lógica da leitura em blocos).</summary>
    public IReadOnlyList<Finding> Scan(string text)
    {
        var scan = Start();
        scan.Feed(text);
        return scan.Complete();
    }

    internal int LeafOf(CustomCondition condition) => _leafIndex[condition];
}

/// <summary>
/// Avaliação incremental: o texto chega em blocos e cada condição conta suas ocorrências em janelas que se
/// sobrepõem em <see cref="Lookahead"/> caracteres. Cada ocorrência é contada uma vez, na janela onde começa,
/// e a busca continua de onde a anterior terminou: o resultado é o mesmo de varrer o texto inteiro, para
/// ocorrências de até <see cref="Lookahead"/> caracteres.
/// </summary>
public sealed class CustomRuleScan
{
    internal const int Window = 64 * 1024;
    internal const int Lookahead = 256;
    private const int LeftContext = 16;

    private readonly CustomRuleSet _set;
    private readonly Stream _raw = new();
    private readonly Stream _folded = new();
    private readonly TextFolder _folder = new();
    private readonly long[] _lastEnd;
    private readonly int[] _counts;
    private readonly string?[] _snippets;
    private bool _complete;

    internal CustomRuleScan(CustomRuleSet set)
    {
        _set = set;
        _lastEnd = new long[set.Leaves.Count];
        _counts = new int[set.Leaves.Count];
        _snippets = new string?[set.Leaves.Count];
    }

    public void Feed(ReadOnlySpan<char> chunk)
    {
        if (_complete) throw new InvalidOperationException("Varredura já concluída.");
        if (_set.Leaves.Count == 0 || chunk.IsEmpty) return;
        _raw.Text.Append(chunk);
        _folder.Append(chunk, _folded.Text);
        Drain(final: false);
    }

    public IReadOnlyList<Finding> Complete()
    {
        if (!_complete)
        {
            _complete = true;
            Drain(final: true);
        }
        var findings = new List<Finding>();
        foreach (var rule in _set.Rules)
        {
            if (!Evaluate(rule.When)) continue;
            string snippet = FirstSnippet(rule.When) ?? Masking.MaskSecret("regra");
            findings.Add(new Finding(rule.Alert ? Category.CustomRuleAlert : Category.CustomRule, snippet) { RuleName = rule.Name });
        }
        return findings;
    }

    private void Drain(bool final)
    {
        Process(_raw, folded: false, final);
        Process(_folded, folded: true, final);
    }

    private void Process(Stream stream, bool folded, bool final)
    {
        while (true)
        {
            long available = stream.Start + stream.Text.Length;
            long ownedEnd;
            if (final) ownedEnd = available;
            else if (available - stream.Pending >= Window + Lookahead) ownedEnd = stream.Pending + Window;
            else return;

            string text = stream.Text.ToString();
            for (int i = 0; i < _set.Leaves.Count; i++)
            {
                var leaf = _set.Leaves[i];
                if (leaf.Folded != folded) continue;
                long from = Math.Max(stream.Pending, _lastEnd[i]);
                if (from >= ownedEnd) continue;
                var match = leaf.Regex.Match(text, (int)(from - stream.Start));
                while (match.Success && stream.Start + match.Index < ownedEnd)
                {
                    if (match.Length == 0) break;
                    _lastEnd[i] = stream.Start + match.Index + match.Length;
                    string value = leaf.Group == 0 ? match.Value : match.Groups[leaf.Group].Value;
                    if (Valid(leaf.Validator, value))
                    {
                        _counts[i] = _counts[i] == int.MaxValue ? int.MaxValue : _counts[i] + 1;
                        _snippets[i] ??= Mask(value, leaf.Validator);
                    }
                    match = match.NextMatch();
                }
            }
            stream.Pending = ownedEnd;
            if (final) return;
            // Mantém só o contexto à esquerda necessário para \b e a próxima janela.
            long keepFrom = Math.Max(stream.Start, stream.Pending - LeftContext);
            stream.Text.Remove(0, (int)(keepFrom - stream.Start));
            stream.Start = keepFrom;
        }
    }

    private bool Evaluate(CustomCondition condition) => condition switch
    {
        AllCondition all => all.Children.All(Evaluate),
        AnyCondition any => any.Children.Any(Evaluate),
        NotCondition not => !Evaluate(not.Child),
        _ => _counts[_set.LeafOf(condition)] >= _set.Leaves[_set.LeafOf(condition)].Minimum
    };

    /// <summary>Trecho do primeiro indício positivo da regra (nunca de dentro de um "não").</summary>
    private string? FirstSnippet(CustomCondition condition) => condition switch
    {
        AllCondition all => all.Children.Select(FirstSnippet).FirstOrDefault(s => s is not null),
        AnyCondition any => any.Children.Where(Evaluate).Select(FirstSnippet).FirstOrDefault(s => s is not null),
        NotCondition => null,
        _ => _snippets[_set.LeafOf(condition)]
    };

    private static bool Valid(CustomValidator validator, string value)
    {
        if (validator == CustomValidator.None) return true;
        Span<char> digits = stackalloc char[Math.Min(value.Length, 64)];
        int count = 0;
        foreach (char c in value)
            if (char.IsAsciiDigit(c))
            {
                if (count == digits.Length) return false;
                digits[count++] = c;
            }
        var normalized = digits[..count];
        return validator switch
        {
            CustomValidator.Cpf => CpfValidator.IsValid(normalized),
            CustomValidator.Cnpj => CnpjValidator.IsValid(normalized),
            CustomValidator.Luhn => normalized.Length is >= 12 and <= 19 && LuhnValidator.IsValid(normalized),
            CustomValidator.Mod11 => Mod11Validator.IsValid(normalized),
            _ => false
        };
    }

    /// <summary>Números ficam com os dois últimos dígitos; texto fica com as duas primeiras e as duas últimas letras.</summary>
    private static string Mask(string value, CustomValidator validator)
    {
        if (validator != CustomValidator.None) return Masking.Mask(value);
        var trimmed = value.Trim();
        if (trimmed.Length <= 4) return new string(Masking.MaskChar, Math.Max(trimmed.Length, 1));
        var middle = new string(trimmed[2..^2].Select(c => char.IsLetterOrDigit(c) ? Masking.MaskChar : c).ToArray());
        return trimmed[..2] + middle + trimmed[^2..];
    }

    private sealed class Stream
    {
        public readonly StringBuilder Text = new();
        public long Start;
        public long Pending;
    }
}
