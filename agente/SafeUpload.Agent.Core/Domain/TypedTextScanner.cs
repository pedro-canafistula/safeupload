using System.Text.RegularExpressions;
using SafeUpload.Agent.Core.Domain.Validators;

namespace SafeUpload.Agent.Core.Domain;

/// <summary>
/// Varre texto que saiu por uma requisição web e não é um arquivo: campo de
/// formulário, prompt de IA, corpo em JSON.
///
/// O <see cref="ContentScanner"/> foi feito para documentos e é agressivo de
/// propósito: qualquer sequência de 11 dígitos com dígito verificador de CPF
/// conta, qualquer 16 que passe no Luhn conta, <c>senha=...</c> conta. Num
/// documento isso é raro por acaso. No tráfego de um navegador é o normal: as
/// páginas mandam telemetria o tempo todo, cheia de identificadores,
/// carimbos de tempo e tokens de sessão, e um em cada dez números de 16
/// dígitos passa no Luhn. Na qualificação (Fase 7) o scanner de documentos
/// barrou o SmartScreen do Edge, métricas do GitHub, do YouTube e do Dropbox,
/// e barraria todo login, porque todo login manda <c>password=...</c>.
///
/// Aqui a régua é a de texto escrito por uma pessoa:
///
/// - <b>CPF, CNPJ e cartão</b> contam quando estão na forma em que se
///   escrevem (<c>529.982.247-25</c>, <c>12.345.678/0001-95</c>,
///   <c>4111 1111 1111 1111</c>) ou quando o nome do dado aparece logo antes
///   (<c>cpf: 52998224725</c>, <c>"cpf":"52998224725"</c>). O número precisa
///   estar inteiro e isolado: um trecho de um identificador mais longo não conta.
/// - <b>Segredos</b> contam os que são do usuário e nunca do site: chave
///   privada, chave da AWS, token do GitHub e do Slack. JWT e chave de API do
///   Google ficam de fora, porque são o que as próprias páginas enviam para
///   se autenticar.
/// - <b>Senha</b> não conta: digitar a senha no formulário de login do site é
///   o uso normal dela.
///
/// O preço: um CPF digitado só com os números, sem a palavra "cpf" por perto,
/// passa. Arquivos enviados continuam no <see cref="ContentScanner"/> completo.
/// </summary>
public static partial class TypedTextScanner
{
    /// <summary>Até quantos caracteres antes do número o nome do dado vale.</summary>
    private const int KeywordReach = 32;

    private static readonly string[] SiteOwnSecrets = ["JSON Web Token", "chave do Google"];

    // Formas escritas. O (?<!...) e o (?!...) exigem que o número esteja
    // isolado, e não no meio de uma sequência maior.
    [GeneratedRegex(@"(?<![\w.\-/])\d{3}\.\d{3}\.\d{3}-\d{2}(?![\w\-/]|\.\d)", RegexOptions.CultureInvariant)]
    private static partial Regex WrittenCpf();

    [GeneratedRegex(@"(?<![\w.\-/])\d{2}\.\d{3}\.\d{3}/\d{4}-\d{2}(?![\w\-/]|\.\d)", RegexOptions.CultureInvariant)]
    private static partial Regex WrittenCnpj();

    [GeneratedRegex(@"(?<![\w.\-/])\d{4}([ \-])\d{4}\1\d{4}\1\d{4}(?![\w\-/]|\.\d| \d)", RegexOptions.CultureInvariant)]
    private static partial Regex WrittenCard();

    // Só os dígitos: valem com o nome do dado antes.
    [GeneratedRegex(@"(?<![\w.\-/])\d{11}(?![\w\-/]|\.\d)", RegexOptions.CultureInvariant)]
    private static partial Regex BareCpf();

    [GeneratedRegex(@"(?<![\w.\-/])\d{14}(?![\w\-/]|\.\d)", RegexOptions.CultureInvariant)]
    private static partial Regex BareCnpj();

    [GeneratedRegex(@"(?<![\w.\-/])\d{16}(?![\w\-/]|\.\d)", RegexOptions.CultureInvariant)]
    private static partial Regex BareCard();

    private static readonly (Category Category, Func<Regex> Written, Func<Regex> Bare, string[] Keywords)[] NumericRules =
    [
        (Category.PaymentCard, WrittenCard, BareCard, ["cartão", "cartao", "card", "crédito", "credito"]),
        (Category.Cnpj, WrittenCnpj, BareCnpj, ["cnpj"]),
        (Category.Cpf, WrittenCpf, BareCpf, ["cpf"]),
    ];

    /// <summary>
    /// Varre <paramref name="text"/> procurando apenas as categorias em
    /// <paramref name="active"/>. Devolve achados mascarados, na ordem em que
    /// aparecem.
    /// </summary>
    public static IReadOnlyList<Finding> Scan(string text, IReadOnlySet<Category> active)
    {
        ArgumentNullException.ThrowIfNull(text);
        ArgumentNullException.ThrowIfNull(active);

        if (text.Length == 0 || active.Count == 0)
        {
            return [];
        }

        var found = new List<(int Start, int End, Finding Finding)>();

        foreach (var (category, written, bare, keywords) in NumericRules)
        {
            if (!active.Contains(category))
            {
                continue;
            }

            foreach (Match match in written().Matches(text))
            {
                AddNumber(found, category, text, match);
            }

            foreach (Match match in bare().Matches(text))
            {
                if (HasKeywordBefore(text, match.Index, keywords))
                {
                    AddNumber(found, category, text, match);
                }
            }
        }

        if (active.Contains(Category.Secret))
        {
            foreach (var secret in SecretDetector.Find(text))
            {
                if (!SiteOwnSecrets.Contains(secret.Kind) && !Overlaps(found, secret.Start, secret.Start + secret.Length - 1))
                {
                    found.Add((secret.Start, secret.Start + secret.Length - 1, new Finding(Category.Secret, Masking.MaskSecret(secret.Kind))));
                }
            }
        }

        found.Sort(static (a, b) => a.Start.CompareTo(b.Start));
        return found.ConvertAll(static entry => entry.Finding);
    }

    private static void AddNumber(List<(int Start, int End, Finding Finding)> found, Category category, string text, Match match)
    {
        int end = match.Index + match.Length - 1;

        if (Overlaps(found, match.Index, end))
        {
            return;
        }

        string digits = string.Concat(match.Value.Where(char.IsAsciiDigit));

        bool valid = category switch
        {
            Category.PaymentCard => LuhnValidator.IsValid(digits),
            Category.Cnpj => CnpjValidator.IsValid(digits),
            Category.Cpf => CpfValidator.IsValid(digits),
            _ => false,
        };

        if (valid)
        {
            found.Add((match.Index, end, new Finding(category, Masking.Mask(digits))));
        }
    }

    private static bool HasKeywordBefore(string text, int position, string[] keywords)
    {
        int start = Math.Max(0, position - KeywordReach);
        ReadOnlySpan<char> before = text.AsSpan(start, position - start);

        foreach (string keyword in keywords)
        {
            if (before.Contains(keyword, StringComparison.OrdinalIgnoreCase))
            {
                return true;
            }
        }

        return false;
    }

    private static bool Overlaps(List<(int Start, int End, Finding Finding)> found, int start, int end)
    {
        foreach (var (otherStart, otherEnd, _) in found)
        {
            if (start <= otherEnd && otherStart <= end)
            {
                return true;
            }
        }

        return false;
    }
}
