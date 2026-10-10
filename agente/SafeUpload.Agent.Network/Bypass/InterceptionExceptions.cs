using System.Globalization;
using System.Net;

namespace SafeUpload.Agent.Network.Bypass;

/// <summary>
/// As exceções de interceptação (Fase 4 do plano): sites cujo tráfego o proxy
/// não abre.
///
/// Para um host em exceção o proxy vira um túnel: conecta no servidor e copia
/// bytes nos dois sentidos, sem trocar o certificado e sem ler nada. O
/// navegador fala TLS direto com o site, como se o proxy não existisse. É o
/// tratamento para o que não deve ser lido (banco, saúde, governo) e para o
/// que não funciona interceptado.
///
/// O casamento é por <b>sufixo de domínio, respeitando o limite do rótulo</b>:
/// a entrada <c>bb.com.br</c> cobre <c>bb.com.br</c> e <c>www2.bb.com.br</c>,
/// mas não <c>fakebb.com.br</c>. Sem o limite, quem registrasse um domínio
/// terminado no nome de um banco ganharia um túnel sem inspeção.
///
/// Cada entrada cobre todos os subdomínios. Uma entrada larga demais
/// (<c>com.br</c>) tira da inspeção tudo o que estiver abaixo dela.
/// </summary>
public sealed class InterceptionExceptions
{
    private static readonly IdnMapping Idn = new();

    private readonly Dictionary<string, string> _categoryByDomain = new(StringComparer.Ordinal);
    private readonly List<string> _ignored = [];

    /// <summary>Cria as exceções a partir de listas de domínios por categoria.</summary>
    /// <param name="categories">Nome da categoria e os domínios dela.</param>
    public InterceptionExceptions(IEnumerable<KeyValuePair<string, IEnumerable<string>>> categories)
    {
        ArgumentNullException.ThrowIfNull(categories);

        foreach ((string category, IEnumerable<string> domains) in categories)
        {
            foreach (string entry in domains)
            {
                if (TryNormalize(entry, out string domain))
                {
                    // Domínio repetido fica com a primeira categoria que o citou.
                    _categoryByDomain.TryAdd(domain, category);
                }
                else
                {
                    _ignored.Add(entry);
                }
            }
        }
    }

    /// <summary>Nenhuma exceção: tudo é interceptado.</summary>
    public static InterceptionExceptions None { get; } = new([]);

    /// <summary>Quantos domínios estão em exceção.</summary>
    public int Count => _categoryByDomain.Count;

    /// <summary>Entradas que não são um domínio e foram descartadas.</summary>
    public IReadOnlyList<string> Ignored => _ignored;

    /// <summary>Quantos domínios cada categoria tem, para o log de subida.</summary>
    public IReadOnlyDictionary<string, int> CountByCategory() =>
        _categoryByDomain.Values.GroupBy(category => category).ToDictionary(group => group.Key, group => group.Count());

    /// <summary>
    /// Categoria da exceção que cobre o host, ou nulo se ele deve ser
    /// interceptado.
    /// </summary>
    public string? Match(string host)
    {
        if (_categoryByDomain.Count == 0 || !TryNormalize(host, out string candidate))
        {
            return null;
        }

        // Do nome inteiro para os sufixos: "a.b.com.br", "b.com.br", "com.br", "br".
        // Cortar sempre num ponto é o que garante o limite do rótulo.
        while (true)
        {
            if (_categoryByDomain.TryGetValue(candidate, out string? category))
            {
                return category;
            }

            int dot = candidate.IndexOf('.');

            if (dot < 0)
            {
                return null;
            }

            candidate = candidate[(dot + 1)..];
        }
    }

    /// <summary>
    /// Reduz uma entrada de lista ou um host à forma comparável: minúsculas,
    /// sem "*." na frente, sem ponto final e em punycode. Endereço IP nunca
    /// casa: exceção é por nome.
    /// </summary>
    internal static bool TryNormalize(string? entry, out string domain)
    {
        domain = string.Empty;

        if (string.IsNullOrWhiteSpace(entry))
        {
            return false;
        }

        string text = entry.Trim();

        if (text.StartsWith("*.", StringComparison.Ordinal))
        {
            text = text[2..];
        }

        text = text.Trim('.');

        if (text.Length == 0 || text.AsSpan().IndexOfAny("/:@ \t") >= 0 || IPAddress.TryParse(text, out _))
        {
            return false;
        }

        try
        {
            domain = Idn.GetAscii(text).ToLowerInvariant();
            return true;
        }
        catch (ArgumentException)
        {
            return false;
        }
    }
}
