using System.Text;

namespace SafeUpload.Agent.Network.Http;

/// <summary>
/// Cabeçalhos de uma mensagem HTTP/1.1, na ordem em que chegaram.
///
/// A ordem e a grafia originais são preservadas porque o proxy repassa os
/// cabeçalhos ao outro lado; alguns servidores e sistemas antifraude reparam
/// quando a ordem muda. A busca por nome ignora maiúsculas, como manda a RFC 9110.
/// </summary>
public sealed class HttpHeaders
{
    private readonly List<KeyValuePair<string, string>> _fields = [];

    /// <summary>Os campos, na ordem original.</summary>
    public IReadOnlyList<KeyValuePair<string, string>> Fields => _fields;

    /// <summary>Acrescenta um campo ao fim.</summary>
    public void Add(string name, string value) => _fields.Add(new(name, value));

    /// <summary>Primeiro valor do campo, ou nulo.</summary>
    public string? Get(string name)
    {
        foreach (KeyValuePair<string, string> field in _fields)
        {
            if (string.Equals(field.Key, name, StringComparison.OrdinalIgnoreCase))
            {
                return field.Value;
            }
        }

        return null;
    }

    /// <summary>Remove todas as ocorrências do campo.</summary>
    public void Remove(string name) =>
        _fields.RemoveAll(field => string.Equals(field.Key, name, StringComparison.OrdinalIgnoreCase));

    /// <summary>Troca o valor do campo (ou o acrescenta, se não existir).</summary>
    public void Set(string name, string value)
    {
        Remove(name);
        Add(name, value);
    }

    /// <summary>
    /// Indica se a lista separada por vírgulas do campo contém o token
    /// (ex.: <c>Connection: keep-alive, Upgrade</c> contém <c>upgrade</c>).
    /// </summary>
    public bool HasToken(string name, string token)
    {
        foreach (KeyValuePair<string, string> field in _fields)
        {
            if (!string.Equals(field.Key, name, StringComparison.OrdinalIgnoreCase))
            {
                continue;
            }

            foreach (string part in field.Value.Split(','))
            {
                if (string.Equals(part.Trim(), token, StringComparison.OrdinalIgnoreCase))
                {
                    return true;
                }
            }
        }

        return false;
    }

    internal void WriteTo(StringBuilder builder)
    {
        foreach (KeyValuePair<string, string> field in _fields)
        {
            builder.Append(field.Key).Append(": ").Append(field.Value).Append("\r\n");
        }
    }
}
