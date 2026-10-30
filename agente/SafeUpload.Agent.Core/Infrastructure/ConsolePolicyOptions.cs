using System.Net;
using System.Net.Sockets;
using System.Text.Json;
using SafeUpload.Agent.Core.Domain;

namespace SafeUpload.Agent.Core.Infrastructure;

/// <summary>Opt-in para o contrato administrativo publicado na main 6e4ec708.
/// O IP seleciona a consulta; id_host continua sendo a identidade conferida.</summary>
public sealed record ConsolePolicyOptions
{
    public int RegisteredHostId { get; }
    public string HostIp { get; }

    public ConsolePolicyOptions(int registeredHostId, string hostIp)
    {
        if (registeredHostId <= 0 ||
            !IPAddress.TryParse(hostIp, out var ip) || ip.AddressFamily != AddressFamily.InterNetwork ||
            ip.ToString() != hostIp)
            throw new ArgumentException("Política da console exige id_host positivo e IPv4 canônico.");
        RegisteredHostId = registeredHostId;
        HostIp = hostIp;
    }

    internal string RequestPath => "api/policy?ip=" + Uri.EscapeDataString(HostIp);

    internal ConsolePolicyCache Wrap(Uri server, PolicyDocument policy) =>
        new(1, server.AbsoluteUri, RegisteredHostId, HostIp, policy);

    internal PolicyDocument ReadCache(ConsolePolicyCache cache, Uri server)
    {
        if (cache.Format != 1 || cache.Server != server.AbsoluteUri ||
            cache.HostId != RegisteredHostId || cache.Ip != HostIp || cache.Policy is null)
            throw new InvalidPolicyException("Cache da console pertence a outro vínculo ou formato.");
        return cache.Policy;
    }

    internal PolicyDocument Translate(JsonElement root, Policy operational)
    {
        RejectDuplicates(root);
        int revision = PositiveInt(root, "idPolitica");
        if (Text(root, "versao") != "1.0")
            throw new InvalidPolicyException("Formato de política da console não suportado.");
        var destination = Field(root, "destino");
        if (PositiveInt(destination, "idHost") != RegisteredHostId || Text(destination, "ip") != HostIp)
            throw new InvalidPolicyException("Política da console destinada a outro host.");

        string action = Text(root, "acao");
        if (action is not ("bloquear" or "alertar"))
            throw new InvalidPolicyException("Ação da console não suportada.");

        var rules = Field(root, "regras");
        if (rules.ValueKind != JsonValueKind.Array || rules.GetArrayLength() is 0 or > 32)
            throw new InvalidPolicyException("Lista de regras da console inválida.");
        var categories = new HashSet<Category>();
        foreach (var rule in rules.EnumerateArray())
        {
            switch (Text(rule, "tipo"))
            {
                case "cpf": categories.Add(Category.Cpf); break;
                case "cnpj": categories.Add(Category.Cnpj); break;
                case "cartao_credito": categories.Add(Category.PaymentCard); break;
                case "credenciais":
                    categories.Add(Category.Password);
                    categories.Add(Category.Secret);
                    break;
                default:
                    // Não aplicar apenas uma fração das regras como se fosse a política completa.
                    throw new InvalidPolicyException("Regra da console não suportada pelo agente.");
            }
        }

        // A console atual envia versao="1.0" em toda publicação.
        // idPolitica identifica cada publicação e invalida decisões da política anterior.
        return PolicyDocument.FromPolicy(operational) with
        {
            Version = revision,
            ActiveCategories = categories.Order().Select(c => c.ToString()).ToArray(),
            AuditOnly = action == "alertar",
            OverrideAllowed = false
        };
    }

    private static JsonElement Field(JsonElement root, string name)
    {
        if (root.ValueKind != JsonValueKind.Object || !root.TryGetProperty(name, out var field))
            throw new InvalidPolicyException("Documento da console incompleto.");
        return field;
    }

    private static int PositiveInt(JsonElement root, string name)
    {
        var field = Field(root, name);
        if (field.ValueKind != JsonValueKind.Number || !field.TryGetInt32(out int value) || value <= 0)
            throw new InvalidPolicyException("Identificador da política da console inválido.");
        return value;
    }

    private static string Text(JsonElement root, string name)
    {
        var field = Field(root, name);
        if (field.ValueKind != JsonValueKind.String || string.IsNullOrWhiteSpace(field.GetString()))
            throw new InvalidPolicyException("Campo textual da console inválido.");
        return field.GetString()!;
    }

    internal static void RejectDuplicates(JsonElement element)
    {
        if (element.ValueKind == JsonValueKind.Object)
        {
            var names = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            foreach (var property in element.EnumerateObject())
            {
                if (!names.Add(property.Name))
                    throw new InvalidPolicyException("Documento de política com campo repetido.");
                RejectDuplicates(property.Value);
            }
        }
        else if (element.ValueKind == JsonValueKind.Array)
            foreach (var child in element.EnumerateArray()) RejectDuplicates(child);
    }
}

internal sealed record ConsolePolicyCache(int Format, string Server, int HostId, string Ip, PolicyDocument Policy);
