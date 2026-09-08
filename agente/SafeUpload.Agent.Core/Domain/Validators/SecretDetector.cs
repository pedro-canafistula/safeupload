using System.Text.RegularExpressions;

namespace SafeUpload.Agent.Core.Domain.Validators;

/// <summary>
/// Detecção de credencial de máquina: chave de nuvem, token de API, chave
/// privada.
///
/// <para><b>Por que existe.</b> Um desenvolvedor copia a pasta do projeto
/// para o Dropbox e leva junto um <c>appsettings.json</c> com a chave da AWS.
/// Nenhuma das outras regras dispara: não é CPF, não é CNPJ, não é cartão, e
/// a heurística de senha só reage ao par <c>senha=</c>. Uma chave vazada dá
/// acesso a tudo que ela abre e não expira sozinha — é o vazamento mais caro
/// por byte que este agente pode ver.</para>
///
/// <para><b>Por que é preciso, ao contrário da senha.</b> A RN-004 assume
/// falso positivo porque senha não tem forma verificável. Aqui é o oposto:
/// cada padrão abaixo tem prefixo fixo e comprimento fixo, definidos por quem
/// emite a credencial. <c>AKIA</c> seguido de 16 caracteres maiúsculos não
/// acontece por acaso num texto em português. O preço dessa precisão é
/// cobertura: só reconhece formatos conhecidos, e uma credencial de um
/// provedor que não está nesta lista passa despercebida.</para>
///
/// <para><b>O que deliberadamente não está aqui.</b> Deteção por entropia —
/// "qualquer sequência aleatória o bastante" — pegaria os provedores
/// desconhecidos e traria junto todo hash, UUID, identificador de commit e
/// string em base64 de qualquer arquivo. Numa regra que leva a bloqueio
/// (RN-005), isso tornaria o agente insuportável em qualquer máquina de
/// desenvolvimento.</para>
/// </summary>
public static partial class SecretDetector
{
    /// <summary>
    /// Uma credencial encontrada. Como em <see cref="PasswordHeuristic"/>, o
    /// valor não faz parte do tipo: quem chama recorta e mascara, de modo que
    /// nenhuma API do domínio devolva segredo em claro.
    /// </summary>
    /// <param name="Start">Início do trecho.</param>
    /// <param name="Length">Comprimento do trecho.</param>
    /// <param name="Kind">Rótulo do que foi reconhecido, para a auditoria.</param>
    public readonly record struct SecretMatch(int Start, int Length, string Kind);

    // Identificador de chave de acesso da AWS. O prefixo indica o tipo -
    // AKIA e chave de longa duracao, ASIA e temporaria de sessao - e os 16
    // caracteres seguintes sao fixos por especificacao.
    [GeneratedRegex(
        @"\b(?:AKIA|ASIA|ABIA|ACCA|A3T[A-Z0-9])[A-Z0-9]{16}\b",
        RegexOptions.CultureInvariant)]
    private static partial Regex AwsAccessKey();

    // Token do GitHub. O prefixo diz o tipo: ghp pessoal, gho de OAuth, ghs
    // de servidor, ghr de refresh.
    [GeneratedRegex(
        @"\bgh[pousr]_[A-Za-z0-9]{36,255}\b",
        RegexOptions.CultureInvariant)]
    private static partial Regex GitHubToken();

    // Chave de API do Google. Prefixo e comprimento fixos.
    [GeneratedRegex(
        @"\bAIza[0-9A-Za-z_\-]{35}\b",
        RegexOptions.CultureInvariant)]
    private static partial Regex GoogleApiKey();

    // Token do Slack.
    [GeneratedRegex(
        @"\bxox[baprs]-[A-Za-z0-9-]{10,}",
        RegexOptions.CultureInvariant)]
    private static partial Regex SlackToken();

    // Cabecalho de chave privada em PEM. Basta o cabecalho: se ele esta no
    // arquivo, a chave esta logo abaixo.
    [GeneratedRegex(
        @"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY-----",
        RegexOptions.CultureInvariant)]
    private static partial Regex PrivateKeyHeader();

    // JSON Web Token: tres segmentos em base64url separados por ponto, o
    // primeiro comecando pelo cabecalho {"alg" codificado, que sempre produz
    // "eyJ".
    [GeneratedRegex(
        @"\beyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}",
        RegexOptions.CultureInvariant)]
    private static partial Regex JsonWebToken();

    private static readonly (Func<Regex> Pattern, string Kind)[] Rules =
    [
        (PrivateKeyHeader, "chave privada"),
        (AwsAccessKey, "chave da AWS"),
        (GitHubToken, "token do GitHub"),
        (GoogleApiKey, "chave do Google"),
        (SlackToken, "token do Slack"),
        (JsonWebToken, "JSON Web Token")
    ];

    /// <summary>
    /// Devolve todas as credenciais reconhecidas, na ordem em que aparecem.
    /// </summary>
    public static IReadOnlyList<SecretMatch> Find(string text)
    {
        ArgumentNullException.ThrowIfNull(text);

        var matches = new List<SecretMatch>();

        foreach ((Func<Regex> pattern, string kind) in Rules)
        {
            foreach (Match match in pattern().Matches(text))
            {
                matches.Add(new SecretMatch(match.Index, match.Length, kind));
            }
        }

        matches.Sort(static (a, b) => a.Start.CompareTo(b.Start));

        return matches;
    }
}
