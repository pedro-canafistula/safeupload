using System.Text.RegularExpressions;

namespace SafeUpload.Agent.Core.Domain.Validators;

/// <summary>
/// RN-004 — detecção de senha em texto.
///
/// Diferente de CPF, CNPJ e cartão, uma senha não tem forma verificável: não há
/// dígito verificador nem checksum que diga "isto é uma senha". A regra aqui é
/// puramente sintática — procura o par chave-valor
/// <c>senha|password|passwd|pwd</c> seguido de <c>:</c> ou <c>=</c> e de pelo
/// menos quatro caracteres sem espaço.
///
/// Consequência assumida: <b>esta regra produz falsos positivos</b>. Frases como
/// "senha: seguir o padrão", trechos de documentação, exemplos em manuais e
/// campos de formulário em branco disparam a detecção. Como qualquer achado
/// leva a bloqueio (RN-005), o custo do falso positivo recai sobre o usuário,
/// que precisa editar o arquivo. A alternativa — exigir entropia mínima no
/// valor — reduziria o ruído mas deixaria passar senhas fracas, que são
/// justamente as que mais aparecem em planilhas compartilhadas. O projeto
/// escolheu errar para o lado do bloqueio e documentar a limitação.
/// </summary>
public static partial class PasswordHeuristic
{
    /// <summary>
    /// Posição de uma ocorrência no texto. O valor da senha propositalmente
    /// não faz parte deste tipo: quem chama recorta e mascara, de modo que
    /// nenhuma API do domínio devolva segredo em claro.
    /// </summary>
    /// <param name="Start">Início do trecho completo (rótulo + separador + valor).</param>
    /// <param name="Length">Comprimento do trecho completo.</param>
    /// <param name="SecretStart">Início apenas do valor.</param>
    /// <param name="SecretLength">Comprimento apenas do valor.</param>
    public readonly record struct PasswordMatch(int Start, int Length, int SecretStart, int SecretLength);

    [GeneratedRegex(
        @"\b(senha|password|passwd|pwd)\s*[:=]\s*(\S{4,})",
        RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex KeyValuePattern();

    /// <summary>
    /// Devolve todas as ocorrências do padrão chave-valor no texto, na ordem
    /// em que aparecem.
    /// </summary>
    public static IReadOnlyList<PasswordMatch> Find(string text)
    {
        ArgumentNullException.ThrowIfNull(text);

        var matches = KeyValuePattern().Matches(text);
        if (matches.Count == 0)
        {
            return [];
        }

        var result = new List<PasswordMatch>(matches.Count);
        foreach (Match match in matches)
        {
            var secret = match.Groups[2];
            result.Add(new PasswordMatch(match.Index, match.Length, secret.Index, secret.Length));
        }

        return result;
    }
}
