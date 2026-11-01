namespace SafeUpload.Agent.Network.Bypass;

/// <summary>
/// As listas iniciais de exceção, por categoria.
///
/// São as categorias em que ler o tráfego do funcionário expõe mais do que
/// protege: extrato e senha de banco, exame e laudo, serviço público com CPF e
/// conta gov.br. O que vai para esses sites não é inspecionado, e isso é uma
/// escolha (ver a decisão em aberto 3 do plano, sobre LGPD).
///
/// É uma lista curta de partida, não um catálogo. O que faltar entra pela
/// configuração (<c>InspecaoTls:Excecoes:Dominios</c>); a edição pelo painel
/// web e o envio com a política ficam para depois.
/// </summary>
public static class DefaultExceptionLists
{
    /// <summary>Bancos e meios de pagamento.</summary>
    public const string Banks = "bancos";

    /// <summary>Operadoras, hospitais e laboratórios.</summary>
    public const string Health = "saude";

    /// <summary>Governo, Judiciário, Legislativo e Ministério Público.</summary>
    public const string Government = "governo";

    /// <summary>Categoria dos domínios acrescentados pela configuração.</summary>
    public const string Configured = "configurado";

    /// <summary>Domínios de cada categoria.</summary>
    public static IReadOnlyDictionary<string, string[]> Categories { get; } = new Dictionary<string, string[]>
    {
        [Banks] =
        [
            "bb.com.br",
            "bancobrasil.com.br",
            "itau.com.br",
            "bradesco.com.br",
            "bradesco", // o banco tem domínio de topo próprio: banco.bradesco
            "santander.com.br",
            "nubank.com.br",
            "bancointer.com.br",
            "inter.co",
            "c6bank.com.br",
            "btgpactual.com",
            "safra.com.br",
            "sicredi.com.br",
            "sicoob.com.br",
            "banrisul.com.br",
            "bancopan.com.br",
            "original.com.br",
            "bv.com.br",
            "brb.com.br",
            "daycoval.com.br",
            "xpi.com.br",
            "pagbank.com.br",
            "pagseguro.uol.com.br",
            "mercadopago.com.br",
            "picpay.com",
            "stone.com.br",
        ],
        [Health] =
        [
            "unimed.coop.br",
            "amil.com.br",
            "bradescosaude.com.br",
            "sulamerica.com.br",
            "hapvida.com.br",
            "gndi.com.br",
            "preventsenior.com.br",
            "einstein.br",
            "hospitalsiriolibanes.org.br",
            "fleury.com.br",
            "dasa.com.br",
        ],
        [Government] =
        [
            // Sufixos reservados: só órgãos públicos registram abaixo deles.
            // caixa.gov.br e bnb.gov.br entram por aqui.
            "gov.br",
            "jus.br",
            "leg.br",
            "mp.br",
            "def.br",
            "mil.br",
        ],
    };
}
