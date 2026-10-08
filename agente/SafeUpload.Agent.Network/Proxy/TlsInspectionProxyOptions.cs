using System.Net;
using System.Net.Security;
using SafeUpload.Agent.Network.Certificates;

namespace SafeUpload.Agent.Network.Proxy;

/// <summary>Configuração do proxy de inspeção.</summary>
public sealed record TlsInspectionProxyOptions
{
    /// <summary>
    /// Onde o proxy escuta. Sempre loopback: o proxy atende só esta máquina, e
    /// aberto na rede viraria um proxy para qualquer um.
    /// </summary>
    public IPEndPoint Listen { get; init; } = new(IPAddress.Loopback, 8877);

    /// <summary>
    /// Maior corpo que o proxy segura para inspecionar. Acima disso a
    /// requisição segue sem inspeção, para não segurar gigabytes em memória
    /// (a Fase 5 decide se isso vira bloqueio, como o limite de tamanho de
    /// arquivo da política).
    /// </summary>
    public int MaxInspectableBodyBytes { get; init; } = 64 * 1024 * 1024;

    /// <summary>
    /// Decide, pelo host do CONNECT, se a conexão é interceptada (verdadeiro)
    /// ou passa por túnel cego (falso). É aqui que entram as exceções da
    /// Fase 4: bancos, saúde, governo e apps com pinning.
    /// </summary>
    public Func<string, bool> ShouldIntercept { get; init; } = _ => true;

    /// <summary>
    /// Validação do certificado do servidor de verdade. Nulo é a validação
    /// padrão do Windows, que é o que deve valer em produção: o proxy nunca
    /// aceita um certificado que o navegador recusaria. Os testes trocam por
    /// uma validação com CA de teste.
    /// </summary>
    public RemoteCertificateValidationCallback? UpstreamCertificateValidation { get; init; }

    /// <summary>
    /// Tempo máximo esperando o navegador ou o servidor sem nenhum byte.
    /// Conexões keep-alive paradas são fechadas depois disso.
    /// </summary>
    public TimeSpan IdleTimeout { get; init; } = TimeSpan.FromMinutes(2);

    /// <summary>
    /// Lista de revogação que o proxy serve em
    /// <see cref="RevocationListPublisher.Path"/>. Precisa ser a mesma passada
    /// à <see cref="HostCertificateFactory"/>, cujos certificados apontam para ela.
    /// </summary>
    public RevocationListPublisher? RevocationList { get; init; }

    /// <summary>Tempo máximo para conectar ao servidor de destino.</summary>
    public TimeSpan ConnectTimeout { get; init; } = TimeSpan.FromSeconds(15);
}
