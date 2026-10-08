using System.Numerics;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace SafeUpload.Agent.Network.Certificates;

/// <summary>
/// A lista de certificados revogados (CRL) da CA de inspeção, servida pelo
/// próprio proxy.
///
/// Por que existe: o TLS do Windows (SChannel), usado pelo curl, pelo Outlook,
/// pelo Teams e por boa parte dos programas que não são navegadores, exige
/// verificar se o certificado do site foi revogado. Um certificado que não diz
/// onde verificar é recusado com CRYPT_E_NO_REVOCATION_CHECK. Chrome e Edge não
/// fazem essa verificação, por isso funcionavam sem ela.
///
/// Cada certificado emitido aponta para esta lista (extensão CRL Distribution
/// Points), e o proxy a entrega em <c>http://127.0.0.1:porta/safeupload-ca.crl</c>.
/// A lista é vazia, porque o agente não revoga certificados (eles valem 7
/// dias), mas é assinada pela CA, e isso basta para a verificação passar.
/// </summary>
public sealed class RevocationListPublisher
{
    /// <summary>Caminho em que o proxy serve a lista.</summary>
    public const string Path = "/safeupload-ca.crl";

    private static readonly TimeSpan Lifetime = TimeSpan.FromDays(7);
    private static readonly TimeSpan RenewalMargin = TimeSpan.FromDays(1);

    private readonly X509Certificate2 _authority;
    private readonly Lock _gate = new();
    private byte[]? _current;
    private DateTimeOffset _nextUpdate;

    public RevocationListPublisher(X509Certificate2 authority, Uri address)
    {
        ArgumentNullException.ThrowIfNull(authority);
        ArgumentNullException.ThrowIfNull(address);
        _authority = authority;
        Address = address;
    }

    /// <summary>Endereço da lista, gravado em cada certificado emitido.</summary>
    public Uri Address { get; }

    /// <summary>
    /// A lista atual, em DER. Assinada de novo quando falta menos de um dia
    /// para vencer: o Windows guarda a lista em cache até a data de próxima
    /// atualização e só então busca outra.
    /// </summary>
    public byte[] GetCurrent()
    {
        lock (_gate)
        {
            DateTimeOffset now = DateTimeOffset.UtcNow;

            if (_current is null || _nextUpdate - now < RenewalMargin)
            {
                _nextUpdate = now.Add(Lifetime);

                // O número da lista só precisa crescer; o horário em segundos
                // cresce sozinho, inclusive entre reinícios do serviço.
                var number = new BigInteger(now.ToUnixTimeSeconds());

                _current = new CertificateRevocationListBuilder().Build(
                    _authority, number, _nextUpdate, HashAlgorithmName.SHA256, thisUpdate: now.AddMinutes(-5));
            }

            return _current;
        }
    }

    /// <summary>A extensão que aponta para esta lista, para pôr nos certificados emitidos.</summary>
    internal X509Extension DistributionPointExtension() =>
        CertificateRevocationListBuilder.BuildCrlDistributionPointExtension([Address.AbsoluteUri], critical: false);
}
