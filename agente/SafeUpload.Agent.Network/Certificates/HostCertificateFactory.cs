using System.Collections.Concurrent;
using System.Net;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace SafeUpload.Agent.Network.Certificates;

/// <summary>
/// Emite, na hora, o certificado que o proxy apresenta ao navegador para cada
/// site (Fase 1 do plano de inspeção TLS).
///
/// Quando o navegador pede drive.google.com, o proxy precisa de um certificado
/// para drive.google.com assinado pela CA local. Gerar um a cada conexão seria
/// caro (uma assinatura por conexão, e o navegador abre várias por página), por
/// isso cada host é emitido uma vez e fica em cache na memória.
///
/// Os certificados de site usam todos a mesma chave, gerada quando o objeto é
/// criado e que nunca sai da memória do processo. É a mesma escolha do
/// mitmproxy: quem consegue ler a memória do serviço já está dentro de tudo o
/// que o proxy vê, e uma chave por site só multiplicaria o custo de cada
/// primeira visita. O que protege a máquina é a chave da CA, que fica no
/// provedor de chaves e não é exportável.
/// </summary>
public sealed class HostCertificateFactory : IDisposable
{
    /// <summary>
    /// Validade de cada certificado emitido. Curta de propósito: não há lista de
    /// revogação, então o que limita o uso de um certificado vazado é o prazo.
    /// O cache troca o certificado antes de vencer.
    /// </summary>
    private static readonly TimeSpan Lifetime = TimeSpan.FromDays(7);

    /// <summary>Antecedência com que um certificado em cache é reemitido.</summary>
    private static readonly TimeSpan RenewalMargin = TimeSpan.FromDays(1);

    /// <summary>
    /// Teto do cache. Navegação comum fica em algumas centenas de hosts; o
    /// teto só existe para que um processo que abra conexões para milhares de
    /// nomes não faça a memória do serviço crescer sem limite.
    /// </summary>
    private const int MaxEntries = 2000;

    private readonly X509Certificate2 _authority;
    private readonly ECDsa _leafKey;
    private readonly ConcurrentDictionary<string, Lazy<X509Certificate2>> _cache =
        new(StringComparer.OrdinalIgnoreCase);

    /// <summary>
    /// Cria a fábrica sobre uma CA. A CA precisa ter chave privada: é ela que
    /// assina cada certificado emitido.
    /// </summary>
    public HostCertificateFactory(X509Certificate2 authority)
    {
        ArgumentNullException.ThrowIfNull(authority);

        if (!authority.HasPrivateKey)
        {
            throw new ArgumentException("A CA precisa ter chave privada para emitir certificados.", nameof(authority));
        }

        _authority = authority;
        _leafKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
    }

    /// <summary>Quantos hosts estão em cache. Serve aos testes e ao diagnóstico.</summary>
    public int CachedCount => _cache.Count;

    /// <summary>
    /// Devolve o certificado para o host, emitindo-o se ainda não estiver em
    /// cache ou se estiver perto de vencer. Aceita nome (drive.google.com) ou
    /// endereço IP.
    /// </summary>
    public X509Certificate2 GetCertificate(string host)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(host);

        string key = host.Trim().TrimEnd('.').ToLowerInvariant();

        if (_cache.TryGetValue(key, out Lazy<X509Certificate2>? cached) && IsFresh(cached))
        {
            return cached.Value;
        }

        if (_cache.Count >= MaxEntries)
        {
            // Esvaziar tudo é grosseiro, mas simples e correto: o pior efeito é
            // reemitir certificados de sites que voltarem a ser visitados.
            // Os certificados descartados não são liberados aqui de propósito,
            // porque uma conexão em andamento pode estar usando um deles; o
            // coletor de lixo cuida deles quando ninguém mais os referenciar.
            _cache.Clear();
        }

        // Lazy garante uma emissão só por host, mesmo com várias conexões
        // pedindo o mesmo site ao mesmo tempo (o que o navegador faz).
        var fresh = new Lazy<X509Certificate2>(() => Issue(key), LazyThreadSafetyMode.ExecutionAndPublication);

        Lazy<X509Certificate2> winner = _cache.AddOrUpdate(
            key,
            fresh,
            (_, current) => IsFresh(current) ? current : fresh);

        try
        {
            return winner.Value;
        }
        catch
        {
            // O Lazy guardaria a exceção para sempre; tirar a entrada faz a
            // próxima conexão para o mesmo host tentar emitir de novo.
            _cache.TryRemove(new KeyValuePair<string, Lazy<X509Certificate2>>(key, winner));
            throw;
        }
    }

    /// <inheritdoc />
    public void Dispose()
    {
        _leafKey.Dispose();
    }

    private static bool IsFresh(Lazy<X509Certificate2> entry) =>
        !entry.IsValueCreated || entry.Value.NotAfter.ToUniversalTime() - DateTime.UtcNow > RenewalMargin;

    private X509Certificate2 Issue(string host)
    {
        var request = new CertificateRequest($"CN={host}", _leafKey, HashAlgorithmName.SHA256);

        // O navegador não olha o CN: o nome do site tem que estar na extensão
        // Subject Alternative Name. Sem ela o Chrome recusa o certificado.
        var names = new SubjectAlternativeNameBuilder();

        if (IPAddress.TryParse(host.Trim('[', ']'), out IPAddress? address))
        {
            names.AddIpAddress(address);
        }
        else
        {
            names.AddDnsName(host);
        }

        request.CertificateExtensions.Add(names.Build(critical: false));
        request.CertificateExtensions.Add(
            new X509BasicConstraintsExtension(certificateAuthority: false, hasPathLengthConstraint: false, pathLengthConstraint: 0, critical: true));
        request.CertificateExtensions.Add(
            new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature, critical: true));

        // Uso estendido "autenticação de servidor": este certificado serve para
        // um site se identificar, e para nada mais.
        request.CertificateExtensions.Add(
            new X509EnhancedKeyUsageExtension([new Oid("1.3.6.1.5.5.7.3.1")], critical: false));
        request.CertificateExtensions.Add(
            new X509SubjectKeyIdentifierExtension(request.PublicKey, critical: false));
        request.CertificateExtensions.Add(
            X509AuthorityKeyIdentifierExtension.CreateFromCertificate(_authority, includeKeyIdentifier: true, includeIssuerAndSerial: false));

        DateTimeOffset now = DateTimeOffset.UtcNow;
        DateTimeOffset notAfter = now.Add(Lifetime);

        // Um certificado não pode valer além da CA que o assinou.
        if (notAfter > _authority.NotAfter)
        {
            notAfter = _authority.NotAfter;
        }

        byte[] serial = RandomNumberGenerator.GetBytes(16);
        serial[0] &= 0x7F; // número de série positivo, como a RFC 5280 exige

        using X509Certificate2 signed = request.Create(_authority, now.AddDays(-1), notAfter, serial);
        using X509Certificate2 withKey = signed.CopyWithPrivateKey(_leafKey);

        // O SslStream no Windows usa o SChannel, que não aceita chave que só
        // existe na memória do .NET ("ephemeral key"). Exportar e reimportar
        // como PKCS#12 coloca a chave num contêiner que o SChannel consegue usar.
        return X509CertificateLoader.LoadPkcs12(withKey.Export(X509ContentType.Pkcs12), password: null);
    }
}
