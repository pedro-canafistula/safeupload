using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace SafeUpload.Agent.Network.Certificates;

/// <summary>
/// A autoridade certificadora local que assina os certificados que o proxy
/// apresenta ao navegador (Fase 1 do plano de inspeção TLS).
///
/// Para inspecionar um upload para drive.google.com, o proxy precisa se
/// apresentar ao navegador como drive.google.com. O navegador só aceita isso
/// se o certificado apresentado for assinado por uma CA em que ele confia. Esta
/// classe cria essa CA e a coloca em LocalMachine\Root, que é a lista de
/// raízes confiáveis do Windows, usada pelo Chrome e pelo Edge (e pelo Firefox,
/// com <see cref="FirefoxEnterpriseRoots"/>).
///
/// Três decisões de segurança, todas pelo mesmo motivo: quem tem a chave
/// privada desta CA consegue se passar por qualquer site nesta máquina.
///
/// - **Uma CA por máquina, gerada na própria máquina.** Uma CA compartilhada
///   faria do vazamento da chave de um único computador um ataque contra todos.
///   Gerada aqui, a chave nunca existiu em outro lugar.
/// - **Chave não exportável.** A chave é criada dentro do provedor de chaves do
///   Windows (CNG) com política de exportação vazia: o sistema assina com ela,
///   mas se recusa a entregá-la, inclusive a administradores pelas APIs comuns.
/// - **Chave da máquina, não do usuário.** O serviço roda como SYSTEM, e a
///   chave precisa existir independentemente de quem estiver logado.
///
/// O algoritmo é ECDSA P-256: assina bem mais rápido que RSA, o que importa
/// porque o proxy gera certificados enquanto o navegador espera, e é aceito por
/// todos os navegadores atuais.
/// </summary>
public sealed class MachineCertificateAuthority
{
    /// <summary>
    /// Antecedência com que uma CA perto de vencer é substituída. Uma CA que
    /// vence com o serviço rodando derrubaria toda a navegação inspecionada.
    /// </summary>
    private static readonly TimeSpan RenewalMargin = TimeSpan.FromDays(30);

    /// <summary>Validade de uma CA nova.</summary>
    private static readonly TimeSpan Lifetime = TimeSpan.FromDays(3650);

    private readonly CertificateAuthorityOptions _options;

    /// <summary>Usa a configuração do agente (<see cref="CertificateAuthorityOptions.Machine"/>).</summary>
    public MachineCertificateAuthority() : this(CertificateAuthorityOptions.Machine)
    {
    }

    /// <summary>Usa uma configuração específica. Serve aos testes.</summary>
    public MachineCertificateAuthority(CertificateAuthorityOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);
        _options = options;
    }

    /// <summary>
    /// Devolve a CA desta máquina, criando-a se ainda não existir ou se estiver
    /// perto de vencer.
    ///
    /// Também refaz a confiança em Root se alguém a tiver removido: sem ela o
    /// navegador recusa todos os sites inspecionados, e o usuário veria isso
    /// como "a internet quebrou".
    ///
    /// Exige administrador (ou SYSTEM) na configuração da máquina.
    /// </summary>
    public X509Certificate2 LoadOrCreate()
    {
        X509Certificate2? existing = Find();

        if (existing is not null && existing.NotAfter.ToUniversalTime() - DateTime.UtcNow > RenewalMargin)
        {
            if (_options.TrustInRoot && !IsTrusted(existing))
            {
                AddToRoot(existing);
            }

            return existing;
        }

        existing?.Dispose();

        // Antes de criar, tira de cena CAs anteriores com o mesmo nome (a
        // vencida, ou restos de uma criação interrompida). Deixá-las em Root
        // manteria confiável uma chave que este agente já abandonou.
        RemoveCertificates();
        Create();

        return Find()
            ?? throw new CryptographicException("A CA foi criada, mas não foi encontrada no repositório de certificados.");
    }

    /// <summary>
    /// Procura a CA já criada: certificado com o assunto configurado, com chave
    /// privada e cuja chave é a chave CNG deste agente. Devolve nulo se não houver.
    /// </summary>
    public X509Certificate2? Find()
    {
        using var store = new X509Store(StoreName.My, _options.Location);
        store.Open(OpenFlags.ReadOnly);

        X509Certificate2? best = null;

        foreach (X509Certificate2 candidate in store.Certificates.Find(
                     X509FindType.FindBySubjectDistinguishedName, _options.SubjectName, validOnly: false))
        {
            if (best is null || candidate.NotAfter > best.NotAfter)
            {
                if (UsesOurKey(candidate))
                {
                    best?.Dispose();
                    best = candidate;
                    continue;
                }
            }

            candidate.Dispose();
        }

        return best;
    }

    /// <summary>Indica se o certificado está na lista de raízes confiáveis.</summary>
    public bool IsTrusted(X509Certificate2 authority)
    {
        ArgumentNullException.ThrowIfNull(authority);

        using var root = new X509Store(StoreName.Root, _options.Location);
        root.Open(OpenFlags.ReadOnly);

        X509Certificate2Collection found = root.Certificates.Find(
            X509FindType.FindByThumbprint, authority.Thumbprint, validOnly: false);

        bool trusted = found.Count > 0;

        foreach (X509Certificate2 certificate in found)
        {
            certificate.Dispose();
        }

        return trusted;
    }

    /// <summary>
    /// Desfaz tudo: tira a CA de Root e de My e apaga a chave. É o passo da
    /// desinstalação. Uma CA de inspeção esquecida numa máquina sem o agente
    /// continuaria confiável sem servir a nada, e isso é risco sem benefício.
    /// </summary>
    public void Remove()
    {
        RemoveCertificates();

        CngKeyOpenOptions openOptions = _options.MachineKey ? CngKeyOpenOptions.MachineKey : CngKeyOpenOptions.None;

        if (CngKey.Exists(_options.KeyName, CngProvider.MicrosoftSoftwareKeyStorageProvider, openOptions))
        {
            using CngKey key = CngKey.Open(_options.KeyName, CngProvider.MicrosoftSoftwareKeyStorageProvider, openOptions);
            key.Delete();
        }
    }

    private void Create()
    {
        var keyParameters = new CngKeyCreationParameters
        {
            Provider = CngProvider.MicrosoftSoftwareKeyStorageProvider,
            KeyCreationOptions = CngKeyCreationOptions.OverwriteExistingKey
                | (_options.MachineKey ? CngKeyCreationOptions.MachineKey : CngKeyCreationOptions.None),

            // A decisão central: a chave pode assinar, mas não pode sair.
            ExportPolicy = CngExportPolicies.None,
            KeyUsage = CngKeyUsages.Signing,
        };

        using CngKey key = CngKey.Create(CngAlgorithm.ECDsaP256, _options.KeyName, keyParameters);
        using var signer = new ECDsaCng(key);

        var request = new CertificateRequest(
            new X500DistinguishedName(_options.SubjectName), signer, HashAlgorithmName.SHA256);

        // CA de um nível só (pathLength 0): pode assinar certificados de sites,
        // mas não outras CAs. Se esta chave for usada indevidamente, ela ao
        // menos não cria uma hierarquia nova.
        request.CertificateExtensions.Add(
            new X509BasicConstraintsExtension(certificateAuthority: true, hasPathLengthConstraint: true, pathLengthConstraint: 0, critical: true));
        request.CertificateExtensions.Add(
            new X509KeyUsageExtension(X509KeyUsageFlags.KeyCertSign | X509KeyUsageFlags.CrlSign, critical: true));
        request.CertificateExtensions.Add(
            new X509SubjectKeyIdentifierExtension(request.PublicKey, critical: false));

        DateTimeOffset now = DateTimeOffset.UtcNow;

        // Começa um dia antes para tolerar relógio atrasado na máquina; um
        // certificado "ainda não válido" é rejeitado do mesmo jeito que um vencido.
        //
        // O certificado criado já aponta para a chave CNG persistida (pelo
        // nome), e é essa ligação que o repositório guarda. Não há cópia da
        // chave em lugar nenhum.
        using X509Certificate2 created = request.CreateSelfSigned(now.AddDays(-1), now.Add(Lifetime));
        created.FriendlyName = "SafeUpload - inspeção TLS";

        using (var store = new X509Store(StoreName.My, _options.Location))
        {
            store.Open(OpenFlags.ReadWrite);
            store.Add(created);
        }

        if (_options.TrustInRoot)
        {
            AddToRoot(created);
        }
    }

    private void AddToRoot(X509Certificate2 authority)
    {
        // Em Root vai só a parte pública. Confiar numa CA não exige a chave dela.
        using X509Certificate2 publicOnly = X509CertificateLoader.LoadCertificate(authority.RawData);
        publicOnly.FriendlyName = "SafeUpload - inspeção TLS";

        using var root = new X509Store(StoreName.Root, _options.Location);
        root.Open(OpenFlags.ReadWrite);
        root.Add(publicOnly);
    }

    private void RemoveCertificates()
    {
        StoreName[] stores = _options.TrustInRoot ? [StoreName.My, StoreName.Root] : [StoreName.My];

        foreach (StoreName name in stores)
        {
            using var store = new X509Store(name, _options.Location);
            store.Open(OpenFlags.ReadWrite);

            foreach (X509Certificate2 certificate in store.Certificates.Find(
                         X509FindType.FindBySubjectDistinguishedName, _options.SubjectName, validOnly: false))
            {
                store.Remove(certificate);
                certificate.Dispose();
            }
        }
    }

    /// <summary>
    /// Confere que a chave do certificado é a nossa chave CNG. Um certificado
    /// com o mesmo assunto, colocado ali por outra pessoa, não vira a CA do agente.
    /// </summary>
    private bool UsesOurKey(X509Certificate2 certificate)
    {
        if (!certificate.HasPrivateKey)
        {
            return false;
        }

        try
        {
            using ECDsa? key = certificate.GetECDsaPrivateKey();
            return key is ECDsaCng cng && string.Equals(cng.Key.KeyName, _options.KeyName, StringComparison.Ordinal);
        }
        catch (CryptographicException)
        {
            // Certificado aponta para uma chave que não existe mais.
            return false;
        }
    }
}
