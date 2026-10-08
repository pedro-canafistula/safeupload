using System.Security.Cryptography.X509Certificates;

namespace SafeUpload.Agent.Network.Certificates;

/// <summary>
/// Onde e como a CA de inspeção é guardada.
///
/// Em produção só existe uma configuração, a <see cref="Machine"/>. O registro
/// existe para os testes: eles precisam criar CAs descartáveis, com nome de
/// chave próprio, no repositório do usuário e sem tocar na lista de raízes
/// confiáveis da máquina.
/// </summary>
/// <param name="KeyName">
/// Nome da chave CNG persistida. É por ele que a chave privada é reencontrada
/// depois de um reinício; ela nunca sai do provedor de chaves.
/// </param>
/// <param name="SubjectName">Nome que aparece no certificado da CA.</param>
/// <param name="Location">
/// Repositório onde o certificado com chave fica guardado
/// (<c>My</c> da máquina ou do usuário).
/// </param>
/// <param name="MachineKey">
/// Chave no repositório da máquina, e não no perfil de quem criou. É o que faz
/// a chave sobreviver independentemente do usuário que estiver logado.
/// </param>
/// <param name="TrustInRoot">
/// Instala o certificado público em <c>Root</c> (Autoridades de Certificação
/// Raiz Confiáveis). É esse passo que faz o navegador aceitar os certificados
/// emitidos pelo proxy.
/// </param>
public sealed record CertificateAuthorityOptions(
    string KeyName,
    string SubjectName,
    StoreLocation Location,
    bool MachineKey,
    bool TrustInRoot)
{
    /// <summary>
    /// A configuração do agente: chave da máquina, certificado em
    /// LocalMachine\My e confiança em LocalMachine\Root.
    ///
    /// O nome da máquina entra no assunto para que um administrador olhando a
    /// lista de raízes saiba de onde aquela CA veio: cada máquina tem a sua
    /// (ver <see cref="MachineCertificateAuthority"/>).
    /// </summary>
    public static CertificateAuthorityOptions Machine { get; } = new(
        KeyName: "SafeUpload Inspection CA",
        SubjectName: $"CN=SafeUpload Inspection CA ({Environment.MachineName}), O=SafeUpload",
        Location: StoreLocation.LocalMachine,
        MachineKey: true,
        TrustInRoot: true);
}
