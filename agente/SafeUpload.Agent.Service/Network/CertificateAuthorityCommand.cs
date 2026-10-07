using System.Security.Cryptography.X509Certificates;
using SafeUpload.Agent.Network.Certificates;

namespace SafeUpload.Agent.Service.Network;

/// <summary>
/// Comandos de manutenção da CA de inspeção TLS, no próprio executável do
/// serviço:
///
/// <code>
/// SafeUpload.Agent.Service.exe ca install   cria (ou reaproveita) a CA e a torna confiável
/// SafeUpload.Agent.Service.exe ca status    mostra a CA e se ela está confiável
/// SafeUpload.Agent.Service.exe ca remove    remove a CA, a confiança e a chave
/// </code>
///
/// Fazem o papel dos passos de instalação e desinstalação enquanto o agente não
/// tem instalador: a CA é parte da instalação, e removê-la é obrigatório ao
/// desinstalar (ver <see cref="MachineCertificateAuthority.Remove"/>).
/// Exigem um terminal de administrador.
/// </summary>
public static class CertificateAuthorityCommand
{
    /// <summary>Executa o subcomando e devolve o código de saída do processo.</summary>
    public static int Run(string[] args, TextWriter output)
    {
        string action = args.Length > 0 ? args[0].ToLowerInvariant() : string.Empty;
        var authority = new MachineCertificateAuthority();

        switch (action)
        {
            case "install":
                using (X509Certificate2 ca = authority.LoadOrCreate())
                {
                    FirefoxEnterpriseRoots.Enable();
                    output.WriteLine("CA de inspeção pronta.");
                    Describe(authority, ca, output);
                }

                return 0;

            case "status":
                using (X509Certificate2? ca = authority.Find())
                {
                    if (ca is null)
                    {
                        output.WriteLine("Nenhuma CA de inspeção nesta máquina.");
                        return 1;
                    }

                    Describe(authority, ca, output);
                }

                return 0;

            case "remove":
                authority.Remove();
                FirefoxEnterpriseRoots.Disable();
                output.WriteLine("CA de inspeção, confiança e chave removidas.");
                return 0;

            default:
                output.WriteLine("Uso: SafeUpload.Agent.Service ca <install|status|remove>");
                return 2;
        }
    }

    private static void Describe(MachineCertificateAuthority authority, X509Certificate2 ca, TextWriter output)
    {
        output.WriteLine($"  Assunto:     {ca.Subject}");
        output.WriteLine($"  Impressão:   {ca.Thumbprint}");
        output.WriteLine($"  Validade:    {ca.NotBefore:yyyy-MM-dd} a {ca.NotAfter:yyyy-MM-dd}");
        output.WriteLine($"  Confiável:   {(authority.IsTrusted(ca) ? "sim (LocalMachine\\Root)" : "NÃO")}");
        output.WriteLine($"  Firefox:     {(FirefoxEnterpriseRoots.IsEnabled() ? "ImportEnterpriseRoots ligado" : "política desligada")}");
    }
}
