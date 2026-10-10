using Microsoft.Win32;

namespace SafeUpload.Agent.Network.Diversion;

/// <summary>
/// Aponta Chrome, Edge e Firefox para o proxy de inspeção, por política
/// corporativa (Fase 3 do plano de inspeção TLS).
///
/// Por política, e não pela configuração de proxy do Windows, por três motivos:
/// - **Só os navegadores.** O proxy do sistema levaria junto Windows Update,
///   Defender, Teams e Outlook, que em parte recusam interceptação (pinning);
///   até a Fase 4 tratar essas exceções, isso quebraria a máquina. Upload pela
///   web acontece no navegador.
/// - **O usuário não muda.** Configuração vinda de política aparece travada no
///   navegador ("gerenciado pela sua organização").
/// - **Documentado e estável.** São políticas públicas dos três navegadores, as
///   mesmas que um administrador aplicaria por GPO.
///
/// As mesmas políticas desligam o QUIC (HTTP/3) no Chrome e no Edge. QUIC roda
/// sobre UDP e não passa por proxy HTTP; desligado, o navegador usa TCP. O
/// Firefox não tem política equivalente, e o filtro WFP de UDP 443 cobre ele
/// (ver <see cref="BrowserEgressFilter"/>).
///
/// Os navegadores releem as políticas sozinhos em alguns minutos; para valer
/// na hora, é preciso reabri-los (ou recarregar em chrome://policy e edge://policy).
/// </summary>
public static class BrowserProxyPolicies
{
    private const string ChromeKey = @"SOFTWARE\Policies\Google\Chrome";
    private const string EdgeKey = @"SOFTWARE\Policies\Microsoft\Edge";
    private const string FirefoxProxyKey = @"SOFTWARE\Policies\Mozilla\Firefox\Proxy";

    /// <summary>Aplica as políticas apontando para o proxy em 127.0.0.1:<paramref name="port"/>. Exige administrador ou SYSTEM.</summary>
    public static void Apply(int port)
    {
        string server = $"127.0.0.1:{port}";

        foreach (string key in new[] { ChromeKey, EdgeKey })
        {
            using RegistryKey policy = Registry.LocalMachine.CreateSubKey(key, writable: true);
            policy.SetValue("ProxyMode", "fixed_servers", RegistryValueKind.String);
            policy.SetValue("ProxyServer", server, RegistryValueKind.String);

            // Endereços locais não passam pelo proxy (é o padrão do Chromium,
            // explícito aqui para não depender dele).
            policy.SetValue("ProxyBypassList", "<local>", RegistryValueKind.String);
            policy.SetValue("QuicAllowed", 0, RegistryValueKind.DWord);
        }

        using (RegistryKey firefox = Registry.LocalMachine.CreateSubKey(FirefoxProxyKey, writable: true))
        {
            firefox.SetValue("Mode", "manual", RegistryValueKind.String);
            firefox.SetValue("HTTPProxy", server, RegistryValueKind.String);

            // Sem isto o Firefox só usaria o proxy para http://, e o HTTPS
            // (o que importa) sairia direto.
            firefox.SetValue("UseHTTPProxyForAllProtocols", 1, RegistryValueKind.DWord);
            firefox.SetValue("Locked", 1, RegistryValueKind.DWord);
        }
    }

    /// <summary>
    /// Remove as políticas que este agente grava. As demais políticas dos
    /// navegadores na máquina ficam como estão.
    /// </summary>
    public static void Remove()
    {
        foreach (string key in new[] { ChromeKey, EdgeKey })
        {
            using RegistryKey? policy = Registry.LocalMachine.OpenSubKey(key, writable: true);

            foreach (string name in new[] { "ProxyMode", "ProxyServer", "ProxyBypassList", "QuicAllowed" })
            {
                policy?.DeleteValue(name, throwOnMissingValue: false);
            }
        }

        Registry.LocalMachine.DeleteSubKeyTree(FirefoxProxyKey, throwOnMissingSubKey: false);
    }

    /// <summary>Indica se as políticas estão aplicadas apontando para a porta.</summary>
    public static bool IsApplied(int port)
    {
        string server = $"127.0.0.1:{port}";

        foreach (string key in new[] { ChromeKey, EdgeKey })
        {
            using RegistryKey? policy = Registry.LocalMachine.OpenSubKey(key);

            if (policy?.GetValue("ProxyServer") as string != server)
            {
                return false;
            }
        }

        using RegistryKey? firefox = Registry.LocalMachine.OpenSubKey(FirefoxProxyKey);
        return firefox?.GetValue("HTTPProxy") as string == server;
    }
}
