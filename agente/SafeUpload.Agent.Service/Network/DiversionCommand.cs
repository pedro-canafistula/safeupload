using SafeUpload.Agent.Network.Diversion;

namespace SafeUpload.Agent.Service.Network;

/// <summary>
/// Comandos de manutenção do desvio dos navegadores:
///
/// <code>
/// SafeUpload.Agent.Service.exe desvio status   mostra se as políticas de proxy estão aplicadas
/// SafeUpload.Agent.Service.exe desvio remove   remove as políticas (devolve a internet aos navegadores)
/// </code>
///
/// O <c>remove</c> é a saída de emergência: se o serviço morrer sem parar
/// direito, as políticas continuam apontando os navegadores para um proxy fora
/// do ar. Os filtros WFP não precisam de comando: somem sozinhos com o serviço.
/// Exige um terminal de administrador.
/// </summary>
public static class DiversionCommand
{
    /// <summary>Executa o subcomando e devolve o código de saída do processo.</summary>
    public static int Run(string[] args, int port, TextWriter output)
    {
        switch (args.Length > 0 ? args[0].ToLowerInvariant() : string.Empty)
        {
            case "status":
                bool applied = BrowserProxyPolicies.IsApplied(port);
                output.WriteLine(applied
                    ? $"Navegadores desviados para o proxy em 127.0.0.1:{port}."
                    : "Políticas de proxy dos navegadores não aplicadas.");
                return applied ? 0 : 1;

            case "remove":
                BrowserProxyPolicies.Remove();
                output.WriteLine("Políticas de proxy dos navegadores removidas. Reabra os navegadores.");
                return 0;

            default:
                output.WriteLine("Uso: SafeUpload.Agent.Service desvio <status|remove>");
                return 2;
        }
    }
}
