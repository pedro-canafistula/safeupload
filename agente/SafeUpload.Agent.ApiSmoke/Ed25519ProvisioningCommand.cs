using System.Globalization;
using System.Runtime.Versioning;
using System.Security.Cryptography;
using System.Text;
using SafeUpload.Agent.Core.Infrastructure;

[SupportedOSPlatform("windows")]
internal static class Ed25519ProvisioningCommand
{
    internal static async Task<int> RunAsync(string[] args)
    {
        if (!OperatingSystem.IsWindows()) { Console.Error.WriteLine("Provisionamento disponível somente no Windows."); return 2; }
        if (args.Length is < 5 or > 6 || args[0] is not ("register" or "heartbeat" or "recover") ||
            args.Length != (args[0] == "recover" ? 6 : 5))
        {
            Console.Error.WriteLine("Uso: --ed25519 register|heartbeat|recover BASE_AGENT/ ARQUIVO_IDENTIDADE IPv4 MASCARA [ID_RECUPERACAO]");
            Console.Error.WriteLine("register lê o token por stdin ou entrada oculta. Nunca passe o token como argumento.");
            return 2;
        }
        try
        {
            var host = AgentHeartbeatHost.ForMachine(args[3], int.Parse(args[4], CultureInfo.InvariantCulture));
            using var handler = new HttpClientHandler { AllowAutoRedirect = false };
            using var http = new HttpClient(handler) { BaseAddress = new Uri(args[1]), Timeout = TimeSpan.FromSeconds(10) };
            var client = new AgentApiClient(http);
            var identities = new SignedHostIdentityStore(args[2]);
            SignedAgentIdentity identity;
            switch (args[0])
            {
                case "register":
                    identity = await identities.RegisterAsync(client, await ReadToken(), host, CancellationToken.None);
                    break;
                case "recover":
                    identity = await identities.RecoverAsync(client, int.Parse(args[5], CultureInfo.InvariantCulture), host, CancellationToken.None);
                    break;
                default:
                    identity = identities.Load(http.BaseAddress);
                    await AgentHeartbeatConfiguration.Parse("AgentApiEd25519", null, signingIdentity: identity, host: host)
                        .CreateSender(http)!.SendAsync(CancellationToken.None);
                    break;
            }
            string fingerprint = Convert.ToHexString(SHA256.HashData(Convert.FromBase64String(identity.PublicKey)));
            Console.WriteLine($"ED25519_OK operation={args[0]} hostId={identity.HostId} publicKeySha256={fingerprint}");
            return 0;
        }
        catch (AgentApiException error)
        {
            Console.Error.WriteLine($"ED25519_FAILED code={error.Code} http={error.StatusCode?.ToString() ?? "none"}. Não repita cadastro após falha; reconcilie a identidade pendente.");
            return 1;
        }
        catch (Exception error) when (error is ArgumentException or InvalidOperationException or FormatException or OverflowException)
        {
            string code = error is AgentIdentityException identity ? identity.Code : "invalid_configuration";
            Console.Error.WriteLine($"ED25519_FAILED code={code}. Revise configuração, permissões e identidade sem apagar a chave ou recadastrar automaticamente.");
            return 2;
        }
    }

    private static async Task<string> ReadToken()
    {
        if (Console.IsInputRedirected) return (await Console.In.ReadLineAsync()) ?? "";
        Console.Error.Write("Token de cadastro (entrada oculta): ");
        var input = new StringBuilder();
        while (true)
        {
            var key = Console.ReadKey(intercept: true);
            if (key.Key == ConsoleKey.Enter) { Console.Error.WriteLine(); return input.ToString(); }
            if (key.Key == ConsoleKey.Backspace) { if (input.Length > 0) input.Length--; }
            else if (!char.IsControl(key.KeyChar)) input.Append(key.KeyChar);
        }
    }
}
