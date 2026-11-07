using System.Runtime.Versioning;
using System.ServiceProcess;
using SafeUpload.Agent.Core.Infrastructure;

namespace SafeUpload.Agent.Service;

/// <summary>
/// <c>SafeUpload.Agent.Service.exe cadastrar &lt;url&gt; &lt;token&gt; [--certificado &lt;sha256&gt;] [--substituir]</c>:
/// cria a chave da máquina, cadastra com o token gerado no console e reinicia o serviço para aplicar.
/// Precisa de administrador (a identidade fica numa pasta só de SYSTEM/Administradores).
/// </summary>
internal static class EnrollCommand
{
    private const string Usage =
        "Uso: SafeUpload.Agent.Service.exe cadastrar https://servidor:8443/agent/ <token> [--certificado <sha256>] [--substituir]";

    public static async Task<int> RunAsync(string[] args, TextWriter output)
    {
        string? address = null, token = null, pin = null;
        bool replace = false;
        for (int i = 0; i < args.Length; i++)
        {
            switch (args[i])
            {
                case "--certificado" when i + 1 < args.Length: pin = args[++i]; break;
                case "--substituir": replace = true; break;
                default:
                    if (address is null) address = args[i];
                    else if (token is null) token = args[i];
                    else { output.WriteLine(Usage); return 2; }
                    break;
            }
        }
        if (address is null || token is null) { output.WriteLine(Usage); return 2; }
        if (!OperatingSystem.IsWindows()) { output.WriteLine("O cadastro só roda no Windows."); return 1; }
        return await EnrollAsync(address, token.Trim(), pin, replace, output).ConfigureAwait(false);
    }

    public static async Task<int> UpdateCertificateAsync(string[] args, TextWriter output)
    {
        if (args.Length != 1)
        {
            output.WriteLine("Uso: SafeUpload.Agent.Service.exe atualizar-certificado <sha256>");
            return 2;
        }
        if (!OperatingSystem.IsWindows()) { output.WriteLine("O comando só roda no Windows."); return 1; }
        var store = OpenIdentityStore();
        try
        {
            var identity = await store.UpdateCertificateAsync(args[0], CancellationToken.None).ConfigureAwait(false);
            output.WriteLine($"Novo certificado validado para o host {identity.HostId}. O cadastro foi preservado.");
        }
        catch (ArgumentException error) { output.WriteLine(error.Message); return 2; }
        catch (AgentIdentityException error) { output.WriteLine(error.Message); return 3; }
        catch (AgentApiException error)
        {
            output.WriteLine(error.StatusCode is { } status
                ? $"O console respondeu HTTP {status} à verificação da identidade. O certificado atual foi preservado."
                : "O console não confirmou a identidade com o novo certificado. O certificado atual foi preservado.");
            return 4;
        }
        RestartService(output);
        return 0;
    }

    [SupportedOSPlatform("windows")]
    private static SignedHostIdentityStore OpenIdentityStore() =>
        new(Path.Combine(AgentPaths.RootDirectory, "authentication", "ed25519-identity.dat"));

    [SupportedOSPlatform("windows")]
    private static async Task<int> EnrollAsync(string address, string token, string? pin, bool replace, TextWriter output)
    {
        Uri server;
        try
        {
            server = AgentHttp.ServerUri(address);
            if (pin is not null) pin = AgentHttp.NormalizePin(pin);
        }
        catch (ArgumentException error) { output.WriteLine(error.Message); return 2; }

        var store = OpenIdentityStore();
        using var http = new HttpClient(AgentHttp.CreateHandler(pin)) { BaseAddress = server, Timeout = TimeSpan.FromSeconds(15) };
        try
        {
            var identity = await store.EnrollAsync(new AgentApiClient(http), pin, token, AgentHeartbeatHost.Detect(), replace,
                CancellationToken.None).ConfigureAwait(false);
            output.WriteLine($"Máquina cadastrada como host {identity.HostId} em {server}.");
        }
        catch (AgentIdentityException error) when (error.Code == "already_registered")
        {
            output.WriteLine("Esta máquina já está cadastrada. Para cadastrar de novo, use --substituir.");
            return 3;
        }
        catch (AgentIdentityException error) when (error.Code is "access_denied" or "unsafe_permissions")
        {
            output.WriteLine("Rode o cadastro como administrador.");
            return 3;
        }
        catch (AgentApiException error)
        {
            output.WriteLine(error.StatusCode switch
            {
                401 => "Token inválido, já usado ou expirado (vale 15 minutos). Gere outro no console.",
                400 => "O servidor recusou os dados do cadastro.",
                { } status => $"O servidor respondeu HTTP {status}.",
                null => "Cadastro sem confirmação. Após restabelecer a conexão, repita o mesmo comando e token antes da expiração."
            });
            return 4;
        }
        catch (AgentIdentityException error)
        {
            output.WriteLine(error.Message);
            return 5;
        }

        RestartService(output);
        return 0;
    }

    [SupportedOSPlatform("windows")]
    private static void RestartService(TextWriter output)
    {
        try
        {
            using var service = new ServiceController(Program.ServiceName);
            if (service.Status != ServiceControllerStatus.Running)
            {
                output.WriteLine("A configuração vale quando o serviço SafeUploadAgent for iniciado.");
                return;
            }
            output.WriteLine("Reiniciando o serviço SafeUploadAgent...");
            service.Stop();
            service.WaitForStatus(ServiceControllerStatus.Stopped, TimeSpan.FromMinutes(2));
            service.Start();
            service.WaitForStatus(ServiceControllerStatus.Running, TimeSpan.FromMinutes(2));
            output.WriteLine("Serviço reiniciado; a máquina já fala com o servidor.");
        }
        catch (Exception error) when (error is InvalidOperationException or System.ServiceProcess.TimeoutException
                                          or System.ComponentModel.Win32Exception)
        {
            output.WriteLine("Não foi possível reiniciar o serviço automaticamente; reinicie SafeUploadAgent para aplicar.");
        }
    }
}

/// <summary>Registra no log do serviço um problema de configuração encontrado antes de o host existir.</summary>
internal sealed class StartupWarning(ILogger<StartupWarning> logger, string message) : IHostedService
{
    public Task StartAsync(CancellationToken cancellationToken)
    {
        logger.LogWarning("{Message}", message);
        return Task.CompletedTask;
    }

    public Task StopAsync(CancellationToken cancellationToken) => Task.CompletedTask;
}
