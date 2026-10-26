using SafeUpload.Agent.Core.Infrastructure;

// Uma operação em cadastro EXISTENTE. Não instala serviço, cadastra host,
// publica política, envia auditoria nem acessa driver/painel administrativo.
if (args.Length != 4 || args[0] != "--base-url" || args[2] != "--registered-user-id")
{
    Console.Error.WriteLine("Uso: --base-url http://localhost:8080/agent/ --registered-user-id ID_EXISTENTE");
    return 2;
}

try
{
    var configuration = AgentHeartbeatConfiguration.Parse("AgentApi", args[3]);
    using var handler = new HttpClientHandler { AllowAutoRedirect = false };
    using var http = new HttpClient(handler)
    {
        BaseAddress = new Uri(args[1], UriKind.Absolute),
        Timeout = TimeSpan.FromSeconds(5)
    };
    await configuration.CreateSender(http)!.SendAsync(CancellationToken.None);
    Console.WriteLine("Heartbeat AgentApi confirmado. Não comprova política, auditoria, painel ou driver.");
    return 0;
}
catch (AgentApiException exception)
{
    Console.Error.WriteLine($"Heartbeat não confirmado: categoria={exception.Code}; HTTP={exception.StatusCode?.ToString() ?? "none"}.");
    return 1;
}
catch (Exception exception) when (exception is ArgumentException or InvalidOperationException or UriFormatException)
{
    Console.Error.WriteLine("Configuração inválida. Confira base /agent/ e identificador inteiro positivo do cadastro existente.");
    return 2;
}
