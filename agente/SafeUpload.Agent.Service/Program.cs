using SafeUpload.Agent.Core.Application;
using SafeUpload.Agent.Service.Interception;
using SafeUpload.Agent.Service.Notifications;
using SafeUpload.Agent.Core.Infrastructure;
using SafeUpload.Agent.Core.Infrastructure.Extraction;
using System.Runtime.Versioning;
using System.Security.Principal;

namespace SafeUpload.Agent.Service;

/// <summary>
/// Ponto de entrada do serviço.
///
/// O mesmo executável roda como serviço do Windows e como aplicação de
/// console. Isso não é conveniência: depurar um serviço exige anexar o
/// depurador a um processo que o gerenciador de serviços iniciou, e sem o modo
/// console cada erro de lógica custaria uma reinstalação. AddWindowsService só
/// tem efeito quando o processo é de fato iniciado pelo gerenciador.
/// </summary>
public static class Program
{
    /// <summary>Nome do serviço no gerenciador de serviços do Windows.</summary>
    public const string ServiceName = "SafeUploadAgent";

    /// <summary>Monta e executa o host.</summary>
    public static async Task Main(string[] args)
    {
        if (args.Contains("--seed-boot-policy", StringComparer.OrdinalIgnoreCase))
        {
            if (args.Length != 1)
            {
                Environment.ExitCode = FailSeedModeUsage();
            }
            else if (!OperatingSystem.IsWindows())
            {
                Console.Error.WriteLine("--seed-boot-policy is supported only on Windows.");
                Environment.ExitCode = 1;
            }
            else
            {
                Environment.ExitCode = await SeedBootPolicyAsync().ConfigureAwait(false);
            }
            return;
        }

        var builder = Host.CreateApplicationBuilder(args);

        builder.Services.AddWindowsService(options => options.ServiceName = ServiceName);

        // A composição é a mesma que o aplicativo WPF fazia à mão, agora do
        // lado do serviço: são estes objetos que decidem, e é por isso que
        // saíram do processo da interface.
        builder.Services.AddSingleton<IPolicyStore, LocalPolicyStore>();
        builder.Services.AddSingleton<IAuditSink, LocalQueueAuditSink>();
        builder.Services.AddSingleton(ExtractorRegistry.CreateDefault());
        builder.Services.AddSingleton<VerdictCache>();
        builder.Services.AddSingleton<InspectionService>();
        builder.Services.AddSingleton<NotificationHub>();
        builder.Services.AddSingleton<PendingOverrides>();
        builder.Services.AddSingleton<StagedJustifications>();
        builder.Services.AddSingleton<OverrideGrantDispatcher>();

        // O gatilho. A partir daqui a protecao existe sem interface nenhuma
        // aberta, que e o ponto de separar os dois processos.
        //
        // Sao dois, e a escolha e de configuracao porque a diferenca entre
        // eles nao e de implementacao, e de natureza. O FileSystemWatcher
        // reage DEPOIS que o arquivo chegou ao destino e "bloqueia" apagando;
        // o minifiltro intercepta ANTES e a negacao impede a operacao. O
        // primeiro roda em qualquer maquina; o segundo exige o driver
        // carregado e assinado.
        //
        // O padrao continua sendo o mock, de proposito: uma maquina sem o
        // driver deve ficar protegida de forma imperfeita em vez de ficar
        // sem protecao nenhuma. Para usar o kernel, em appsettings.json:
        //
        //   "Interception": { "Mode": "Minifilter" }
        //
        // Os dois nunca sobem juntos. Rodando em paralelo, o watcher veria os
        // arquivos que o minifiltro deixou passar e os apagaria depois - dois
        // vereditos sobre a mesma operacao, com o segundo desfazendo o
        // primeiro.
        string mode = builder.Configuration["Interception:Mode"] ?? "FileSystemWatcher";

        if (string.Equals(mode, "Minifilter", StringComparison.OrdinalIgnoreCase))
        {
            builder.Services.AddHostedService<MinifilterInterceptor>();
        }
        else
        {
            builder.Services.AddHostedService<FileSystemInterceptor>();
        }

        // A entrega das notificacoes aos aplicativos conectados.
        builder.Services.AddHostedService<NotificationPipeServer>();

        // O caminho de volta, e o unico: recebe justificativas do aplicativo.
        // Nao altera veredito - submete um motivo para um bloqueio que este
        // servico registrou, e valida contra o registro dele.
        builder.Services.AddHostedService<JustificationPipeServer>();

        await builder.Build().RunAsync();
    }

    private static int FailSeedModeUsage()
    {
        Console.Error.WriteLine("--seed-boot-policy must be the only argument.");
        return 2;
    }

    [SupportedOSPlatform("windows")]
    private static async Task<int> SeedBootPolicyAsync()
    {
        if (!OperatingSystem.IsWindows())
        {
            Console.Error.WriteLine("--seed-boot-policy is supported only on Windows.");
            return 1;
        }

        using WindowsIdentity identity = WindowsIdentity.GetCurrent();
        if (identity.User?.IsWellKnown(WellKnownSidType.LocalSystemSid) != true)
        {
            Console.Error.WriteLine("--seed-boot-policy requires the LocalSystem identity.");
            return 1;
        }

        try
        {
            var writer = new BootPolicyRegistryWriter(new WindowsBootPolicyRegistryBackend());
            await BootPolicySeeder.SeedAsync(new LocalPolicyStore(), writer,
                CancellationToken.None).ConfigureAwait(false);
            Console.WriteLine("BootPolicySeeded=True");
            return 0;
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"Boot policy seed failed: {ex}");
            return 1;
        }
    }
}
