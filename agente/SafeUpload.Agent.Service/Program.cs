using SafeUpload.Agent.Core.Application;
using SafeUpload.Agent.Service.Clipboard;
using SafeUpload.Agent.Service.Dispatch;
using SafeUpload.Agent.Service.Interception;
using SafeUpload.Agent.Service.Network;
using SafeUpload.Agent.Service.Notifications;
using SafeUpload.Agent.Core.Infrastructure;
using SafeUpload.Agent.Core.Infrastructure.Extraction;
using System.Runtime.Versioning;
using System.Security.Principal;
using SafeUpload.Agent.Service.Diagnostics;
using SafeUpload.Agent.Service.Policies;

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
        if (args.Length == 1 && args[0] == "--staged-parser")
        {
            Environment.ExitCode = OperatingSystem.IsWindows()
                ? await StagedParserProcess.RunWorkerAsync().ConfigureAwait(false) : 2;
            return;
        }
        if (args.Contains("--seed-boot-policy", StringComparer.OrdinalIgnoreCase))
        {
            if (!TryGetBootPolicyConfigurationArguments(args, out var configurationArguments))
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
                Environment.ExitCode = await SeedBootPolicyAsync(configurationArguments).ConfigureAwait(false);
            }
            return;
        }

        // Comandos de manutenção da CA de inspeção TLS ("ca install", "ca
        // status", "ca remove"). Rodam e encerram, sem subir o serviço.
        if (args.Length > 0 && string.Equals(args[0], "ca", StringComparison.OrdinalIgnoreCase))
        {
            // Sem isso o console do Windows usa a página de código antiga e os
            // acentos das mensagens saem trocados.
            Console.OutputEncoding = System.Text.Encoding.UTF8;

            Environment.ExitCode = CertificateAuthorityCommand.Run(args[1..], Console.Out);
            return;
        }

        // "desvio status" e "desvio remove": políticas de proxy dos navegadores.
        if (args.Length > 0 && string.Equals(args[0], "desvio", StringComparison.OrdinalIgnoreCase))
        {
            Console.OutputEncoding = System.Text.Encoding.UTF8;
            IConfiguration settings = new ConfigurationBuilder()
                .SetBasePath(AppContext.BaseDirectory)
                .AddJsonFile("appsettings.json", optional: true)
                .AddEnvironmentVariables()
                .Build();
            int port = int.TryParse(settings["InspecaoTls:Porta"], out int configured) ? configured : 8877;

            Environment.ExitCode = DiversionCommand.Run(args[1..], port, Console.Out);
            return;
        }

        var builder = CreateConfiguredServiceBuilder(args);
        await builder.Build().RunAsync();
    }

    // Building the registration graph does not start the host, parser or interceptors.
    internal static HostApplicationBuilder CreateConfiguredServiceBuilder(string[] args)
    {
        var builder = CreateServiceBuilder(args);

        builder.Services.AddWindowsService(options => options.ServiceName = ServiceName);

        // A composição é a mesma que o aplicativo WPF fazia à mão, agora do
        // lado do serviço: são estes objetos que decidem, e é por isso que
        // saíram do processo da interface.
        //
        // A fila de auditoria é SEMPRE a local, com ou sem Centro de
        // Administração configurado: é ela que deixa o endpoint continuar
        // registrando com a rede fora do ar. O envio ao painel é uma etapa
        // posterior, feita pelo HttpAgentDispatcher, e não um substituto.
        builder.Services.AddSingleton<IAuditSink, LocalQueueAuditSink>();
        builder.Services.AddSingleton(ExtractorRegistry.CreateDefault());
        builder.Services.AddSingleton<VerdictCache>();
        builder.Services.AddSingleton<InspectionService>(services =>
        {
            IStagedParser? parser = null;
            if (StagedSpaceConfiguration.IsEnabled(builder.Configuration))
            {
                parser = new StagedParserProcess(StagedSpaceConfiguration.ParserMemoryBytes(builder.Configuration));
            }
            return new InspectionService(services.GetRequiredService<IPolicyStore>(),
                services.GetRequiredService<IAuditSink>(), services.GetRequiredService<ExtractorRegistry>(),
                services.GetRequiredService<VerdictCache>(), stagedParser: parser);
        });
        builder.Services.AddSingleton<INotificationRecord>(services =>
        {
            var logger = services.GetRequiredService<ILogger<NotificationRecord>>();
            try
            {
                return new NotificationRecord(Path.Combine(Environment.GetFolderPath(
                    Environment.SpecialFolder.CommonApplicationData), "SafeUpload", "notifications"), logger);
            }
            catch (Exception ex)
            {
                logger.LogError(ex, "Cannot open notification record; all notifications will be suppressed");
                return new UnavailableNotificationRecord(ex);
            }
        });
        builder.Services.AddSingleton<NotificationHub>();
        builder.Services.AddSingleton<PendingOverrides>();
        builder.Services.AddSingleton<StagedJustifications>();
        builder.Services.AddSingleton<OverrideGrantDispatcher>();
        builder.Services.AddSingleton<DriverDiagnosticsSource>();
#if SAFEUPLOAD_ADMISSION_EVIDENCE
        builder.Services.AddSingleton<AdmissionEvidenceEndpoint>();
#endif
        builder.Services.AddSingleton<ClipboardCopyStore>();
        builder.Services.AddSingleton<ClipboardMetrics>();
        builder.Services.AddSingleton<ClipboardService>();

        // De onde vem a politica, e para onde vai a trilha (HU-10).
        //
        // Sem "CentroAdministracao:BaseUrl" configurado, o agente e autonomo:
        // le a politica do arquivo local e so acumula auditoria em disco. Com
        // a URL configurada, a politica passa a vir do painel e um despachante
        // sobe para entregar os eventos pendentes.
        //
        // O padrao e o local pelo mesmo motivo do gatilho logo abaixo: uma
        // maquina que ainda nao aponta para nenhum painel precisa proteger de
        // forma autonoma, e nao ficar esperando um servidor que talvez nunca
        // seja configurado.
        builder.Services.AddAgentPolicies(builder.Configuration, Environment.MachineName);

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

            // Administrator-only field diagnostics relayed over the interceptor's own filter-port connection
            // (the port accepts a single client, so no other tool can read the driver while the service runs).
            builder.Services.AddHostedService<DiagnosticsPipeServer>();
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

        // O canal de clipboard (Fase 1: classifica e mede, sem interferir).
        // Com "clipboard.mode" Off na politica, que e o padrao, ele responde
        // "limpo" a tudo e nao conta nada.
        builder.Services.AddHostedService<ClipboardPipeServer>();

        // A inspeção do tráfego web (proxy TLS). Desligada por padrão: ligar
        // instala uma CA confiável na máquina, e isso tem de ser uma decisão
        // explícita. Ver docs/rede/PLANO-INSPECAO-TLS.md.
        if (string.Equals(builder.Configuration["InspecaoTls:Habilitada"], "true", StringComparison.OrdinalIgnoreCase))
        {
            builder.Services.AddHostedService<TlsInspectionService>();
        }

        return builder;
    }

    internal static HostApplicationBuilder CreateServiceBuilder(string[] args) =>
        Host.CreateApplicationBuilder(new HostApplicationBuilderSettings
        { Args = args, ContentRootPath = AppContext.BaseDirectory });

    internal static HostApplicationBuilder CreateBootPolicyBuilder(string[] configurationArguments)
    {
        var builder = CreateServiceBuilder(configurationArguments);
        builder.Services.AddAgentPolicies(builder.Configuration, Environment.MachineName, includeHostedServices: false);
        return builder;
    }

    private static int FailSeedModeUsage()
    {
        Console.Error.WriteLine("Use --seed-boot-policy followed only by configuration switches (--key=value or --key value).");
        return 2;
    }

    [SupportedOSPlatform("windows")]
    private static async Task<int> SeedBootPolicyAsync(string[] configurationArguments)
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
            var builder = CreateBootPolicyBuilder(configurationArguments);
            using var provider = builder.Services.BuildServiceProvider();
            var writer = new BootPolicyRegistryWriter(new WindowsBootPolicyRegistryBackend());
            await BootPolicySeeder.SeedAsync(provider.GetRequiredService<IPolicyStore>(), writer,
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

    // The seed accepts configuration only; it never starts maintenance commands.
    internal static bool TryGetBootPolicyConfigurationArguments(string[] args, out string[] configurationArguments)
    {
        configurationArguments = [];
        if (args.Length == 0 || !string.Equals(args[0], "--seed-boot-policy", StringComparison.OrdinalIgnoreCase))
            return false;
        for (int index = 1; index < args.Length; index++)
        {
            string option = args[index];
            if (!option.StartsWith("--", StringComparison.Ordinal) || option.Length <= 2)
                return false;
            string key = option[2..].Split('=', 2)[0];
            if (string.Equals(key, "seed-boot-policy", StringComparison.OrdinalIgnoreCase)
                || !System.Text.RegularExpressions.Regex.IsMatch(key, "^[A-Za-z][A-Za-z0-9:_-]*$"))
                return false;
            if (!option.Contains('='))
            {
                if (++index >= args.Length || args[index].StartsWith("--", StringComparison.Ordinal))
                    return false;
            }
        }
        configurationArguments = args[1..];
        return true;
    }
}
