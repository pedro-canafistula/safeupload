using SafeUpload.Agent.Core.Application;
using SafeUpload.Agent.Service.Clipboard;
using SafeUpload.Agent.Service.Dispatch;
using SafeUpload.Agent.Service.Drive;
using SafeUpload.Agent.Service.Gate;
using SafeUpload.Agent.Service.Interception;
using SafeUpload.Agent.Service.Network;
using SafeUpload.Agent.Service.Notifications;
using SafeUpload.Agent.Core.Infrastructure;
using SafeUpload.Agent.Core.Infrastructure.Extraction;
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
        builder.Services.AddSingleton<SafeUpload.Agent.Service.Audit.AuditWriteFailureDiagnostics>();
        builder.Services.AddSingleton<IAuditWriteFailureObserver>(services =>
            services.GetRequiredService<SafeUpload.Agent.Service.Audit.AuditWriteFailureDiagnostics>());
        builder.Services.AddSingleton<IAuditSink>(services => new LocalQueueAuditSink(AgentPaths.QueueFile,
            services.GetRequiredService<IAuditWriteFailureObserver>()));
        builder.Services.AddSingleton(ExtractorRegistry.CreateDefault());
        builder.Services.AddSingleton<VerdictCache>();
        builder.Services.AddSingleton<InspectionService>(services =>
            new InspectionService(services.GetRequiredService<IPolicyStore>(),
                services.GetRequiredService<IAuditSink>(), services.GetRequiredService<ExtractorRegistry>(),
                services.GetRequiredService<VerdictCache>()));
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
        builder.Services.AddSingleton<DriveJustifications>();
        builder.Services.AddSingleton<GateClient>();
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

        // O gatilho. A partir daqui a protecao existe sem interface nenhuma aberta.
        //
        // "Drive" (padrao): cada pasta protegida da politica ganha uma unidade SafeUpload (WinFsp). O que o usuario
        // grava fica privado ate ser inspecionado; so versoes aprovadas chegam a pasta real, que fica somente
        // leitura para usuarios. O driver gate, se carregado, recusa gravacoes diretas de outros processos.
        //
        // "FileSystemWatcher": o mock antigo, para maquinas sem WinFsp. Reage DEPOIS que o arquivo chegou ao
        // destino e "bloqueia" apagando.
        string mode = builder.Configuration["Interception:Mode"] ?? "Drive";

        if (string.Equals(mode, "FileSystemWatcher", StringComparison.OrdinalIgnoreCase))
        {
            builder.Services.AddHostedService<FileSystemInterceptor>();
        }
        else
        {
            builder.Services.AddSingleton<DriveService>();
            builder.Services.AddHostedService(services => services.GetRequiredService<DriveService>());
        }

        // A entrega das notificacoes aos aplicativos conectados.
        builder.Services.AddHostedService<NotificationPipeServer>();
        builder.Services.AddHostedService<PolicyIntegrationStatusPublisher>();
        builder.Services.AddHostedService<SafeUpload.Agent.Service.Audit.AuditWriteStatusPublisher>();

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
}
