using SafeUpload.Agent.Core.Application;
using SafeUpload.Agent.Service.Clipboard;
using SafeUpload.Agent.Service.Dispatch;
using SafeUpload.Agent.Service.Drive;
using SafeUpload.Agent.Service.Gate;
using SafeUpload.Agent.Service.Interception;
using SafeUpload.Agent.Service.Network;
using SafeUpload.Agent.Service.Notifications;
using SafeUpload.Agent.Service.Policies;
using SafeUpload.Agent.Core.Infrastructure;
using SafeUpload.Agent.Core.Infrastructure.Extraction;
using SafeUpload.Agent.Service.Diagnostics;

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

    /// <summary>Cliente nomeado usado para falar com o Centro de Administração.</summary>
    internal const string HttpClientName = "CentroAdministracao";

    /// <summary>Monta e executa o host.</summary>
    public static async Task Main(string[] args)
    {
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

        var builder = Host.CreateApplicationBuilder(args);

        builder.Services.AddWindowsService(options => options.ServiceName = ServiceName);

        // A composição é a mesma que o aplicativo WPF fazia à mão, agora do
        // lado do serviço: são estes objetos que decidem, e é por isso que
        // saíram do processo da interface.
        //
        // A fila de auditoria é SEMPRE a local, com ou sem Centro de
        // Administração configurado: é ela que deixa o endpoint continuar
        // registrando com a rede fora do ar. O envio ao painel é uma etapa
        // posterior, feita pelo HttpAgentDispatcher, e não um substituto.
        ConfigureAuditStorage(builder.Services);
        builder.Services.AddSingleton(ExtractorRegistry.CreateDefault());
        builder.Services.AddSingleton<VerdictCache>();
        builder.Services.AddSingleton<InspectionService>();
        builder.Services.AddSingleton<INotificationRecord>(services =>
        {
            var logger = services.GetRequiredService<ILogger<NotificationRecord>>();
            return new RecoveringNotificationRecord(() => new NotificationRecord(Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
                "SafeUpload", "notifications"), logger), logger);
        });
        builder.Services.AddSingleton<NotificationHub>();
        builder.Services.AddSingleton<DriveJustifications>();
        builder.Services.AddSingleton<GateClient>();
        builder.Services.AddSingleton<ClipboardCopyStore>();
        builder.Services.AddSingleton<ClipboardMetrics>();

        // Clipboard usa diretamente o snapshot remoto, já atualizado em fundo.
        // O cache adicional fica somente no modo local para limitar leituras de disco.
        builder.Services.AddSingleton(provider => new ClipboardInspectionService(
            provider.GetRequiredService<IPolicyStore>() is RefreshingPolicyStore remotePolicy
                ? remotePolicy
                : new CachedPolicyStore(provider.GetRequiredService<IPolicyStore>(),
                    ClipboardInspectionService.PolicyLifetime),
            provider.GetRequiredService<ClipboardCopyStore>(),
            provider.GetRequiredService<ClipboardMetrics>()));

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
        var administration = AdministrationConfiguration.Parse(builder.Configuration,
            new RegisteredHostIdentityStore(Path.Combine(AgentPaths.RootDirectory, "identity", "host-registration.json")),
            new SignedHostIdentityStore(Path.Combine(AgentPaths.RootDirectory, "authentication", "ed25519-identity.dat")));
        string endpointId = Environment.MachineName;
        builder.Services.AddSingleton(new CommunicationHealth(administration.BaseUri is not null));
        builder.Services.AddHostedService<CommunicationStatusPublisher>();
        var heartbeatConfiguration = administration.Heartbeat;

        if (administration.BaseUri is null)
        {
            builder.Services.AddSingleton<IPolicyStore, LocalPolicyStore>();
        }
        else
        {
            var adminUri = administration.BaseUri;

            // A rede só é consultada em segundo plano. Inspeções usam o último
            // snapshot validado mesmo durante timeout, falha ou reconexão.
            ConfigureAdministrationHttpClient(builder.Services, adminUri, (int)administration.Timeout.TotalSeconds);

            if (heartbeatConfiguration.RegisteredHostId is not null)
            {
                // Cliente separado: não altera o transporte legado de política/auditoria.
                builder.Services.AddHttpClient(HttpClientName + "AgentApi", client =>
                {
                    client.BaseAddress = adminUri;
                    client.Timeout = administration.Timeout;
                })
                .ConfigurePrimaryHttpMessageHandler(() => new HttpClientHandler { AllowAutoRedirect = false })
                .RemoveAllLoggers();
            }

            builder.Services.AddSingleton<RefreshingPolicyStore>(provider =>
            {
                var factory = provider.GetRequiredService<IHttpClientFactory>();
                var health = provider.GetRequiredService<CommunicationHealth>();
                var remote = administration.ConsolePolicy is { } console
                    ? new DurableHttpPolicyStore(
                        factory.CreateClient(HttpClientName + "AgentApi"), endpointId,
                        Path.Combine(AgentPaths.RootDirectory, "console-policy-cache.json"),
                        health, console, new LocalPolicyStore())
                    : new DurableHttpPolicyStore(factory.CreateClient(HttpClientName), endpointId,
                        Path.Combine(AgentPaths.RootDirectory, "server-policy-cache.json"), health);
                return new RefreshingPolicyStore(remote, TimeSpan.FromSeconds(30),
                    provider.GetRequiredService<ILogger<RefreshingPolicyStore>>());
            });
            builder.Services.AddSingleton<IPolicyStore>(provider => provider.GetRequiredService<RefreshingPolicyStore>());
            builder.Services.AddHostedService(provider => provider.GetRequiredService<RefreshingPolicyStore>());

            builder.Services.AddHostedService(provider =>
                new HttpAgentDispatcher(
                    provider.GetRequiredService<IAuditSink>(),
                    provider.GetRequiredService<IPolicyStore>(),
                    provider.GetRequiredService<IHttpClientFactory>().CreateClient(HttpClientName),
                    endpointId,
                    administration.DispatchInterval,
                    provider.GetRequiredService<ILogger<HttpAgentDispatcher>>(),
                    provider.GetRequiredService<CommunicationHealth>())
                {
                    HeartbeatSender = heartbeatConfiguration.RegisteredHostId is null ? null :
                        heartbeatConfiguration.CreateSender(
                            provider.GetRequiredService<IHttpClientFactory>().CreateClient(HttpClientName + "AgentApi"),
                            provider.GetRequiredService<CommunicationHealth>())
                });
        }

        // O gatilho. A partir daqui a protecao existe sem interface nenhuma aberta.
        //
        // "Drive" (padrao): cada pasta protegida da politica (local ou compartilhamento) e cada pendrive ganham uma
        // unidade SafeUpload (WinFsp). O que o usuario grava fica privado ate ser inspecionado; so versoes aprovadas
        // chegam ao destino real. O driver gate recusa gravacoes diretas de qualquer outro processo.
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
            builder.Services.AddHostedService(provider => provider.GetRequiredService<DriveService>());
        }

        // Communication diagnostics work without a loaded driver in either interception mode.
        builder.Services.AddHostedService(provider => new DiagnosticsPipeServer(
            provider.GetRequiredService<GateClient>(),
            provider.GetRequiredService<ILogger<DiagnosticsPipeServer>>(),
            communicationHealth: provider.GetRequiredService<CommunicationHealth>(),
            auditQueue: provider.GetRequiredService<LocalQueueAuditSink>(),
            auditHealth: provider.GetRequiredService<AuditQueueHealth>()));

        // A entrega das notificacoes aos aplicativos conectados.
        builder.Services.AddSingleton<AuditHistoryReader>();
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
            builder.Services.AddSingleton<WebInspectionService>();
            builder.Services.AddSingleton<WebUploadInspector>();
            builder.Services.AddHostedService<TlsInspectionService>();
        }

        await builder.Build().RunAsync();
    }

    internal static void ConfigureAuditStorage(IServiceCollection services)
    {
        services.AddSingleton(_ => new LocalQueueAuditSink()); // Never select the isolated-path test constructor through DI.
        services.AddSingleton<AuditQueueHealth>();
        services.AddSingleton<MonitoredAuditSink>(provider => new MonitoredAuditSink(
            provider.GetRequiredService<LocalQueueAuditSink>(), provider.GetRequiredService<AuditQueueHealth>(),
            provider.GetRequiredService<ILogger<MonitoredAuditSink>>()));
        services.AddSingleton<IAuditSink>(provider => provider.GetRequiredService<MonitoredAuditSink>());
    }

    internal static IHttpClientBuilder ConfigureAdministrationHttpClient(IServiceCollection services, Uri adminUri, int timeoutSeconds) =>
        services.AddHttpClient(HttpClientName, client =>
        {
            client.BaseAddress = adminUri;
            client.Timeout = TimeSpan.FromSeconds(timeoutSeconds);
        }).RemoveAllLoggers();

}
