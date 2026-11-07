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

        // "cadastrar <url> <token> [--certificado <sha256>] [--substituir]": liga esta máquina ao console.
        if (args.Length > 0 && string.Equals(args[0], "cadastrar", StringComparison.OrdinalIgnoreCase))
        {
            Console.OutputEncoding = System.Text.Encoding.UTF8;
            Environment.ExitCode = await EnrollCommand.RunAsync(args[1..], Console.Out);
            return;
        }

        if (args.Length > 0 && string.Equals(args[0], "atualizar-certificado", StringComparison.OrdinalIgnoreCase))
        {
            Console.OutputEncoding = System.Text.Encoding.UTF8;
            Environment.ExitCode = await EnrollCommand.UpdateCertificateAsync(args[1..], Console.Out);
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
        ConfigureOperationalLogging(builder.Services);

        // A composição é a mesma que o aplicativo WPF fazia à mão, agora do
        // lado do serviço: são estes objetos que decidem, e é por isso que
        // saíram do processo da interface.
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
        // Sem cadastro ("cadastrar <url> <token>"), o agente e autonomo: le a politica do arquivo local e so acumula
        // auditoria em disco. Cadastrado, toda requisicao ao servidor e assinada com a chave da maquina; a politica
        // vem do console (com cache offline) e um despachante entrega heartbeat e eventos (docs/console-agente.md).
        var identities = new SignedHostIdentityStore(Path.Combine(AgentPaths.RootDirectory, "authentication", "ed25519-identity.dat"));
        var administration = AdministrationConfiguration.Parse(builder.Configuration, identities.Load);
        // A fila registra localmente em ambos os modos. O despacho usa apenas os registros do cadastro ativo.
        ConfigureAuditStorage(builder.Services, administration.Identity);
        string endpointId = Environment.MachineName;
        builder.Services.AddSingleton(new CommunicationHealth(administration.BaseUri is not null));
        builder.Services.AddHostedService<CommunicationStatusPublisher>();
        if (administration.Problem is { } problem)
            builder.Services.AddHostedService(provider => new StartupWarning(
                provider.GetRequiredService<ILogger<StartupWarning>>(), problem));

        if (administration.Identity is not { } identity)
        {
            builder.Services.AddSingleton<IPolicyStore, LocalPolicyStore>();
        }
        else
        {
            // A rede só é consultada em segundo plano. Inspeções usam o último snapshot validado mesmo durante
            // timeout, falha ou reconexão.
            ConfigureAdministrationHttpClient(builder.Services, identity, administration.Timeout);
            builder.Services.AddSingleton(provider => new DurableHttpPolicyStore(
                provider.GetRequiredService<IHttpClientFactory>().CreateClient(HttpClientName),
                identity,
                Path.Combine(AgentPaths.RootDirectory, "console-policy-cache.json"), new LocalPolicyStore(),
                provider.GetRequiredService<CommunicationHealth>()));
            builder.Services.AddSingleton(provider => new RefreshingPolicyStore(
                provider.GetRequiredService<DurableHttpPolicyStore>(), TimeSpan.FromSeconds(30),
                provider.GetRequiredService<ILogger<RefreshingPolicyStore>>()));
            builder.Services.AddSingleton<IPolicyStore>(provider => provider.GetRequiredService<RefreshingPolicyStore>());
            builder.Services.AddHostedService(provider => provider.GetRequiredService<RefreshingPolicyStore>());

            builder.Services.AddHostedService(provider =>
            {
                var client = provider.GetRequiredService<IHttpClientFactory>().CreateClient(HttpClientName);
                var health = provider.GetRequiredService<CommunicationHealth>();
                var console = provider.GetRequiredService<DurableHttpPolicyStore>();
                return new HttpAgentDispatcher(
                    provider.GetRequiredService<IAuditSink>(),
                    provider.GetRequiredService<IPolicyStore>(),
                    client,
                    endpointId,
                    administration.DispatchInterval,
                    provider.GetRequiredService<ILogger<HttpAgentDispatcher>>(),
                    health)
                {
                    HeartbeatSender = new SignedAgentHeartbeat(new AgentApiClient(client, health), identity.HostId,
                        () => console.ConsoleVersion, HttpAgentDispatcher.AgentVersion)
                };
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

        // A inspeção do tráfego web (proxy TLS). Quem liga é a política (bloco "web", publicado pelo console):
        // ligar instala uma CA confiável na máquina, e isso tem de ser uma decisão explícita do administrador.
        // Ver docs/rede/ARQUITETURA-INSPECAO-TLS.md.
        builder.Services.AddSingleton<WebInspectionService>();
        builder.Services.AddSingleton<WebUploadInspector>();
        builder.Services.AddHostedService<TlsInspectionService>();

        await builder.Build().RunAsync();
    }

    internal static void ConfigureOperationalLogging(IServiceCollection services)
    {
        services.AddLogging();
        services.AddSingleton(typeof(ILogger<>), typeof(BestEffortLogger<>));
    }

    internal static void ConfigureAuditStorage(IServiceCollection services, SignedAgentIdentity? identity = null)
    {
        services.AddSingleton(_ => new LocalQueueAuditSink(identity)); // Never select the isolated-path test constructor through DI.
        services.AddSingleton<AuditQueueHealth>();
        services.AddSingleton<MonitoredAuditSink>(provider => new MonitoredAuditSink(
            provider.GetRequiredService<LocalQueueAuditSink>(), provider.GetRequiredService<AuditQueueHealth>(),
            provider.GetRequiredService<ILogger<MonitoredAuditSink>>()));
        services.AddSingleton<IAuditSink>(provider => provider.GetRequiredService<MonitoredAuditSink>());
    }

    /// <summary>Cliente do servidor: assina cada requisição e, com certificado fixado, só aceita aquele certificado.</summary>
    internal static IHttpClientBuilder ConfigureAdministrationHttpClient(IServiceCollection services,
        SignedAgentIdentity identity, TimeSpan timeout) =>
        services.AddHttpClient(HttpClientName, client =>
        {
            client.BaseAddress = identity.Server;
            client.Timeout = timeout;
        }).ConfigurePrimaryHttpMessageHandler(() => AgentHttp.CreateHandler(identity.CertificateSha256))
        .AddHttpMessageHandler(() => new SignedRequestHandler(identity))
        .RemoveAllLoggers();

}
