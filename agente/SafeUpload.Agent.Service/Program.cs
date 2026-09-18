using SafeUpload.Agent.Core.Application;
using SafeUpload.Agent.Service.Dispatch;
using SafeUpload.Agent.Service.Interception;
using SafeUpload.Agent.Service.Notifications;
using SafeUpload.Agent.Core.Infrastructure;
using SafeUpload.Agent.Core.Infrastructure.Extraction;

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
    private const string HttpClientName = "CentroAdministracao";

    /// <summary>Monta e executa o host.</summary>
    public static async Task Main(string[] args)
    {
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
        builder.Services.AddSingleton<IAuditSink, LocalQueueAuditSink>();
        builder.Services.AddSingleton(ExtractorRegistry.CreateDefault());
        builder.Services.AddSingleton<VerdictCache>();
        builder.Services.AddSingleton<InspectionService>();
        builder.Services.AddSingleton<NotificationHub>();
        builder.Services.AddSingleton<PendingOverrides>();
        builder.Services.AddSingleton<OverrideGrantQueue>();

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
        string adminBaseUrl = builder.Configuration["CentroAdministracao:BaseUrl"] ?? string.Empty;
        string endpointId = Environment.MachineName;

        if (string.IsNullOrWhiteSpace(adminBaseUrl))
        {
            builder.Services.AddSingleton<IPolicyStore, LocalPolicyStore>();
        }
        else
        {
            var adminUri = new Uri(adminBaseUrl.EndsWith('/') ? adminBaseUrl : adminBaseUrl + "/");

            int timeoutSeconds =
                int.TryParse(builder.Configuration["CentroAdministracao:TimeoutSeconds"], out int parsedTimeout)
                    ? parsedTimeout
                    : 5;

            int intervalSeconds =
                int.TryParse(builder.Configuration["CentroAdministracao:DispatchIntervalSeconds"], out int parsedInterval)
                    ? parsedInterval
                    : 30;

            // Timeout curto de proposito: a politica e lida no caminho da
            // decisao, e um painel lento nao pode virar uma inspecao lenta. Se
            // estourar, a HttpPolicyStore cai no padrao embutido.
            builder.Services
                .AddHttpClient(HttpClientName, client =>
                {
                    client.BaseAddress = adminUri;
                    client.Timeout = TimeSpan.FromSeconds(timeoutSeconds);
                });

            builder.Services.AddSingleton<IPolicyStore>(provider =>
                new HttpPolicyStore(
                    provider.GetRequiredService<IHttpClientFactory>().CreateClient(HttpClientName),
                    endpointId));

            builder.Services.AddHostedService(provider =>
                new HttpAgentDispatcher(
                    provider.GetRequiredService<IAuditSink>(),
                    provider.GetRequiredService<IPolicyStore>(),
                    provider.GetRequiredService<IHttpClientFactory>().CreateClient(HttpClientName),
                    endpointId,
                    TimeSpan.FromSeconds(intervalSeconds),
                    provider.GetRequiredService<ILogger<HttpAgentDispatcher>>()));
        }

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
}
