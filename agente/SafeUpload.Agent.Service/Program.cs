using SafeUpload.Agent.Core.Application;
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

    /// <summary>Monta e executa o host.</summary>
    public static async Task Main(string[] args)
    {
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

        // O gatilho. A partir daqui a protecao existe sem interface nenhuma
        // aberta, que e o ponto de separar os dois processos.
        builder.Services.AddHostedService<FileSystemInterceptor>();

        // A entrega das notificacoes aos aplicativos conectados.
        builder.Services.AddHostedService<NotificationPipeServer>();

        await builder.Build().RunAsync();
    }
}
