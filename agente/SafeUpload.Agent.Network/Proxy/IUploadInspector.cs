using SafeUpload.Agent.Network.Http;

namespace SafeUpload.Agent.Network.Proxy;

/// <summary>
/// O ponto onde o proxy pergunta "isto pode sair?".
///
/// O proxy (Fase 2) só sabe transportar: abre as conexões, lê as mensagens e
/// segura o corpo. Quem decide é a implementação desta interface, que na Fase 5
/// vai extrair o conteúdo (multipart, corpo bruto, JSON) e passá-lo ao motor de
/// inspeção do Core. Separar os dois deixa o transporte testável sem o motor e
/// o motor intocado pelo transporte.
/// </summary>
public interface IUploadInspector
{
    /// <summary>
    /// Decide sobre uma requisição com corpo, antes de ela seguir para o
    /// servidor. Só é chamada quando o corpo inteiro coube no limite de
    /// inspeção; acima dele a requisição segue sem passar por aqui (ver
    /// <see cref="TlsInspectionProxyOptions.MaxInspectableBodyBytes"/>).
    /// </summary>
    ValueTask<UploadDecision> InspectAsync(UploadRequest request, CancellationToken cancellationToken);
}

/// <summary>Uma requisição com corpo, segurada pelo proxy.</summary>
/// <param name="Host">Site de destino (ex.: drive.google.com).</param>
/// <param name="Port">Porta de destino.</param>
/// <param name="Head">Primeira linha e cabeçalhos, como chegaram do navegador.</param>
/// <param name="Body">Corpo inteiro, já sem a moldura de pedaços.</param>
/// <param name="ProcessId">
/// Processo que abriu a conexão (o navegador), quando foi possível descobrir.
/// </param>
/// <param name="Encrypted">Se veio por HTTPS (interceptado) ou HTTP puro.</param>
public sealed record UploadRequest(
    string Host,
    int Port,
    HttpRequestHead Head,
    ReadOnlyMemory<byte> Body,
    int? ProcessId,
    bool Encrypted);

/// <summary>O que fazer com a requisição.</summary>
/// <param name="Allowed">Segue para o servidor.</param>
/// <param name="Reason">Motivo do bloqueio, mostrado ao usuário na página de erro.</param>
public sealed record UploadDecision(bool Allowed, string? Reason = null)
{
    /// <summary>Deixa seguir.</summary>
    public static UploadDecision Allow { get; } = new(true);

    /// <summary>Barra, com o motivo.</summary>
    public static UploadDecision Block(string reason) => new(false, reason);
}

/// <summary>Libera tudo. É o comportamento até a Fase 5 ligar o motor de inspeção.</summary>
public sealed class AllowAllInspector : IUploadInspector
{
    /// <inheritdoc />
    public ValueTask<UploadDecision> InspectAsync(UploadRequest request, CancellationToken cancellationToken) =>
        ValueTask.FromResult(UploadDecision.Allow);
}
