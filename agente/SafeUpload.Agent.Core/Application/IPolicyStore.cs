using SafeUpload.Agent.Core.Domain;

namespace SafeUpload.Agent.Core.Application;

/// <summary>
/// Origem da política validada: arquivo local, HTTP, cache durável ou snapshot
/// mantido pelo serviço. O motor de inspeção não escolhe o transporte.
/// A composição define a autoridade vigente: provedores HTTP diretos exigem
/// uma leitura remota em LoadCurrentAsync; a composição offline do serviço usa
/// o último snapshot validado, inclusive sem rede, e o renova em segundo plano.
/// </summary>
public interface IPolicyStore
{
    /// <summary>
    /// Devolve uma política validada, admitindo o fallback documentado pelo provedor.
    /// </summary>
    /// <exception cref="InvalidPolicyException">
    /// Se a política armazenada não puder ser aplicada, entre outros motivos
    /// por não ter categoria ativa nenhuma (RN-009).
    /// </exception>
    Task<Policy> LoadAsync(CancellationToken cancellationToken);

    /// <summary>
    /// Loads the current validated policy according to the configured provider. Direct HTTP providers reject origin
    /// failures; the service's offline snapshot remains current until its next successful background refresh.
    /// This call alone does not prove a fresh remote read. Other providers default to <see cref="LoadAsync"/>.
    /// </summary>
    Task<Policy> LoadCurrentAsync(CancellationToken cancellationToken) => LoadAsync(cancellationToken);
}
