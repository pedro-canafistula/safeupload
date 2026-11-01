using SafeUpload.Agent.Core.Domain;

namespace SafeUpload.Agent.Core.Application;

/// <summary>
/// De onde o agente lê a política vigente.
///
/// PONTO DE TROCA PARA O SERVIDOR CENTRAL.
///
/// Nesta entrega existe uma única implementação, a LocalPolicyStore, que lê um
/// JSON em %ProgramData%\SafeUpload. A integração com o Centro de
/// Administração (HU-10) consiste em escrever uma HttpPolicyStore que busque a
/// política publicada pelo painel, provavelmente com cache local para o
/// endpoint continuar protegido quando o servidor estiver fora do ar, e
/// registrá-la no composition root. Nada além da composição muda: o motor de
/// inspeção depende desta interface e não sabe da origem da política.
///
/// Legacy consumers may keep protection available with a validated fallback.
/// Staged decisions require a distinct current read, so a fallback can never
/// silently become authority to publish, justify or export retained bytes.
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
    /// Loads the current validated policy. Providers that can tell a fresh read from a fallback override this so read
    /// failures cannot substitute a previous/default policy; the others answer with <see cref="LoadAsync"/>.
    /// </summary>
    Task<Policy> LoadCurrentAsync(CancellationToken cancellationToken) => LoadAsync(cancellationToken);
}
