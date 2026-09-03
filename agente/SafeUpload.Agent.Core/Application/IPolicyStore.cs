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
/// A interface é deliberadamente mínima — uma única operação de leitura — para
/// que a versão HTTP não precise expor semântica de rede a quem a consome.
/// </summary>
public interface IPolicyStore
{
    /// <summary>
    /// Devolve a política vigente, já validada.
    /// </summary>
    /// <exception cref="InvalidPolicyException">
    /// Se a política armazenada não puder ser aplicada, entre outros motivos
    /// por não ter categoria ativa nenhuma (RN-009).
    /// </exception>
    Task<Policy> LoadAsync(CancellationToken cancellationToken);
}
