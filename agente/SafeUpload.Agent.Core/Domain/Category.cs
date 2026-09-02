namespace SafeUpload.Agent.Core.Domain;

/// <summary>
/// Categorias de dado sensível que o agente sabe reconhecer.
/// Cada valor corresponde a uma regra de negócio do projeto:
/// <list type="bullet">
///   <item><description><see cref="Cpf"/> — RN-001</description></item>
///   <item><description><see cref="Cnpj"/> — RN-002</description></item>
///   <item><description><see cref="PaymentCard"/> — RN-003</description></item>
///   <item><description><see cref="Password"/> — RN-004</description></item>
/// </list>
/// A política declara quais categorias estão ativas; o domínio nunca decide
/// isso sozinho, recebe o conjunto ativo como parâmetro.
/// </summary>
public enum Category
{
    Cpf,
    Cnpj,
    PaymentCard,
    Password
}
