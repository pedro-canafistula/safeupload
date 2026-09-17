namespace SafeUpload.Agent.Core.Domain;

/// <summary>
/// Uma ocorrência de dado sensível encontrada no conteúdo de um arquivo.
///
/// O trecho já vem mascarado (RN-007): este tipo é o único canal pelo qual a
/// varredura conta o que achou, e ele não tem como carregar o valor original.
/// </summary>
/// <param name="Category">Categoria da regra que reconheceu o trecho.</param>
/// <param name="MaskedSnippet">Trecho mascarado, seguro para exibir e registrar.</param>
public sealed record Finding(Category Category, string MaskedSnippet);
