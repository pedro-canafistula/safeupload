using SafeUpload.Agent.Core.Domain;

namespace SafeUpload.Agent.App.ViewModels;

/// <summary>
/// Um achado mostrado na tela, já mascarado.
///
/// O trecho chega assim do domínio, do outro lado do canal: o serviço mascara
/// no momento da varredura e é o valor mascarado que viaja pelo pipe. Esta
/// camada não teria como desmascarar nada, porque o valor original nunca saiu
/// do processo que leu o arquivo.
/// </summary>
/// <param name="Category">Nome da categoria em português.</param>
/// <param name="MaskedSnippet">Trecho mascarado.</param>
public sealed record FindingViewModel
{
    public FindingViewModel(string category, string maskedSnippet)
    {
        Category = AuditTextPrivacy.Sanitize(category);
        MaskedSnippet = AuditTextPrivacy.Sanitize(maskedSnippet);
    }
    public string Category { get; }
    public string MaskedSnippet { get; }
}
