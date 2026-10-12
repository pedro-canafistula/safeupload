using SafeUpload.Agent.Core.Contracts;

namespace SafeUpload.Agent.Core.Application;

/// <summary>
/// Decide, do lado do aplicativo, se o texto copiado pode ir ao serviço.
///
/// <para><b>Por que existe.</b> Com o canal desligado (<c>clipboard.mode =
/// Off</c>, que é o padrão), o serviço descarta o texto e responde "limpo". O
/// texto, porém, já saiu do processo do usuário à toa. Esta porta guarda o que
/// o serviço disse por último sobre o canal e, quando não sabe que ele está
/// ligado, pergunta antes (<c>state</c>, que não leva texto nenhum).</para>
///
/// <para><b>O ciclo.</b> Sem saber o estado (no início, ou depois de ouvir
/// "desligado"), cada cópia pergunta primeiro. Sabendo que está ligado, manda
/// o texto direto, sem a pergunta extra. Quando a resposta de uma classificação
/// diz "desligado", a porta volta a perguntar a partir da cópia seguinte; o
/// texto daquela cópia já tinha ido, o que é o custo de um canal desligado no
/// meio do caminho.</para>
///
/// <para><b>A falha libera (RN-013), e aqui liberar é não mandar.</b> Sem
/// resposta à pergunta, o canal é tratado como desligado para aquela cópia:
/// nada é classificado, e o clipboard fica limpo. Um serviço antigo, que não
/// envia o campo de estado, é tratado como canal ligado: é o que acontecia
/// antes do campo existir.</para>
///
/// <para><b>Compatibilidade.</b> Um serviço anterior a <c>state</c> não responde
/// a essa pergunta, e um aplicativo novo trataria o canal como desligado. App e
/// serviço são instalados juntos, então isso só acontece numa instalação pela
/// metade, e o efeito é seguro: nada é classificado.</para>
///
/// <para>Não é segura para threads: o monitor a usa só na thread da interface.</para>
/// </summary>
public sealed class ClipboardChannelGate
{
    private bool _knownEnabled;

    /// <summary>A próxima cópia precisa perguntar o estado antes de mandar o texto.</summary>
    public bool MustAskFirst => !_knownEnabled;

    /// <summary>
    /// Registra a resposta à pergunta de estado e diz se o texto pode ir.
    /// </summary>
    /// <param name="response">A resposta, ou <c>null</c> se não veio.</param>
    /// <returns><c>true</c> se o canal está ligado.</returns>
    public bool OnStateResponse(ClipboardResponse? response)
    {
        _knownEnabled = response is { Type: ClipboardProtocol.StateType, Enabled: true };
        return _knownEnabled;
    }

    /// <summary>Registra o que a resposta de uma classificação diz sobre o canal.</summary>
    /// <param name="response">A resposta, ou <c>null</c> se não veio.</param>
    public void OnClassifyResponse(ClipboardResponse? response)
    {
        if (response is null)
        {
            // Sem resposta não se sabe nada de novo; o próximo pedido decide.
            return;
        }

        // Serviço antigo, sem o campo: segue como ligado.
        _knownEnabled = response.Enabled ?? true;
    }
}
