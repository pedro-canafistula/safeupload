// Aviso de prontidao para quem estiver esperando.
//
// Existe porque a alternativa obvia - o observador ficar lendo o log do
// processo ate ver a linha de conectado - e I/O de arquivo, e I/O de arquivo
// nesta maquina passa pelo proprio filtro que este processo responde. O
// observador termina esperando por quem espera por ele. O impasse e limitado
// pelo timeout de veredito em vez de fatal, o que o faz parecer travamento em
// vez de defeito, e ja custou uma tarde.
//
// Nada acontece quando ninguem esta esperando: o evento nao e criado aqui, so
// aberto se ja existir. Em producao isto e uma chamada que nao faz nada.

using System.Runtime.Versioning;

namespace SafeUpload.Agent.Minifilter;

[SupportedOSPlatform("windows")]
public static class ReadySignal
{
    /// <summary>Evento que a sonda da bateria sinaliza.</summary>
    public const string ProbeEvent = @"Global\SafeUploadInspectorReady";

    /// <summary>Evento que o servico sinaliza quando o gatilho de kernel sobe.</summary>
    public const string ServiceEvent = @"Global\SafeUploadServiceReady";

    /// <summary>
    /// Sinaliza o evento, se ele existir.
    ///
    /// Deve ser chamado <b>depois</b> de a politica entrar, nunca antes: o
    /// driver sem politica nao inspeciona nada, e anunciar prontidao mais cedo
    /// deixaria o primeiro caso da bateria rodar contra um filtro incapaz de
    /// responder a ele.
    /// </summary>
    public static void Announce(string name)
    {
        try
        {
            if (EventWaitHandle.TryOpenExisting(name, out EventWaitHandle? ready))
            {
                using (ready)
                {
                    ready.Set();
                }
            }
        }
        catch (UnauthorizedAccessException)
        {
            // O evento existe mas pertence a uma sessao que este processo nao
            // alcanca. Nao e fatal e nao e problema deste programa.
        }
        catch (WaitHandleCannotBeOpenedException)
        {
        }
    }
}
