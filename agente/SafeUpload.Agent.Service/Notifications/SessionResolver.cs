using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

namespace SafeUpload.Agent.Service.Notifications;

/// <summary>
/// Descobre a que sessão do Windows pertence um processo.
///
/// Serve para entregar a notificação a quem de fato realizou a operação. Numa
/// máquina com duas sessões abertas — troca rápida de usuário, ou um servidor
/// de terminal —, cada sessão tem seu próprio aplicativo de bandeja, e mandar
/// o bloqueio de um usuário para a tela do outro seria vazar por notificação o
/// que o agente existe para não vazar: nome de arquivo é dado.
///
/// <b>Limitação assumida neste mock:</b> quem dispara a inspeção é um
/// <see cref="FileSystemWatcher"/>, que informa o caminho do arquivo e nada
/// mais. Não há como saber qual processo escreveu, então o PID que chega à
/// inspeção é zero e a sessão de origem é indeterminável na prática. O
/// roteamento existe e está correto, mas o caminho que ele realmente percorre
/// hoje é sempre o de difusão. Só a interceptação em modo kernel resolveria
/// isso — o minifiltro conhece o processo que originou a operação.
/// </summary>
public static class SessionResolver
{
    /// <summary>
    /// Sessão de um processo, ou <c>null</c> quando não é possível determinar.
    /// </summary>
    /// <param name="processId">
    /// PID a consultar. Zero significa origem desconhecida e devolve
    /// <c>null</c> sem consultar o sistema.
    /// </param>
    public static uint? TryGetSessionId(int processId)
    {
        if (processId <= 0)
        {
            return null;
        }

        return ProcessIdToSessionId((uint)processId, out var sessionId) ? sessionId : null;
    }

    /// <summary>
    /// Sessão do processo do outro lado de um named pipe já conectado.
    /// </summary>
    public static uint? TryGetClientSessionId(SafePipeHandle pipeHandle)
    {
        ArgumentNullException.ThrowIfNull(pipeHandle);

        if (!GetNamedPipeClientProcessId(pipeHandle, out var clientProcessId))
        {
            return null;
        }

        return ProcessIdToSessionId(clientProcessId, out var sessionId) ? sessionId : null;
    }

    // DllImport, e nao LibraryImport: o gerador do LibraryImport exige
    // AllowUnsafeBlocks no projeto inteiro, e ligar codigo inseguro num servico
    // de prevencao de vazamento so para consultar duas funcoes do kernel32
    // seria um preco alto pago no lugar errado.
    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetNamedPipeClientProcessId(SafePipeHandle pipe, out uint clientProcessId);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool ProcessIdToSessionId(uint processId, out uint sessionId);
}
