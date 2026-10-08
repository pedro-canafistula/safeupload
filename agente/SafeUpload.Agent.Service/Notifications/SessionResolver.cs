using System.Runtime.InteropServices;
using System.Security.Principal;
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
/// Events observed only through a filesystem watcher may have no reliable
/// originating process. Kernel-staged requests use <see cref="GetRequiredProcessIdentity"/>
/// instead, and bind their journal, hand-back, and notifications to the
/// process token SID and session captured during allocation.
/// </summary>
public static class SessionResolver
{
    private const uint ProcessQueryLimitedInformation = 0x1000;
    private const uint TokenQuery = 0x0008;
    private const int TokenUser = 1;
    private const int TokenSessionId = 12;
    private const int ErrorInsufficientBuffer = 122;

    public sealed record ProcessIdentity(uint SessionId, SecurityIdentifier UserSid,
        long CreationTimeFileTime);

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
    /// Opens the requesting process and reads its token identity while the
    /// kernel allocation request is being handled. Failure is explicit so a
    /// caller cannot silently allocate an unbound staged version.
    /// </summary>
    public static ProcessIdentity GetRequiredProcessIdentity(int processId)
    {
        if (processId <= 0) throw new ArgumentOutOfRangeException(nameof(processId));
        using SafeProcessHandle process = OpenProcess(ProcessQueryLimitedInformation,
            inheritHandle: false, checked((uint)processId));
        if (process.IsInvalid)
            throw new IOException("The requesting process could not be opened.",
                new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error()));
        if (!OpenProcessToken(process, TokenQuery, out SafeAccessTokenHandle token))
            throw new IOException("The requesting process token could not be opened.",
                new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error()));
        using (token)
        {
            if (!GetProcessTimes(process, out var creation, out _, out _, out _))
                throw new IOException("The requesting process creation time could not be read.",
                    new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error()));
            uint sessionId = ReadTokenUInt32(token, TokenSessionId);
            return new ProcessIdentity(sessionId, ReadTokenUserSid(token),
                ((long)(uint)creation.dwHighDateTime << 32) | unchecked((uint)creation.dwLowDateTime));
        }
    }

    /// <summary>SID currently associated with a Windows terminal session.</summary>
    public static SecurityIdentifier? TryGetSessionUserSid(uint? sessionId)
    {
        if (sessionId is null || !WTSQueryUserToken(sessionId.Value, out SafeAccessTokenHandle token))
            return null;
        using (token)
        {
            if (ReadTokenUInt32(token, TokenSessionId) != sessionId.Value) return null;
            return ReadTokenUserSid(token);
        }
    }

    /// <summary>Authenticated identity of the process connected to a named pipe.</summary>
    public static ProcessIdentity? TryGetClientIdentity(SafePipeHandle pipeHandle)
    {
        ArgumentNullException.ThrowIfNull(pipeHandle);
        if (!GetNamedPipeClientProcessId(pipeHandle, out uint processId)) return null;
        try { return GetRequiredProcessIdentity(checked((int)processId)); }
        catch (Exception) { return null; }
    }

    /// <summary>
    /// Sessão do processo do outro lado de um named pipe já conectado.
    /// </summary>
    public static uint? TryGetClientSessionId(SafePipeHandle pipeHandle)
    {
        return TryGetClientIdentity(pipeHandle)?.SessionId;
    }

    private static SecurityIdentifier ReadTokenUserSid(SafeAccessTokenHandle token)
    {
        _ = GetTokenInformation(token, TokenUser, IntPtr.Zero, 0, out uint required);
        int error = Marshal.GetLastWin32Error();
        if (error != ErrorInsufficientBuffer || required == 0 || required > 64 * 1024)
            throw new IOException("The process token SID could not be read.",
                new System.ComponentModel.Win32Exception(error));
        IntPtr buffer = Marshal.AllocHGlobal(checked((int)required));
        try
        {
            if (!GetTokenInformation(token, TokenUser, buffer, required, out _))
                throw new IOException("The process token SID could not be read.",
                    new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error()));
            return new SecurityIdentifier(Marshal.ReadIntPtr(buffer));
        }
        finally { Marshal.FreeHGlobal(buffer); }
    }

    private static uint ReadTokenUInt32(SafeAccessTokenHandle token, int informationClass)
    {
        IntPtr buffer = Marshal.AllocHGlobal(sizeof(uint));
        try
        {
            if (!GetTokenInformation(token, informationClass, buffer, sizeof(uint), out _))
                throw new IOException("The process token identity could not be read.",
                    new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error()));
            return unchecked((uint)Marshal.ReadInt32(buffer));
        }
        finally { Marshal.FreeHGlobal(buffer); }
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

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern SafeProcessHandle OpenProcess(uint desiredAccess,
        [MarshalAs(UnmanagedType.Bool)] bool inheritHandle, uint processId);

    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool OpenProcessToken(SafeProcessHandle process, uint desiredAccess,
        out SafeAccessTokenHandle token);

    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetTokenInformation(SafeAccessTokenHandle token,
        int informationClass, IntPtr information, uint informationLength, out uint returnLength);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetProcessTimes(SafeProcessHandle process,
        out System.Runtime.InteropServices.ComTypes.FILETIME creationTime,
        out System.Runtime.InteropServices.ComTypes.FILETIME exitTime,
        out System.Runtime.InteropServices.ComTypes.FILETIME kernelTime,
        out System.Runtime.InteropServices.ComTypes.FILETIME userTime);

    [DllImport("wtsapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool WTSQueryUserToken(uint sessionId, out SafeAccessTokenHandle token);
}
