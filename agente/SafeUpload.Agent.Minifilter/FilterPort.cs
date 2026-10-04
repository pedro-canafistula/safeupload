// Connection to the minifilter's communication port.
//
// Wraps the four fltlib entry points the contract needs and nothing else.
// The port takes ONE client at a time and its ACL admits only SYSTEM and
// Administrators, so the process that owns this object is the Windows
// service - not the WPF UI, which talks to the service instead.

using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

namespace SafeUpload.Agent.Minifilter;

/// <summary>
/// Header the Filter Manager puts in front of every kernel-to-user
/// message. 16 bytes: the ulong forces 8-byte alignment, so there are
/// four bytes of padding after ReplyLength.
/// </summary>
[StructLayout(LayoutKind.Sequential, Pack = 8)]
public struct FilterMessageHeader
{
    public uint ReplyLength;
    public ulong MessageId;
}

/// <summary>
/// Header that must precede every reply. MessageId has to be the one that
/// arrived; Status is an NTSTATUS and is not the verdict - the verdict
/// travels in the payload.
/// </summary>
[StructLayout(LayoutKind.Sequential, Pack = 8)]
public struct FilterReplyHeader
{
    public int Status;
    public ulong MessageId;
}

public sealed class FilterPort : IDisposable
{
    private const int StatusSuccess = 0;

    private SafeFileHandle? _handle;

    private FilterPort(SafeFileHandle handle) => _handle = handle;

    public static FilterPort Connect(string portName = Contract.PortName)
    {
        int hr = FilterConnectCommunicationPort(
            portName, 0, IntPtr.Zero, 0, IntPtr.Zero, out SafeFileHandle handle);

        if (hr != 0)
        {
            handle.Dispose();

            // E_ACCESSDENIED here usually means the process is not
            // elevated, and ERROR_FILE_NOT_FOUND wrapped as an HRESULT
            // means the filter is not loaded - neither is a bug in this
            // code, and both are worth telling apart in a log.
            throw new Win32Exception(hr, $"FilterConnectCommunicationPort falhou: 0x{hr:X8}");
        }

        return new FilterPort(handle);
    }

    private SafeFileHandle Handle =>
        _handle ?? throw new ObjectDisposedException(nameof(FilterPort));

    /// <summary>
    /// Blocks until the driver sends a request.
    ///
    /// This call is synchronous and the driver is waiting on the other
    /// side with a 500 ms budget. Whatever happens between this returning
    /// and Reply() being called is time the file open is stalled - and if
    /// it runs past the budget the driver stops waiting and allows the
    /// operation uninspected (RN-013), silently. Anything slow belongs on
    /// another thread, not here.
    /// </summary>
    public unsafe bool TryGetMessage(out SafeUploadRequest request, out ulong messageId,
        CancellationToken cancellationToken = default)
    {
        int size = sizeof(FilterMessageHeader) + sizeof(SafeUploadRequest);
        byte* buffer = stackalloc byte[size];

        // A null OVERLAPPED waits on the port handle itself. A concurrent
        // FilterSendMessage can signal that same handle and wake the receive
        // before its request has completed. Own the completion event for this
        // receive and keep its buffer/OVERLAPPED alive until completion.
        using var completed = new EventWaitHandle(false, EventResetMode.ManualReset);
        NativeOverlapped overlapped = new()
        {
            EventHandle = completed.SafeWaitHandle.DangerousGetHandle()
        };
        IntPtr pending = (IntPtr)(&overlapped);
        int hr = FilterGetMessage(Handle, (IntPtr) buffer, (uint) size, pending);
        if (hr == unchecked((int)0x800703E5)) // HRESULT_FROM_WIN32(ERROR_IO_PENDING)
        {
            bool canceled = false;
            while (!completed.WaitOne(250))
            {
                if (!canceled && cancellationToken.IsCancellationRequested)
                {
                    _ = CancelIoEx(Handle, pending);
                    canceled = true;
                }
            }
            hr = GetOverlappedResult(Handle, pending, out _, false)
                ? 0 : Marshal.GetHRForLastWin32Error();
        }

        if (hr != 0)
        {
            request = default;
            messageId = 0;
            return false;
        }

        var header = *(FilterMessageHeader*) buffer;
        request = *(SafeUploadRequest*) (buffer + sizeof(FilterMessageHeader));
        messageId = header.MessageId;

        return true;
    }

    public unsafe void Reply(ulong messageId, ulong requestId, uint verdict,
        string? stageName = null)
    {
        if (stageName is { Length: >= Contract.MaxStageNameChars } ||
            (stageName is not null &&
             (stageName.IndexOfAny(['\\', '/', ':']) >= 0 || stageName is "." or "..")))
        {
            throw new ArgumentException("Invalid stage basename.", nameof(stageName));
        }

        int size = sizeof(FilterReplyHeader) + sizeof(SafeUploadResponse);
        byte* buffer = stackalloc byte[size];
        new Span<byte>(buffer, size).Clear();

        *(FilterReplyHeader*) buffer = new FilterReplyHeader
        {
            Status = StatusSuccess,
            MessageId = messageId,
        };

        SafeUploadResponse* response = (SafeUploadResponse*) (buffer + sizeof(FilterReplyHeader));
        *response = new SafeUploadResponse
        {
            Version = Contract.Version,
            StructSize = (uint) sizeof(SafeUploadResponse),
            RequestId = requestId,
            Verdict = verdict,
            StageNameLength = (uint) ((stageName?.Length ?? 0) * sizeof(char)),
        };
        if (stageName is not null)
        {
            for (int i = 0; i < stageName.Length; i += 1)
            {
                response->StageName[i] = stageName[i];
            }
        }

        int hr = FilterReplyMessage(Handle, (IntPtr) buffer, (uint) size);

        // A reply that misses its window is not fatal: the driver has
        // already timed out and allowed the operation. Worth counting,
        // not worth throwing over.
        if (hr != 0 && hr != unchecked((int) 0x8007010B))
        {
            throw new Win32Exception(hr, $"FilterReplyMessage falhou: 0x{hr:X8}");
        }
    }

    /// <summary>
    /// Pushes the policy. Until this succeeds the driver has no policy at
    /// all and inspects nothing, so this is not optional setup - it is the
    /// step that turns the filter on.
    /// </summary>
    public unsafe void SetPolicy(in SafeUploadPolicyMessage policy, bool finalizeDurableBootScopes = false)
    {
        fixed (SafeUploadPolicyMessage* p = &policy)
        {
            p->Control.Version = Contract.Version;
            p->Control.StructSize = (uint) sizeof(SafeUploadPolicyMessage);
            p->Control.Command = ControlCommand.SetPolicy;
            p->Control.Reserved = finalizeDurableBootScopes ? Contract.FinalizeDurableBootScopes : 0;

            int hr = FilterSendMessage(Handle, (IntPtr) p, (uint) sizeof(SafeUploadPolicyMessage),
                                       IntPtr.Zero, 0, out _);

            if (hr != 0)
            {
                throw new Win32Exception(hr, $"Envio da politica falhou: 0x{hr:X8}");
            }
        }
    }

    /// <summary>
    /// Concede uma excecao: um processo, um caminho de destino exato, por um
    /// prazo curto e valida para um uso.
    ///
    /// Quem chama tem de ter registrado a justificativa ANTES - a excecao e
    /// a consequencia do registro, nao o contrario. Um caminho que conceda
    /// primeiro e audite depois deixa de auditar quando o segundo passo
    /// falha, e o que fica e o buraco sem o registro.
    /// </summary>
    /// <param name="processId">Processo que levou a recusa.</param>
    /// <param name="ntPath">Caminho de destino em forma de dispositivo.</param>
    /// <param name="duration">Prazo pedido; o driver limita.</param>
    public unsafe void GrantOverride(uint processId, string ntPath, TimeSpan duration)
    {
        ArgumentException.ThrowIfNullOrEmpty(ntPath);

        if (ntPath.Length >= Contract.MaxPathChars)
        {
            throw new ArgumentException($"Caminho com {ntPath.Length} caracteres; o limite e {Contract.MaxPathChars - 1}.", nameof(ntPath));
        }

        var message = new SafeUploadOverrideMessage
        {
            Control = new SafeUploadControl
            {
                Version = Contract.Version,
                StructSize = (uint) sizeof(SafeUploadOverrideMessage),
                Command = ControlCommand.GrantOverride,
                Reserved = 0,
            },
            ProcessId = processId,
            DurationSeconds = (uint) Math.Clamp(duration.TotalSeconds, 1, 600),
            PathLength = (uint) (ntPath.Length * sizeof(char)),
            Reserved = 0,
        };

        for (int i = 0; i < ntPath.Length; i += 1)
        {
            message.Path[i] = ntPath[i];
        }

        int hr = FilterSendMessage(Handle, (IntPtr) (&message), (uint) sizeof(SafeUploadOverrideMessage),
                                   IntPtr.Zero, 0, out _);

        if (hr != 0)
        {
            throw new Win32Exception(hr, $"Concessao de excecao falhou: 0x{hr:X8}");
        }
    }

    public void SetPublicationPermit(Guid transferId, string temporaryPath, string destinationPath, string digest)
        => SendPublicationPermit(transferId, PolicyBuilder.ToNtPath(temporaryPath),
            PolicyBuilder.ToNtPath(destinationPath), Convert.FromHexString(digest), false);

    public void RevokePublicationPermit(Guid transferId)
        => SendPublicationPermit(transferId, "", "", new byte[32], true);

    private unsafe void SendPublicationPermit(Guid id, string temporaryPath,
        string destinationPath, byte[] digest, bool revoke)
    {
        if (id == Guid.Empty || digest.Length != 32 ||
            temporaryPath.Length >= Contract.MaxPathChars ||
            destinationPath.Length >= Contract.MaxPathChars)
            throw new ArgumentException("Invalid publication permit.");
        SafeUploadPublicationMessage message = new()
        {
            Control = new() { Version = Contract.Version,
                StructSize = (uint)sizeof(SafeUploadPublicationMessage),
                Command = ControlCommand.StagePublication },
            TransferId = id, Revoke = revoke ? 1u : 0u,
            TemporaryPathLength = (uint)(temporaryPath.Length * sizeof(char)),
            DestinationPathLength = (uint)(destinationPath.Length * sizeof(char))
        };
        for (int i = 0; i < digest.Length; ++i) message.Digest[i] = digest[i];
        for (int i = 0; i < temporaryPath.Length; ++i) message.TemporaryPath[i] = temporaryPath[i];
        for (int i = 0; i < destinationPath.Length; ++i) message.DestinationPath[i] = destinationPath[i];
        int hr = FilterSendMessage(Handle, (IntPtr)(&message), (uint)sizeof(SafeUploadPublicationMessage),
            IntPtr.Zero, 0, out _);
        if (hr != 0) throw new Win32Exception(hr, $"Publication permit refused: 0x{hr:X8}");
    }

    public unsafe SafeUploadCounters GetCounters()
    {
        var control = new SafeUploadControl
        {
            Version = Contract.Version,
            StructSize = (uint) sizeof(SafeUploadControl),
            Command = ControlCommand.GetCounters,
            Reserved = 0,
        };

        SafeUploadCounters counters = default;

        int hr = FilterSendMessage(Handle, (IntPtr) (&control), (uint) sizeof(SafeUploadControl),
                                   (IntPtr) (&counters), (uint) sizeof(SafeUploadCounters), out _);

        if (hr != 0)
        {
            throw new Win32Exception(hr, $"Leitura dos contadores falhou: 0x{hr:X8}");
        }

        return counters;
    }

    public void Dispose()
    {
        _handle?.Dispose();
        _handle = null;
    }

    [DllImport("fltlib.dll", CharSet = CharSet.Unicode)]
    private static extern int FilterConnectCommunicationPort(
        string lpPortName, uint dwOptions, IntPtr lpContext, ushort wSizeOfContext,
        IntPtr lpSecurityAttributes, out SafeFileHandle hPort);

    [DllImport("fltlib.dll")]
    private static extern int FilterGetMessage(
        SafeFileHandle hPort, IntPtr lpMessageBuffer, uint dwMessageBufferSize, IntPtr lpOverlapped);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetOverlappedResult(SafeFileHandle handle,
        IntPtr overlapped, out uint bytes, [MarshalAs(UnmanagedType.Bool)] bool wait);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CancelIoEx(SafeFileHandle handle, IntPtr overlapped);

    [DllImport("fltlib.dll")]
    private static extern int FilterReplyMessage(
        SafeFileHandle hPort, IntPtr lpReplyBuffer, uint dwReplyBufferSize);

    [DllImport("fltlib.dll")]
    private static extern int FilterSendMessage(
        SafeFileHandle hPort, IntPtr lpInBuffer, uint dwInBufferSize,
        IntPtr lpOutBuffer, uint dwOutBufferSize, out uint lpBytesReturned);
}
