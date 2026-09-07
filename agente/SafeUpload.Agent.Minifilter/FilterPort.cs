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
    public unsafe bool TryGetMessage(out SafeUploadRequest request, out ulong messageId)
    {
        int size = sizeof(FilterMessageHeader) + sizeof(SafeUploadRequest);
        byte* buffer = stackalloc byte[size];

        int hr = FilterGetMessage(Handle, (IntPtr) buffer, (uint) size, IntPtr.Zero);

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

    public unsafe void Reply(ulong messageId, ulong requestId, uint verdict)
    {
        int size = sizeof(FilterReplyHeader) + sizeof(SafeUploadResponse);
        byte* buffer = stackalloc byte[size];

        *(FilterReplyHeader*) buffer = new FilterReplyHeader
        {
            Status = StatusSuccess,
            MessageId = messageId,
        };

        *(SafeUploadResponse*) (buffer + sizeof(FilterReplyHeader)) = new SafeUploadResponse
        {
            Version = Contract.Version,
            StructSize = (uint) sizeof(SafeUploadResponse),
            RequestId = requestId,
            Verdict = verdict,
            Reserved = 0,
        };

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
    public unsafe void SetPolicy(in SafeUploadPolicyMessage policy)
    {
        fixed (SafeUploadPolicyMessage* p = &policy)
        {
            p->Control.Version = Contract.Version;
            p->Control.StructSize = (uint) sizeof(SafeUploadPolicyMessage);
            p->Control.Command = ControlCommand.SetPolicy;
            p->Control.Reserved = 0;

            int hr = FilterSendMessage(Handle, (IntPtr) p, (uint) sizeof(SafeUploadPolicyMessage),
                                       IntPtr.Zero, 0, out _);

            if (hr != 0)
            {
                throw new Win32Exception(hr, $"Envio da politica falhou: 0x{hr:X8}");
            }
        }
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

    [DllImport("fltlib.dll")]
    private static extern int FilterReplyMessage(
        SafeFileHandle hPort, IntPtr lpReplyBuffer, uint dwReplyBufferSize);

    [DllImport("fltlib.dll")]
    private static extern int FilterSendMessage(
        SafeFileHandle hPort, IntPtr lpInBuffer, uint dwInBufferSize,
        IntPtr lpOutBuffer, uint dwOutBufferSize, out uint lpBytesReturned);
}
