#if SAFEUPLOAD_ADMISSION_EVIDENCE
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

namespace SafeUpload.Agent.Minifilter;

// Real adapter only. The optional barrier observes admission before the native
// invocation; it cannot manufacture a result or replace FilterSendMessage.
internal sealed class Nu501NativeSender : IResourceNativeSender
{
    internal Action? BeforeNative;
    internal long Entered, Returned;
    internal int LastHResult;
    internal uint LastBytesReturned;
    public unsafe int Send(SafeFileHandle handle, ReadOnlyMemory<byte> input, Memory<byte> output, out uint bytesReturned)
    {
        Interlocked.Increment(ref Entered);
        BeforeNative?.Invoke();
        try
        {
            fixed (byte* source = input.Span)
            fixed (byte* target = output.Span)
            {
                int hr = FilterSendMessage(handle, (IntPtr)source, (uint)input.Length,
                    (IntPtr)target, (uint)output.Length, out bytesReturned);
                LastHResult = hr; LastBytesReturned = bytesReturned;
                return hr;
            }
        }
        finally { Interlocked.Increment(ref Returned); }
    }
    [DllImport("fltlib.dll")]
    private static extern int FilterSendMessage(SafeFileHandle port, IntPtr input, uint inputBytes,
        IntPtr output, uint outputBytes, out uint returned);
}

public sealed partial class FilterPort
{
    internal (bool Accepting, bool Disposed, int Active, bool HandlesOpen) Nu501Lifetime
    {
        get { lock (_sendLifecycle) return (_acceptingSends, _disposed, _activeSenders,
            _handle is { IsClosed: false } && _resourceHandle is { IsClosed: false }); }
    }

    // Bootstrap is nonwaiting and never queues behind SetPolicy/_sendGate.
    internal unsafe ResourceSendResult Nu501Bootstrap(byte[] input, int outputBytes)
    {
        lock (_sendLifecycle)
        {
            if (!_acceptingSends || _resourceRevoked) return new(ResourceSendStatus.Revoked);
            if (!_sendGate.Wait(0)) return new(ResourceSendStatus.Busy);
            _activeSenders++;
        }
        using (var lease = new SendLease(this, Handle))
        {
            byte[] output = new byte[outputBytes];
            fixed (byte* source = input)
            fixed (byte* target = output)
            {
                int hr = FilterSendMessage(lease.Handle, (IntPtr)source, (uint)input.Length,
                    (IntPtr)target, (uint)output.Length, out uint returned);
                return new(ResourceSendStatus.Completed, hr, output, returned);
            }
        }
    }

    internal unsafe int Nu501Pair(ResourcePairContextV32 context, Nu501NativeSender sender)
    {
        // Only the original connected service calls this before starting any
        // harness sends. Never publish a handle across disposal.
        using var lease = EnterSend();
        int hr = FilterConnectCommunicationPort("\\SafeUploadResourcePort", 0,
            (IntPtr)(&context), 24, IntPtr.Zero, out var resource);
        if (hr != 0) { resource.Dispose(); return hr; }
        lock (_sendLifecycle)
        {
            if (!_acceptingSends || _resourceHandle is not null) { resource.Dispose(); throw new InvalidOperationException("Pair lifecycle changed."); }
            _resourceHandle = resource;
            _resourceNativeSender = sender;
        }
        return hr;
    }
}
#endif
