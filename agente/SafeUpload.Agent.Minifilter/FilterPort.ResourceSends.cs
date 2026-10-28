#if SAFEUPLOAD_ADMISSION_EVIDENCE
using Microsoft.Win32.SafeHandles;

namespace SafeUpload.Agent.Minifilter;

internal enum ResourceSendClass { MetadataProgress, Resolution, Revoke }
internal enum ResourceSendStatus { Completed, Busy, Canceled, Revoked }
internal sealed record ResourceSendResult(ResourceSendStatus Status, int HResult = 0, byte[]? Output = null, uint BytesReturned = 0);
internal interface IResourceNativeSender
{
    int Send(SafeFileHandle handle, ReadOnlyMemory<byte> input, Memory<byte> output, out uint bytesReturned);
}

public sealed partial class FilterPort
{
    private sealed class ResourceClass(int limit, int queueLimit)
    {
        internal readonly int Limit = limit, QueueLimit = queueLimit;
        internal int Active;
        internal readonly LinkedList<ResourceWaiter> Queue = new();
    }
    private sealed class ResourceWaiter(ResourceClass lane)
    {
        internal readonly ResourceClass Lane = lane;
        internal readonly TaskCompletionSource<bool> Ready = new(TaskCreationOptions.RunContinuationsAsynchronously);
        internal LinkedListNode<ResourceWaiter>? Node;
    }
    private readonly ResourceClass _metadataSends = new(8, 0), _resolutionSends = new(2, 8), _revokeSends = new(1, 0);
    private SafeFileHandle? _resourceHandle;
    private IResourceNativeSender? _resourceNativeSender;
    private bool _resourceRevoked;

    // Dormant seam: no production connection/registration/caller in increment 3.
    internal static FilterPort CreateResourceForTesting(SafeFileHandle main, SafeFileHandle resource, IResourceNativeSender sender) =>
        new(main, Contract.PortName) { _resourceHandle = resource, _resourceNativeSender = sender };

    internal (int Active, int Queued) ResourceSendPopulation(ResourceSendClass kind)
    { lock (_sendLifecycle) { var lane = ResourceLane(kind); return (lane.Active, lane.Queue.Count); } }
    internal static ResourceSendClass ResourceClassForOpcode(ResourceControlOpcodeV32 opcode) => opcode switch
    {
        ResourceControlOpcodeV32.RegisterRoot or ResourceControlOpcodeV32.RegisterChildIntent => ResourceSendClass.MetadataProgress,
        ResourceControlOpcodeV32.FenceAllocation or ResourceControlOpcodeV32.ResolveAllocationAck or ResourceControlOpcodeV32.ShellSnapshot => ResourceSendClass.Resolution,
        ResourceControlOpcodeV32.Revoke => ResourceSendClass.Revoke,
        _ => throw new ArgumentException("Negotiation belongs to the closed-admission main-port bootstrap slot.", nameof(opcode))
    };
    private ResourceClass ResourceLane(ResourceSendClass kind) => kind switch
    {
        ResourceSendClass.MetadataProgress => _metadataSends, ResourceSendClass.Resolution => _resolutionSends,
        ResourceSendClass.Revoke => _revokeSends, _ => throw new ArgumentOutOfRangeException(nameof(kind))
    };

    internal void RevokeResourceSends()
    {
        lock (_sendLifecycle)
        {
            _resourceRevoked = true;
            CancelResourceQueue(_resolutionSends);
        }
    }
    private void CancelResourceQueue(ResourceClass lane)
    {
        while (lane.Queue.First is { } first)
        {
            lane.Queue.Remove(first); first.Value.Node = null;
            _activeSenders--; first.Value.Ready.TrySetResult(false);
        }
        if (_activeSenders == 0) Monitor.PulseAll(_sendLifecycle);
    }
    private void CloseResourceSends()
    {
        _resourceRevoked = true;
        CancelResourceQueue(_resolutionSends);
    }

    internal async Task<ResourceSendResult> TrySendResourceAsync(ResourceSendClass kind, Func<byte[]> constructInput,
        int outputBytes, CancellationToken token = default)
    {
        if (outputBytes is < 0 or > 65536) throw new ArgumentOutOfRangeException(nameof(outputBytes));
        ResourceWaiter waiter;
        lock (_sendLifecycle)
        {
            // Revoke is local first, even when its dedicated remote slot is full.
            if (kind == ResourceSendClass.Revoke) { _resourceRevoked = true; CancelResourceQueue(_resolutionSends); }
            if (!_acceptingSends || _resourceHandle is null || (_resourceRevoked && kind != ResourceSendClass.Revoke))
                return new(ResourceSendStatus.Revoked);
            if (token.IsCancellationRequested) return new(ResourceSendStatus.Canceled);
            var lane = ResourceLane(kind);
            if (lane.Active == lane.Limit && lane.Queue.Count == lane.QueueLimit) return new(ResourceSendStatus.Busy);
            waiter = new(lane);
            checked { _activeSenders++; }
            if (lane.Active < lane.Limit) { lane.Active++; waiter.Ready.SetResult(true); }
            else waiter.Node = lane.Queue.AddLast(waiter);
        }
        using var cancellation = token.Register(() =>
        {
            lock (_sendLifecycle)
            {
                if (waiter.Node is null) return;
                waiter.Lane.Queue.Remove(waiter.Node); waiter.Node = null;
                _activeSenders--; waiter.Ready.TrySetResult(false);
                if (_activeSenders == 0) Monitor.PulseAll(_sendLifecycle);
            }
        });
        if (!await waiter.Ready.Task.ConfigureAwait(false))
            return new(token.IsCancellationRequested ? ResourceSendStatus.Canceled : ResourceSendStatus.Revoked);
        bool reference = false;
        SafeFileHandle? handle = null;
        try
        {
            lock (_sendLifecycle)
            {
                if (!_acceptingSends || (_resourceRevoked && kind != ResourceSendClass.Revoke)) return new(ResourceSendStatus.Revoked);
                handle = _resourceHandle!;
                handle.DangerousAddRef(ref reference);
            }
            if (token.IsCancellationRequested) return new(ResourceSendStatus.Canceled);
            // Admission precedes buffer construction/retention. Cancellation of
            // an active call stops adoption, never its native buffer lifetime.
            byte[] source = constructInput();
            if (source.Length > 65536) throw new ArgumentException("Oversized bounded resource control.");
            byte[] input = (byte[])source.Clone(), output = new byte[outputBytes];
            var sender = _resourceNativeSender ?? throw new InvalidOperationException("No provisional resource sender.");
            var native = await Task.Run(() =>
            {
                int hr = sender.Send(handle, input, output, out uint returned);
                return (HResult: hr, Returned: returned);
            }).ConfigureAwait(false);
            if (native.Returned > output.Length) throw new IOException("Oversized native resource reply.");
            lock (_sendLifecycle)
            {
                if (!_acceptingSends || (_resourceRevoked && kind != ResourceSendClass.Revoke)) return new(ResourceSendStatus.Revoked);
                if (token.IsCancellationRequested) return new(ResourceSendStatus.Canceled);
            }
            return new(ResourceSendStatus.Completed, native.HResult, output, native.Returned);
        }
        finally
        {
            if (reference) handle!.DangerousRelease();
            lock (_sendLifecycle)
            {
                waiter.Lane.Active--; _activeSenders--;
                if (waiter.Lane.Queue.First is { } next)
                {
                    waiter.Lane.Queue.RemoveFirst(); next.Value.Node = null;
                    waiter.Lane.Active++; next.Value.Ready.TrySetResult(true);
                }
                if (_activeSenders == 0) Monitor.PulseAll(_sendLifecycle);
            }
        }
    }

    internal Task HoldLegacySendForTesting(Action native) => Task.Run(() => { using var lease = EnterSend(); native(); });
}
#endif
