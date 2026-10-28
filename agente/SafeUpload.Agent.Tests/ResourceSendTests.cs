#if SAFEUPLOAD_ADMISSION_EVIDENCE
using Microsoft.Win32.SafeHandles;
using SafeUpload.Agent.Minifilter;

namespace SafeUpload.Agent.Tests;

public sealed class ResourceSendTests
{
    private sealed class Sender : IResourceNativeSender, IDisposable
    {
        internal readonly SemaphoreSlim Entered = new(0), Release = new(0);
        internal readonly List<byte> Calls = new();
        public int Send(SafeFileHandle handle, ReadOnlyMemory<byte> input, Memory<byte> output, out uint bytesReturned)
        {
            Assert.False(handle.IsClosed);
            lock (Calls) Calls.Add(input.Span[0]);
            Entered.Release();
            Assert.True(Release.Wait(TimeSpan.FromSeconds(10)), "Fake native send did not receive finite test release.");
            Assert.False(handle.IsClosed);
            if (!output.IsEmpty) output.Span[0] = input.Span[0];
            bytesReturned = output.IsEmpty ? 0u : 1u; return 0;
        }
        internal async Task WaitEntered(int count)
        { for (int i = 0; i < count; i++) Assert.True(await Entered.WaitAsync(TimeSpan.FromSeconds(10))); }
        public void Dispose() { Entered.Dispose(); Release.Dispose(); }
    }
    private static FilterPort Port(Sender sender, out SafeFileHandle main, out SafeFileHandle resource)
    { main = new((IntPtr)101, false); resource = new((IntPtr)102, false); return FilterPort.CreateResourceForTesting(main, resource, sender); }

    [Fact]
    public async Task Metadata_eight_active_zero_queued_Busy_before_constructing_and_bypasses_legacy_gate()
    {
        using var sender = new Sender(); using var port = Port(sender, out _, out _);
        using var legacyEntered = new ManualResetEventSlim(); using var legacyRelease = new ManualResetEventSlim();
        Task legacy = port.HoldLegacySendForTesting(() => { legacyEntered.Set(); Assert.True(legacyRelease.Wait(TimeSpan.FromSeconds(10))); });
        Assert.True(legacyEntered.Wait(TimeSpan.FromSeconds(10)));
        try
        {
            var sends = Enumerable.Range(0, 8).Select(i => port.TrySendResourceAsync(ResourceSendClass.MetadataProgress, () => [(byte)i], 1)).ToArray();
            await sender.WaitEntered(8);
            int constructed = 0;
            Assert.Equal(ResourceSendStatus.Busy, (await port.TrySendResourceAsync(ResourceSendClass.MetadataProgress,
                () => { constructed++; return [99]; }, 1)).Status);
            Assert.Equal(0, constructed); Assert.Equal((8, 0), port.ResourceSendPopulation(ResourceSendClass.MetadataProgress));
            sender.Release.Release(8);
            var results = await Task.WhenAll(sends);
            Assert.All(results, result => Assert.Equal(ResourceSendStatus.Completed, result.Status));
            for (int i = 0; i < 8; i++) Assert.Equal((byte)i, results[i].Output![0]);
            Assert.False(legacy.IsCompleted);
        }
        finally { sender.Release.Release(8); legacyRelease.Set(); await legacy; }
    }

    [Fact]
    public async Task Resolution_two_active_eight_queued_cancel_removes_exact_item_and_preserves_FIFO()
    {
        using var sender = new Sender(); using var port = Port(sender, out _, out _);
        using var cancel = new CancellationTokenSource();
        var sends = Enumerable.Range(0, 10).Select(i => port.TrySendResourceAsync(ResourceSendClass.Resolution, () => [(byte)i], 1,
            i == 4 ? cancel.Token : default)).ToArray();
        try
        {
            await sender.WaitEntered(2);
            Assert.Equal((2, 8), port.ResourceSendPopulation(ResourceSendClass.Resolution));
            Assert.Equal(ResourceSendStatus.Busy, (await port.TrySendResourceAsync(ResourceSendClass.Resolution,
                () => throw new InvalidOperationException("Busy must not construct input"), 0)).Status);
            cancel.Cancel(); Assert.Equal(ResourceSendStatus.Canceled, (await sends[4]).Status);
            Assert.Equal((2, 7), port.ResourceSendPopulation(ResourceSendClass.Resolution));
            // Both initial sends may enter in either order. Thereafter release
            // one completion at a time to independently observe queue promotion.
            for (int i = 2; i < 10; i++)
            {
                if (i == 4) continue;
                sender.Release.Release(); await sender.WaitEntered(1);
                lock (sender.Calls) Assert.Equal((byte)i, sender.Calls[^1]);
            }
            sender.Release.Release(2);
            await Task.WhenAll(sends);
            Assert.Equal((0, 0), port.ResourceSendPopulation(ResourceSendClass.Resolution));
        }
        finally { sender.Release.Release(10); await Task.WhenAll(sends); }
    }

    [Fact]
    public async Task Revoke_publishes_locally_first_and_has_one_independent_no_queue_slot()
    {
        using var sender = new Sender(); using var port = Port(sender, out _, out _);
        var active = Enumerable.Range(0, 2).Select(_ => port.TrySendResourceAsync(ResourceSendClass.Resolution, () => [1], 0)).ToArray();
        var queued = port.TrySendResourceAsync(ResourceSendClass.Resolution, () => throw new InvalidOperationException("revoked queue"), 0);
        var metadata = port.TrySendResourceAsync(ResourceSendClass.MetadataProgress, () => [2], 0);
        await sender.WaitEntered(3);
        var revoke = port.TrySendResourceAsync(ResourceSendClass.Revoke, () => [3], 0);
        try
        {
            await sender.WaitEntered(1);
            Assert.Equal(ResourceSendStatus.Revoked, (await queued).Status);
            Assert.Equal(ResourceSendStatus.Revoked, (await port.TrySendResourceAsync(ResourceSendClass.MetadataProgress, () => [4], 0)).Status);
            Assert.Equal(ResourceSendStatus.Busy, (await port.TrySendResourceAsync(ResourceSendClass.Revoke, () => [5], 0)).Status);
            Assert.Equal((1, 0), port.ResourceSendPopulation(ResourceSendClass.Revoke));
            sender.Release.Release(4);
            Assert.Equal(ResourceSendStatus.Completed, (await revoke).Status);
            Assert.Equal(ResourceSendStatus.Revoked, (await metadata).Status);
            Assert.All(await Task.WhenAll(active), result => Assert.Equal(ResourceSendStatus.Revoked, result.Status));
        }
        finally { sender.Release.Release(4); await Task.WhenAll(active.Append(metadata).Append(revoke)); }
    }

    [Fact]
    public async Task Dispose_cancels_queued_and_joins_active_native_ownership_after_caller_cancellation()
    {
        using var sender = new Sender(); var port = Port(sender, out var main, out var resource);
        using var cancel = new CancellationTokenSource();
        var first = port.TrySendResourceAsync(ResourceSendClass.Resolution, () => [1], 1, cancel.Token);
        var second = port.TrySendResourceAsync(ResourceSendClass.Resolution, () => [2], 1);
        var queued = port.TrySendResourceAsync(ResourceSendClass.Resolution, () => throw new InvalidOperationException("dispose queue"), 0);
        await sender.WaitEntered(2); cancel.Cancel();
        var disposal = Task.Run(port.Dispose);
        try
        {
            Assert.Equal(ResourceSendStatus.Revoked, (await queued.WaitAsync(TimeSpan.FromSeconds(10))).Status);
            Assert.False(first.IsCompleted); Assert.False(disposal.IsCompleted);
            Assert.False(main.IsClosed); Assert.False(resource.IsClosed);
            sender.Release.Release(2);
            Assert.All(await Task.WhenAll(first, second), result => Assert.Equal(ResourceSendStatus.Revoked, result.Status));
            await disposal.WaitAsync(TimeSpan.FromSeconds(10));
            Assert.True(main.IsClosed); Assert.True(resource.IsClosed);
        }
        finally { sender.Release.Release(2); await disposal; port.Dispose(); }
    }

    [Fact]
    public async Task Active_cancellation_waits_for_native_return_and_owns_an_independent_input_copy()
    {
        using var sender = new Sender(); using var port = Port(sender, out _, out var resource);
        using var cancel = new CancellationTokenSource(); byte[] input = [7];
        var canceled = port.TrySendResourceAsync(ResourceSendClass.MetadataProgress, () => input, 1, cancel.Token);
        await sender.WaitEntered(1); input[0] = 99; cancel.Cancel();
        Assert.False(canceled.IsCompleted); Assert.False(resource.IsClosed);
        sender.Release.Release(); Assert.Equal(ResourceSendStatus.Canceled, (await canceled).Status);
        var successful = port.TrySendResourceAsync(ResourceSendClass.MetadataProgress, () => input, 1);
        await sender.WaitEntered(1); input[0] = 55;
        sender.Release.Release(); var result = await successful;
        Assert.Equal(ResourceSendStatus.Completed, result.Status); Assert.Equal((byte)99, result.Output![0]);
        port.RevokeResourceSends();
        await Assert.ThrowsAsync<ObjectDisposedException>(() => port.HoldLegacySendForTesting(() => throw new InvalidOperationException("revoked group")));
    }

    [Fact]
    public async Task Construction_failure_returns_the_exact_class_and_common_lifetime_credit()
    {
        using var sender = new Sender(); using var port = Port(sender, out _, out _);
        await Assert.ThrowsAsync<IOException>(() => port.TrySendResourceAsync(ResourceSendClass.MetadataProgress,
            () => throw new IOException("buffer construction"), 0));
        Assert.Equal((0, 0), port.ResourceSendPopulation(ResourceSendClass.MetadataProgress));
        using var cancel = new CancellationTokenSource(); cancel.Cancel();
        Assert.Equal(ResourceSendStatus.Canceled, (await port.TrySendResourceAsync(ResourceSendClass.MetadataProgress,
            () => throw new InvalidOperationException("already canceled"), 0, cancel.Token)).Status);
    }
}
#endif
