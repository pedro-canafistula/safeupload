using System.IO.Pipes;
using SafeUpload.Agent.App.ClipboardWatch;
using SafeUpload.Agent.App.Notifications;
using SafeUpload.Agent.Core.Contracts;
using SafeUpload.Agent.Core.Infrastructure;

namespace SafeUpload.Agent.Tests;

public sealed class ServicePipePeerTests
{
    [Theory]
    [InlineData(4u, 16u, 71u, 71u, @"C:\Program Files\SafeUpload\Agent\service\SafeUpload.Agent.Service.exe", true)]
    [InlineData(2u, 16u, 71u, 71u, @"C:\Program Files\SafeUpload\Agent\service\SafeUpload.Agent.Service.exe", false)]
    [InlineData(1u, 16u, 71u, 71u, @"C:\Program Files\SafeUpload\Agent\service\SafeUpload.Agent.Service.exe", false)]
    [InlineData(4u, 32u, 71u, 71u, @"C:\Program Files\SafeUpload\Agent\service\SafeUpload.Agent.Service.exe", false)]
    [InlineData(4u, 16u, 72u, 71u, @"C:\Program Files\SafeUpload\Agent\service\SafeUpload.Agent.Service.exe", false)]
    [InlineData(4u, 16u, 0u, 0u, @"C:\Program Files\SafeUpload\Agent\service\SafeUpload.Agent.Service.exe", false)]
    [InlineData(4u, 16u, 71u, 71u, @"C:\Other\SafeUpload.Agent.Service.exe", false)]
    [InlineData(4u, 16u, 71u, 71u, "SafeUpload.Agent.Service.exe", false)]
    public void Peer_requires_running_own_process_service_pid_and_exact_image(uint state, uint type, uint peer, uint registered, string image, bool expected) =>
        Assert.Equal(expected, ServicePipePeer.Matches(state, type, peer, registered, image,
            @"C:\Program Files\SafeUpload\Agent\service\SafeUpload.Agent.Service.exe"));

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task Unverified_server_receives_no_clipboard_text_or_justification(bool reason)
    {
        string name = "SafeUpload.Peer.Test." + Guid.NewGuid().ToString("N");
        using var server = new NamedPipeServerStream(name, PipeDirection.InOut, 1, PipeTransmissionMode.Byte, PipeOptions.Asynchronous);
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        var waiting = server.WaitForConnectionAsync(timeout.Token);
        Task sending = reason
            ? Assert.ThrowsAsync<IOException>(() => JustificationPipeClient.SendAsync(Guid.NewGuid().ToString(), "SYNTHETIC-SECRET-REASON", name))
            : SendClipboard();
        await waiting;
        byte[] bytes = new byte[1];
        Assert.Equal(0, await server.ReadAsync(bytes, timeout.Token));
        await sending;
        async Task SendClipboard() => Assert.Null(await new ClipboardPipeClient(name).SendAsync(
            ClipboardRequest.Classify("SYNTHETIC-SECRET-TEXT", "editor.exe"), TimeSpan.FromSeconds(5), timeout.Token));
    }

    [Fact]
    public async Task Unverified_notification_server_cannot_mark_connected_or_present_status()
    {
        string name = "SafeUpload.Peer.Status." + Guid.NewGuid().ToString("N");
        using var server = new NamedPipeServerStream(name, PipeDirection.Out, 1, PipeTransmissionMode.Byte, PipeOptions.Asynchronous);
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        var waiting = server.WaitForConnectionAsync(timeout.Token);
        await using var client = new PipeClient(name);
        int received = 0, connected = 0;
        var rejected = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        client.NotificationReceived += (_, _) => Interlocked.Increment(ref received);
        client.ConnectionChanged += (_, online) => { if (online) Interlocked.Increment(ref connected); else rejected.TrySetResult(); };
        client.Start();
        await waiting;
        try { await server.WriteAsync(NotificationProtocol.Encoding.GetBytes(NotificationProtocol.Serialize(new StatusNotification(1, 5, true))), timeout.Token); }
        catch (IOException) { /* Rejection can close the pipe before the synthetic status is written. */ }
        await rejected.Task.WaitAsync(timeout.Token);
        Assert.Equal(0, received); Assert.Equal(0, connected);
    }
}
