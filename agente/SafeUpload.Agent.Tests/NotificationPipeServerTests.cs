using System.IO.Pipes;
using Microsoft.Extensions.Logging.Abstractions;
using SafeUpload.Agent.Service.Notifications;

namespace SafeUpload.Agent.Tests;

public sealed class NotificationPipeServerTests
{
    // m2t5boot5: with a quiet status no notification was written, so every status probe that
    // connected and left kept its server instance; after 16 of them no client, including the
    // tray, could connect ("All pipe instances are busy"). Departed clients must release their
    // instances without any write.
    [Fact]
    public async Task Departed_clients_release_their_instances_without_any_notification()
    {
        string name = "SafeUpload.Agent.Test." + Guid.NewGuid().ToString("N");
        var server = new NotificationPipeServer(NotificationTestHub.Create(),
            NullLogger<NotificationPipeServer>.Instance, name);
        await server.StartAsync(CancellationToken.None);
        try
        {
            for (int i = 0; i < 40; ++i)
            {
                using var client = new NamedPipeClientStream(".", name, PipeDirection.In, PipeOptions.Asynchronous);
                using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(10));
                await client.ConnectAsync(timeout.Token);
                Assert.True(client.IsConnected, $"client {i} could not connect");
            }
        }
        finally
        {
            await server.StopAsync(CancellationToken.None);
        }
    }

    [Fact]
    public async Task Concurrent_connected_clients_keep_their_connections()
    {
        string name = "SafeUpload.Agent.Test." + Guid.NewGuid().ToString("N");
        var server = new NotificationPipeServer(NotificationTestHub.Create(),
            NullLogger<NotificationPipeServer>.Instance, name);
        await server.StartAsync(CancellationToken.None);
        var clients = new List<NamedPipeClientStream>();
        try
        {
            for (int i = 0; i < 4; ++i)
            {
                var client = new NamedPipeClientStream(".", name, PipeDirection.In, PipeOptions.Asynchronous);
                clients.Add(client);
                using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(10));
                await client.ConnectAsync(timeout.Token);
            }
            // A connected client that only reads is never mistaken for a departed one: with no
            // notification to deliver, a server that dropped it would end its read at once (0 bytes).
            foreach (var client in clients)
            {
                var buffer = new byte[1];
                using var wait = new CancellationTokenSource(TimeSpan.FromMilliseconds(300));
                await Assert.ThrowsAnyAsync<OperationCanceledException>(async () =>
                {
                    int read = await client.ReadAsync(buffer, wait.Token);
                    Assert.Fail($"the server ended a connected client's read ({read} bytes)");
                });
            }
        }
        finally
        {
            foreach (var client in clients) client.Dispose();
            await server.StopAsync(CancellationToken.None);
        }
    }
}
