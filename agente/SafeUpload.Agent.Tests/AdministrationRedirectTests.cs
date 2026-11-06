using System.Net;
using System.Net.Sockets;
using System.Text;
using Microsoft.Extensions.DependencyInjection;

namespace SafeUpload.Agent.Tests;

public sealed class AdministrationRedirectTests
{
    [Theory]
    [InlineData(301, false)]
    [InlineData(302, false)]
    [InlineData(307, false)]
    [InlineData(308, false)]
    [InlineData(307, true)]
    [InlineData(308, true)]
    public async Task Policy_and_audit_do_not_follow_redirects_to_another_server(int status, bool post)
    {
        await using var destination = new Server("HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
        await using var origin = new Server($"HTTP/1.1 {status} Redirect\r\nLocation: {destination.Address}agent/events\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
        var services = new ServiceCollection();
        SafeUpload.Agent.Service.Program.ConfigureAdministrationHttpClient(services, new Uri(origin.Address, "agent/"), 5);
        using var provider = services.BuildServiceProvider();
        using var client = provider.GetRequiredService<IHttpClientFactory>()
            .CreateClient(SafeUpload.Agent.Service.Program.HttpClientName);
        using var response = post
            ? await client.PostAsync("events", new StringContent("synthetic-audit", Encoding.UTF8))
            : await client.GetAsync("api/policy?ip=127.0.0.1");

        Assert.Equal(status, (int)response.StatusCode);
        Assert.Equal(1, origin.Requests);
        Assert.Equal(0, destination.Requests);
    }

    private sealed class Server : IAsyncDisposable
    {
        private readonly TcpListener _listener = new(IPAddress.Loopback, 0);
        private readonly CancellationTokenSource _stop = new(TimeSpan.FromSeconds(10));
        private readonly Task _serve;
        private int _requests;
        public Uri Address { get; }
        public int Requests => Volatile.Read(ref _requests);

        public Server(string response)
        {
            _listener.Start();
            Address = new Uri($"http://127.0.0.1:{((IPEndPoint)_listener.LocalEndpoint).Port}/");
            _serve = RespondAsync(response);
        }

        private async Task RespondAsync(string response)
        {
            try
            {
                using var connection = await _listener.AcceptTcpClientAsync(_stop.Token);
                await using var stream = connection.GetStream();
                using var reader = new StreamReader(stream, Encoding.UTF8, leaveOpen: true);
                int length = 0;
                while (await reader.ReadLineAsync(_stop.Token) is { Length: > 0 } line)
                {
                    if (line.StartsWith("Content-Length:", StringComparison.OrdinalIgnoreCase))
                        length = int.Parse(line[15..], System.Globalization.CultureInfo.InvariantCulture);
                }
                if (length > 0) await reader.ReadBlockAsync(new char[length], _stop.Token);
                Interlocked.Increment(ref _requests);
                await stream.WriteAsync(Encoding.ASCII.GetBytes(response), _stop.Token);
            }
            catch (OperationCanceledException) when (_stop.IsCancellationRequested) { }
        }

        public async ValueTask DisposeAsync()
        {
            await _stop.CancelAsync();
            _listener.Stop();
            try { await _serve; }
            catch (SocketException) when (_stop.IsCancellationRequested) { }
            _stop.Dispose();
        }
    }
}
