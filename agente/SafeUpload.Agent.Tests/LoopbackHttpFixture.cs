using System.Collections.Concurrent;
using System.Globalization;
using System.Net;
using System.Net.Sockets;
using System.Text;

namespace SafeUpload.Agent.Tests;

// Test-only HTTP/1.1 peer. Binds only loopback on an OS-assigned port and never
// installs an HTTP.sys reservation or contacts a backend. Supports the chunked
// requests emitted by HttpClient.JsonContent, with bounded headers and bodies.
internal sealed class LoopbackHttpFixture : IAsyncDisposable
{
    internal sealed record Request(string Method, string Target, string Body);
    internal sealed record Reply(int Status, string Body);

    private const int Limit = 1024 * 1024;
    private readonly TcpListener _listener = new(IPAddress.Loopback, 0);
    private readonly CancellationTokenSource _stop = new();
    private readonly Func<Request, Reply?> _respond;
    private readonly Task _server;
    public ConcurrentQueue<Request> Requests { get; } = new();
    public Uri BaseAddress { get; }

    public LoopbackHttpFixture(Func<Request, Reply?> respond)
    {
        _respond = respond;
        _listener.Start();
        BaseAddress = new Uri($"http://127.0.0.1:{((IPEndPoint)_listener.LocalEndpoint).Port}/agent/");
        _server = ServeAsync();
    }

    public HttpClient CreateClient() => new(new SocketsHttpHandler
    {
        UseProxy = false,
        AllowAutoRedirect = false
    }) { BaseAddress = BaseAddress, Timeout = TimeSpan.FromSeconds(5) };

    private async Task ServeAsync()
    {
        try
        {
            while (!_stop.IsCancellationRequested)
            {
                using var client = await _listener.AcceptTcpClientAsync(_stop.Token);
                await using var stream = client.GetStream();
                var start = (await ReadLineAsync(stream)).Split(' ');
                if (start.Length != 3) throw new InvalidDataException("Invalid request line.");
                var headers = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
                var headerBytes = 0;
                for (;;)
                {
                    var line = await ReadLineAsync(stream);
                    if (line.Length == 0) break;
                    headerBytes += line.Length;
                    if (headerBytes > 32 * 1024) throw new InvalidDataException("Headers too large.");
                    var colon = line.IndexOf(':');
                    if (colon <= 0) throw new InvalidDataException("Invalid header.");
                    headers.Add(line[..colon], line[(colon + 1)..].Trim());
                }

                using var body = new MemoryStream();
                if (headers.TryGetValue("Transfer-Encoding", out var encoding))
                {
                    if (!encoding.Equals("chunked", StringComparison.OrdinalIgnoreCase))
                        throw new InvalidDataException("Unexpected transfer encoding.");
                    for (;;)
                    {
                        var sizeLine = await ReadLineAsync(stream);
                        var size = int.Parse(sizeLine.Split(';')[0], NumberStyles.HexNumber, CultureInfo.InvariantCulture);
                        if (size == 0)
                        {
                            if ((await ReadLineAsync(stream)).Length != 0)
                                throw new InvalidDataException("Trailers are not used by this fixture.");
                            break;
                        }
                        await ReadBodyAsync(stream, body, size);
                        if ((await ReadLineAsync(stream)).Length != 0)
                            throw new InvalidDataException("Invalid chunk ending.");
                    }
                }
                else if (headers.TryGetValue("Content-Length", out var length))
                    await ReadBodyAsync(stream, body, int.Parse(length, CultureInfo.InvariantCulture));

                var request = new Request(start[0], start[1], Encoding.UTF8.GetString(body.ToArray()));
                Requests.Enqueue(request);
                var reply = _respond(request);
                // A null reply means the peer recorded the request in memory,
                // then lost the connection before delivering its receipt.
                if (reply is null) continue;
                var bytes = Encoding.UTF8.GetBytes(reply.Body);
                var responseHeaders = Encoding.ASCII.GetBytes(
                    $"HTTP/1.1 {reply.Status} Synthetic\r\nContent-Type: application/json\r\nContent-Length: {bytes.Length}\r\nConnection: close\r\n\r\n");
                await stream.WriteAsync(responseHeaders, _stop.Token);
                await stream.WriteAsync(bytes, _stop.Token);
            }
        }
        catch (OperationCanceledException) when (_stop.IsCancellationRequested) { }
        catch (SocketException) when (_stop.IsCancellationRequested) { }
    }

    private async Task ReadBodyAsync(Stream stream, MemoryStream body, int count)
    {
        if (count < 0 || count > Limit - body.Length) throw new InvalidDataException("Body too large.");
        var bytes = new byte[count];
        await stream.ReadExactlyAsync(bytes, _stop.Token);
        await body.WriteAsync(bytes, _stop.Token);
    }

    private async Task<string> ReadLineAsync(Stream stream)
    {
        using var line = new MemoryStream();
        var single = new byte[1];
        while (line.Length < 8192)
        {
            await stream.ReadExactlyAsync(single, _stop.Token);
            if (single[0] == '\n')
            {
                var bytes = line.ToArray();
                if (bytes.Length == 0 || bytes[^1] != '\r') throw new InvalidDataException("CRLF required.");
                return Encoding.ASCII.GetString(bytes, 0, bytes.Length - 1);
            }
            line.WriteByte(single[0]);
        }
        throw new InvalidDataException("Line too large.");
    }

    public async ValueTask DisposeAsync()
    {
        await _stop.CancelAsync();
        _listener.Stop();
        try { await _server; }
        finally { _stop.Dispose(); }
    }
}
