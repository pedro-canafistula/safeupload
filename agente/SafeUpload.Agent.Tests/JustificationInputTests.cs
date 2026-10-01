using System.Text;
using SafeUpload.Agent.Core.Contracts;
using SafeUpload.Agent.Service.Notifications;

namespace SafeUpload.Agent.Tests;

public sealed class JustificationInputTests
{
    [Theory]
    [InlineData("\n")]
    [InlineData("\r\n")]
    [InlineData("")]
    public async Task Valid_request_preserves_unicode_and_supported_line_endings(string ending)
    {
        var request = new JustificationRequest(Guid.NewGuid().ToString(), "Permissão para análise");
        using var input = new StreamReader(new MemoryStream(Encoding.UTF8.GetBytes(
            JustificationProtocol.Serialize(request) + ending)));
        Assert.Equal(request, JustificationProtocol.Deserialize(
            await BoundedPipeLine.ReadAsync(input, CancellationToken.None)));
    }

    [Fact]
    public async Task Exact_line_limit_is_accepted_without_consuming_the_whole_following_request()
    {
        var request = new JustificationRequest(Guid.NewGuid().ToString(), "Bounded request");
        string line = JustificationProtocol.Serialize(request).PadRight(JustificationProtocol.MaxLineLength);
        using var bytes = new MemoryStream(Encoding.UTF8.GetBytes(line + "\n" + new string('x', 1000000)));
        using var input = new StreamReader(bytes);
        Assert.Equal(request, JustificationProtocol.Deserialize(
            await BoundedPipeLine.ReadAsync(input, CancellationToken.None)));
        Assert.InRange(bytes.Position, line.Length, 8192);
    }

    [Fact]
    public async Task Oversized_unterminated_request_is_rejected_with_bounded_read_ahead()
    {
        using var bytes = new MemoryStream(Encoding.UTF8.GetBytes(new string('x', 1000000)));
        using var input = new StreamReader(bytes);
        Assert.Null(await BoundedPipeLine.ReadAsync(input, CancellationToken.None));
        Assert.InRange(bytes.Position, 4097, 8192);
    }

    [Fact]
    public async Task A_peer_that_stalls_mid_request_is_cancelled()
    {
        string name = "SafeUpload-Test-" + Guid.NewGuid().ToString("N");
        using var source = new System.IO.Pipes.NamedPipeServerStream(name,
            System.IO.Pipes.PipeDirection.In, 1, System.IO.Pipes.PipeTransmissionMode.Byte,
            System.IO.Pipes.PipeOptions.Asynchronous);
        using var peer = new System.IO.Pipes.NamedPipeClientStream(".", name,
            System.IO.Pipes.PipeDirection.Out, System.IO.Pipes.PipeOptions.Asynchronous);
        Task connected = source.WaitForConnectionAsync();
        await peer.ConnectAsync();
        await connected;
        using var input = new StreamReader(source);
        using var deadline = new CancellationTokenSource(TimeSpan.FromMilliseconds(100));
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() =>
            BoundedPipeLine.ReadAsync(input, deadline.Token).WaitAsync(TimeSpan.FromSeconds(5)));
    }
}
