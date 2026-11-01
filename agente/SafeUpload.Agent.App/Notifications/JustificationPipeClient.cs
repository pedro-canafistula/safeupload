using System.IO;
using System.IO.Pipes;
using SafeUpload.Agent.Core.Contracts;

namespace SafeUpload.Agent.App.Notifications;

/// <summary>Sends a reason for a block ID that the service issued.</summary>
public static class JustificationPipeClient
{
    public static async Task SendAsync(string eventId, string reason)
        => await SendAsync(eventId, reason, JustificationProtocol.PipeName).ConfigureAwait(false);

    internal static async Task SendAsync(string eventId, string reason, string pipeName)
    {
        var request = new JustificationRequest(eventId, reason);
        string line = JustificationProtocol.Serialize(request);

        using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(3));
        await using var pipe = new NamedPipeClientStream(
            ".", pipeName,
            PipeDirection.InOut, PipeOptions.Asynchronous);

        await pipe.ConnectAsync(deadline.Token).ConfigureAwait(false);
        ServicePeer.Require(pipe);

        await using var writer = new StreamWriter(
            pipe, JustificationProtocol.Encoding, bufferSize: 1024,
            leaveOpen: true);
        await writer.WriteLineAsync(line.AsMemory(), deadline.Token).ConfigureAwait(false);
        await writer.FlushAsync(deadline.Token).ConfigureAwait(false);

        using var reader = new StreamReader(
            pipe, JustificationProtocol.Encoding,
            detectEncodingFromByteOrderMarks: false, bufferSize: 1024,
            leaveOpen: true);
        string? reply = await reader.ReadLineAsync(deadline.Token).ConfigureAwait(false);

        if (reply != JustificationProtocol.Accepted)
        {
            throw new InvalidOperationException("O serviço não aceitou a justificativa.");
        }
    }
}
