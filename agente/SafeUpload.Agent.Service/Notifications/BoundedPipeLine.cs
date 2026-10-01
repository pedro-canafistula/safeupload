using System.Text;
using SafeUpload.Agent.Core.Contracts;

namespace SafeUpload.Agent.Service.Notifications;

internal static class BoundedPipeLine
{
    // ReadLineAsync allocates the entire untrusted line before the protocol can
    // reject it. Keep both retained characters and read-ahead bounded instead.
    internal static async Task<string?> ReadAsync(StreamReader reader, CancellationToken token)
    {
        char[] buffer = new char[256];
        var line = new StringBuilder();
        for (;;)
        {
            int count = await reader.ReadAsync(buffer.AsMemory(), token).ConfigureAwait(false);
            if (count == 0) return line.Length == 0 ? null : line.ToString();
            for (int index = 0; index < count; index++)
            {
                char value = buffer[index];
                if (value is '\r' or '\n') return line.ToString();
                if (line.Length == JustificationProtocol.MaxLineLength) return null;
                line.Append(value);
            }
        }
    }
}
