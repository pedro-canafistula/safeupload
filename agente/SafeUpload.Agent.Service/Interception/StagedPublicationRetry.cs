using System.ComponentModel;

namespace SafeUpload.Agent.Service.Interception;

// Only the native CREATE/rename boundary can issue this classification. Generic
// I/O, transport, cleanup and post-commit failures are never retry authority.
internal sealed class StagedPublicationBusyException(Win32Exception error)
    : IOException("Another program is preventing publication.", error);

internal static class StagedPublicationRetry
{
    internal const int MaximumAttempts = 6;

    internal static async Task ExecuteAsync(Func<CancellationToken, Task> attempt,
        Func<CancellationToken, Task<bool>> validate, Func<bool> committed, CancellationToken token,
        Func<TimeSpan, CancellationToken, Task>? delay = null)
    {
        delay ??= Task.Delay;
        for (int index = 0; ; index++)
        {
            token.ThrowIfCancellationRequested();
            if (!await validate(token).ConfigureAwait(false))
                throw new IOException("Publication authority changed before the attempt.");
            try
            {
                await attempt(token).ConfigureAwait(false);
                return;
            }
            catch (StagedPublicationBusyException) when (!committed() && index < MaximumAttempts - 1)
            {
                await delay(TimeSpan.FromMilliseconds(100 << index), token).ConfigureAwait(false);
            }
        }
    }
}
