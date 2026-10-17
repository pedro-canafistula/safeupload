using System.ComponentModel;

namespace SafeUpload.Agent.Service.Interception;

// Retry only a failed private-metadata rename, on its still-held source handle.
// Serialization/flush, post-commit observers and public mutations are outside
// this loop. A successful rename is never repeated, including on cancellation.
internal static class StagedJournalReplacement
{
    internal const int MaximumAttempts = 6;

    internal static async Task CommitAsync(FileStream stream, string temporary,
        string destination, CancellationToken token)
    {
        using (StagedRequestTiming.Measure("journal-flush")) stream.Flush(flushToDisk: true);
        using var renameTiming = StagedRequestTiming.Measure("journal-replace");
        await ReplaceAsync(() =>
        {
            if (OperatingSystem.IsWindows())
                StagedDestinationFile.CommitHandle(stream.SafeFileHandle, destination);
            else File.Move(temporary, destination, overwrite: true);
        }, Task.Delay, token).ConfigureAwait(false);
    }

    // The wait seam makes the finite native-error/backoff contract executable
    // on a portable host; production always uses cancellable Task.Delay.
    internal static async Task ReplaceAsync(Action replace,
        Func<TimeSpan, CancellationToken, Task> wait, CancellationToken token)
    {
        for (int attempt = 0; ; ++attempt)
        {
            token.ThrowIfCancellationRequested();
            try { replace(); return; }
            catch (IOException error) when (attempt < MaximumAttempts - 1 && IsTransientRename(error))
            {
                // Five waits: 20+40+80+160+320 = 620 ms, six attempts total.
                await wait(TimeSpan.FromMilliseconds(20 << attempt), token).ConfigureAwait(false);
            }
        }
    }

    private static bool IsTransientRename(IOException error) =>
        error.InnerException is Win32Exception { NativeErrorCode: 5 or 32 or 33 };
}
