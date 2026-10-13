using System.ComponentModel;
using SafeUpload.Agent.Minifilter;

namespace SafeUpload.Agent.Service.Interception;

// One instance per poll, including when QueryAsync rethrows or is cancelled.
internal sealed class AdmissionCoverageRetryCounts
{
    internal int RetriesUsed { get; set; }
    internal bool Exhausted { get; set; }
}

internal static class AdmissionCoverageRetry
{
    private const int RetryHResult = unchecked((int)0x800704D5);
    private const int MaximumRetries = 3;

    internal static async Task<AdmissionCoverageReceipt> QueryAsync(
        Func<AdmissionCoverageReceipt> query,
        Func<TimeSpan, CancellationToken, Task> delay,
        CancellationToken token,
        AdmissionCoverageRetryCounts counts)
    {
        for (int retries = 0; ; ++retries)
        {
            token.ThrowIfCancellationRequested();
            if (retries != 0) counts.RetriesUsed++;
            try
            {
                // The synchronous coverage call disposes its send lease on
                // return/throw, before we await any delay. Native sends and
                // their gate wait are not cancellable; only the delays are.
                return query();
            }
            catch (Win32Exception ex) when (ex.NativeErrorCode == RetryHResult)
            {
                if (retries == MaximumRetries)
                {
                    counts.Exhausted = true;
                    throw;
                }

                // 70 ms is the total delay budget, plus three extra query
                // durations/queue waits. This is only a reporting retry.
                await delay(TimeSpan.FromMilliseconds(10 << retries), token).ConfigureAwait(false);
            }
        }
    }
}
