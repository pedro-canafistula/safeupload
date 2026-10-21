namespace SafeUpload.Agent.Service.Interception;

/// <summary>
/// Pacing for the exact private-stage cleanup loop. A private delete is requested when the delete disposition is set,
/// which can be before the application closes its own handle, so the first exact delete may fail on sharing a few
/// milliseconds before it would succeed. A flat one-second pass interval made that retry, and the staging-budget refund
/// that follows it, outlast the refund grace of a back-to-back save (T5 row m2t5ord4: discard request to
/// acknowledgement 1.54 s; the next save failed with Win32 32).
/// Wake the loop when a discard is recorded and, while discards stay pending, retry on a short bounded backoff before
/// falling back to the idle interval. Nothing here changes what a discard may delete or acknowledge.
/// </summary>
internal sealed class StagedDiscardCleanupSchedule
{
    internal static readonly TimeSpan IdleInterval = TimeSpan.FromSeconds(1);
    private static readonly int[] RetryMilliseconds = [25, 50, 100, 200, 400, 800];

    private readonly SemaphoreSlim _wake = new(0, 1);
    private int _stalledPasses;

    /// <summary>Signals that a discard was recorded; repeated signals before the next wait coalesce.</summary>
    internal void Notify()
    {
        try { _wake.Release(); }
        catch (SemaphoreFullException) { }
    }

    /// <summary>Delay before the next pass: short and growing while discards remain pending, otherwise the idle interval.</summary>
    internal TimeSpan NextDelay(bool pendingRemained)
    {
        if (!pendingRemained)
        {
            _stalledPasses = 0;
            return IdleInterval;
        }
        int pass = _stalledPasses++;
        return pass < RetryMilliseconds.Length ? TimeSpan.FromMilliseconds(RetryMilliseconds[pass]) : IdleInterval;
    }

    /// <summary>Waits for the delay or a signal; a signal restarts the short backoff.</summary>
    internal async Task WaitAsync(TimeSpan delay, CancellationToken cancellationToken)
    {
        if (await _wake.WaitAsync(delay, cancellationToken).ConfigureAwait(false)) _stalledPasses = 0;
    }
}
