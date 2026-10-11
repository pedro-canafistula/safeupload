namespace SafeUpload.Agent.Service.Interception;

public sealed partial class StagedTransferJournal
{
    private readonly SemaphoreSlim _epochStartupGate = new(1, 1);

    // Invoked by connection startup while dispatch and physical publication
    // remain closed. Replay supplies authenticated boot metadata, not private
    // lifetime proof. The reviewed service-stop/unload invariants and a full
    // OS restart qualify replacement; existing private recovery must succeed
    // separately before that replacement is durably accepted.
    internal async Task<StagedDriverEpochReconcileV20> ReconcileDriverStartupAsync(
        Guid driverInstanceId, uint requiredCapabilities, StagedNativeRecoverySession.Proof bootEvidence,
        Func<CancellationToken, Task> recoverPrivateStages, CancellationToken token)
    {
        ArgumentNullException.ThrowIfNull(bootEvidence);
        ArgumentNullException.ThrowIfNull(recoverPrivateStages);
        if (driverInstanceId == Guid.Empty || requiredCapabilities != RequiredStageV20Capabilities)
            return StagedDriverEpochReconcileV20.Rejected;
        uint boot = bootEvidence.RequireCurrentBoot(driverInstanceId);

        await _epochStartupGate.WaitAsync(token).ConfigureAwait(false);
        try
        {
            DriverEpochRecord? original;
            await _gate.WaitAsync(token).ConfigureAwait(false);
            try
            {
                original = await ReadDriverEpochCoreAsync(token).ConfigureAwait(false);
                if (original is not null)
                {
                    if (original.DriverInstanceId == driverInstanceId)
                    {
                        // A live instance captures one immutable baseline.
                        // Resume cannot acquire a new boot/lifetime identity.
                        if (original.OsBootSequence is { } saved && saved != boot)
                            return StagedDriverEpochReconcileV20.Rejected;
                        if (original.DrainNonce is not null)
                            return StagedDriverEpochReconcileV20.DrainReplayOnly;
                    }
                    else if (original.DrainNonce is null &&
                             (original.OsBootSequence is not { } previousBoot || boot <= previousBoot))
                    {
                        // Includes legacy missing metadata, rollback and wrap.
                        // Never fill a prior instance's boot value from this one.
                        return StagedDriverEpochReconcileV20.Rejected;
                    }
                }
            }
            finally { _gate.Release(); }

            // Do not hold the journal lock across recovery/I/O. The receive
            // loop reports existing EpochBusy meanwhile, never a fake drain.
            await recoverPrivateStages(token).ConfigureAwait(false);
            token.ThrowIfCancellationRequested();
            if (bootEvidence.RequireCurrentBoot(driverInstanceId) != boot)
                throw new IOException("Authenticated boot evidence changed during private recovery.");

            await _gate.WaitAsync(token).ConfigureAwait(false);
            try
            {
                DriverEpochRecord? current = await ReadDriverEpochCoreAsync(token).ConfigureAwait(false);
                if (current != original) return StagedDriverEpochReconcileV20.Rejected;
                // Recheck after obtaining the lock: a disconnected or replaced
                // replay may not durably authorize a new epoch.
                bootEvidence.RequireCurrentBoot(driverInstanceId);
                if (original is not null && original.DriverInstanceId == driverInstanceId)
                {
                    if (original.OsBootSequence is null)
                        await WriteDriverEpochCoreAsync(original with { OsBootSequence = boot }, token)
                            .ConfigureAwait(false);
                }
                else
                {
                    await WriteDriverEpochCoreAsync(new DriverEpochRecord(driverInstanceId, null,
                        null, DateTimeOffset.UtcNow, null, boot), token).ConfigureAwait(false);
                }
                return StagedDriverEpochReconcileV20.Active;
            }
            finally { _gate.Release(); }
        }
        finally { _epochStartupGate.Release(); }
    }
}
