#if SAFEUPLOAD_ADMISSION_EVIDENCE
using SafeUpload.Agent.Core.Contracts;
using SafeUpload.Agent.Minifilter;

namespace SafeUpload.Agent.Service.Interception;

// A wake is only a reason to obtain fresh evidence. Startup, last CLEANUP and
// directory-change all use this same destination turn and exact proof path.
internal sealed class StagedNativeRecoveryDispatcher(StagedTransferJournal journal,
    Func<NativeRecordReplay> readReplay, Func<NativeNameObservationRequest, NativeNameObservation> observe,
    Action<StagedDestinationHead, StagedPublicDeleteRecord, StagedRecoveryAdvice, string>? report = null)
{
    internal async Task ReconcileAsync(NativeRecordReplay replay, StagedNativeRecoverySession.Proof proof,
        CancellationToken token)
    {
        var heads = await journal.ReadDestinationHeadsAsync(token).ConfigureAwait(false);
        StagedNativeStartupRecovery.ReconcileRecords(replay, heads);
        foreach (var head in heads)
        foreach (var saved in head.Deletes.Where(d => d.Kind == StagedPublicDeleteKind.NativeOnClose))
        {
            token.ThrowIfCancellationRequested();
            using var turn = await journal.EnterDestinationCommitTurnAsync(head.Destination,
                StagedDestinationTurnPurpose.Reconciliation, token).ConfigureAwait(false);
            RequireCurrent(replay);
            var row = replay.Records.SingleOrDefault(r => r.TransferId == saved.Binding.TransferId);
            var delete = saved;
            if (delete.State == StagedPublicDeleteState.Admitted &&
                (row is null || head.Destination.MountManagerVolumeId is null || delete.Binding.MountManagerVolumeId is null))
                delete = await journal.RetainNativeReconciliationHoldAsync(turn, delete.Binding,
                    delete.OperationId!.Value, token).ConfigureAwait(false);
            if (row is not null)
            {
                if (row.Facts.HasFlag(NativeRecordFacts.CreateOutcomeKnown))
                    delete = await journal.RecordNativeDeleteOnCloseCreateResultAsync(turn, saved.Binding,
                        saved.OperationId!.Value, row.Facts.HasFlag(NativeRecordFacts.CreateAccepted),
                        row.Facts.HasFlag(NativeRecordFacts.CreateAccepted | NativeRecordFacts.IdentityChecked),
                        new((uint)row.Facts & 0x0f, row.CreateStatus, row.IdentityStatus)).ConfigureAwait(false);
                if (row.Facts.HasFlag(NativeRecordFacts.CleanupCoverageLost) && delete.State == StagedPublicDeleteState.Admitted)
                    delete = await journal.RetainNativeReconciliationHoldAsync(turn, delete.Binding,
                        delete.OperationId!.Value, token).ConfigureAwait(false);
            }
            if (delete.State is StagedPublicDeleteState.AcceptedUnresolved or StagedPublicDeleteState.Admitted)
            {
                try { proof.RequireExactLifetimeEnded(delete.Binding, delete.OperationId!.Value); }
                catch (IOException)
                {
                    if (delete.State == StagedPublicDeleteState.AcceptedUnresolved)
                        await ReportAsync(head.Destination, delete.Binding,
                            head.Destination.MountManagerVolumeId is null || delete.Binding.MountManagerVolumeId is null
                                ? StagedRecoveryAdvice.CollectDiagnostics :
                            row?.Facts.HasFlag(NativeRecordFacts.CleanupCoverageLost) == true || row is null
                                ? StagedRecoveryAdvice.RestartWindows : StagedRecoveryAdvice.CloseApplication,
                            row?.Facts.HasFlag(NativeRecordFacts.CleanupCoverageLost) == true
                                ? "NativeCleanupCoverageLost" : "NativeLifetimeUnproved", token).ConfigureAwait(false);
                    continue;
                }
                try
                {
                    var destination = head.Destination;
                    if (destination.MountManagerVolumeId is not { } volume || volume == Guid.Empty ||
                        delete.Binding.MountManagerVolumeId != volume)
                        throw new IOException("NativeAnchorMissing");
                    var expected = new NativeNameObservationRequest(replay.DriverInstanceId, replay.ConnectionEpoch,
                        replay.Revision, replay.OsBootSequence, volume, Wire(destination.VolumeRoot),
                        Wire(destination.Parent), destination.CaseSensitive, destination.CanonicalLeaf);
                    var name = observe(expected); // fixed NTFS checked in the authenticated driver, no child reopen
                    if (name.Binding != expected) throw new IOException("NativeObservationBindingChanged");
                    RequireCurrent(replay);
                    var observation = new StagedDestinationNameObservation(destination, destination.Parent,
                        destination.Parent, true, name.ChildIdentity is { } child
                            ? new(child.VolumeSerialNumber, child.FileIdHigh, child.FileIdLow) : null);
                    if (delete.State == StagedPublicDeleteState.AcceptedUnresolved)
                        delete = await journal.ReconcileNativeDeleteOnCloseAsync(turn, delete.Binding,
                            delete.OperationId!.Value, proof, observation, token).ConfigureAwait(false);
                    if (delete.State == StagedPublicDeleteState.Admitted)
                        delete = await journal.CompleteNativeDeleteOnCloseAsync(turn, delete.Binding,
                            delete.OperationId!.Value, proof, observation, token).ConfigureAwait(false);
                }
                catch (Exception error) when (error is IOException or System.ComponentModel.Win32Exception or UnauthorizedAccessException)
                {
                    RequireCurrent(replay); // stale replay is a failed pass, never an observation result
                    var current = (await journal.ReadDestinationHeadAsync(head.Destination, token).ConfigureAwait(false))!;
                    delete = current.Deletes.Single(d => d.Binding == saved.Binding);
                    if (delete.State is not (StagedPublicDeleteState.Admitted or StagedPublicDeleteState.AcceptedUnresolved))
                        throw; // a lost durable-completion reply is bookkeeping, not a new recovery hold
                    if (delete.State == StagedPublicDeleteState.Admitted)
                        delete = await journal.RetainNativeReconciliationHoldAsync(turn, delete.Binding,
                            delete.OperationId!.Value, token).ConfigureAwait(false);
                    await ReportAsync(head.Destination, delete.Binding, StagedRecoveryAdvice.CollectDiagnostics,
                        "NativeAnchoredReconciliationUnresolved", token).ConfigureAwait(false);
                    continue;
                }
            }
            if (delete.State is StagedPublicDeleteState.Complete or StagedPublicDeleteState.Superseded or StagedPublicDeleteState.Failed)
            {
                RequireCurrent(replay);
                if (row is not null)
                    await journal.ArmNativeAcknowledgementAsync(turn, delete.Binding, delete.OperationId!.Value,
                        replay.Revision, token).ConfigureAwait(false); // worker returns the typed terminal ACK
                else
                    await journal.RetireNativeDeleteReceiptAsync(turn, delete.Binding, delete.OperationId!.Value,
                        proof, delete.NativeAcknowledgementRevision ?? 0, token).ConfigureAwait(false);
            }
        }
        RequireCurrent(replay);
    }

    private async Task ReportAsync(StagedDestinationIdentity destination, StagedPublicDeleteBinding binding,
        StagedRecoveryAdvice advice, string reason, CancellationToken token)
    {
        if (report is null) return;
        var head = (await journal.ReadDestinationHeadAsync(destination, token).ConfigureAwait(false))!;
        report(head, head.Deletes.Single(d => d.Binding == binding), advice, reason);
    }

    private void RequireCurrent(NativeRecordReplay expected)
    {
        var current = readReplay();
        if (current.DriverInstanceId != expected.DriverInstanceId || current.ConnectionEpoch != expected.ConnectionEpoch ||
            current.Revision != expected.Revision || current.OsBootSequence != expected.OsBootSequence ||
            !current.Records.SequenceEqual(expected.Records))
            throw new IOException("NativeRecoveryReplayChanged");
    }
    private static SafeUploadStageIdentityV19 Wire(StagedStageIdentity id) => new()
        { VolumeSerialNumber = id.VolumeSerialNumber, FileIdHigh = id.FileIdHigh, FileIdLow = id.FileIdLow };
}
#endif
