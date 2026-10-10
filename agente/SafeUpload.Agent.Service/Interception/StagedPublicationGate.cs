using SafeUpload.Agent.Minifilter;

namespace SafeUpload.Agent.Service.Interception;

public interface IStagedPublicationGate
{
    IDisposable Authorize(StagedTransfer transfer, string temporaryDestination, string digest);

    /// <summary>
    /// The service no longer needs this staged version (StageDisposeOutcome). True: the driver still holds it and
    /// releases it, deleting a released stage file, once nothing references it; false: the stage is the caller's to delete.
    /// </summary>
    bool DisposeStage(Guid transferId, uint outcome, uint committedRenames);
}

public sealed class StagedPublicationGate(FilterPort port) : IStagedPublicationGate
{
    public IDisposable Authorize(StagedTransfer transfer, string temporaryDestination, string digest)
    {
        port.SetPublicationPermit(transfer.TransferId, temporaryDestination,
            transfer.DestinationPath, digest);
        return new Permit(port, transfer.TransferId);
    }

    public bool DisposeStage(Guid transferId, uint outcome, uint committedRenames) =>
        port.DisposeStage(transferId, outcome, committedRenames);

    private sealed class Permit(FilterPort port, Guid id) : IDisposable
    {
        public void Dispose() => port.RevokePublicationPermit(id);
    }
}
