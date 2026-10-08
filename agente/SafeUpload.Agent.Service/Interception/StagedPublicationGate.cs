using SafeUpload.Agent.Minifilter;

namespace SafeUpload.Agent.Service.Interception;

public interface IStagedPublicationGate
{
    IDisposable Authorize(StagedTransfer transfer, string temporaryDestination, string digest);
}

public sealed class StagedPublicationGate(FilterPort port) : IStagedPublicationGate
{
    public IDisposable Authorize(StagedTransfer transfer, string temporaryDestination, string digest)
    {
        port.SetPublicationPermit(transfer.TransferId, temporaryDestination,
            transfer.DestinationPath, digest);
        return new Permit(port, transfer.TransferId);
    }

    private sealed class Permit(FilterPort port, Guid id) : IDisposable
    {
        public void Dispose() => port.RevokePublicationPermit(id);
    }
}
