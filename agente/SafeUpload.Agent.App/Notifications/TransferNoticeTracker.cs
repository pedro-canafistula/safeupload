using SafeUpload.Agent.Core.Contracts;

namespace SafeUpload.Agent.App.Notifications;

// Older transfer messages have no nested audit event. Keep their replay from raising
// another balloon/window too, without suppressing a later phase of the same version.
internal sealed class TransferNoticeTracker
{
    private readonly HashSet<(Guid, TransferPhase)> _seen = [];
    private readonly Queue<(Guid, TransferPhase)> _order = [];

    internal bool ShouldDisplay(TransferNotification notice)
    {
        var key = (notice.Event?.EventId ?? notice.TransferId, notice.Phase);
        if (!_seen.Add(key)) return false;
        _order.Enqueue(key);
        while (_order.Count > 512) _seen.Remove(_order.Dequeue());
        return true;
    }
}
