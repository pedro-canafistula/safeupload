using Microsoft.Extensions.Logging.Abstractions;
using SafeUpload.Agent.Core.Contracts;
using SafeUpload.Agent.Service.Notifications;

namespace SafeUpload.Agent.Tests;

internal static class NotificationTestHub
{
    internal static NotificationHub Create(TimeProvider? clock = null) => new(
        new MemoryRecord(), NullLogger<NotificationHub>.Instance, clock ?? TimeProvider.System);
    private sealed class MemoryRecord : INotificationRecord
    {
        public void Append(AgentNotification notification, uint? targetSessionId) { }
    }
}
