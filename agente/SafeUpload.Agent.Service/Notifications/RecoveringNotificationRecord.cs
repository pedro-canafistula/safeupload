using SafeUpload.Agent.Core.Contracts;
using SafeUpload.Agent.Service.Diagnostics;

namespace SafeUpload.Agent.Service.Notifications;

/// <summary>
/// Retries admission after a failed constructor. Every attempt uses the original
/// recorder's strict lease, path and ACL checks; no notification is accepted
/// until both admission and its durable append succeed. Once admitted, the
/// recorder owns recovery of uncertain writes and is never replaced here.
/// </summary>
internal sealed class RecoveringNotificationRecord : INotificationRecord, IDisposable
{
    private readonly Func<INotificationRecord> _open;
    private readonly ILogger _logger;
    private readonly TimeProvider _clock;
    private readonly Lock _gate = new();
    private INotificationRecord? _record;
    private Exception? _failure;
    private long _failedAt;
    private bool _disposed;

    internal RecoveringNotificationRecord(Func<INotificationRecord> open, ILogger logger,
        TimeProvider? clock = null)
    {
        _open = open;
        _logger = logger;
        _clock = clock ?? TimeProvider.System;
    }

    public void Append(AgentNotification notification, uint? targetSessionId)
    {
        lock (_gate)
        {
            ObjectDisposedException.ThrowIf(_disposed, this);
            if (_record is null)
            {
                if (_failure is not null &&
                    _clock.GetElapsedTime(_failedAt) < TimeSpan.FromSeconds(1))
                    throw new IOException("Notification record admission pending; delivery refused.", _failure);
                try
                {
                    _record = _open();
                    _failure = null;
                }
                catch (Exception error)
                {
                    _failure = error;
                    _failedAt = _clock.GetTimestamp();
                    _logger.LogSafeError(error, "Cannot open notification record; delivery held pending admission retry");
                    throw new IOException("Notification record unavailable; delivery refused.", error);
                }
            }
            _record.Append(notification, targetSessionId);
        }
    }

    public void Dispose()
    {
        lock (_gate)
        {
            if (_disposed) return;
            _disposed = true;
            (_record as IDisposable)?.Dispose();
        }
    }
}
