using SafeUpload.Agent.Minifilter;

namespace SafeUpload.Agent.Service.Notifications;

/// <summary>
/// Delivers justified grants through the service's single minifilter port.
/// The port can receive FilterSendMessage while its inspection thread waits
/// in FilterGetMessage. A cached verdict may produce no new request, so
/// waiting to drain grants in that loop leaves a retry blocked.
/// </summary>
public sealed class OverrideGrantDispatcher
{
    private readonly object _gate = new();
    private FilterPort? _port;

    public bool IsConnected
    {
        get
        {
            lock (_gate)
            {
                return _port is not null;
            }
        }
    }

    public void Bind(FilterPort port)
    {
        lock (_gate)
        {
            _port = port;
        }
    }

    public void Unbind(FilterPort port)
    {
        lock (_gate)
        {
            if (ReferenceEquals(_port, port))
            {
                _port = null;
            }
        }
    }

    /// <summary>Delivers now or fails if the kernel channel has gone away.</summary>
    public void Grant(uint processId, string ntPath, TimeSpan duration)
    {
        ArgumentException.ThrowIfNullOrEmpty(ntPath);

        lock (_gate)
        {
            if (_port is null)
            {
                throw new InvalidOperationException("O minifiltro nao esta conectado.");
            }

            _port.GrantOverride(processId, ntPath, duration);
        }
    }
}
