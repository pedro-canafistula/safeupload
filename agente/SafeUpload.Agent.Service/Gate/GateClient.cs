using System.Runtime.InteropServices;
using System.Text;

namespace SafeUpload.Agent.Service.Gate;

public enum GateApplyResult { Applied, Unavailable, Rejected }

/// <summary>Applies the existing v1 gate scope and checks the connection on unchanged-scope polls.</summary>
public sealed class GateClient : IDisposable
{
    public const string PortName = @"\SafeUploadGatePort";
    private readonly ILogger<GateClient> _logger;
    private readonly object _gate = new();
    private readonly IGateConnection _connection;
    private readonly Func<string, string?> _resolve;
    private readonly bool _enabled;
    private string? _appliedKey;

    public GateClient(ILogger<GateClient> logger)
        : this(logger, new NativeGateConnection(logger), ToNtPath, OperatingSystem.IsWindows()) { }

    internal GateClient(ILogger<GateClient> logger, IGateConnection connection, Func<string, string?> resolve, bool enabled = true)
    {
        _logger = logger;
        _connection = connection;
        _resolve = resolve;
        _enabled = enabled;
    }

    /// <summary>Local handle state only; it does not assert that the current scope was accepted.</summary>
    public bool IsConnected { get { lock (_gate) return _connection.IsConnected; } }

    public GateApplyResult Apply(IReadOnlyList<string> folders, bool removable, bool network)
    {
        if (!_enabled) return GateApplyResult.Unavailable;
        // Keep complete validation before connecting or starting the driver.
        var policy = GatePolicyMessage.Create(folders, removable, network, _resolve);
        lock (_gate)
        {
            if (!Connect()) return GateApplyResult.Unavailable;
            if (policy.Key == _appliedKey)
                return ReadCounters() is not null ? GateApplyResult.Applied : GateApplyResult.Unavailable;
            int hr = _connection.Send(policy.Bytes, null, out _);
            if (hr != 0)
            {
                _logger.LogWarning("Gate driver refused the policy (HRESULT 0x{Hr:X8}); reconnecting later", hr);
                Disconnect();
                return GateApplyResult.Rejected;
            }
            _appliedKey = policy.Key;
            _logger.LogInformation("Gate driver accepted {Count} folder(s), removable={Removable}, network={Network}",
                policy.PathCount, removable, network);
            return GateApplyResult.Applied;
        }
    }

    public (ulong Refused, ulong RenamesRefused)? Counters()
    {
        lock (_gate) return Connect() ? ReadCounters() : null;
    }

    private (ulong Refused, ulong RenamesRefused)? ReadCounters()
    {
        var request = new byte[8];
        BitConverter.TryWriteBytes(request.AsSpan(0), 2u);
        BitConverter.TryWriteBytes(request.AsSpan(4), GatePolicyMessage.ProtocolVersion);
        var reply = new byte[16];
        if (_connection.Send(request, reply, out uint returned) != 0 || returned != reply.Length)
        {
            Disconnect();
            return null;
        }
        return (BitConverter.ToUInt64(reply, 0), BitConverter.ToUInt64(reply, 8));
    }

    private bool Connect()
    {
        bool wasConnected = _connection.IsConnected;
        if (!_connection.Connect()) { _appliedKey = null; return false; }
        if (!wasConnected) _appliedKey = null;
        return true;
    }

    private void Disconnect()
    {
        _connection.Disconnect();
        _appliedKey = null;
    }

    public void Dispose() { lock (_gate) Disconnect(); }

    /// <summary>C:\Folder -> \Device\HarddiskVolume3\Folder (shares: \Device\Mup\server\share), the form the driver sees.</summary>
    internal static string? ToNtPath(string dosPath)
    {
        var full = Path.GetFullPath(dosPath).TrimEnd('\\');
        if (full.StartsWith(@"\\", StringComparison.Ordinal))
            return @"\Device\Mup" + full[1..];        // \\server\share -> \Device\Mup\server\share
        if (full.Length < 2 || full[1] != ':') return null;
        var device = new StringBuilder(1024);
        if (QueryDosDevice(full[..2], device, device.Capacity) == 0) return null;
        return device.ToString() + full[2..];
    }

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern uint QueryDosDevice(string deviceName, StringBuilder targetPath, int max);
}
