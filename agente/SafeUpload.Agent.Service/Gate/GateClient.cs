using System.Runtime.InteropServices;
using System.Text;
using Microsoft.Win32.SafeHandles;

namespace SafeUpload.Agent.Service.Gate;

/// <summary>
/// Talks to the gate minifilter (driver/SafeUpload.Minifilter). The driver refuses writes to the protected folders, and
/// optionally to removable and network volumes, for every process except the one holding this connection: the agent,
/// which publishes approved files. Layout must match driver/SafeUpload.Minifilter/GateProtocol.h.
/// Without the driver the agent still works; the folder ACLs then keep users from writing there directly.
/// </summary>
public sealed class GateClient : IDisposable
{
    public const string PortName = @"\SafeUploadGatePort";
    private const uint ProtocolVersion = GatePolicyMessage.ProtocolVersion;
    private const uint CommandGetCounters = 2;

    private readonly ILogger<GateClient> _logger;
    private readonly object _gate = new();
    private SafeFileHandle? _port;
    private string? _appliedKey;
    private bool _warned;

    public GateClient(ILogger<GateClient> logger) => _logger = logger;

    public bool IsConnected { get { lock (_gate) return _port is { IsInvalid: false, IsClosed: false }; } }

    /// <summary>Sends the protected folders (DOS paths) and volume flags, if they changed or after a reconnect.</summary>
    public void Apply(IReadOnlyList<string> folders, bool removable, bool network)
    {
        if (!OperatingSystem.IsWindows()) return;
        // Validate the complete scope before connecting, starting the driver or sending anything.
        var policy = GatePolicyMessage.Create(folders, removable, network, ToNtPath);
        var key = policy.Key;
        lock (_gate)
        {
            if (!Connect()) return;
            if (key == _appliedKey) return;
            var message = policy.Bytes;
            int hr = FilterSendMessage(_port!, message, (uint)message.Length, null, 0, out _);
            if (hr != 0)
            {
                _logger.LogWarning("Gate driver refused the policy (HRESULT 0x{Hr:X8}); reconnecting later", hr);
                Disconnect();
                return;
            }
            _appliedKey = key;
            _logger.LogInformation("Gate driver protects {Count} folder(s), removable={Removable}, network={Network}: {Paths}",
                policy.PathCount, removable, network, string.Join(", ", folders));
        }
    }

    /// <summary>Writes refused by the driver since it loaded, or null without the driver.</summary>
    public (ulong Refused, ulong RenamesRefused)? Counters()
    {
        lock (_gate)
        {
            if (!Connect()) return null;
            var request = new byte[8];
            BitConverter.TryWriteBytes(request.AsSpan(0), CommandGetCounters);
            BitConverter.TryWriteBytes(request.AsSpan(4), ProtocolVersion);
            var reply = new byte[16];
            if (FilterSendMessage(_port!, request, (uint)request.Length, reply, (uint)reply.Length, out uint returned) != 0 ||
                returned < 16)
                return null;
            return (BitConverter.ToUInt64(reply, 0), BitConverter.ToUInt64(reply, 8));
        }
    }

    private bool Connect()
    {
        if (_port is { IsInvalid: false, IsClosed: false }) return true;
        int hr = FilterConnectCommunicationPort(PortName, 0, IntPtr.Zero, 0, IntPtr.Zero, out var port);
        if (hr != 0)
        {
            // The gate is demand-start: start its driver service once (the service manager holds the load privilege).
            port.Dispose();
            try
            {
                using var driver = new System.ServiceProcess.ServiceController("SafeUpload");
                if (driver.Status == System.ServiceProcess.ServiceControllerStatus.Stopped)
                {
                    driver.Start();
                    driver.WaitForStatus(System.ServiceProcess.ServiceControllerStatus.Running, TimeSpan.FromSeconds(10));
                }
            }
            catch (Exception error) when (error is InvalidOperationException or System.ServiceProcess.TimeoutException
                or System.ComponentModel.Win32Exception)
            {
                _logger.LogWarning(error, "Could not start the gate driver");
            }
            for (int attempt = 0; attempt < 10; attempt++)
            {
                hr = FilterConnectCommunicationPort(PortName, 0, IntPtr.Zero, 0, IntPtr.Zero, out port);
                if (hr == 0) break;
                port.Dispose();
                Thread.Sleep(500);
            }
        }
        if (hr != 0)
        {
            port.Dispose();
            if (!_warned)
                _logger.LogWarning("Gate driver not available (HRESULT 0x{Hr:X8}); protected folders rely on their ACLs only", hr);
            _warned = true;
            return false;
        }
        _port = port;
        _appliedKey = null;
        _warned = false;
        _logger.LogInformation("Connected to the gate driver");
        return true;
    }

    private void Disconnect()
    {
        _port?.Dispose();
        _port = null;
        _appliedKey = null;
    }

    public void Dispose()
    {
        lock (_gate) Disconnect();
    }

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

    [DllImport("fltlib.dll", CharSet = CharSet.Unicode)]
    private static extern int FilterConnectCommunicationPort(string portName, uint options, IntPtr context,
        ushort sizeOfContext, IntPtr securityAttributes, out SafeFileHandle port);

    [DllImport("fltlib.dll")]
    private static extern int FilterSendMessage(SafeFileHandle port, byte[] inBuffer, uint inBufferSize,
        byte[]? outBuffer, uint outBufferSize, out uint bytesReturned);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern uint QueryDosDevice(string deviceName, StringBuilder targetPath, int max);
}
