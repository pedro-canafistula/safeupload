using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

namespace SafeUpload.Agent.Service.Gate;

internal interface IGateConnection
{
    bool IsConnected { get; }
    bool Connect();
    int Send(byte[] request, byte[]? reply, out uint returned);
    void Disconnect();
}

/// <summary>The native connection and demand-start behavior, serialized by GateClient.</summary>
internal sealed class NativeGateConnection(ILogger<GateClient> logger) : IGateConnection
{
    private readonly ILogger<GateClient> _logger = logger;
    private SafeFileHandle? _port;
    private bool _warned;
    public bool IsConnected => _port is { IsInvalid: false, IsClosed: false };

    public bool Connect()
    {
        if (_port is { IsInvalid: false, IsClosed: false }) return true;
        if (!OperatingSystem.IsWindows()) return false;
        int hr = FilterConnectCommunicationPort(GateClient.PortName, 0, IntPtr.Zero, 0, IntPtr.Zero, out var port);
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
                hr = FilterConnectCommunicationPort(GateClient.PortName, 0, IntPtr.Zero, 0, IntPtr.Zero, out port);
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
        _warned = false;
        _logger.LogInformation("Connected to the gate driver");
        return true;
    }


    public int Send(byte[] request, byte[]? reply, out uint returned) =>
        FilterSendMessage(_port!, request, (uint)request.Length, reply, (uint)(reply?.Length ?? 0), out returned);

    public void Disconnect()
    {
        _port?.Dispose();
        _port = null;
    }

    [DllImport("fltlib.dll", CharSet = CharSet.Unicode)]
    private static extern int FilterConnectCommunicationPort(string portName, uint options, IntPtr context,
        ushort sizeOfContext, IntPtr securityAttributes, out SafeFileHandle port);

    [DllImport("fltlib.dll")]
    private static extern int FilterSendMessage(SafeFileHandle port, byte[] inBuffer, uint inBufferSize,
        byte[]? outBuffer, uint outBufferSize, out uint bytesReturned);

}
