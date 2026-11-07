using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Text.Json.Serialization;
using Microsoft.Win32;

namespace SafeUpload.Agent.Core.Infrastructure;

/// <summary>Dados da máquina mostrados no console (só exibição; a identidade é a chave Ed25519).</summary>
public sealed record AgentHeartbeatHost(
    [property: JsonPropertyName("ip")] string? Ip,
    [property: JsonPropertyName("mascara")] int? Mask,
    [property: JsonPropertyName("hostname")] string Hostname,
    [property: JsonPropertyName("sistema_operacional")] string OperatingSystem,
    [property: JsonPropertyName("versao_so")] string OsVersion,
    [property: JsonPropertyName("mac_address")] string? MacAddress)
{
    /// <summary>Detecta hostname, sistema e a interface IPv4 ativa com gateway (ou a primeira ativa).</summary>
    public static AgentHeartbeatHost Detect()
    {
        string? ip = null, mac = null;
        int? mask = null;
        try
        {
            var candidates = NetworkInterface.GetAllNetworkInterfaces()
                .Where(n => n.OperationalStatus == OperationalStatus.Up &&
                            n.NetworkInterfaceType is not (NetworkInterfaceType.Loopback or NetworkInterfaceType.Tunnel))
                .Select(n => (Nic: n, Props: n.GetIPProperties()))
                .Select(c => (c.Nic, c.Props, Address: c.Props.UnicastAddresses
                    .FirstOrDefault(a => a.Address.AddressFamily == AddressFamily.InterNetwork)))
                .Where(c => c.Address is not null)
                .OrderByDescending(c => c.Props.GatewayAddresses.Any(g => g.Address.AddressFamily == AddressFamily.InterNetwork))
                .ToList();
            if (candidates.FirstOrDefault() is { Address: { } address } best)
            {
                ip = address.Address.ToString();
                mask = address.PrefixLength;
                var bytes = best.Nic.GetPhysicalAddress().GetAddressBytes();
                mac = bytes.Length is 0 or > 6 ? null : string.Join(':', bytes.Select(b => b.ToString("X2")));
            }
        }
        catch (NetworkInformationException) { }

        var (system, version) = Windows();
        return new AgentHeartbeatHost(ip, mask, Truncate(Environment.MachineName, 100), Truncate(system, 60),
            Truncate(version, 40), mac);
    }

    private static (string System, string Version) Windows()
    {
        string version = Environment.OSVersion.Version.ToString();
        if (!System.OperatingSystem.IsWindows()) return (System.Runtime.InteropServices.RuntimeInformation.OSDescription, version);
        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Windows NT\CurrentVersion");
            string product = key?.GetValue("ProductName") as string ?? "Windows";
            string? display = key?.GetValue("DisplayVersion") as string;
            string? build = key?.GetValue("CurrentBuild") as string;
            return (product, string.Join(' ', new[] { display, build is null ? null : "build " + build }.Where(v => v is not null)));
        }
        catch (Exception error) when (error is System.Security.SecurityException or UnauthorizedAccessException or IOException)
        {
            return ("Windows", version);
        }
    }

    private static string Truncate(string value, int max) => value.Length <= max ? value : value[..max];

    internal void EnsureValid()
    {
        if (string.IsNullOrWhiteSpace(Hostname) || Hostname.Length > 100 || OperatingSystem.Length > 60 ||
            OsVersion.Length > 40 || Ip?.Length > 45 || Mask is < 0 or > 128 || MacAddress?.Length > 20)
            throw new ArgumentException("Dados do host fora dos limites do contrato.");
    }
}
