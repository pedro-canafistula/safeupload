using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Text.Json.Serialization;

namespace SafeUpload.Agent.Core.Infrastructure;

/// <summary>Exactly HostRequest in the #96 contract. No former usuarioSo/manufacturer/serial fields.</summary>
public sealed record AgentHeartbeatHost(
    [property: JsonPropertyName("ip")] string Ip,
    [property: JsonPropertyName("mascara")] int Mask,
    [property: JsonPropertyName("hostname")] string Hostname,
    [property: JsonPropertyName("sistema_operacional")] string OperatingSystem,
    [property: JsonPropertyName("versao_so")] string OsVersion,
    [property: JsonPropertyName("mac_address")] string? MacAddress)
{
    public static AgentHeartbeatHost ForMachine(string ip, int mask)
    {
        string? mac = NetworkInterface.GetAllNetworkInterfaces()
            .FirstOrDefault(n => n.GetIPProperties().UnicastAddresses.Any(a => a.Address.ToString() == ip))?
            .GetPhysicalAddress().ToString();
        var host = new AgentHeartbeatHost(ip, mask, Environment.MachineName, "Windows",
            Environment.OSVersion.Version.ToString(), mac);
        host.EnsureValid();
        return host;
    }

    internal void EnsureValid()
    {
        if (!IPAddress.TryParse(Ip, out var parsed) || parsed.AddressFamily != AddressFamily.InterNetwork ||
            parsed.ToString() != Ip || Mask is < 0 or > 32 ||
            string.IsNullOrWhiteSpace(Hostname) || Hostname.Length > 100 ||
            string.IsNullOrWhiteSpace(OperatingSystem) || OperatingSystem.Length > 40 ||
            string.IsNullOrWhiteSpace(OsVersion) || OsVersion.Length > 20 || MacAddress?.Length > 20)
            throw new ArgumentException("Dados do host incompatíveis com o contrato AgentApi Ed25519.");
    }
}
