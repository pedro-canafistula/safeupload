using System.Buffers.Binary;
using System.Net;
using System.Runtime.InteropServices;

namespace SafeUpload.Agent.Network.Proxy;

/// <summary>
/// Descobre qual processo abriu uma conexão com o proxy.
///
/// Para o proxy, todo cliente é só "127.0.0.1, porta 51234". A auditoria
/// precisa dizer "chrome.exe": o Windows sabe, porque mantém a tabela de
/// conexões TCP com o PID dono de cada uma (é a mesma informação do
/// <c>netstat -ano</c>). A busca é pela ponta do cliente: a conexão cuja
/// porta local é a porta de origem do navegador e cuja porta remota é a do proxy.
/// </summary>
public static class TcpConnectionOwner
{
    private const int AfInet = 2;
    private const int TcpTableOwnerPidConnections = 4;
    private const uint ErrorInsufficientBuffer = 122;

    /// <summary>
    /// PID do processo dono da conexão <paramref name="client"/> → <paramref name="server"/>,
    /// ou nulo se não for encontrada (a conexão pode ter fechado). Só IPv4,
    /// que é onde o proxy escuta.
    /// </summary>
    public static int? FindProcessId(IPEndPoint client, IPEndPoint server)
    {
        if (client.AddressFamily != System.Net.Sockets.AddressFamily.InterNetwork)
        {
            return null;
        }

        int size = 0;
        uint result = GetExtendedTcpTable(IntPtr.Zero, ref size, false, AfInet, TcpTableOwnerPidConnections, 0);

        if (result != ErrorInsufficientBuffer)
        {
            return null;
        }

        // A tabela pode crescer entre as duas chamadas; uma folga evita repetir.
        size += 4096;
        IntPtr table = Marshal.AllocHGlobal(size);

        try
        {
            if (GetExtendedTcpTable(table, ref size, false, AfInet, TcpTableOwnerPidConnections, 0) != 0)
            {
                return null;
            }

            int count = Marshal.ReadInt32(table);
            int rowSize = Marshal.SizeOf<MibTcpRowOwnerPid>();
            IntPtr row = table + 4;

            for (int i = 0; i < count; i++, row += rowSize)
            {
                MibTcpRowOwnerPid entry = Marshal.PtrToStructure<MibTcpRowOwnerPid>(row);

                if (Port(entry.LocalPort) == client.Port
                    && Port(entry.RemotePort) == server.Port
                    && entry.LocalAddr == AddressValue(client.Address)
                    && entry.RemoteAddr == AddressValue(server.Address))
                {
                    return (int)entry.OwningPid;
                }
            }

            return null;
        }
        finally
        {
            Marshal.FreeHGlobal(table);
        }
    }

    /// <summary>A porta vem em ordem de rede nos dois bytes baixos.</summary>
    private static int Port(uint networkOrder) => BinaryPrimitives.ReverseEndianness((ushort)networkOrder);

    private static uint AddressValue(IPAddress address) =>
        BitConverter.ToUInt32(address.GetAddressBytes(), 0);

    [StructLayout(LayoutKind.Sequential)]
    private struct MibTcpRowOwnerPid
    {
        public uint State;
        public uint LocalAddr;
        public uint LocalPort;
        public uint RemoteAddr;
        public uint RemotePort;
        public uint OwningPid;
    }

    [DllImport("iphlpapi.dll", SetLastError = true)]
    private static extern uint GetExtendedTcpTable(
        IntPtr table, ref int size, bool sort, int addressFamily, int tableClass, uint reserved);
}
