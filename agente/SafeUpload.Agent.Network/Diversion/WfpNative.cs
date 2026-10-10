using System.Runtime.InteropServices;

namespace SafeUpload.Agent.Network.Diversion;

/// <summary>
/// Declarações da API de gerenciamento da Windows Filtering Platform
/// (fwpuclnt.dll), só o necessário para criar filtros de bloqueio.
///
/// As estruturas seguem fwpmtypes.h e fwptypes.h com o layout de 64 bits;
/// as uniões do C viram campos do tamanho do maior membro.
/// </summary>
internal static class WfpNative
{
    /// <summary>Autenticação padrão do RPC com o serviço de filtragem.</summary>
    public const uint RpcAuthnDefault = 0xFFFFFFFF;

    /// <summary>Objetos da sessão somem quando ela é fechada (ou o processo morre).</summary>
    public const uint SessionFlagDynamic = 0x00000001;

    public const uint ActionBlock = 0x00000001 | 0x00001000; // FWP_ACTION_BLOCK | FWP_ACTION_FLAG_TERMINATING

    public const uint MatchEqual = 0;

    public const uint DataEmpty = 0;
    public const uint DataUInt8 = 1;
    public const uint DataUInt16 = 2;
    public const uint DataByteBlob = 12;

    public const byte ProtocolTcp = 6;
    public const byte ProtocolUdp = 17;

    /// <summary>FWPM_LAYER_ALE_AUTH_CONNECT_V4: decisão de abrir conexão de saída (IPv4).</summary>
    public static readonly Guid LayerAleAuthConnectV4 = new("c38d57d1-05a7-4c33-904f-7fbceee60e82");

    /// <summary>FWPM_LAYER_ALE_AUTH_CONNECT_V6: o mesmo, IPv6.</summary>
    public static readonly Guid LayerAleAuthConnectV6 = new("4a72393b-319f-44bc-84c3-ba54dcb3b6b4");

    /// <summary>FWPM_CONDITION_ALE_APP_ID: o executável que abre a conexão.</summary>
    public static readonly Guid ConditionAleAppId = new("d78e1e87-8644-4ea5-9437-d809ecefc971");

    /// <summary>FWPM_CONDITION_IP_REMOTE_PORT.</summary>
    public static readonly Guid ConditionIpRemotePort = new("c35a604d-d22b-4e1a-91b4-68f674ee674b");

    /// <summary>FWPM_CONDITION_IP_PROTOCOL.</summary>
    public static readonly Guid ConditionIpProtocol = new("3971ef2b-623e-4f9a-8cb1-6e79b806b9a7");

    [StructLayout(LayoutKind.Sequential)]
    public struct DisplayData
    {
        public IntPtr Name;
        public IntPtr Description;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct ByteBlob
    {
        public uint Size;
        public IntPtr Data;
    }

    /// <summary>FWP_VALUE0 / FWP_CONDITION_VALUE0: tipo + união de 8 bytes.</summary>
    [StructLayout(LayoutKind.Sequential)]
    public struct Value
    {
        public uint Type;
        public ulong Data;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct Session
    {
        public Guid SessionKey;
        public DisplayData DisplayData;
        public uint Flags;
        public uint TxnWaitTimeoutInMSec;
        public uint ProcessId;
        public IntPtr Sid;
        public IntPtr Username;
        public int KernelMode;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct SubLayer
    {
        public Guid SubLayerKey;
        public DisplayData DisplayData;
        public uint Flags;
        public IntPtr ProviderKey;
        public ByteBlob ProviderData;
        public ushort Weight;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct FilterCondition
    {
        public Guid FieldKey;
        public uint MatchType;
        public Value ConditionValue;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct Action
    {
        public uint Type;
        public Guid FilterType;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct Filter
    {
        public Guid FilterKey;
        public DisplayData DisplayData;
        public uint Flags;
        public IntPtr ProviderKey;
        public ByteBlob ProviderData;
        public Guid LayerKey;
        public Guid SubLayerKey;
        public Value Weight;
        public uint NumFilterConditions;
        public IntPtr FilterCondition;
        public Action Action;

        // união { UINT64 rawContext; GUID providerContextKey; }
        public ulong ContextLow;
        public ulong ContextHigh;

        public IntPtr Reserved;
        public ulong FilterId;
        public Value EffectiveWeight;
    }

    [DllImport("fwpuclnt.dll", CharSet = CharSet.Unicode)]
    public static extern uint FwpmEngineOpen0(
        string? serverName, uint authnService, IntPtr authIdentity, ref Session session, out IntPtr engineHandle);

    [DllImport("fwpuclnt.dll")]
    public static extern uint FwpmEngineClose0(IntPtr engineHandle);

    [DllImport("fwpuclnt.dll")]
    public static extern uint FwpmSubLayerAdd0(IntPtr engineHandle, ref SubLayer subLayer, IntPtr securityDescriptor);

    [DllImport("fwpuclnt.dll")]
    public static extern uint FwpmFilterAdd0(IntPtr engineHandle, ref Filter filter, IntPtr securityDescriptor, out ulong id);

    [DllImport("fwpuclnt.dll", CharSet = CharSet.Unicode)]
    public static extern uint FwpmGetAppIdFromFileName0(string fileName, out IntPtr appId);

    [DllImport("fwpuclnt.dll")]
    public static extern void FwpmFreeMemory0(ref IntPtr pointer);

    [DllImport("fwpuclnt.dll")]
    public static extern uint FwpmTransactionBegin0(IntPtr engineHandle, uint flags);

    [DllImport("fwpuclnt.dll")]
    public static extern uint FwpmTransactionCommit0(IntPtr engineHandle);

    [DllImport("fwpuclnt.dll")]
    public static extern uint FwpmTransactionAbort0(IntPtr engineHandle);
}
